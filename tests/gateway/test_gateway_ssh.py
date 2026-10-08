"""`gateway ssh`: the hardened OpenSSH argv, ProxyCommand quoting, refusals."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest
from click.testing import CliRunner

from gateway_keyblobs import ED25519_LINE
from pocketshell.cli import cli
from pocketshell.gateway import client_cli, pins, sshcmd
from pocketshell.gateway.endpoint import host_key_alias, resolve_endpoint
from pocketshell.gateway.sshcmd import SshArgsError, build_ssh_argv, parse_extra_args

PROD = resolve_endpoint(None, False)
LAB = resolve_endpoint("ws://127.0.0.1:8080", True, trust_gateway="127.0.0.1")
SSH = "/usr/bin/ssh"


def _argv(tmp_path, **kw):
    params = dict(
        ssh=SSH,
        device_id="home-lab",
        endpoint=PROD,
        pin_file=tmp_path / "pins",
        python="/opt/py/bin/python3",
    )
    params.update(kw)
    return build_ssh_argv(**params)


def _options(argv):
    """-o values in order, up to the `--` separator."""
    end = argv.index("--")
    return [argv[i + 1] for i in range(end) if argv[i] == "-o"]


def _proxy_argv(argv):
    pc = next(o for o in _options(argv) if o.startswith("ProxyCommand="))
    return shlex.split(pc[len("ProxyCommand="):].replace("%%", "%"))


def test_every_hardening_option_is_present_and_first(tmp_path):
    argv = _argv(tmp_path, user="me", extra=["-N", "-L", "8080:localhost:80", "--", "uptime"])
    assert argv[:3] == [SSH, "-F", "none"]
    opts = _options(argv)
    for required in (
        "StrictHostKeyChecking=yes",
        f"UserKnownHostsFile={tmp_path / 'pins'}",
        "GlobalKnownHostsFile=/dev/null",
        f"HostKeyAlias={host_key_alias('home-lab')}",
        "UpdateHostKeys=no",
        "ForwardAgent=no",
        "ForwardX11=no",
        "ForwardX11Trusted=no",
        "PermitLocalCommand=no",
        "ControlMaster=no",
        "ControlPath=none",
        "ControlPersist=no",
        "ProxyUseFdpass=no",
        "Tunnel=no",
        "CanonicalizeHostname=no",
        "VerifyHostKeyDNS=no",
        "PasswordAuthentication=no",
        "KbdInteractiveAuthentication=no",
        "GSSAPIAuthentication=no",
        "HostbasedAuthentication=no",
        "PreferredAuthentications=publickey",
        "IdentitiesOnly=yes",
        "CheckHostIP=no",
        "EnableEscapeCommandline=no",
        "Compression=no",
    ):
        assert required in opts, required
    assert opts.index("IgnoreUnknown=EnableEscapeCommandline") < opts.index(
        "EnableEscapeCommandline=no"
    )
    # forwards were requested, so ClearAllForwardings must not cancel them
    assert "ClearAllForwardings=yes" not in opts
    # every -o precedes every user-supplied flag (ssh: first value wins)
    last_o = max(i for i, a in enumerate(argv) if a == "-o")
    assert last_o < argv.index("-N")
    # destination after `--`, remote command after the destination
    assert argv[-3:] == ["--", host_key_alias("home-lab"), "uptime"]
    assert argv[argv.index("-l") + 1] == "me"


def test_clear_all_forwardings_without_user_forwards(tmp_path):
    assert "ClearAllForwardings=yes" in _options(_argv(tmp_path))
    assert "ClearAllForwardings=yes" in _options(_argv(tmp_path, extra=["-N", "-t"]))


def test_proxy_command_is_the_exact_pocketshell_argv(tmp_path):
    assert _proxy_argv(_argv(tmp_path)) == [
        "/opt/py/bin/python3", "-P", "-m", "pocketshell", "gateway", "proxy", "home-lab",
    ]
    assert _proxy_argv(_argv(tmp_path, endpoint=LAB, insecure_dev=True)) == [
        "/opt/py/bin/python3", "-P", "-m", "pocketshell", "gateway", "proxy", "home-lab",
        "--server", "ws://127.0.0.1:8080", "--trust-gateway", "127.0.0.1", "--insecure-dev",
    ]


def test_proxy_command_uses_no_ssh_tokens(tmp_path):
    pc = next(o for o in _options(_argv(tmp_path)) if o.startswith("ProxyCommand="))
    assert "%h" not in pc and "%n" not in pc and "%p" not in pc


def test_hostile_interpreter_path_survives_sh_and_ssh_token_quoting(tmp_path):
    """A python path full of shell/ssh metacharacters reaches exec intact."""
    weird_dir = tmp_path / "py dir $(touch PWNED) ; `id` 'q' %h %% {a,b} *"
    weird_dir.mkdir()
    record = tmp_path / "argv.json"
    fake_python = weird_dir / "python3"
    fake_python.write_text(
        "#!" + sys.executable + "\nimport json, sys\n"
        f"json.dump(sys.argv[1:], open({str(record)!r}, 'w'))\n"
    )
    fake_python.chmod(0o755)
    argv = _argv(tmp_path, python=str(fake_python))
    pc = next(o for o in _options(argv) if o.startswith("ProxyCommand="))[len("ProxyCommand="):]
    # what ssh does: %-expansion (%% → %), then `$SHELL -c "exec <cmd>"`, SHELL=/bin/sh
    expanded = pc.replace("%%", "%")
    subprocess.run(["/bin/sh", "-c", "exec " + expanded], cwd=tmp_path, check=True)
    assert json.loads(record.read_text()) == [
        "-P", "-m", "pocketshell", "gateway", "proxy", "home-lab",
    ]
    assert not (tmp_path / "PWNED").exists()


@pytest.mark.parametrize(
    "python", ["relative/python", "/opt/py\n/python", "/opt/py\\/python", ""]
)
def test_unusable_interpreter_paths_are_refused(tmp_path, python):
    with pytest.raises(SshArgsError):
        _argv(tmp_path, python=python)


@pytest.mark.parametrize(
    "device_id",
    ["-oProxyCommand=sh", "a b", "abc;id", "a%hb", "abc\n", "abc$(id)", "ab", "x*y*z"],
)
def test_hostile_device_ids_cannot_reach_ssh(tmp_path, device_id):
    with pytest.raises(ValueError):
        _argv(tmp_path, device_id=device_id)


@pytest.mark.parametrize(
    "name", ["pins file", "pins%d", "pins$HOME", "pins${HOME}", "~pins", "pi'ns", 'pi"ns', "pi\\ns", "pinš"]
)
def test_unsafe_pin_file_paths_are_refused(tmp_path, name):
    with pytest.raises(SshArgsError):
        _argv(tmp_path, pin_file=tmp_path / name)


@pytest.mark.parametrize("name", ["id key", "id%u", "id$X", "id~"])
def test_unsafe_identity_paths_are_refused(tmp_path, name):
    key = tmp_path / name
    key.write_text("k")
    with pytest.raises(SshArgsError):
        _argv(tmp_path, identity=str(key))


def test_identity_is_absolute_and_must_exist(tmp_path, monkeypatch):
    key = tmp_path / "id_ed25519"
    key.write_text("k")
    monkeypatch.chdir(tmp_path)
    argv = _argv(tmp_path, identity="id_ed25519")
    assert argv[argv.index("-i") + 1] == str(key)
    with pytest.raises(SshArgsError, match="does not exist"):
        _argv(tmp_path, identity="missing")


@pytest.mark.parametrize("user", ["-oProxyCommand=x", "a b", "me;id", "me%u", "me$X", ""])
def test_hostile_login_names_are_refused(tmp_path, user):
    with pytest.raises(SshArgsError):
        _argv(tmp_path, user=user)


@pytest.mark.parametrize(
    ("extra", "flags", "command"),
    [
        ([], [], []),
        (["-N"], ["-N"], []),
        (["-NT", "-vvv"], ["-NT", "-vvv"], []),
        (["-L8080:localhost:80"], ["-L", "8080:localhost:80"], []),
        (["-D", "1080", "-q"], ["-D", "1080", "-q"], []),
        (["uptime"], [], ["uptime"]),
        (["-t", "--", "-o", "x"], ["-t"], ["-o", "x"]),
        (["ls", "-la", "-oProxyCommand=x"], [], ["ls", "-la", "-oProxyCommand=x"]),
    ],
)
def test_allowlisted_extra_args(extra, flags, command):
    parsed = parse_extra_args(extra)
    assert parsed.flags == flags
    assert parsed.command == command


@pytest.mark.parametrize(
    "extra",
    [
        ["-o", "ProxyCommand=sh"],
        ["-oStrictHostKeyChecking=no"],
        ["-F", "/tmp/cfg"],
        ["-J", "jump"],
        ["-W", "h:22"],
        ["-A"],
        ["-X"],
        ["-Y"],
        ["-R", "8080:localhost:80"],
        ["-M"],
        ["-S", "/tmp/sock"],
        ["-w", "0"],
        ["-f"],
        ["-p", "22"],
        ["-E", "/tmp/log"],
        ["-NA"],
        ["-L"],
        ["-L", "-oProxyCommand=x"],
        ["-L", "8080:local host:80"],
        ["--help"],
    ],
)
def test_dangerous_extra_args_are_refused(extra):
    with pytest.raises(SshArgsError):
        parse_extra_args(extra)


def test_ssh_environment_forces_bin_sh():
    env = sshcmd.ssh_environment({"SHELL": "/usr/bin/fish", "PATH": "/bin"})
    assert env == {"SHELL": "/bin/sh", "PATH": "/bin"}


def test_python_dash_p_ignores_modules_in_cwd(tmp_path):
    """Why -P: a click.py in the cwd would otherwise run as the proxy."""
    (tmp_path / "click.py").write_text(
        "open('PWNED', 'w').close()\nraise SystemExit(99)\n"
    )
    env = {k: v for k, v in os.environ.items() if k != "PYTHONSAFEPATH"}
    with_p = subprocess.run(
        [sys.executable, "-P", "-m", "pocketshell", "gateway", "--help"],
        cwd=tmp_path, env=env, capture_output=True,
    )
    assert with_p.returncode == 0
    assert not (tmp_path / "PWNED").exists()
    without = subprocess.run(
        [sys.executable, "-m", "pocketshell", "gateway", "--help"],
        cwd=tmp_path, env=env, capture_output=True,
    )
    assert (tmp_path / "PWNED").exists() or without.returncode == 99


# --- real OpenSSH: the options are accepted and effective ----------------------


@pytest.mark.skipif(shutil.which("ssh") is None, reason="OpenSSH client unavailable")
def test_real_ssh_accepts_options_and_ignores_user_config(tmp_path):
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh" / "config").write_text(
        "Host *\n  ForwardAgent yes\n  ProxyJump evil\n  StrictHostKeyChecking no\n"
        "  LocalCommand touch /tmp/pwned\n  PermitLocalCommand yes\n"
    )
    ssh = os.path.abspath(shutil.which("ssh"))
    argv = _argv(tmp_path, ssh=ssh, device_id="home:lab_1", user="me",
                 extra=["-L", "8080:localhost:80"])
    out = subprocess.run(
        [argv[0], "-G", *argv[1:]], capture_output=True, text=True,
        env={**os.environ, "HOME": str(home)}, check=True,
    ).stdout
    conf = {}
    for line in out.splitlines():
        key, _, value = line.partition(" ")
        conf.setdefault(key, value)
    assert conf["forwardagent"] == "no"
    assert "proxyjump" not in conf or conf["proxyjump"] in ("none", "")
    assert conf["stricthostkeychecking"] in ("true", "yes")
    assert conf["permitlocalcommand"] == "no"
    assert conf["userknownhostsfile"] == str(tmp_path / "pins")
    assert conf["globalknownhostsfile"] == "/dev/null"
    assert conf["hostkeyalias"] == host_key_alias("home:lab_1")
    assert conf["identitiesonly"] == "yes"
    assert conf["passwordauthentication"] == "no"
    assert conf["kbdinteractiveauthentication"] == "no"
    assert conf["user"] == "me"
    assert conf["proxycommand"].startswith("/opt/py/bin/python3 -P -m pocketshell")


# --- CLI ------------------------------------------------------------------------


@pytest.fixture
def exec_ssh(monkeypatch):
    calls = []

    def fake(path, argv, env):
        calls.append((path, argv, env))
        raise SystemExit(0)

    monkeypatch.setattr(client_cli, "_exec_ssh", fake)
    return calls


@pytest.fixture
def logged_in(monkeypatch):
    """A real stored `pocketshell login` session (no broker is contacted:
    `gateway ssh` only checks it locally; the ProxyCommand mints)."""
    from pocketshell.account import credentials

    monkeypatch.delenv("POCKETSHELL_BROKER_URL", raising=False)
    credentials.save(
        credentials.Credentials(
            broker_url="https://broker.example",
            access_token="psc_" + "S" * 43,
            token_id="tok_1",
            email="me@example.com",
            expires_at=int(time.time()) + 3600,
            label="me@laptop",
        )
    )


def test_cli_refuses_without_a_pin_and_explains(exec_ssh):
    result = CliRunner().invoke(cli, ["gateway", "ssh", "home-lab"])
    assert result.exit_code == 1
    assert "gateway show --host-key" in result.output
    assert "pocketshell gateway pin home-lab" in result.output
    assert exec_ssh == []


def test_cli_refuses_an_untrusted_pin_file(exec_ssh):
    path = pins.pin_file_path()
    path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    path.write_text(
        f"pocketshell-gateway.home-lab {ED25519_LINE}\n@cert-authority * {ED25519_LINE}\n"
    )
    path.chmod(0o600)
    result = CliRunner().invoke(cli, ["gateway", "ssh", "home-lab"])
    assert result.exit_code == 1
    assert exec_ssh == []


@pytest.mark.skipif(shutil.which("ssh") is None, reason="OpenSSH client unavailable")
def test_cli_execs_hardened_ssh(exec_ssh, logged_in):
    pins.add_pin("home-lab", pins.parse_host_key(ED25519_LINE))
    result = CliRunner().invoke(
        cli, ["gateway", "ssh", "home-lab", "-l", "me", "--", "-N", "-D", "1080"]
    )
    assert result.exit_code == 0, result.output
    path, argv, env = exec_ssh[0]
    assert os.path.isabs(path) and argv[0] == path
    assert env["SHELL"] == "/bin/sh"
    assert f"UserKnownHostsFile={pins.pin_file_path()}" in argv
    assert argv[-2:] == ["--", host_key_alias("home-lab")]
    assert Path(_proxy_argv(argv)[0]) == Path(sys.executable)


@pytest.mark.parametrize(
    "args",
    [
        ["ssh", "home-lab", "-o", "StrictHostKeyChecking=no"],  # not a gateway ssh option
        ["ssh", "home-lab", "--", "-o", "StrictHostKeyChecking=no"],
        ["ssh", "home-lab", "--", "-A"],
        ["ssh", "-bad-id"],
        ["ssh", "home-lab", "--server", "wss://other.example"],
    ],
)
def test_cli_refusals(exec_ssh, args):
    pins.add_pin("home-lab", pins.parse_host_key(ED25519_LINE))
    result = CliRunner().invoke(cli, ["gateway", *args])
    assert result.exit_code == 2, result.output
    assert exec_ssh == []


@pytest.mark.skipif(shutil.which("ssh") is None, reason="OpenSSH client unavailable")
def test_cli_not_logged_in_is_exit_3_before_ssh(exec_ssh):
    # Without this preflight ssh would start, the ProxyCommand would exit 3
    # and the user would get ssh's generic 255 instead.
    pins.add_pin("home-lab", pins.parse_host_key(ED25519_LINE))
    result = CliRunner().invoke(cli, ["gateway", "ssh", "home-lab", "--", "uptime"])
    assert result.exit_code == client_cli.EXIT_NOT_LOGGED_IN, result.output
    assert "run `pocketshell login`" in result.output
    assert result.output.count("pocketshell login") == 1  # hint not repeated
    assert exec_ssh == []


@pytest.mark.skipif(shutil.which("ssh") is None, reason="OpenSSH client unavailable")
def test_cli_session_for_another_broker_is_exit_3_before_ssh(exec_ssh, logged_in, monkeypatch):
    monkeypatch.setenv("POCKETSHELL_BROKER_URL", "https://other-broker.example")
    pins.add_pin("home-lab", pins.parse_host_key(ED25519_LINE))
    result = CliRunner().invoke(cli, ["gateway", "ssh", "home-lab"])
    assert result.exit_code == client_cli.EXIT_NOT_LOGGED_IN, result.output
    assert "differs from the broker you logged in to" in result.output
    # the account layer's advice arrives whole, not cut at the gateway-text cap
    assert "run `pocketshell login --force` for that broker." in result.output
    assert exec_ssh == []


@pytest.mark.skipif(shutil.which("ssh") is None, reason="OpenSSH client unavailable")
def test_cli_expired_session_is_exit_3_before_ssh(exec_ssh, logged_in):
    from pocketshell.account import credentials

    creds = credentials.load()
    credentials.save(
        credentials.Credentials(**{**creds.__dict__, "expires_at": int(time.time()) - 1})
    )
    pins.add_pin("home-lab", pins.parse_host_key(ED25519_LINE))
    result = CliRunner().invoke(cli, ["gateway", "ssh", "home-lab"])
    assert result.exit_code == client_cli.EXIT_NOT_LOGGED_IN, result.output
    assert "expired" in result.output
    assert exec_ssh == []


@pytest.mark.skipif(shutil.which("ssh") is None, reason="OpenSSH client unavailable")
def test_cli_uses_the_alias_in_a_legacy_pin_file(exec_ssh, logged_in):
    path = pins.pin_file_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(f"pocketshell-gateway.home-lab {ED25519_LINE}\n")
    os.chmod(path, 0o600)
    result = CliRunner().invoke(cli, ["gateway", "ssh", "home-lab"])
    assert result.exit_code == 0, result.output
    _path, argv, _env = exec_ssh[0]
    assert "HostKeyAlias=pocketshell-gateway.home-lab" in argv
    assert argv[-2:] == ["--", "pocketshell-gateway.home-lab"]


def test_build_argv_refuses_a_foreign_alias(tmp_path):
    with pytest.raises(SshArgsError, match="alias"):
        _argv(tmp_path, alias=host_key_alias("other-host"))
