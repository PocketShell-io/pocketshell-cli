"""`gateway ssh --key NAME`: argv narrowing, refusals, and the private-agent
lifecycle against the real ssh-agent/ssh-add with a recording fake ssh.

The full path through a real sshd is tests/gateway/test_gateway_ssh_key_e2e.py.
"""

from __future__ import annotations

import os
import shutil
import tempfile
import time
from pathlib import Path

import pytest
from click.testing import CliRunner

from pocketshell.cli import cli
from pocketshell.gateway import client_cli, pins, sshcmd
from pocketshell.gateway.endpoint import resolve_endpoint
from pocketshell.keys import crypto, prompt, session, sshkeys, store

from gateway_keyblobs import ED25519_LINE

HAVE_AGENT = bool(shutil.which("ssh-agent") and shutil.which("ssh-add") and shutil.which("ssh"))
needs_agent = pytest.mark.skipif(not HAVE_AGENT, reason="OpenSSH ssh-agent/ssh-add unavailable")
PW = "device-password"


@pytest.fixture(autouse=True)
def fast_kdf(monkeypatch):
    monkeypatch.setattr(crypto, "KDF_ITERATIONS", 1000)


@pytest.fixture
def short_tmp(monkeypatch):
    """A short TMPDIR (unix socket paths are limited to ~104 bytes)."""
    base = tempfile.mkdtemp(prefix="pk", dir="/tmp")
    monkeypatch.setattr(tempfile, "tempdir", base)
    yield Path(base)
    shutil.rmtree(base, ignore_errors=True)


@pytest.fixture
def password(monkeypatch):
    seen = []

    def read(text):
        seen.append(text)
        return seen_value[0]

    seen_value = [PW]
    monkeypatch.setattr(prompt, "read_password", read)
    read.prompts = seen
    read.value = seen_value
    return read


@pytest.fixture
def logged_in(monkeypatch):
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
    pins.add_pin("home-lab", pins.parse_host_key(ED25519_LINE))


@pytest.fixture
def no_exec(monkeypatch):
    def fake(*_a):
        raise AssertionError("--key must not exec ssh (the agent needs cleanup)")

    monkeypatch.setattr(client_cli, "_exec_ssh", fake)


def _vault_key(name="lab", key_type="ed25519"):
    private, public = sshkeys.generate(key_type, name)
    with store.locked() as txn:
        txn.vault.entries[name] = store.new_entry(name, public, False, private, PW)
        txn.commit()
    return public


FAKE_SSH = """#!/bin/sh
# Records what a real ssh would get: the args and what the agent holds.
out={out}
printf '%s\\n' "$@" > "$out/argv"
for a in "$@"; do
  case "$a" in
    IdentityAgent=*) sock="${{a#IdentityAgent=}}" ;;
    IdentityFile=*) pub="${{a#IdentityFile=}}" ;;
  esac
done
SSH_AUTH_SOCK="$sock" ssh-add -L > "$out/agent_keys" 2>&1
cp "$pub" "$out/pub"
ls -ld "$(dirname "$sock")" > "$out/dirmode"
echo "$sock" > "$out/sock"
exit {code}
"""


@pytest.fixture
def fake_ssh(tmp_path, monkeypatch):
    out = tmp_path / "rec"
    out.mkdir()

    def install(code=0):
        script = tmp_path / "fake-ssh"
        script.write_text(FAKE_SSH.format(out=out, code=code))
        script.chmod(0o755)
        monkeypatch.setattr(sshcmd, "find_ssh", lambda: str(script))
        return out

    return install


def _agents_for(sock: str) -> list[int]:
    found = []
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            cmd = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
        except OSError:
            continue
        if sock.encode() in cmd:
            found.append(int(pid))
    return found


# --- argv narrowing -------------------------------------------------------------


def test_with_identity_agent_inserts_both_options_first(tmp_path):
    argv = sshcmd.build_ssh_argv(
        ssh="/usr/bin/ssh", device_id="home-lab", endpoint=resolve_endpoint(None, False),
        pin_file=tmp_path / "pins", python="/opt/py/bin/python3", extra=["--", "uptime"],
    )
    out = sshcmd.with_identity_agent(argv, "/tmp/d/agent.sock", "/tmp/d/key.pub")
    assert out[:7] == [
        "/usr/bin/ssh", "-F", "none",
        "-o", "IdentityAgent=/tmp/d/agent.sock", "-o", "IdentityFile=/tmp/d/key.pub",
    ]
    assert out[7:] == argv[3:]
    assert "IdentitiesOnly=yes" in out and "ForwardAgent=no" in out
    assert "-i" not in out


def test_with_identity_agent_refuses_unsafe_paths_and_dash_i(tmp_path):
    argv = sshcmd.build_ssh_argv(
        ssh="/usr/bin/ssh", device_id="home-lab", endpoint=resolve_endpoint(None, False),
        pin_file=tmp_path / "pins", python="/opt/py/bin/python3",
    )
    with pytest.raises(sshcmd.SshArgsError):
        sshcmd.with_identity_agent(argv, "/tmp/%d/agent.sock", "/tmp/d/key.pub")
    with pytest.raises(sshcmd.SshArgsError):
        sshcmd.with_identity_agent(argv, "/tmp/d/agent.sock", "relative.pub")
    key = tmp_path / "id"
    key.write_text("x")
    with_i = sshcmd.build_ssh_argv(
        ssh="/usr/bin/ssh", device_id="home-lab", endpoint=resolve_endpoint(None, False),
        pin_file=tmp_path / "pins", python="/opt/py/bin/python3", identity=str(key),
    )
    with pytest.raises(sshcmd.SshArgsError, match="-i"):
        sshcmd.with_identity_agent(with_i, "/tmp/d/agent.sock", "/tmp/d/key.pub")


# --- CLI refusals ---------------------------------------------------------------


def test_key_and_identity_are_mutually_exclusive(no_exec, password, tmp_path):
    result = CliRunner().invoke(
        cli, ["gateway", "ssh", "home-lab", "--key", "lab", "-i", str(tmp_path / "id")]
    )
    assert result.exit_code == 2
    assert "mutually exclusive" in result.output
    assert password.prompts == []


@needs_agent
def test_unknown_key_fails_before_any_prompt(no_exec, password, logged_in):
    result = CliRunner().invoke(cli, ["gateway", "ssh", "home-lab", "--key", "ghost"])
    assert result.exit_code == 1
    assert "no key named 'ghost'" in result.output
    assert password.prompts == []


@needs_agent
def test_not_logged_in_fails_before_the_password_prompt(no_exec, password):
    pins.add_pin("home-lab", pins.parse_host_key(ED25519_LINE))
    _vault_key()
    result = CliRunner().invoke(cli, ["gateway", "ssh", "home-lab", "--key", "lab"])
    assert result.exit_code == 3
    assert password.prompts == []


@needs_agent
def test_wrong_password_starts_nothing(no_exec, password, logged_in, monkeypatch):
    _vault_key()
    password.value[0] = "not-it"

    def boom(*_a, **_k):
        raise AssertionError("ssh-agent started despite a wrong password")

    monkeypatch.setattr(session, "_start_agent", boom)
    monkeypatch.setattr(session.tempfile, "mkdtemp", boom)
    result = CliRunner().invoke(cli, ["gateway", "ssh", "home-lab", "--key", "lab"])
    assert result.exit_code == 1
    assert "wrong device password" in result.output
    assert password.prompts == ["Device password for key 'lab': "]


# --- the agent lifecycle ----------------------------------------------------------


@needs_agent
@pytest.mark.parametrize("code", [0, 7])
def test_agent_holds_exactly_the_key_and_is_gone_after_ssh(
    no_exec, password, logged_in, fake_ssh, short_tmp, code
):
    public = _vault_key()
    rec = fake_ssh(code)
    result = CliRunner().invoke(
        cli, ["gateway", "ssh", "home-lab", "-l", "me", "--key", "lab", "--", "uptime"]
    )
    assert result.exit_code == code, result.output
    argv = (rec / "argv").read_text().splitlines()
    assert argv[:2] == ["-F", "none"]
    assert argv[2] == "-o" and argv[3].startswith("IdentityAgent=")
    assert argv[4] == "-o" and argv[5].startswith("IdentityFile=")
    assert "IdentitiesOnly=yes" in argv and "ForwardAgent=no" in argv
    assert argv[-1] == "uptime"
    # The private agent held exactly this key, and the .pub given to ssh is it.
    agent_keys = (rec / "agent_keys").read_text().splitlines()
    assert [k.split()[:2] for k in agent_keys] == [public.line.split()[:2]]
    assert (rec / "pub").read_text().split()[:2] == public.line.split()[:2]
    assert (rec / "dirmode").read_text().startswith("drwx------")
    sock = (rec / "sock").read_text().strip()
    assert sock.startswith(str(short_tmp))
    # Afterwards: socket dir removed, agent process gone, nothing left in TMPDIR.
    assert not os.path.exists(os.path.dirname(sock))
    assert _agents_for(sock) == []
    assert list(short_tmp.iterdir()) == []


@needs_agent
def test_failed_ssh_add_cleans_up(no_exec, password, logged_in, fake_ssh, short_tmp, monkeypatch):
    _vault_key()
    rec = fake_ssh(0)
    monkeypatch.setattr(session, "_tool", lambda name: "/bin/false" if name == "ssh-add"
                        else shutil.which(name))
    seen = {}
    real_start = session._start_agent

    def spy(agent, sock, lifetime):
        seen["sock"] = sock
        seen["lifetime"] = lifetime
        return real_start(agent, sock, lifetime)

    monkeypatch.setattr(session, "_start_agent", spy)
    result = CliRunner().invoke(cli, ["gateway", "ssh", "home-lab", "--key", "lab"])
    assert result.exit_code == 1
    assert "ssh-add could not load the key" in result.output
    assert not (rec / "argv").exists()  # ssh never ran
    assert seen["lifetime"] == session.KEY_LIFETIME_SECONDS
    assert _agents_for(seen["sock"]) == []
    assert list(short_tmp.iterdir()) == []


@needs_agent
def test_interrupt_while_loading_cleans_up(no_exec, password, logged_in, fake_ssh, short_tmp,
                                           monkeypatch):
    _vault_key()
    fake_ssh(0)
    seen = {}

    def interrupted(_bin, sock, key, _env):
        seen["sock"] = sock
        seen["key"] = key
        raise KeyboardInterrupt

    monkeypatch.setattr(session, "_add_key", interrupted)
    result = CliRunner().invoke(cli, ["gateway", "ssh", "home-lab", "--key", "lab"])
    assert result.exit_code == 1  # click: Aborted!
    assert _agents_for(seen["sock"]) == []
    assert list(short_tmp.iterdir()) == []
    assert seen["key"] == bytearray(len(seen["key"]))  # decrypted key wiped
