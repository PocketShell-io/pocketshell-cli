"""Private inetd endpoint init and enrollment integration."""
import json
import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from pocketshell.cli import cli
from pocketshell.gateway import helper, private_endpoint, status


@pytest.fixture
def endpoint_home(tmp_path, monkeypatch):
    if not hasattr(os, "getuid"):
        pytest.skip("Unix endpoint permission tests")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(private_endpoint.sys, "platform", "linux")
    original = Path.is_file
    monkeypatch.setattr(Path, "is_file", lambda p: True if str(p) == "/usr/sbin/sshd" else original(p))
    # Deterministic policy: the session environment depends on the machine.
    monkeypatch.setattr(private_endpoint, "session_env_lines", lambda: [])
    return tmp_path


def test_init_private_policy_and_idempotent_host_key(endpoint_home):
    argv = private_endpoint.init()
    assert argv[:3] == ["/usr/sbin/sshd", "-i", "-f"]
    config = Path(argv[3])
    directory = config.parent
    assert directory.stat().st_mode & 0o777 == 0o700
    assert config.stat().st_mode & 0o777 == 0o600
    assert (directory / "ssh_host_ed25519_key").stat().st_mode & 0o777 == 0o600
    public = (directory / "ssh_host_ed25519_key.pub").read_text()
    assert public.startswith("ssh-ed25519 ")
    text = config.read_text()
    for rule in ["PasswordAuthentication no", "KbdInteractiveAuthentication no", "PubkeyAuthentication yes",
                 "PermitRootLogin no", "UsePAM no", "StrictModes yes", "PidFile none",
                 "Subsystem sftp internal-sftp", "LogLevel ERROR", "AllowUsers ",
                 "AllowTcpForwarding local", "GatewayPorts no", "X11Forwarding no",
                 "AllowAgentForwarding no", "AllowStreamLocalForwarding no", "PermitTunnel no"]:
        assert rule in text
    assert 'Port ' not in text and 'ListenAddress ' not in text
    assert 'DisableForwarding yes' not in text
    assert str(endpoint_home / ".ssh/authorized_keys") in text
    assert private_endpoint.init() == argv
    assert (directory / "ssh_host_ed25519_key.pub").read_text() == public


def test_init_refuses_insecure_directory(endpoint_home):
    directory = private_endpoint.default_dir()
    directory.mkdir(parents=True, mode=0o755)
    with pytest.raises(private_endpoint.EndpointError, match="mode 700"):
        private_endpoint.init()


def test_init_refuses_missing_sshd(endpoint_home, monkeypatch):
    monkeypatch.setattr(Path, "is_file", lambda p: False)
    with pytest.raises(private_endpoint.EndpointError, match="No OpenSSH sshd"):
        private_endpoint.init()


def test_enroll_passes_exec_argv(endpoint_home, pin_helper, exec_calls):
    pin_helper("#!/bin/sh\nexit 0\n")
    result = CliRunner().invoke(cli, ["gateway", "enroll", "--token-stdin"])
    assert result.exit_code == 0, result.output
    argv = exec_calls[-1][1]
    assert "--ssh-host" not in argv
    assert json.loads(argv[argv.index("--ssh-exec") + 1]) == private_endpoint.init()


def test_migration_publishes_pin_before_config_replacement(endpoint_home, pin_helper, exec_calls):
    pin_helper("#!/bin/sh\nexit 0\n")
    config = endpoint_home / "enrollment"
    config.mkdir()
    (config / "config.json").write_text(json.dumps({"server": "wss://gateway.pocketshell.io",
                                                  "device_id": "device", "ssh_host": "127.0.0.1:22"}))
    result = CliRunner().invoke(cli, ["gateway", "endpoint", "migrate", "--config-dir", str(config),
                                    "--token-stdin"])
    assert result.exit_code == 0, result.output
    argv = exec_calls[-1][1]
    assert "--re-enroll" in argv and "--ssh-exec" in argv
    pin = argv[argv.index("--expect-host-key") + 1]
    assert pin.startswith("ssh-ed25519 ") and pin in result.output
    assert "--ssh-host" not in argv


def test_helper_refuses_port_22():
    with pytest.raises(ValueError, match="port 22"):
        helper.build_helper_argv("enroll", ssh_host="127.0.0.1:22")


def test_exec_status_never_probes_tcp_or_auth_logs(endpoint_home, monkeypatch):
    cfg = endpoint_home / "enrollment"
    cfg.mkdir()
    (cfg / "config.json").write_text(json.dumps({"device_id": "device", "server": "wss://example.org",
                                               "ssh_exec": ["/usr/sbin/sshd", "-i", "-f", "/private/config"]}))
    monkeypatch.setattr(status, "collect_agent_status", lambda *a, **k: (
        {"installed": True, "running": True, "connected": True}, []))
    monkeypatch.setattr(status, "live_link_configs", lambda: [])
    monkeypatch.setattr(status, "check_sshd_reachable", lambda *a, **k: pytest.fail("TCP probe"))
    monkeypatch.setattr(status, "collect_clients_status", lambda *a, **k: pytest.fail("system auth logs"))
    doc = status.collect_gateway_status(config_dir=str(cfg), enumerate_sessions_fn=lambda: ([], []))
    assert doc["endpoint"] == {"kind": "exec"}
    assert doc["state"] == "online"


def test_legacy_port_22_status_refuses_system_probe(endpoint_home, monkeypatch):
    cfg = endpoint_home / "enrollment"
    cfg.mkdir()
    (cfg / "config.json").write_text(json.dumps({"device_id": "device", "server": "wss://example.org",
                                               "ssh_host": "127.0.0.1:22"}))
    monkeypatch.setattr(status, "collect_agent_status", lambda *a, **k: (
        {"installed": True, "running": True, "connected": True}, []))
    monkeypatch.setattr(status, "live_link_configs", lambda: [])
    monkeypatch.setattr(status, "check_sshd_reachable", lambda *a, **k: pytest.fail("system TCP probe"))
    monkeypatch.setattr(status, "collect_clients_status", lambda *a, **k: pytest.fail("system auth logs"))
    doc = status.collect_gateway_status(config_dir=str(cfg), enumerate_sessions_fn=lambda: ([], []))
    assert not doc["sshd"]["reachable"]
    assert any("migrate" in error for error in doc["errors"])


def test_macos_endpoint_directory(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setattr(private_endpoint.sys, "platform", "darwin")
    assert private_endpoint.default_dir() == tmp_path / "Library/Application Support/PocketShell/endpoint"


def test_allowusers_refuses_pattern_names(endpoint_home, monkeypatch):
    import pwd
    from types import SimpleNamespace
    monkeypatch.setattr(pwd, "getpwuid", lambda uid: SimpleNamespace(pw_name="user[other]"))
    with pytest.raises(private_endpoint.EndpointError, match="unsupported account name"):
        private_endpoint.init()
    assert not (private_endpoint.default_dir() / "sshd_config").exists()


def test_init_upgrades_only_exact_previous_generated_config(endpoint_home):
    argv = private_endpoint.init()
    config = Path(argv[3])
    current = config.read_text()
    forwarding = ("AllowTcpForwarding local\nGatewayPorts no\nX11Forwarding no\n"
                  "AllowAgentForwarding no\nAllowStreamLocalForwarding no\nPermitTunnel no\n")
    legacy = current.replace(forwarding, "DisableForwarding yes\n")
    public_path = config.parent / "ssh_host_ed25519_key.pub"
    public = public_path.read_text()
    config.write_text(legacy)
    assert private_endpoint.init() == argv
    assert config.read_text() == current
    assert config.stat().st_mode & 0o777 == 0o600
    assert public_path.read_text() == public
    custom = legacy + "# operator customization\n"
    config.write_text(custom)
    private_endpoint.init()
    assert config.read_text() == custom


def test_keygen_never_reads_enrollment_stdin(endpoint_home, monkeypatch):
    real_run = private_endpoint.subprocess.run
    calls = []
    def run(argv, **kwargs):
        calls.append(kwargs["stdin"])
        return real_run(argv, **kwargs)
    monkeypatch.setattr(private_endpoint.subprocess, "run", run)
    private_endpoint.init()
    assert calls == [private_endpoint.subprocess.DEVNULL]


def test_session_env_gives_sessions_the_user_runtime_dir(tmp_path, monkeypatch):
    if not hasattr(os, "getuid"):
        pytest.skip("Unix only")
    monkeypatch.setattr(private_endpoint.sys, "platform", "linux")
    runtime = tmp_path / str(os.getuid())
    assert private_endpoint.session_env_lines(tmp_path, (9, 6)) == []  # no runtime dir: nothing
    runtime.mkdir()
    assert private_endpoint.session_env_lines(tmp_path, (9, 6)) == [f"SetEnv XDG_RUNTIME_DIR={runtime}"]
    (runtime / "bus").touch()
    assert private_endpoint.session_env_lines(tmp_path, (9, 6)) == [
        f"SetEnv XDG_RUNTIME_DIR={runtime} DBUS_SESSION_BUS_ADDRESS=unix:path={runtime}/bus"]
    assert private_endpoint.session_env_lines(tmp_path, (8, 6)) == []  # SetEnv needs OpenSSH 8.7+
    monkeypatch.setattr(private_endpoint.sys, "platform", "darwin")
    assert private_endpoint.session_env_lines(tmp_path, (9, 6)) == []


def test_init_adds_session_env_to_an_untouched_generated_config(endpoint_home, monkeypatch):
    argv = private_endpoint.init()
    config = Path(argv[3])
    without_env = config.read_text()
    line = "SetEnv XDG_RUNTIME_DIR=/run/user/1000"
    monkeypatch.setattr(private_endpoint, "session_env_lines", lambda: [line])
    assert private_endpoint.init() == argv
    assert config.read_text() == without_env + line + "\n"
    custom = without_env + "# operator customization\n"
    config.write_text(custom)
    private_endpoint.init()
    assert config.read_text() == custom
