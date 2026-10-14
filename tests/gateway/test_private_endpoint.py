"""Private inetd endpoint init and enrollment integration."""
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from pocketshell.cli import cli
from pocketshell.gateway import helper, private_endpoint, status


@pytest.fixture
def endpoint_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(private_endpoint.sys, "platform", "linux")
    original = Path.is_file
    monkeypatch.setattr(Path, "is_file", lambda p: True if str(p) == "/usr/sbin/sshd" else original(p))
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
                 "Subsystem sftp internal-sftp", "LogLevel ERROR", "AllowUsers "]:
        assert rule in text
    assert 'Port ' not in text and 'ListenAddress ' not in text
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
    monkeypatch.setattr(status, "check_sshd_reachable", lambda *a, **k: pytest.fail("system TCP probe"))
    monkeypatch.setattr(status, "collect_clients_status", lambda *a, **k: pytest.fail("system auth logs"))
    doc = status.collect_gateway_status(config_dir=str(cfg), enumerate_sessions_fn=lambda: ([], []))
    assert not doc["sshd"]["reachable"]
    assert any("migrate" in error for error in doc["errors"])
