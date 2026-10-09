"""End to end: `pocketshell login` → `gateway pin` → `gateway ssh` → real sshd.

Every step runs the real CLI as a subprocess, exactly as a user would, with
nothing monkeypatched inside pocketshell:

1. `pocketshell login --no-open` performs the device flow against the
   local fake broker (tests/fake_broker.py: pending once, then approved)
   and stores a real psc_ CLI session in an isolated XDG_CONFIG_HOME;
2. `pocketshell gateway pin` trusts the sshd host key, read from stdin;
3. `pocketshell gateway ssh` execs real OpenSSH, whose ProxyCommand
   (`python -P -m pocketshell gateway proxy …`) mints a broker JWT through
   `POST /cli/gateway/token` with the psc_ bearer and bridges to a fake
   gateway, which forwards to an unprivileged sshd on 127.0.0.1. The fake
   gateway advertises a WRONG `ssh_host_key` in `ready` to prove the client
   ignores it.
4. `pocketshell logout`, after which `gateway ssh` refuses with exit 3
   before ssh (or the gateway) is ever started.

Skipped when sshd/ssh/ssh-keygen are unavailable or sshd cannot start.
"""

from __future__ import annotations

import getpass
import os
import shutil
import socket
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

pytest.importorskip("websockets")

from fake_gateway import BridgeGateway  # noqa: E402
from gateway_keyblobs import ED25519_LINE  # noqa: E402
from tests.fake_broker import DEVICE_CODE, SESSION_TOKEN  # noqa: E402

SSHD = shutil.which("sshd") or ("/usr/sbin/sshd" if os.path.exists("/usr/sbin/sshd") else None)
pytestmark = pytest.mark.skipif(
    not (SSHD and shutil.which("ssh") and shutil.which("ssh-keygen")),
    reason="OpenSSH server/client/ssh-keygen unavailable",
)

DEVICE = "e2e-host"
EXIT_NOT_LOGGED_IN = 3


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _keygen(path: Path) -> str:
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", str(path)],
        check=True,
    )
    return " ".join(path.with_suffix(".pub").read_text().split()[:2])


@pytest.fixture
def sshd(tmp_path):
    d = tmp_path / "sshd"
    d.mkdir()
    host_pub = _keygen(d / "host_key")
    client_pub = _keygen(tmp_path / "client_key")
    (d / "authorized_keys").write_text(client_pub + "\n")
    os.chmod(d / "authorized_keys", 0o600)
    port = _free_port()
    (d / "sshd_config").write_text(
        textwrap.dedent(
            f"""
            Port {port}
            ListenAddress 127.0.0.1
            HostKey {d / 'host_key'}
            PidFile none
            AuthorizedKeysFile {d / 'authorized_keys'}
            StrictModes no
            UsePAM no
            PubkeyAuthentication yes
            AuthenticationMethods publickey
            PasswordAuthentication no
            KbdInteractiveAuthentication no
            """
        )
    )
    proc = subprocess.Popen(
        [SSHD, "-D", "-e", "-f", str(d / "sshd_config")],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            pytest.skip(f"sshd could not start: {proc.stderr.read().decode()[-300:]}")
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
            break
        except OSError:
            time.sleep(0.05)
    else:
        proc.kill()
        pytest.skip("sshd did not start listening")
    yield {"port": port, "host_pub": host_pub, "client_key": tmp_path / "client_key"}
    proc.kill()
    proc.wait()


@pytest.fixture
def gateway(sshd):
    gw = BridgeGateway(sshd["port"])
    yield {"port": gw.port, "seen": gw.seen}
    gw.close()


def _env(tmp_path) -> dict:
    """The user's environment: isolated HOME/XDG, the fake broker selected
    by POCKETSHELL_BROKER_URL + POCKETSHELL_BROKER_INSECURE_DEV=1 (set by
    the fake_broker fixture), no ssh-agent."""
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True, exist_ok=True)
    # A hostile user config that -F none must neutralize.
    (home / ".ssh" / "config").write_text("Host *\n  StrictHostKeyChecking no\n  ForwardAgent yes\n")
    env = {k: v for k, v in os.environ.items() if k not in ("SSH_AUTH_SOCK", "PYTHONSAFEPATH")}
    env["HOME"] = str(home)
    assert env["POCKETSHELL_BROKER_INSECURE_DEV"] == "1"
    assert env["POCKETSHELL_BROKER_URL"].startswith("http://127.0.0.1:")
    return env


def _pocketshell(tmp_path, *args, stdin: bytes = b"") -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "pocketshell", *args],
        input=stdin, capture_output=True, env=_env(tmp_path), cwd=tmp_path, timeout=60,
    )


def _gateway_ssh(tmp_path, gateway, sshd, *command) -> subprocess.CompletedProcess:
    return _pocketshell(
        tmp_path,
        "gateway", "ssh", DEVICE,
        "-l", getpass.getuser(), "-i", str(sshd["client_key"]),
        "--server", f"ws://127.0.0.1:{gateway['port']}", "--insecure-dev",
        "--trust-gateway", "127.0.0.1",
        "--", *command,
    )


def _assert_no_secrets(proc: subprocess.CompletedProcess, broker) -> None:
    out = proc.stdout + proc.stderr
    for secret in (SESSION_TOKEN, DEVICE_CODE, broker.gateway_jwt):
        assert secret.encode() not in out


@pytest.fixture
def logged_in(tmp_path, fake_broker):
    """`pocketshell login --no-open` for real, against the fake broker."""
    fake_broker.start_response["interval"] = 1  # pending once, then approved
    proc = _pocketshell(tmp_path, "login", "--no-open", "--label", "e2e@laptop")
    assert proc.returncode == 0, proc.stderr.decode()
    assert b"BCDF-GHJK" in proc.stdout
    assert b"Logged in as me@example.com." in proc.stdout
    _assert_no_secrets(proc, fake_broker)
    assert [r["path"] for r in fake_broker.requests] == [
        "/auth/device/start", "/auth/device/token", "/auth/device/token", "/cli/session",
    ]
    fake_broker.requests.clear()
    return fake_broker


def _pin(tmp_path, key_line: str) -> None:
    proc = _pocketshell(tmp_path, "gateway", "pin", DEVICE, stdin=key_line.encode() + b"\n")
    assert proc.returncode == 0, proc.stderr.decode()
    assert proc.stdout.startswith(f"pinned {DEVICE}: SHA256:".encode())


def test_login_pin_ssh_logout_through_gateway_to_real_sshd(tmp_path, sshd, gateway, logged_in):
    broker = logged_in
    _pin(tmp_path, sshd["host_pub"])

    proc = _gateway_ssh(tmp_path, gateway, sshd, "echo", "hello-through-gateway")
    assert proc.returncode == 0, proc.stderr.decode()
    assert proc.stdout == b"hello-through-gateway\n"
    _assert_no_secrets(proc, broker)

    # The proxy minted the broker JWT with the psc_ session as bearer …
    [mint] = broker.requests_to("/cli/gateway/token")
    assert mint["method"] == "POST" and mint["body"] == b""
    assert mint["headers"]["Authorization"] == f"Bearer {SESSION_TOKEN}"
    # … and the gateway saw exactly that JWT, never the session token.
    assert gateway["seen"]["path"] == f"/api/v1/hosts/{DEVICE}/ssh"
    assert gateway["seen"]["auth"] == {
        "type": "auth", "v": 1, "token": broker.gateway_jwt, "device_id": DEVICE,
    }
    assert SESSION_TOKEN not in gateway["seen"]["raw"]
    assert SESSION_TOKEN not in gateway["seen"]["headers"]
    assert "psc_" not in gateway["seen"]["raw"] + gateway["seen"]["headers"]
    assert gateway["seen"]["connections"] == 1

    proc = _pocketshell(tmp_path, "logout")
    assert proc.returncode == 0, proc.stderr.decode()
    assert proc.stdout == b"Logged out.\n"
    _assert_no_secrets(proc, broker)
    assert broker.logged_out
    [revoke] = broker.requests_to("/cli/logout")
    assert revoke["headers"]["Authorization"] == f"Bearer {SESSION_TOKEN}"

    broker.requests.clear()
    proc = _gateway_ssh(tmp_path, gateway, sshd, "echo", "must-not-run")
    assert proc.returncode == EXIT_NOT_LOGGED_IN, proc.stderr.decode()
    assert b"must-not-run" not in proc.stdout
    assert b"pocketshell login" in proc.stderr
    _assert_no_secrets(proc, broker)
    assert gateway["seen"]["connections"] == 1  # the gateway was never contacted
    assert broker.requests == []  # nor the broker: there is no session to use


def test_wrong_pin_fails_closed_despite_gateway_advertisement(tmp_path, sshd, gateway, logged_in):
    # Pin the key the gateway advertises (not the real sshd key): OpenSSH
    # must refuse, whatever the gateway or ~/.ssh/config say.
    _pin(tmp_path, ED25519_LINE)
    proc = _gateway_ssh(tmp_path, gateway, sshd, "echo", "must-not-run")
    assert proc.returncode == 255
    assert b"must-not-run" not in proc.stdout
    assert b"HOST IDENTIFICATION HAS CHANGED" in proc.stderr or b"verification failed" in proc.stderr
    _assert_no_secrets(proc, logged_in)
    assert gateway["seen"]["auth"]["token"] == logged_in.gateway_jwt
