"""End to end: real `ssh` → `gateway proxy` → fake gateway → real local sshd.

Runs `pocketshell gateway ssh` exactly as a user would (subprocess, real
OpenSSH, ProxyCommand `python -P -m pocketshell gateway proxy …`). The fake
gateway bridges the WebSocket to an unprivileged sshd on 127.0.0.1 and
advertises a WRONG `ssh_host_key` in `ready` to prove the client ignores
it. A fake `pocketshell.account` is injected into the proxy subprocess via
`sitecustomize` on PYTHONPATH (the real account layer lands separately).
Skipped when sshd/ssh/ssh-keygen are unavailable or sshd cannot start.
"""

from __future__ import annotations

import getpass
import json
import os
import shutil
import socket
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path

import pytest

pytest.importorskip("websockets")

from websockets.exceptions import ConnectionClosed  # noqa: E402
from websockets.sync.server import serve  # noqa: E402

from conftest import FAKE_JWT  # noqa: E402
from gateway_keyblobs import ED25519_LINE  # noqa: E402
from pocketshell.gateway import pins  # noqa: E402

SSHD = shutil.which("sshd") or ("/usr/sbin/sshd" if os.path.exists("/usr/sbin/sshd") else None)
pytestmark = pytest.mark.skipif(
    not (SSHD and shutil.which("ssh") and shutil.which("ssh-keygen")),
    reason="OpenSSH server/client/ssh-keygen unavailable",
)

DEVICE = "e2e-host"

SITECUSTOMIZE = textwrap.dedent(
    """
    import dataclasses, sys, types
    m = types.ModuleType("pocketshell.account")
    class AccountError(Exception): pass
    class NotLoggedIn(AccountError): pass
    @dataclasses.dataclass(frozen=True)
    class GatewayToken:
        token: str
        expires_at: int
    m.AccountError, m.NotLoggedIn, m.GatewayToken = AccountError, NotLoggedIn, GatewayToken
    m.mint_gateway_token = lambda *, broker_url=None: GatewayToken({token!r}, 2000000000)
    m.broker_url = lambda: "https://broker.invalid"
    sys.modules["pocketshell.account"] = m
    """
)


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
    seen = {}

    def handle(ws):
        auth = json.loads(ws.recv(timeout=10))
        seen["auth"] = auth
        seen["path"] = ws.request.path
        # A hostile/compromised gateway's advertised key: must be ignored.
        ws.send(json.dumps({
            "type": "ready", "v": 1, "device_id": auth["device_id"],
            "ssh_host_key": ED25519_LINE,
        }))
        tcp = socket.create_connection(("127.0.0.1", sshd["port"]))

        def down():
            try:
                while True:
                    data = tcp.recv(32768)
                    if not data:
                        break
                    ws.send(data)
            except (OSError, ConnectionClosed):
                pass
            finally:
                try:
                    ws.close()
                except Exception:
                    pass

        t = threading.Thread(target=down, daemon=True)
        t.start()
        try:
            while True:
                msg = ws.recv()
                if isinstance(msg, str):
                    break
                tcp.sendall(msg)
        except ConnectionClosed:
            pass
        finally:
            try:
                tcp.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            tcp.close()
            t.join(5)

    server = serve(handle, "127.0.0.1", 0, compression=None)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield {"port": server.socket.getsockname()[1], "seen": seen}
    server.shutdown()


def _run_gateway_ssh(tmp_path, gateway, sshd, *command):
    site = tmp_path / "site"
    site.mkdir(exist_ok=True)
    (site / "sitecustomize.py").write_text(SITECUSTOMIZE.format(token=FAKE_JWT))
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True, exist_ok=True)
    # A hostile user config that -F none must neutralize.
    (home / ".ssh" / "config").write_text("Host *\n  StrictHostKeyChecking no\n  ForwardAgent yes\n")
    env = {k: v for k, v in os.environ.items() if k not in ("SSH_AUTH_SOCK", "PYTHONSAFEPATH")}
    env.update({
        "HOME": str(home),
        "PYTHONPATH": str(site),
        "XDG_CONFIG_HOME": os.environ["XDG_CONFIG_HOME"],
    })
    return subprocess.run(
        [
            sys.executable, "-m", "pocketshell", "gateway", "ssh", DEVICE,
            "-l", getpass.getuser(), "-i", str(sshd["client_key"]),
            "--server", f"ws://127.0.0.1:{gateway['port']}", "--insecure-dev",
            "--trust-gateway", "127.0.0.1",
            "--", *command,
        ],
        capture_output=True, env=env, cwd=tmp_path, timeout=60,
    )


def test_ssh_through_gateway_to_real_sshd(tmp_path, sshd, gateway):
    pins.add_pin(DEVICE, pins.parse_host_key(sshd["host_pub"]))
    proc = _run_gateway_ssh(tmp_path, gateway, sshd, "echo", "hello-through-gateway")
    assert proc.returncode == 0, proc.stderr.decode()
    assert proc.stdout == b"hello-through-gateway\n"
    assert gateway["seen"]["path"] == f"/api/v1/hosts/{DEVICE}/ssh"
    assert gateway["seen"]["auth"] == {
        "type": "auth", "v": 1, "token": FAKE_JWT, "device_id": DEVICE,
    }
    assert FAKE_JWT.encode() not in proc.stdout + proc.stderr


def test_wrong_pin_fails_closed_despite_gateway_advertisement(tmp_path, sshd, gateway):
    # Pin the key the gateway advertises (not the real sshd key): OpenSSH
    # must refuse, whatever the gateway or ~/.ssh/config say.
    pins.add_pin(DEVICE, pins.parse_host_key(ED25519_LINE))
    proc = _run_gateway_ssh(tmp_path, gateway, sshd, "echo", "must-not-run")
    assert proc.returncode == 255
    assert b"must-not-run" not in proc.stdout
    assert b"HOST IDENTIFICATION HAS CHANGED" in proc.stderr or b"verification failed" in proc.stderr
