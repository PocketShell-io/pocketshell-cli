"""`gateway proxy` (the ssh ProxyCommand bridge) against a local fake gateway.

The fake speaks the pocketshell-gateway client route
(`/api/v1/hosts/<id>/ssh`, JSON auth → ready/error, then binary bytes) and
is scripted per test to misbehave the ways a compromised gateway could.
"""

from __future__ import annotations

import io
import json
import os
import socket
import threading
import time

import pytest

pytest.importorskip("websockets")

from websockets.exceptions import ConnectionClosed  # noqa: E402
from websockets.sync.server import serve  # noqa: E402

from click.testing import CliRunner  # noqa: E402
from conftest import FAKE_JWT  # noqa: E402
from pocketshell.cli import cli  # noqa: E402
from pocketshell.gateway import proxy as gw_proxy  # noqa: E402
from pocketshell.gateway.endpoint import resolve_endpoint  # noqa: E402

DEVICE = "home-lab"
HOSTKEY_SENTINEL = "ssh-ed25519 AAAAGATEWAYCLAIMEDKEYSENTINEL"


def ready(device=DEVICE, **extra):
    doc = {"type": "ready", "v": 1, "device_id": device, "ssh_host_key": HOSTKEY_SENTINEL}
    doc.update(extra)
    return json.dumps(doc)


class FakeGateway:
    def __init__(self, script):
        self.script = script
        self.auth_raw = None
        self.path = None
        self.headers = None
        self.received = []  # binary messages from the client
        self.received_text_after_auth = []
        self.done = threading.Event()
        self.server = serve(
            self._handle, "127.0.0.1", 0, compression=None, max_size=1 << 22
        )
        self.port = self.server.socket.getsockname()[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def _handle(self, ws):
        self.path = ws.request.path
        self.headers = ws.request.headers
        try:
            self.auth_raw = ws.recv(timeout=5)
            self.script(ws, self)
        except ConnectionClosed:
            pass
        finally:
            self.done.set()

    def drain(self, ws):
        """Collect client binary messages until the client closes."""
        try:
            while True:
                msg = ws.recv()
                if isinstance(msg, str):
                    self.received_text_after_auth.append(msg)
                else:
                    self.received.append(msg)
        except ConnectionClosed:
            pass

    @property
    def endpoint(self):
        return resolve_endpoint(
            f"ws://127.0.0.1:{self.port}", True, trust_gateway="127.0.0.1"
        )

    def close(self):
        self.server.shutdown()


class Run:
    """run_proxy in a thread with pipe-backed stdin/stdout."""

    def __init__(self, gateway_endpoint, provider, timeout=5.0):
        self.in_r, self.in_w = os.pipe()
        self.out_r, self.out_w = os.pipe()
        self.stderr = io.StringIO()
        self.stdout = bytearray()
        self.code = None
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._reader.start()

        def target():
            self.code = gw_proxy.run_proxy(
                DEVICE, gateway_endpoint, provider,
                stdin_fd=self.in_r, stdout_fd=self.out_w,
                stderr=self.stderr, handshake_timeout=timeout,
            )
            os.close(self.out_w)

        self.thread = threading.Thread(target=target, daemon=True)
        self.thread.start()

    def _read(self):
        while True:
            chunk = os.read(self.out_r, 65536)
            if not chunk:
                return
            self.stdout.extend(chunk)

    def send_stdin(self, data: bytes):
        view = memoryview(data)
        while view:
            view = view[os.write(self.in_w, view):]

    def close_stdin(self):
        if self.in_w is not None:
            os.close(self.in_w)
            self.in_w = None

    def wait(self, timeout=15):
        self.thread.join(timeout)
        assert not self.thread.is_alive(), "proxy did not finish"
        self._reader.join(5)
        self.close_stdin()
        return self.code


@pytest.fixture
def gateway_factory():
    made = []

    def make(script):
        gw = FakeGateway(script)
        made.append(gw)
        return gw

    yield make
    for gw in made:
        gw.close()


@pytest.fixture
def provider(fake_account):
    return fake_account.module.mint_gateway_token


def test_bytes_are_pumped_intact_both_ways(gateway_factory, provider):
    down = os.urandom(150_000)

    def script(ws, gw):
        ws.send(ready())
        for i in range(0, len(down), 32768):
            ws.send(down[i:i + 32768])
        gw.drain(ws)

    gw = gateway_factory(script)
    run = Run(gw.endpoint, provider)
    up = os.urandom(300_001)
    run.send_stdin(up)
    # wait until the downstream bytes all arrived, then end the session
    deadline = time.monotonic() + 10
    while len(run.stdout) < len(down) and time.monotonic() < deadline:
        time.sleep(0.01)
    run.close_stdin()
    assert run.wait() == gw_proxy.EXIT_OK, run.stderr.getvalue()
    gw.done.wait(5)
    assert bytes(run.stdout) == down
    assert b"".join(gw.received) == up
    assert all(len(m) <= 32 * 1024 for m in gw.received)
    assert gw.received_text_after_auth == []
    # wire contract: exact route, no query, no Origin, auth as first TEXT frame
    assert gw.path == f"/api/v1/hosts/{DEVICE}/ssh"
    assert "Origin" not in gw.headers
    assert isinstance(gw.auth_raw, str)
    assert json.loads(gw.auth_raw) == {
        "type": "auth", "v": 1, "token": FAKE_JWT, "device_id": DEVICE,
    }
    # the gateway's advertised host key is never echoed anywhere
    assert HOSTKEY_SENTINEL not in run.stderr.getvalue()
    assert FAKE_JWT not in run.stderr.getvalue()


def test_remote_normal_close_after_ready_exits_0(gateway_factory, provider):
    def script(ws, gw):
        ws.send(ready())
        ws.send(b"SSH-2.0-x\r\n")
        ws.close(1000)

    gw = gateway_factory(script)
    run = Run(gw.endpoint, provider)
    assert run.wait() == gw_proxy.EXIT_OK
    assert bytes(run.stdout) == b"SSH-2.0-x\r\n"


def test_abnormal_drop_after_ready_is_connection_lost(gateway_factory, provider):
    def script(ws, gw):
        ws.send(ready())
        ws.socket.shutdown(socket.SHUT_RDWR)

    gw = gateway_factory(script)
    run = Run(gw.endpoint, provider)
    assert run.wait() == gw_proxy.EXIT_LOST
    assert "lost" in run.stderr.getvalue()


def test_mismatched_ready_device_is_rejected(gateway_factory, provider):
    def script(ws, gw):
        ws.send(ready(device="other-host"))
        ws.send(b"must never reach stdout")
        gw.drain(ws)

    gw = gateway_factory(script)
    run = Run(gw.endpoint, provider)
    assert run.wait() == gw_proxy.EXIT_PROTOCOL
    assert bytes(run.stdout) == b""
    assert "different device" in run.stderr.getvalue()


@pytest.mark.parametrize(
    ("close_code", "exit_code"),
    [
        (4400, gw_proxy.EXIT_PROTOCOL),
        (4401, gw_proxy.EXIT_UNAUTHORIZED),
        (4403, gw_proxy.EXIT_UNAUTHORIZED),
        (4404, gw_proxy.EXIT_NOT_FOUND),
        (4408, gw_proxy.EXIT_TIMEOUT),
        (4429, gw_proxy.EXIT_QUOTA),
        (4503, gw_proxy.EXIT_HOST_OFFLINE),
    ],
)
def test_error_frames_map_close_codes_and_are_sanitized(
    gateway_factory, provider, close_code, exit_code
):
    hostile = (
        "host \x1b[31mred\x1b[0m \x1b]0;title\x07 \x9b2J ‮gnp.exe​\r\n"
        "pocketshell: fake prompt " + "A" * 5000
    )

    def script(ws, gw):
        ws.send(json.dumps({"type": "error", "v": 1, "code": "x\x1b[2Jy", "message": hostile}))
        ws.close(close_code, "e")

    gw = gateway_factory(script)
    run = Run(gw.endpoint, provider)
    assert run.wait() == exit_code
    err = run.stderr.getvalue()
    assert bytes(run.stdout) == b""
    assert "gateway refused: xy: host red" in err
    for bad in ("\x1b", "\x07", "\x9b", "‮", "​", "\r"):
        assert bad not in err
    assert err.count("\n") == 1  # one diagnostic line, no injected lines
    assert len(err) < 400


def test_error_code_classifies_when_close_code_is_missing(gateway_factory, provider):
    def script(ws, gw):
        ws.send(json.dumps({"type": "error", "v": 1, "code": "host_offline", "message": "m"}))
        time.sleep(3)

    gw = gateway_factory(script)
    run = Run(gw.endpoint, provider)
    assert run.wait() == gw_proxy.EXIT_HOST_OFFLINE


def test_binary_before_ready_is_rejected(gateway_factory, provider):
    def script(ws, gw):
        ws.send(b"SSH-2.0-sneaky\r\n")
        gw.drain(ws)

    gw = gateway_factory(script)
    run = Run(gw.endpoint, provider)
    assert run.wait() == gw_proxy.EXIT_PROTOCOL
    assert bytes(run.stdout) == b""


def test_text_after_ready_aborts(gateway_factory, provider):
    def script(ws, gw):
        ws.send(ready())
        ws.send(b"before")
        ws.send(json.dumps({"type": "ready", "v": 1}))
        ws.send(b"after")
        gw.drain(ws)

    gw = gateway_factory(script)
    run = Run(gw.endpoint, provider)
    assert run.wait() == gw_proxy.EXIT_PROTOCOL
    assert bytes(run.stdout) == b"before"
    assert "text message after ready" in run.stderr.getvalue()


def test_oversize_binary_message_aborts(gateway_factory, provider):
    def script(ws, gw):
        ws.send(ready())
        ws.send(b"x" * (gw_proxy.MAX_MESSAGE_BYTES + 1))
        gw.drain(ws)

    gw = gateway_factory(script)
    run = Run(gw.endpoint, provider)
    assert run.wait() == gw_proxy.EXIT_PROTOCOL
    assert bytes(run.stdout) == b""
    assert "oversize" in run.stderr.getvalue()


def test_oversize_control_frame_is_rejected(gateway_factory, provider):
    def script(ws, gw):
        ws.send(ready(pad="p" * (gw_proxy.MAX_CONTROL_BYTES + 10)))
        gw.drain(ws)

    gw = gateway_factory(script)
    run = Run(gw.endpoint, provider)
    assert run.wait() == gw_proxy.EXIT_PROTOCOL


@pytest.mark.parametrize(
    "frame",
    [
        "not json",
        "[]",
        '{"type":"ready","v":1,"device_id":"home-lab","ssh_host_key":"","extra":1}',
        '{"type":"ready","v":1,"device_id":"home-lab"}',
        '{"type":"ready","v":true,"device_id":"home-lab","ssh_host_key":""}',
        '{"type":"ready","v":1.0,"device_id":"home-lab","ssh_host_key":""}',
        '{"type":"ready","v":2,"device_id":"home-lab","ssh_host_key":""}',
        '{"type":"ready","v":1,"device_id":"home-lab","ssh_host_key":null}',
        '{"type":"ready","v":1,"device_id":"x","device_id":"home-lab","ssh_host_key":""}',
        '{"type":"ready","v":NaN,"device_id":"home-lab","ssh_host_key":""}',
        '{"type":"ok","v":1}',
        '{"type":"error","v":1,"code":5,"message":"m"}',
        '{"type":"error","v":1,"code":"c"}',
    ],
)
def test_strict_control_frames(gateway_factory, provider, frame):
    def script(ws, gw):
        ws.send(frame)
        gw.drain(ws)

    gw = gateway_factory(script)
    run = Run(gw.endpoint, provider)
    assert run.wait() == gw_proxy.EXIT_PROTOCOL
    assert bytes(run.stdout) == b""


def test_handshake_timeout(gateway_factory, provider):
    def script(ws, gw):
        time.sleep(3)

    gw = gateway_factory(script)
    started = time.monotonic()
    run = Run(gw.endpoint, provider, timeout=0.5)
    assert run.wait() == gw_proxy.EXIT_TIMEOUT
    assert time.monotonic() - started < 2.5
    assert bytes(run.stdout) == b""


def test_connect_refused(provider):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    ep = resolve_endpoint(f"ws://127.0.0.1:{port}", True, trust_gateway="127.0.0.1")
    run = Run(ep, provider)
    assert run.wait() == gw_proxy.EXIT_CONNECT


def test_not_logged_in_never_connects(gateway_factory, fake_account):
    fake_account.error = fake_account.module.NotLoggedIn("nope")
    gw = gateway_factory(lambda ws, g: None)
    run = Run(gw.endpoint, fake_account.module.mint_gateway_token)
    assert run.wait() == gw_proxy.EXIT_NO_TOKEN
    assert gw.path is None
    assert "pocketshell login" in run.stderr.getvalue()


def test_unexpected_errors_never_print_tracebacks(gateway_factory, provider):
    def boom():
        raise RuntimeError("secret \x1b[2J detail")

    gw = gateway_factory(lambda ws, g: None)
    run = Run(gw.endpoint, boom)
    assert run.wait() == gw_proxy.EXIT_INTERNAL
    err = run.stderr.getvalue()
    assert "Traceback" not in err and "secret" not in err


# --- CLI surface --------------------------------------------------------------


@pytest.mark.parametrize(
    "args",
    [
        ["proxy", "-x"],
        ["proxy", "a b"],
        ["proxy", "home-lab", "--server", "ws://127.0.0.1:1"],  # no --insecure-dev
        ["proxy", "home-lab", "--server", "wss://evil.example"],  # no --trust-gateway
    ],
)
def test_proxy_cli_refuses_bad_input_before_minting(fake_account, args):
    result = CliRunner().invoke(cli, ["gateway", *args])
    assert result.exit_code == 2
    assert fake_account.calls == 0
