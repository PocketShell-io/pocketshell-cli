"""Workload-integrity suite: ordering, interleaving, PTY byte fidelity.

test_exec_semantics.py pins sizes and edge cases; this suite pins the
properties a terminal session silently depends on: stdin frame ordering,
stdout/stderr isolation under interleave, PTY 8-bit cleanliness, winsize
propagation, and route retirement after many channels.
"""

import asyncio
import sys

import pytest

from pocketshell.link.client import LinkClient, build_client_url  # noqa: E402
from pocketshell.link.daemon import LinkDaemon  # noqa: E402
from pocketshell.link.protocol import (  # noqa: E402
    LINK_PROTO_VERSION,
    decode_control,
    decode_data,
    encode_control,
    encode_data,
)
from pocketshell.link.relay import Relay  # noqa: E402

websockets = pytest.importorskip("websockets")

TOKEN = "workload-token"
HOST_ID = "workload-host"
OP_TIMEOUT = 30.0


async def _start_stack():
    relay = Relay(TOKEN)
    server = await relay.serve("127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    url = f"ws://127.0.0.1:{port}"
    daemon = LinkDaemon(url, TOKEN, HOST_ID, "Workload Host", reconnect=False)
    task = asyncio.create_task(daemon.run_forever())
    for _ in range(200):
        if HOST_ID in relay.hosts:
            return server, task, url, relay, daemon
        await asyncio.sleep(0.02)
    task.cancel()
    server.close()
    await server.wait_closed()
    raise AssertionError("daemon did not register with the relay")


async def _stop_stack(server, task) -> None:
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
    except Exception:  # noqa: BLE001 - teardown must not mask the test result
        pass
    server.close()
    await server.wait_closed()


def _run(scenario):
    return asyncio.run(scenario())


class RawClient:
    """Minimal hand-rolled client leg (stdin framing needs frame-level control)."""

    def __init__(self, url: str) -> None:
        self._host_id = HOST_ID
        self._url = build_client_url(url, TOKEN, HOST_ID)
        self.ws = None
        self._counter = 0

    async def connect(self) -> "RawClient":
        self.ws = await websockets.asyncio.client.connect(self._url, max_size=None)
        await self.ws.send(
            encode_control(
                "hello", role="client", host_id=self._host_id, proto=LINK_PROTO_VERSION
            )
        )
        while True:
            frame = decode_control(await self.ws.recv())
            if frame.get("t") == "ready":
                return self

    async def open_exec(self, cmd: str) -> int:
        self._counter += 1
        ch = self._counter
        await self.ws.send(encode_control("open", ch=ch, mode="exec", cmd=cmd))
        return ch

    async def recv_control(self, timeout: float = OP_TIMEOUT) -> dict:
        raw = await asyncio.wait_for(self.ws.recv(), timeout)
        return decode_control(raw)

    async def close(self) -> None:
        if self.ws is not None:
            await self.ws.close()
            self.ws = None


def test_multi_frame_stdin_preserves_order():
    """Twelve 64 KiB stdin frames arrive at `cat` in exactly the sent order."""

    async def scenario():
        server, task, url, _relay, _daemon = await _start_stack()
        try:
            raw = await RawClient(url).connect()
            ch = await raw.open_exec("cat")
            opened = await raw.recv_control()
            assert opened["t"] == "opened" and opened.get("ok") is True

            chunks = [bytes([(i % 251) + 1]) * 65536 for i in range(12)]
            for chunk in chunks:
                await raw.ws.send(encode_data(ch, chunk))
            await raw.ws.send(encode_control("eof", ch=ch))

            stdout = b""
            exit_code = None
            while exit_code is None:
                raw_frame = await asyncio.wait_for(raw.ws.recv(), OP_TIMEOUT)
                if isinstance(raw_frame, str):
                    frame = decode_control(raw_frame)
                    if frame.get("t") == "exit" and frame.get("ch") == ch:
                        exit_code = frame.get("exit_code")
                else:
                    data_ch, payload = decode_data(raw_frame)
                    if data_ch == ch:
                        stdout += payload
            assert exit_code == 0
            assert stdout == b"".join(chunks)
            await raw.close()
        finally:
            await _stop_stack(server, task)

    _run(scenario)


def test_large_stdout_is_byte_exact_not_just_size_exact():
    """8 MiB of a 256-byte pattern survives the 64 KiB pump frames untouched."""

    async def scenario():
        server, task, url, _relay, _daemon = await _start_stack()
        try:
            client = await asyncio.wait_for(LinkClient(url, TOKEN, HOST_ID).connect(), OP_TIMEOUT)
            cmd = (
                f"'{sys.executable}' -c "
                f"'import sys; sys.stdout.buffer.write(bytes(range(256)) * 32768)'"
            )
            result = await asyncio.wait_for(client.exec(cmd), 90.0)
            assert result.exit_code == 0
            assert result.stdout == bytes(range(256)) * 32768
            await client.close()
        finally:
            await _stop_stack(server, task)

    _run(scenario)


def test_stdout_stderr_interleaved_stay_isolated():
    """Alternating 16 KiB blocks on both streams never cross-contaminate."""

    async def scenario():
        server, task, url, _relay, _daemon = await _start_stack()
        try:
            client = await asyncio.wait_for(LinkClient(url, TOKEN, HOST_ID).connect(), OP_TIMEOUT)
            # Double quotes inside: the payload is single-quoted for the shell.
            script = (
                "import sys\n"
                'o = b"O" * 16384\n'
                'e = b"E" * 16384\n'
                "for _ in range(4):\n"
                "    sys.stdout.buffer.write(o)\n"
                "    sys.stdout.buffer.flush()\n"
                "    sys.stderr.buffer.write(e)\n"
                "    sys.stderr.buffer.flush()\n"
            )
            cmd = f"'{sys.executable}' -c '{script}'"
            result = await asyncio.wait_for(client.exec(cmd), OP_TIMEOUT)
            assert result.exit_code == 0, f"child failed: {result.stderr[:400]!r}"
            assert result.stdout == b"O" * 65536
            assert result.stderr == b"E" * 65536
            await client.close()
        finally:
            await _stop_stack(server, task)

    _run(scenario)


def test_pty_carries_binary_payload_intact_in_raw_mode():
    """512 KiB through `stty raw -echo; cat` comes back byte-identical."""

    async def scenario():
        server, task, url, _relay, _daemon = await _start_stack()
        try:
            client = await asyncio.wait_for(LinkClient(url, TOKEN, HOST_ID).connect(), OP_TIMEOUT)
            pty = await asyncio.wait_for(
                client.open_pty("stty raw -echo && echo READY && sleep 1 && exec cat"), OP_TIMEOUT
            )
            # `stty raw` races our first writes unless we wait it out: the tty
            # starts canonical, which mangles and truncates payloads.
            # The `sleep 1` before `cat` keeps the tty input undrained while the
            # paced writes start, so lost backpressure bytes fail deterministically
            # instead of only under machine load.
            handshake = b""
            for _ in range(50):
                handshake += await pty.read(timeout=0.2)
                if b"READY" in handshake:
                    break
            assert b"READY" in handshake, f"raw mode never settled: {handshake!r}"
            sent = bytes(range(256)) * 2048  # 512 KiB
            received = bytearray()
            chunk_size = 4096  # stays under the pty input buffer; paced writes below
            for offset in range(0, len(sent), chunk_size):
                pty.write(sent[offset : offset + chunk_size])
                await asyncio.sleep(0.01)
                received += await pty.read(timeout=0.05)
            loop = asyncio.get_running_loop()
            deadline = loop.time() + 15.0
            while len(received) < len(sent) and loop.time() < deadline:
                received += await pty.read(timeout=0.3)
            assert bytes(received) == sent, (
                f"pty payload corrupted: sent {len(sent)}, got {len(received)}"
            )
            await pty.close()
            for _ in range(60):
                await pty.read(timeout=0.3)
                if pty.exit_code is not None:
                    break
            # close() tears the channel down with SIGKILL by design.
            assert pty.exit_code is not None
            await client.close()
        finally:
            await _stop_stack(server, task)

    _run(scenario)


def test_pty_resize_propagates_to_the_child():
    """resize() updates the child's winsize; `stty size` reports rows x cols."""

    async def scenario():
        server, task, url, _relay, _daemon = await _start_stack()
        try:
            client = await asyncio.wait_for(LinkClient(url, TOKEN, HOST_ID).connect(), OP_TIMEOUT)
            pty = await asyncio.wait_for(
                client.open_pty(
                    "stty raw -echo && echo READY && "
                    'while IFS= read -r line; do sh -c "$line" 2>&1; done'
                ),
                OP_TIMEOUT,
            )
            handshake = b""
            for _ in range(50):
                handshake += await pty.read(timeout=0.2)
                if b"READY" in handshake:
                    break
            assert b"READY" in handshake, f"raw mode never settled: {handshake!r}"
            await pty.resize(cols=111, rows=30)
            await asyncio.sleep(0.2)  # let the control frame reach the daemon
            pty.write(b"stty size\n")
            data = b""
            for _ in range(50):
                data += await pty.read(timeout=0.2)
                if b"30 111" in data:
                    break
            assert b"30 111" in data, f"winsize not applied, got {data!r}"
            await pty.close()
            for _ in range(40):
                await pty.read(timeout=0.3)
                if pty.exit_code is not None:
                    break
            # close() tears the channel down with SIGKILL by design.
            assert pty.exit_code is not None
            await client.close()
        finally:
            await _stop_stack(server, task)

    _run(scenario)


def test_channel_routes_fully_retired_after_many_execs():
    """40 sequential execs leave zero routes behind on relay or daemon."""

    async def scenario():
        server, task, url, relay, daemon = await _start_stack()
        try:
            client = await asyncio.wait_for(LinkClient(url, TOKEN, HOST_ID).connect(), OP_TIMEOUT)
            for i in range(40):
                result = await asyncio.wait_for(client.exec(f"echo route-{i}"), OP_TIMEOUT)
                assert result.stdout.strip() == f"route-{i}".encode()
            registration = relay.hosts[HOST_ID]
            assert registration.routes == {}, "host-side routes leaked"
            assert registration.err_channels == {}, "stderr sibling routes leaked"
            assert daemon._channels == {}, "daemon channels leaked"
            await client.close()
            await asyncio.sleep(0.3)
            assert relay.clients == set(), "client session leaked after close"
        finally:
            await _stop_stack(server, task)

    _run(scenario)
