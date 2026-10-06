"""Loopback E2E: real relay + real daemon over real sockets, in-process.

These tests exercise the full v1 protocol path — auth, pairing, channel
namespacing, exec, PTY, timeouts, reconnect — exactly what a client
implementation must satisfy.
"""

import asyncio
import json

import pytest

websockets = pytest.importorskip("websockets")
from websockets.exceptions import InvalidStatus  # noqa: E402

from pocketshell.link.client import LinkClient, LinkError  # noqa: E402
from pocketshell.link.daemon import LinkDaemon  # noqa: E402
from pocketshell.link.relay import Relay  # noqa: E402

TOKEN = "loopback-token"
HOST_ID = "loopback-host"
OP_TIMEOUT = 15.0


async def _start_stack():
    relay = Relay(TOKEN)
    server = await relay.serve("127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    url = f"ws://127.0.0.1:{port}"
    daemon = LinkDaemon(url, TOKEN, HOST_ID, "Loopback Host", reconnect=False)
    task = asyncio.create_task(daemon.run_forever())
    for _ in range(200):
        if HOST_ID in relay.hosts:
            return server, task, url, relay
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


def test_wrong_token_rejected_at_http_upgrade():
    async def scenario():
        relay = Relay(TOKEN)
        server = await relay.serve("127.0.0.1", 0)
        try:
            port = server.sockets[0].getsockname()[1]
            with pytest.raises(InvalidStatus) as excinfo:
                await websockets.asyncio.client.connect(
                    f"ws://127.0.0.1:{port}/client?token=WRONG&host_id=h"
                )
            assert excinfo.value.response.status_code == 401
        finally:
            server.close()
            await server.wait_closed()

    _run(scenario)


def test_client_to_unknown_host_gets_host_offline():
    async def scenario():
        relay = Relay(TOKEN)
        server = await relay.serve("127.0.0.1", 0)
        try:
            port = server.sockets[0].getsockname()[1]
            with pytest.raises(LinkError) as excinfo:
                await asyncio.wait_for(
                    LinkClient(f"ws://127.0.0.1:{port}", TOKEN, "ghost").connect(),
                    OP_TIMEOUT,
                )
            assert excinfo.value.code == "HOST_OFFLINE"
        finally:
            server.close()
            await server.wait_closed()

    _run(scenario)


def test_exec_roundtrip_stdout_stderr_exit_code():
    async def scenario():
        server, task, url, _relay = await _start_stack()
        try:
            client = await asyncio.wait_for(LinkClient(url, TOKEN, HOST_ID).connect(), OP_TIMEOUT)
            result = await asyncio.wait_for(
                client.exec("printf hello-out; printf err-text >&2; exit 7"), OP_TIMEOUT
            )
            assert result.stdout == b"hello-out"
            assert result.stderr == b"err-text"
            assert result.exit_code == 7
            assert result.timed_out is False
            await client.close()
        finally:
            await _stop_stack(server, task)

    _run(scenario)


def test_exec_stdin_reaches_the_command():
    async def scenario():
        server, task, url, _relay = await _start_stack()
        try:
            client = await asyncio.wait_for(LinkClient(url, TOKEN, HOST_ID).connect(), OP_TIMEOUT)
            result = await asyncio.wait_for(
                client.exec("cat", stdin=b"secret-payload"),
                OP_TIMEOUT,
            )
            assert result.stdout == b"secret-payload"
            assert result.exit_code == 0
            await client.close()
        finally:
            await _stop_stack(server, task)

    _run(scenario)


def test_exec_timeout_kills_and_reports():
    async def scenario():
        server, task, url, _relay = await _start_stack()
        try:
            client = await asyncio.wait_for(LinkClient(url, TOKEN, HOST_ID).connect(), OP_TIMEOUT)
            result = await asyncio.wait_for(
                client.exec("sleep 30", timeout_ms=400), OP_TIMEOUT
            )
            assert result.timed_out is True
            assert result.exit_code != 0
            await client.close()
        finally:
            await _stop_stack(server, task)

    _run(scenario)


def test_pty_roundtrip_write_read_resize_close():
    async def scenario():
        server, task, url, _relay = await _start_stack()
        try:
            client = await asyncio.wait_for(LinkClient(url, TOKEN, HOST_ID).connect(), OP_TIMEOUT)
            pty = await asyncio.wait_for(client.open_pty("cat", cols=80, rows=24), OP_TIMEOUT)
            pty.write(b"ping\n")
            data = b""
            for _ in range(40):
                data += await pty.read(timeout=0.3)
                if b"ping" in data:
                    break
            assert b"ping" in data, f"expected echo, got {data!r}"
            await pty.resize(cols=40, rows=12)
            await pty.close()
            for _ in range(40):
                await pty.read(timeout=0.3)
                if pty.exit_code is not None:
                    break
            assert pty.exit_code is not None, "pty did not exit after close"
            await client.close()
        finally:
            await _stop_stack(server, task)

    _run(scenario)


def test_two_clients_are_namespaced_independently():
    async def scenario():
        server, task, url, _relay = await _start_stack()
        try:
            client_a = await asyncio.wait_for(LinkClient(url, TOKEN, HOST_ID).connect(), OP_TIMEOUT)
            client_b = await asyncio.wait_for(LinkClient(url, TOKEN, HOST_ID).connect(), OP_TIMEOUT)
            result_a = await asyncio.wait_for(client_a.exec("echo from-A"), OP_TIMEOUT)
            result_b = await asyncio.wait_for(client_b.exec("echo from-B"), OP_TIMEOUT)
            assert result_a.stdout.strip() == b"from-A"
            assert result_b.stdout.strip() == b"from-B"
            await client_a.close()
            await client_b.close()
        finally:
            await _stop_stack(server, task)

    _run(scenario)


def test_host_reconnect_replaces_registration():
    async def scenario():
        server, task, url, relay = await _start_stack()
        try:
            client = await asyncio.wait_for(LinkClient(url, TOKEN, HOST_ID).connect(), OP_TIMEOUT)
            first = await asyncio.wait_for(client.exec("echo first"), OP_TIMEOUT)
            assert first.stdout.strip() == b"first"
            await client.close()
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            await asyncio.sleep(0.1)

            daemon = LinkDaemon(url, TOKEN, HOST_ID, "Loopback Host", reconnect=False)
            task2 = asyncio.create_task(daemon.run_forever())
            try:
                for _ in range(200):
                    if HOST_ID in relay.hosts:
                        break
                    await asyncio.sleep(0.02)
                else:
                    raise AssertionError("restarted daemon never registered")
                client2 = await asyncio.wait_for(LinkClient(url, TOKEN, HOST_ID).connect(), OP_TIMEOUT)
                second = await asyncio.wait_for(client2.exec("echo second"), OP_TIMEOUT)
                assert second.stdout.strip() == b"second"
                await client2.close()
            finally:
                task2.cancel()
                try:
                    await task2
                except asyncio.CancelledError:
                    pass
        finally:
            await _stop_stack(server, task)

    _run(scenario)


def test_bad_hello_gets_protocol_error_and_close():
    async def scenario():
        relay = Relay(TOKEN)
        server = await relay.serve("127.0.0.1", 0)
        try:
            port = server.sockets[0].getsockname()[1]
            ws = await websockets.asyncio.client.connect(
                f"ws://127.0.0.1:{port}/client?token={TOKEN}&host_id=whatever"
            )
            await ws.send(json.dumps({"v": 9, "t": "hello"}))
            reply = await asyncio.wait_for(ws.recv(), OP_TIMEOUT)
            frame = json.loads(reply)
            assert frame["t"] == "error"
            assert frame["code"] == "PROTOCOL_ERROR"
            await ws.close()
        finally:
            server.close()
            await server.wait_closed()

    _run(scenario)
