"""Exec-semantics regression suite: edge cases the loopback suite doesn't pin.

Complements tests/link/test_loopback.py with the use-cases real clients hit:
unbounded timeouts, multi-megabyte streams, binary payloads, stdin edge
cases (empty, oversized single-frame, command-never-reads), child cleanup
on client drop, pending-exec failure on host drop, and concurrent
multi-client load with exec and PTY channels live at once.
"""

import asyncio
import os
import signal
import time

import pytest

from pocketshell.link.client import LinkClient, LinkError  # noqa: E402
from pocketshell.link.daemon import LinkDaemon  # noqa: E402
from pocketshell.link.relay import Relay  # noqa: E402

TOKEN = "exec-semantics-token"
HOST_ID = "exec-semantics-host"
OP_TIMEOUT = 15.0
MiB = 1024 * 1024


async def _start_stack():
    relay = Relay(TOKEN)
    server = await relay.serve("127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    url = f"ws://127.0.0.1:{port}"
    daemon = LinkDaemon(url, TOKEN, HOST_ID, "Exec Host", reconnect=False)
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


def test_timeout_zero_runs_to_completion():
    """timeout_ms=0 opts out of the kill timer entirely (minutes-long execs)."""

    async def scenario():
        server, task, url, _relay, _daemon = await _start_stack()
        try:
            client = await asyncio.wait_for(LinkClient(url, TOKEN, HOST_ID).connect(), OP_TIMEOUT)
            result = await asyncio.wait_for(
                client.exec("sleep 0.4 && echo slow-done", timeout_ms=0), OP_TIMEOUT
            )
            assert result.timed_out is False
            assert result.exit_code == 0
            assert result.stdout.strip() == b"slow-done"
            await client.close()
        finally:
            await _stop_stack(server, task)

    _run(scenario)


def test_timeout_kills_child_and_reports_sigkill():
    async def scenario():
        server, task, url, _relay, _daemon = await _start_stack()
        try:
            client = await asyncio.wait_for(LinkClient(url, TOKEN, HOST_ID).connect(), OP_TIMEOUT)
            started = time.monotonic()
            result = await asyncio.wait_for(
                client.exec("sleep 30", timeout_ms=300), OP_TIMEOUT
            )
            assert result.timed_out is True
            assert result.exit_code == -signal.SIGKILL
            assert time.monotonic() - started < 5.0
            await client.close()
        finally:
            await _stop_stack(server, task)

    _run(scenario)


def test_large_stdout_streams_multi_mib():
    """4 MiB of output rides 64 KiB pump frames; the client reassembles it all."""

    async def scenario():
        server, task, url, _relay, _daemon = await _start_stack()
        try:
            client = await asyncio.wait_for(LinkClient(url, TOKEN, HOST_ID).connect(), OP_TIMEOUT)
            result = await asyncio.wait_for(
                client.exec(f"head -c {4 * MiB} /dev/zero | tr '\\0' 'x'"), OP_TIMEOUT
            )
            assert result.exit_code == 0
            assert len(result.stdout) == 4 * MiB
            assert result.stdout.count(b"x") == 4 * MiB
            await client.close()
        finally:
            await _stop_stack(server, task)

    _run(scenario)


def test_binary_stdout_with_nul_and_high_bytes():
    async def scenario():
        server, task, url, _relay, _daemon = await _start_stack()
        try:
            client = await asyncio.wait_for(LinkClient(url, TOKEN, HOST_ID).connect(), OP_TIMEOUT)
            result = await asyncio.wait_for(client.exec("printf 'a\\000b\\377c'"), OP_TIMEOUT)
            assert result.stdout == b"a\x00b\xffc"
            await client.close()
        finally:
            await _stop_stack(server, task)

    _run(scenario)


def test_large_single_frame_stdin_roundtrips():
    """Whole-stdin-as-one-frame is the contract core's exec rides on."""

    async def scenario():
        server, task, url, _relay, _daemon = await _start_stack()
        try:
            client = await asyncio.wait_for(LinkClient(url, TOKEN, HOST_ID).connect(), OP_TIMEOUT)
            payload = os.urandom(2 * MiB)
            result = await asyncio.wait_for(client.exec("cat", stdin=payload), OP_TIMEOUT)
            assert result.exit_code == 0
            assert result.stdout == payload
            await client.close()
        finally:
            await _stop_stack(server, task)

    _run(scenario)


def test_empty_stdin_signals_immediate_eof():
    """stdin=b'' must deliver EOF, or commands reading stdin hang forever."""

    async def scenario():
        server, task, url, _relay, _daemon = await _start_stack()
        try:
            client = await asyncio.wait_for(LinkClient(url, TOKEN, HOST_ID).connect(), OP_TIMEOUT)
            result = await asyncio.wait_for(client.exec("cat", stdin=b""), 10.0)
            assert result.exit_code == 0
            assert result.stdout == b""
            await client.close()
        finally:
            await _stop_stack(server, task)

    _run(scenario)


def test_stdin_to_command_that_never_reads_it():
    async def scenario():
        server, task, url, _relay, _daemon = await _start_stack()
        try:
            client = await asyncio.wait_for(LinkClient(url, TOKEN, HOST_ID).connect(), OP_TIMEOUT)
            result = await asyncio.wait_for(
                client.exec("true", stdin=b"never-read"), 10.0
            )
            assert result.exit_code == 0
            await client.close()
        finally:
            await _stop_stack(server, task)

    _run(scenario)


def test_client_drop_kills_running_child():
    """Client leg gone -> relay forwards close -> daemon SIGKILLs the child."""

    async def scenario():
        server, task, url, _relay, daemon = await _start_stack()
        try:
            client = await asyncio.wait_for(LinkClient(url, TOKEN, HOST_ID).connect(), OP_TIMEOUT)
            pending = asyncio.create_task(client.exec("sleep 30"))
            for _ in range(100):
                channels = list(daemon._channels.values())
                if channels and channels[0].proc is not None:
                    break
                await asyncio.sleep(0.02)
            else:
                raise AssertionError("exec channel never spawned")
            proc = channels[0].proc
            await client.close()
            for _ in range(250):
                if proc.poll() is not None:
                    break
                await asyncio.sleep(0.02)
            assert proc.poll() is not None, "child survived the client disconnect"
            pending.cancel()
            try:
                await pending
            except BaseException:  # noqa: BLE001 - the socket is gone either way
                pass
        finally:
            await _stop_stack(server, task)

    _run(scenario)


def test_host_drop_fails_pending_exec_with_host_offline():
    async def scenario():
        server, task, url, _relay, daemon = await _start_stack()
        try:
            client = await asyncio.wait_for(LinkClient(url, TOKEN, HOST_ID).connect(), OP_TIMEOUT)
            pending = asyncio.create_task(client.exec("sleep 30"))
            for _ in range(100):
                if daemon._channels:
                    break
                await asyncio.sleep(0.02)
            else:
                raise AssertionError("exec channel never spawned")
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            with pytest.raises(LinkError) as excinfo:
                await asyncio.wait_for(pending, 10.0)
            assert excinfo.value.code == "HOST_OFFLINE"
            await client.close()
        finally:
            await _stop_stack(server, task)

    _run(scenario)


def test_parallel_clients_exec_without_crosstalk():
    async def scenario():
        server, task, url, _relay, _daemon = await _start_stack()
        try:
            clients = [
                await asyncio.wait_for(LinkClient(url, TOKEN, HOST_ID).connect(), OP_TIMEOUT)
                for _ in range(3)
            ]
            results = await asyncio.wait_for(
                asyncio.gather(*(c.exec(f"echo payload-{i}") for i, c in enumerate(clients))),
                OP_TIMEOUT,
            )
            for i, result in enumerate(results):
                assert result.stdout.strip() == f"payload-{i}".encode()
            for client in clients:
                await client.close()
        finally:
            await _stop_stack(server, task)

    _run(scenario)


def test_exec_and_pty_simultaneously_across_clients():
    async def scenario():
        server, task, url, _relay, _daemon = await _start_stack()
        try:
            client_a = await asyncio.wait_for(LinkClient(url, TOKEN, HOST_ID).connect(), OP_TIMEOUT)
            client_b = await asyncio.wait_for(LinkClient(url, TOKEN, HOST_ID).connect(), OP_TIMEOUT)
            exec_task = asyncio.create_task(client_a.exec("echo exec-side && sleep 0.2"))
            pty = await asyncio.wait_for(client_b.open_pty("cat", cols=80, rows=24), OP_TIMEOUT)
            pty.write(b"pty-side\n")
            data = b""
            for _ in range(40):
                data += await pty.read(timeout=0.3)
                if b"pty-side" in data:
                    break
            assert b"pty-side" in data, f"expected pty echo, got {data!r}"
            result = await asyncio.wait_for(exec_task, OP_TIMEOUT)
            assert b"exec-side" in result.stdout
            await pty.close()
            for _ in range(40):
                await pty.read(timeout=0.3)
                if pty.exit_code is not None:
                    break
            assert pty.exit_code is not None, "pty did not exit after close"
            await client_a.close()
            await client_b.close()
        finally:
            await _stop_stack(server, task)

    _run(scenario)
