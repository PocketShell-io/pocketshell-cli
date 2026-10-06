"""Topology-resilience suite: relays die, daemons die, hosts collide.

test_loopback.py covers the happy paths and test_exec_semantics.py covers
exec semantics; this suite attacks the failure modes a real deployment
hits - relay restarts, reconnect backoff, superseded host legs, half-open
clients - because a laptop behind NAT lives exactly in those conditions.
"""

import asyncio
import logging
import re
import socket
from contextlib import suppress
from typing import Any

import pytest

websockets = pytest.importorskip("websockets")

from pocketshell.link import daemon as daemon_mod  # noqa: E402
from pocketshell.link.client import LinkClient, LinkError, build_client_url  # noqa: E402
from pocketshell.link.daemon import LinkDaemon  # noqa: E402
from pocketshell.link.protocol import (  # noqa: E402
    LINK_PROTO_VERSION,
    decode_control,
    decode_data,
    encode_control,
    encode_data,
)
from pocketshell.link.relay import Relay  # noqa: E402

TOKEN = "resilience-token"
HOST_ID = "resilience-host"
OP_TIMEOUT = 15.0


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _run(scenario):
    return asyncio.run(scenario())


async def _wait_until(predicate, timeout: float, what: str) -> None:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.02)
    raise AssertionError(f"timed out waiting for {what}")


async def _stop_task(task: "asyncio.Task[None]") -> None:
    task.cancel()
    with suppress(asyncio.CancelledError, Exception):
        await task


async def _close_server(server: Any) -> None:
    server.close()
    await server.wait_closed()


def _fast_backoff(monkeypatch: pytest.MonkeyPatch, minimum: float = 0.1) -> None:
    """Shrink the backoff ladder and pin its jitter for deterministic timing."""
    monkeypatch.setattr(daemon_mod, "_BACKOFF_MIN", minimum)
    monkeypatch.setattr(daemon_mod, "_BACKOFF_MAX", minimum * 8)
    # pause = delay * (0.5 + random()/2); pinned to 0.5 * delay.
    monkeypatch.setattr(daemon_mod.random, "random", lambda: 0.0)


def _reconnect_pauses(caplog) -> list:
    return [
        float(match)
        for match in re.findall(r"reconnecting in ([0-9]+(?:\.[0-9]+)?)s", caplog.text)
    ]


class RawClient:
    """Hand-rolled client leg for scenarios the stock client cannot express."""

    def __init__(self, url: str, host_id: str = HOST_ID) -> None:
        self._host_id = host_id
        self._url = build_client_url(url, TOKEN, host_id)
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

    def next_channel(self) -> int:
        self._counter += 1
        return self._counter

    async def open_exec(self, cmd: str, timeout_ms=None) -> int:
        ch = self.next_channel()
        fields = {"ch": ch, "mode": "exec", "cmd": cmd}
        if timeout_ms is not None:
            fields["timeout_ms"] = timeout_ms
        await self.ws.send(encode_control("open", **fields))
        return ch

    async def recv_control(self, timeout: float = OP_TIMEOUT) -> dict:
        raw = await asyncio.wait_for(self.ws.recv(), timeout)
        return decode_control(raw)

    async def close(self) -> None:
        if self.ws is not None:
            await self.ws.close()
            self.ws = None


# ----------------------------------------------------------------------
# relay lifecycle
# ----------------------------------------------------------------------


def test_relay_restart_mid_session_daemon_reconnects_and_serves(monkeypatch):
    """The relay VPS reboots; the daemon dials back in once it returns."""
    _fast_backoff(monkeypatch)
    port = _free_port()

    async def scenario():
        url = f"ws://127.0.0.1:{port}"
        relay1 = Relay(TOKEN)
        server1 = await relay1.serve("127.0.0.1", port)
        daemon = LinkDaemon(url, TOKEN, HOST_ID, "Laptop", reconnect=True)
        task = asyncio.create_task(daemon.run_forever())
        servers = [server1]
        try:
            await _wait_until(lambda: HOST_ID in relay1.hosts, OP_TIMEOUT, "first registration")
            client = await asyncio.wait_for(LinkClient(url, TOKEN, HOST_ID).connect(), OP_TIMEOUT)
            first = await asyncio.wait_for(client.exec("echo before-restart"), OP_TIMEOUT)
            assert first.stdout.strip() == b"before-restart"
            await client.close()

            await _close_server(server1)  # ...the reboot happens here...
            relay2 = Relay(TOKEN)
            server2 = await relay2.serve("127.0.0.1", port)  # ...and it comes back.
            servers.append(server2)
            await _wait_until(
                lambda: HOST_ID in relay2.hosts, OP_TIMEOUT, "re-registration after restart"
            )
            client2 = await asyncio.wait_for(LinkClient(url, TOKEN, HOST_ID).connect(), OP_TIMEOUT)
            second = await asyncio.wait_for(client2.exec("echo after-restart"), OP_TIMEOUT)
            assert second.stdout.strip() == b"after-restart"
            await client2.close()
        finally:
            await _stop_task(task)
            for server in servers:
                await _close_server(server)

    _run(scenario)


def test_backoff_grows_while_relay_stays_down(monkeypatch, caplog):
    """Repeated failures double the reconnect delay; logs record the ladder."""
    caplog.set_level(logging.INFO, logger="pocketshell.link.daemon")
    _fast_backoff(monkeypatch, minimum=0.5)
    monkeypatch.setattr(daemon_mod, "_HEALTHY_UPTIME", 3600.0)
    port = _free_port()

    async def scenario():
        url = f"ws://127.0.0.1:{port}"
        relay = Relay(TOKEN)
        server = await relay.serve("127.0.0.1", port)
        daemon = LinkDaemon(url, TOKEN, HOST_ID, reconnect=True)
        task = asyncio.create_task(daemon.run_forever())
        try:
            await _wait_until(lambda: HOST_ID in relay.hosts, OP_TIMEOUT, "initial registration")
            await _close_server(server)  # down and stays down for a while
            await _wait_until(
                lambda: len(_reconnect_pauses(caplog)) >= 3, OP_TIMEOUT, "three backoff pauses"
            )
            relay2 = Relay(TOKEN)
            server2 = await relay2.serve("127.0.0.1", port)
            await _wait_until(
                lambda: HOST_ID in relay2.hosts, OP_TIMEOUT, "re-registration after backoff"
            )
        finally:
            await _stop_task(task)
            await _close_server(server)

    _run(scenario)
    # Jitter pinned to 0.5: delays 1.0, 2.0, 4.0 (min=0.5 doubled per failure).
    assert _reconnect_pauses(caplog)[:3] == [0.5, 1.0, 2.0]


def test_backoff_resets_after_healthy_serve(monkeypatch, caplog):
    """With _HEALTHY_UPTIME reached, every outage restarts at the minimum."""
    caplog.set_level(logging.INFO, logger="pocketshell.link.daemon")
    # minimum=1.0 so the reset pauses (0.5s) survive the daemon's %.1f log
    # rounding - 0.25s pauses would log as "0.2s" and the parsed ladder lies.
    _fast_backoff(monkeypatch, minimum=1.0)
    monkeypatch.setattr(daemon_mod, "_HEALTHY_UPTIME", 0.0)
    port = _free_port()

    async def scenario():
        url = f"ws://127.0.0.1:{port}"
        relay = Relay(TOKEN)
        server = await relay.serve("127.0.0.1", port)
        daemon = LinkDaemon(url, TOKEN, HOST_ID, reconnect=True)
        task = asyncio.create_task(daemon.run_forever())
        servers = [server]
        try:
            await _wait_until(lambda: HOST_ID in relay.hosts, OP_TIMEOUT, "initial registration")
            for blip in range(2):
                await _close_server(server)
                relay = Relay(TOKEN)
                server = await relay.serve("127.0.0.1", port)
                servers.append(server)
                await _wait_until(
                    lambda: HOST_ID in relay.hosts,
                    OP_TIMEOUT,
                    f"re-registration after blip {blip}",
                )
        finally:
            await _stop_task(task)
            for pending in servers:
                await _close_server(pending)

    _run(scenario)
    pauses = _reconnect_pauses(caplog)
    assert len(pauses) == 2
    # Without the healthy-uptime reset these would be 1.0 then 2.0.
    assert pauses == [0.5, 0.5]


# ----------------------------------------------------------------------
# host leg lifecycle
# ----------------------------------------------------------------------


def test_superseded_host_leg_drops_paired_client():
    """A second daemon with the same host_id takes over; the old client is told."""
    port = _free_port()

    async def scenario():
        url = f"ws://127.0.0.1:{port}"
        relay = Relay(TOKEN)
        server = await relay.serve("127.0.0.1", port)
        old = LinkDaemon(url, TOKEN, HOST_ID, "Old Leg", reconnect=False)
        old_task = asyncio.create_task(old.run_forever())
        try:
            await _wait_until(lambda: HOST_ID in relay.hosts, OP_TIMEOUT, "old leg registration")
            raw = await RawClient(url).connect()
            await raw.open_exec("sleep 30")
            opened = await raw.recv_control()
            assert opened["t"] == "opened" and opened.get("ok") is True

            new = LinkDaemon(url, TOKEN, HOST_ID, "New Leg", reconnect=False)
            new_task = asyncio.create_task(new.run_forever())
            try:
                await _wait_until(
                    lambda: relay.hosts.get(HOST_ID) is not None
                    and relay.hosts[HOST_ID].name == "New Leg",
                    OP_TIMEOUT,
                    "new leg to supersede the old",
                )
                error = await raw.recv_control()
                assert error["t"] == "error"
                assert error["code"] == "HOST_OFFLINE"

                client = await asyncio.wait_for(
                    LinkClient(url, TOKEN, HOST_ID).connect(), OP_TIMEOUT
                )
                result = await asyncio.wait_for(client.exec("echo on-new-leg"), OP_TIMEOUT)
                assert result.stdout.strip() == b"on-new-leg"
                await client.close()
            finally:
                await _stop_task(new_task)
            await raw.close()
        finally:
            await _stop_task(old_task)
            await _close_server(server)

    _run(scenario)


def test_daemon_death_kills_running_children():
    """Daemon gone: the pending exec is reaped, not orphaned."""
    port = _free_port()

    async def scenario():
        url = f"ws://127.0.0.1:{port}"
        relay = Relay(TOKEN)
        server = await relay.serve("127.0.0.1", port)
        daemon = LinkDaemon(url, TOKEN, HOST_ID, reconnect=False)
        task = asyncio.create_task(daemon.run_forever())
        try:
            await _wait_until(lambda: HOST_ID in relay.hosts, OP_TIMEOUT, "registration")
            raw = await RawClient(url).connect()
            await raw.open_exec("sleep 30")
            opened = await raw.recv_control()
            assert opened.get("ok") is True
            channel = next(iter(daemon._channels.values()))
            assert channel.proc is not None and channel.proc.poll() is None

            await _stop_task(task)  # the daemon process dies
            await _wait_until(
                lambda: channel.proc.poll() is not None, 5.0, "exec child killed on daemon death"
            )
            await raw.close()
        finally:
            await _stop_task(task)
            await _close_server(server)

    _run(scenario)


# ----------------------------------------------------------------------
# pairing and robustness
# ----------------------------------------------------------------------


def test_client_before_host_online_pairs_once_host_joins():
    """Laptop still asleep: HOST_OFFLINE now, clean pairing once it wakes."""
    port = _free_port()

    async def scenario():
        url = f"ws://127.0.0.1:{port}"
        relay = Relay(TOKEN)
        server = await relay.serve("127.0.0.1", port)
        try:
            with pytest.raises(LinkError) as excinfo:
                await asyncio.wait_for(LinkClient(url, TOKEN, HOST_ID).connect(), OP_TIMEOUT)
            assert excinfo.value.code == "HOST_OFFLINE"

            daemon = LinkDaemon(url, TOKEN, HOST_ID, "Late Laptop", reconnect=False)
            task = asyncio.create_task(daemon.run_forever())
            try:
                await _wait_until(lambda: HOST_ID in relay.hosts, OP_TIMEOUT, "host joining")
                client = await asyncio.wait_for(
                    LinkClient(url, TOKEN, HOST_ID).connect(), OP_TIMEOUT
                )
                result = await asyncio.wait_for(client.exec("echo awake"), OP_TIMEOUT)
                assert result.stdout.strip() == b"awake"
                await client.close()
            finally:
                await _stop_task(task)
        finally:
            await _close_server(server)

    _run(scenario)


def test_garbage_frames_do_not_disturb_a_live_exec():
    """Unknown channels, short headers, bogus types: exec stays byte-exact."""
    port = _free_port()

    async def scenario():
        url = f"ws://127.0.0.1:{port}"
        relay = Relay(TOKEN)
        server = await relay.serve("127.0.0.1", port)
        daemon = LinkDaemon(url, TOKEN, HOST_ID, reconnect=False)
        task = asyncio.create_task(daemon.run_forever())
        try:
            await _wait_until(lambda: HOST_ID in relay.hosts, OP_TIMEOUT, "registration")
            raw = await RawClient(url).connect()
            ch = await raw.open_exec("printf payload-123")
            opened = await raw.recv_control()
            assert opened["t"] == "opened" and opened.get("ok") is True
            # stderr rides a sibling channel in the client's upper-id space.
            assert opened.get("err_ch") == 0x40000000 + ch

            await raw.ws.send(encode_data(0xDEADBEEF, b"stray"))  # unknown channel
            await raw.ws.send(b"\x00\x00\x01")  # shorter than the header
            await raw.ws.send(encode_control("bogus-frame", ch=ch))  # unknown type

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
            assert stdout == b"payload-123"
            assert exit_code == 0
            await raw.close()
        finally:
            await _stop_task(task)
            await _close_server(server)

    _run(scenario)


def test_two_hosts_share_one_relay():
    """One relay, two laptops: clients pair strictly by host_id."""
    port = _free_port()

    async def scenario():
        url = f"ws://127.0.0.1:{port}"
        relay = Relay(TOKEN)
        server = await relay.serve("127.0.0.1", port)
        daemons = [
            LinkDaemon(url, TOKEN, "host-one", "One", reconnect=False),
            LinkDaemon(url, TOKEN, "host-two", "Two", reconnect=False),
        ]
        tasks = [asyncio.create_task(d.run_forever()) for d in daemons]
        try:
            await _wait_until(
                lambda: set(relay.hosts) == {"host-one", "host-two"},
                OP_TIMEOUT,
                "both hosts registering",
            )
            assert relay.hosts["host-one"].name == "One"
            assert relay.hosts["host-two"].name == "Two"

            client_a = await asyncio.wait_for(
                LinkClient(url, TOKEN, "host-one").connect(), OP_TIMEOUT
            )
            client_b = await asyncio.wait_for(
                LinkClient(url, TOKEN, "host-two").connect(), OP_TIMEOUT
            )
            result_a = await asyncio.wait_for(client_a.exec("echo for-one"), OP_TIMEOUT)
            result_b = await asyncio.wait_for(client_b.exec("echo for-two"), OP_TIMEOUT)
            assert result_a.stdout.strip() == b"for-one"
            assert result_b.stdout.strip() == b"for-two"
            await client_a.close()
            await client_b.close()
        finally:
            for task in tasks:
                await _stop_task(task)
            await _close_server(server)

    _run(scenario)
