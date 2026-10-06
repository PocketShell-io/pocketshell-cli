"""Reference link relay: pair hosts and clients, namespace channel ids.

Deployed wherever inbound reachability exists (a VPS, a forwarded port, a
tunnel target).  The relay is deliberately dumb: it authenticates both legs
with the shared token, pairs them by ``host_id``, and rewrites channel ids
so concurrent clients cannot collide.  It never inspects payload bytes.
"""

from __future__ import annotations

import itertools
import logging
import urllib.parse
from typing import Any

import websockets.asyncio.server
from websockets.asyncio.server import ServerConnection
from websockets.exceptions import ConnectionClosed

from . import protocol

log = logging.getLogger(__name__)

# Exec stderr rides a sibling channel the daemon derives in the upper half of
# the u32 space (see daemon._ERR_CHANNEL_BASE).  The relay mirrors the same
# convention when rewriting err_ch into a client's id space: client main ids
# are small per-connection counters, so the upper half can never collide.
_ERR_CHANNEL_BASE = 0x40000000


class _Route:
    """Where a host-side channel id leads back to."""

    __slots__ = ("client", "client_channel")

    def __init__(self, client: "ClientSession", client_channel: int) -> None:
        self.client = client
        self.client_channel = client_channel


class HostRegistration:
    """One live host leg plus its routing table (host channel -> route)."""

    def __init__(self, ws: ServerConnection, host_id: str, name: str) -> None:
        self.ws = ws
        self.host_id = host_id
        self.name = name
        self._counter = itertools.count(1)
        self.routes: dict[int, _Route] = {}
        # main host channel -> the stderr sibling channel (exec only)
        self.err_channels: dict[int, int] = {}

    def alloc_channel(self) -> int:
        return next(self._counter)


class ClientSession:
    """One live client leg plus its forwarding map (client channel -> host channel)."""

    def __init__(self, ws: ServerConnection, host_id: str) -> None:
        self.ws = ws
        self.host_id = host_id
        self._counter = itertools.count(1)
        self.routes: dict[int, int] = {}

    def alloc_channel(self) -> int:
        return next(self._counter)


async def _safe_send(ws: Any, data: Any) -> None:
    try:
        await ws.send(data)
    except ConnectionClosed:
        pass


async def _fail(ws: Any, code: str, message: str) -> None:
    """Best-effort error frame + policy close (used before/without pairing)."""
    await _safe_send(ws, protocol.encode_control("error", code=code, message=message))
    try:
        await ws.close(code=1008, reason=code[:120])
    except Exception:  # noqa: BLE001 - close is best-effort during teardown
        pass


class Relay:
    """Authenticates both legs, pairs them, rewrites channel ids both ways."""

    def __init__(self, token: str) -> None:
        self.token = token
        self.hosts: dict[str, HostRegistration] = {}
        self.clients: set[ClientSession] = set()

    async def serve(self, host: str, port: int) -> Any:
        """Start the WebSocket server; returns the server (caller closes it)."""
        return await websockets.asyncio.server.serve(
            self._handle, host, port, process_request=self._auth
        )

    # ------------------------------------------------------------------
    # handshake
    # ------------------------------------------------------------------

    def _auth(self, connection: Any, request: Any) -> Any:
        """HTTP-upgrade gate: only /host and /client with the shared token."""
        split = urllib.parse.urlsplit(request.path)
        if split.path not in ("/host", "/client"):
            return connection.respond(404, "not found\n")
        query = urllib.parse.parse_qs(split.query)
        if (query.get("token") or [""])[0] != self.token:
            return connection.respond(401, "bad token\n")
        return None

    async def _handle(self, ws: ServerConnection) -> None:
        request = ws.request
        assert request is not None
        split = urllib.parse.urlsplit(request.path)
        query = urllib.parse.parse_qs(split.query)
        host_id = (query.get("host_id") or [""])[0]
        if split.path == "/host":
            await self._run_host(ws, host_id)
        else:
            await self._run_client(ws, host_id)

    async def _recv_hello(self, ws: ServerConnection, expected_role: str) -> dict[str, Any] | None:
        try:
            raw = await ws.recv()
        except ConnectionClosed:
            return None
        if not isinstance(raw, str):
            await _fail(ws, protocol.PROTOCOL_ERROR, "first frame must be the text hello")
            return None
        try:
            frame = protocol.decode_control(raw)
        except protocol.ProtocolError as exc:
            await _fail(ws, exc.code, exc.message)
            return None
        if (
            frame.get("t") != "hello"
            or frame.get("role") != expected_role
            or frame.get("proto") != protocol.LINK_PROTO_VERSION
        ):
            await _fail(ws, protocol.PROTOCOL_ERROR, "bad hello")
            return None
        return frame

    # ------------------------------------------------------------------
    # host leg
    # ------------------------------------------------------------------

    async def _run_host(self, ws: ServerConnection, host_id: str) -> None:
        if not host_id:
            await _fail(ws, protocol.PROTOCOL_ERROR, "host leg requires host_id")
            return
        hello = await self._recv_hello(ws, "host")
        if hello is None:
            return
        stale = self.hosts.get(host_id)
        if stale is not None:
            log.info("relay: host %r reconnected; dropping stale socket", host_id)
            try:
                await stale.ws.close(code=1000, reason="superseded")
            except Exception:  # noqa: BLE001
                pass
        reg = HostRegistration(ws, host_id, str(hello.get("name") or host_id))
        self.hosts[host_id] = reg
        log.info("relay: host %r connected (%s)", host_id, reg.name)
        try:
            await ws.send(protocol.encode_control("ready"))
            async for raw in ws:
                if isinstance(raw, str):
                    await self._host_control(reg, raw)
                else:
                    await self._host_binary(reg, raw)
        except ConnectionClosed:
            pass
        finally:
            if self.hosts.get(host_id) is reg:
                del self.hosts[host_id]
            await self._detach_clients(reg)
            log.info("relay: host %r disconnected", host_id)

    async def _host_control(self, reg: HostRegistration, raw: str) -> None:
        try:
            frame = protocol.decode_control(raw)
        except protocol.ProtocolError:
            return
        kind = frame.get("t")
        channel = frame.get("ch")
        route = reg.routes.get(channel) if isinstance(channel, int) else None
        if kind in ("opened", "exit", "eof", "ch_error") and route is None:
            return
        if kind == "opened":
            out = dict(frame)
            out["ch"] = route.client_channel
            if frame.get("ok") and isinstance(frame.get("err_ch"), int):
                # stderr rides a second channel; give it an id in the client's
                # upper-id space so it cannot collide with client-owned mains.
                err_client_ch = _ERR_CHANNEL_BASE + route.client_channel
                route.client.routes[err_client_ch] = frame["err_ch"]
                reg.routes[frame["err_ch"]] = _Route(route.client, err_client_ch)
                reg.err_channels[channel] = frame["err_ch"]
                out["err_ch"] = err_client_ch
            await _safe_send(route.client.ws, protocol.encode_frame(out))
        elif kind in ("exit", "ch_error"):
            out = dict(frame)
            out["ch"] = route.client_channel
            self._drop_route(reg, channel)
            err_host_channel = reg.err_channels.pop(channel, None)
            if err_host_channel is not None:
                self._drop_route(reg, err_host_channel)
            await _safe_send(route.client.ws, protocol.encode_frame(out))
        elif kind == "eof":
            out = dict(frame)
            out["ch"] = route.client_channel
            await _safe_send(route.client.ws, protocol.encode_frame(out))
        # Unknown types are ignored (compatibility rule).

    async def _host_binary(self, reg: HostRegistration, raw: bytes) -> None:
        try:
            channel, payload = protocol.decode_data(raw)
        except protocol.ProtocolError:
            return
        route = reg.routes.get(channel)
        if route is not None:
            await _safe_send(route.client.ws, protocol.encode_data(route.client_channel, payload))

    def _drop_route(self, reg: HostRegistration, host_channel: int) -> None:
        route = reg.routes.pop(host_channel, None)
        if route is not None:
            route.client.routes.pop(route.client_channel, None)

    async def _detach_clients(self, reg: HostRegistration) -> None:
        for session in [s for s in self.clients if s.host_id == reg.host_id]:
            self.clients.discard(session)
            for client_channel, host_channel in list(session.routes.items()):
                session.routes.pop(client_channel, None)
                reg.routes.pop(host_channel, None)
            await _fail(session.ws, protocol.HOST_OFFLINE, "host disconnected")

    # ------------------------------------------------------------------
    # client leg
    # ------------------------------------------------------------------

    async def _run_client(self, ws: ServerConnection, host_id: str) -> None:
        if not host_id:
            await _fail(ws, protocol.PROTOCOL_ERROR, "client leg requires host_id")
            return
        hello = await self._recv_hello(ws, "client")
        if hello is None:
            return
        host = self.hosts.get(host_id)
        if host is None:
            await _fail(ws, protocol.HOST_OFFLINE, f"host {host_id!r} is not connected")
            return
        session = ClientSession(ws, host_id)
        self.clients.add(session)
        log.info("relay: client paired with host %r", host_id)
        try:
            await ws.send(protocol.encode_control("ready", host_name=host.name))
            async for raw in ws:
                if isinstance(raw, str):
                    await self._client_control(session, host, raw)
                else:
                    await self._client_binary(session, host, raw)
        except ConnectionClosed:
            pass
        finally:
            self.clients.discard(session)
            for client_channel, host_channel in list(session.routes.items()):
                session.routes.pop(client_channel, None)
                host.routes.pop(host_channel, None)
                await _safe_send(host.ws, protocol.encode_control("close", ch=host_channel))

    async def _client_control(self, session: ClientSession, host: HostRegistration, raw: str) -> None:
        try:
            frame = protocol.decode_control(raw)
        except protocol.ProtocolError:
            return
        kind = frame.get("t")
        channel = frame.get("ch")
        if kind == "open":
            if not isinstance(channel, int) or channel in session.routes:
                return
            host_channel = host.alloc_channel()
            session.routes[channel] = host_channel
            host.routes[host_channel] = _Route(session, channel)
            out = dict(frame)
            out["ch"] = host_channel
            await _safe_send(host.ws, protocol.encode_frame(out))
        elif kind in ("resize", "close", "eof"):
            # `eof` client→host is exec stdin EOF (host→client `eof` — the
            # PTY child ended — rides the other direction and is not
            # rewritten here).
            host_channel = session.routes.get(channel) if isinstance(channel, int) else None
            if host_channel is None:
                return
            out = dict(frame)
            out["ch"] = host_channel
            # The route survives `close`: the host's trailing eof/exit for the
            # channel must still reach the client.  Routes are retired when
            # the host reports exit/ch_error, or when either leg disconnects.
            await _safe_send(host.ws, protocol.encode_frame(out))
        # Unknown types are ignored (compatibility rule).

    async def _client_binary(self, session: ClientSession, host: HostRegistration, raw: bytes) -> None:
        try:
            channel, payload = protocol.decode_data(raw)
        except protocol.ProtocolError:
            return
        host_channel = session.routes.get(channel)
        if host_channel is not None:
            await _safe_send(host.ws, protocol.encode_data(host_channel, payload))
