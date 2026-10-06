"""Minimal link client: the reference for every client port of the transport.

Used by the loopback test-suite and the docker E2E; web, desktop and Android
implementations speak the same frames (see docs/link-transport.md).
Operations on one client are serialized by design — open one client per
concurrent workload, exactly like one SSH connection per workload.
"""

from __future__ import annotations

import asyncio
import itertools
import urllib.parse
from dataclasses import dataclass

import websockets.asyncio.client
from websockets.asyncio.client import ClientConnection
from websockets.exceptions import ConnectionClosed

from . import protocol

DEFAULT_FRAME_WAIT = 15.0


class LinkError(Exception):
    """A link-level failure carrying a stable protocol error code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass
class ExecResult:
    stdout: bytes
    stderr: bytes
    exit_code: int | None
    timed_out: bool


def build_client_url(relay_url: str, token: str, host_id: str) -> str:
    split = urllib.parse.urlsplit(relay_url)
    query = urllib.parse.urlencode({"token": token, "host_id": host_id})
    path = split.path.rstrip("/") + "/client"
    return urllib.parse.urlunsplit((split.scheme, split.netloc, path, query, ""))


class PtyHandle:
    """One remote PTY: write/resize/close plus queued reads until exit."""

    def __init__(self, ws: ClientConnection, channel: int) -> None:
        self.ws = ws
        self.channel = channel
        self.exit_code: int | None = None
        self._queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._reader = asyncio.create_task(self._read_loop())

    async def _read_loop(self) -> None:
        try:
            while True:
                raw = await self.ws.recv()
                if isinstance(raw, str):
                    frame = protocol.decode_control(raw)
                    if frame.get("t") == "exit" and frame.get("ch") == self.channel:
                        self.exit_code = frame.get("exit_code")
                        await self._queue.put(b"")
                        return
                else:
                    data_channel, payload = protocol.decode_data(raw)
                    if data_channel == self.channel:
                        await self._queue.put(payload)
        except (ConnectionClosed, protocol.ProtocolError):
            await self._queue.put(b"")

    async def read(self, timeout: float = 5.0) -> bytes:
        """Next output chunk; b\"\" means the channel is gone (exit or drop)."""
        try:
            return await asyncio.wait_for(self._queue.get(), timeout)
        except asyncio.TimeoutError:
            return b""

    def write(self, payload: bytes) -> None:
        try:
            asyncio.create_task(self.ws.send(protocol.encode_data(self.channel, payload)))
        except ConnectionClosed as exc:
            raise LinkError(protocol.HOST_OFFLINE, "pty write after close") from exc

    async def resize(self, cols: int, rows: int) -> None:
        await self.ws.send(protocol.encode_control("resize", ch=self.channel, cols=cols, rows=rows))

    async def close(self) -> None:
        try:
            await self.ws.send(protocol.encode_control("close", ch=self.channel))
        except ConnectionClosed:
            pass


class LinkClient:
    """Dials the relay's /client leg and pairs with one host."""

    def __init__(self, relay_url: str, token: str, host_id: str) -> None:
        self._url = build_client_url(relay_url, token, host_id)
        self.host_id = host_id
        self._ws: ClientConnection | None = None
        self._counter = itertools.count(1)

    async def connect(self) -> "LinkClient":
        ws = await websockets.asyncio.client.connect(self._url, max_size=None)
        try:
            await ws.send(
                protocol.encode_control(
                    "hello", role="client", host_id=self.host_id,
                    proto=protocol.LINK_PROTO_VERSION,
                )
            )
            while True:
                raw = await ws.recv()
                if not isinstance(raw, str):
                    continue
                frame = protocol.decode_control(raw)
                if frame.get("t") == "error":
                    await ws.close()
                    raise LinkError(str(frame.get("code")), str(frame.get("message")))
                if frame.get("t") == "ready":
                    break
        except BaseException:
            await ws.close()
            raise
        self._ws = ws
        return self

    async def close(self) -> None:
        if self._ws is not None:
            await self._ws.close()
            self._ws = None

    def _require_ws(self) -> ClientConnection:
        if self._ws is None:
            raise LinkError(protocol.PROTOCOL_ERROR, "client is not connected")
        return self._ws

    async def _next_frame(self) -> tuple[str, object]:
        """('control', frame) or ('data', (channel, payload)); error frames raise."""
        ws = self._require_ws()
        while True:
            raw = await ws.recv()
            if isinstance(raw, str):
                frame = protocol.decode_control(raw)
                if frame.get("t") == "error":
                    raise LinkError(str(frame.get("code")), str(frame.get("message")))
                return "control", frame
            return "data", protocol.decode_data(raw)

    async def exec(
        self,
        cmd: str,
        timeout_ms: int | None = None,
        stdin: bytes | None = None,
    ) -> ExecResult:
        ws = self._require_ws()
        channel = next(self._counter)
        fields: dict[str, object] = {"ch": channel, "mode": "exec", "cmd": cmd}
        if timeout_ms is not None:
            fields["timeout_ms"] = timeout_ms
        await ws.send(protocol.encode_control("open", **fields))
        stdout = bytearray()
        stderr = bytearray()
        err_channel: int | None = None
        if stdin is not None:  # empty stdin still sends the EOF, or readers hang
            # After `opened` the daemon's stdin pipe is live: data frames are
            # the command's stdin, the client→host `eof` is its EOF.
            while True:
                kind, payload = await self._next_frame()
                if kind == "control" and payload.get("ch") == channel and payload.get("t") == "opened":
                    if not payload.get("ok"):
                        raise LinkError(str(payload.get("code")), str(payload.get("message")))
                    err_channel = payload.get("err_ch")
                    break
            await ws.send(protocol.encode_data(channel, stdin))
            await ws.send(protocol.encode_control("eof", ch=channel))
        while True:
            kind, payload = await self._next_frame()
            if kind == "data":
                data_channel, chunk = payload  # type: ignore[misc]
                if data_channel == channel:
                    stdout += chunk
                elif err_channel is not None and data_channel == err_channel:
                    stderr += chunk
                continue
            frame = payload  # type: ignore[assignment]
            if frame.get("ch") != channel:
                continue
            if frame.get("t") == "opened":
                if not frame.get("ok"):
                    raise LinkError(str(frame.get("code")), str(frame.get("message")))
                err_channel = frame.get("err_ch")
            elif frame.get("t") == "exit":
                return ExecResult(bytes(stdout), bytes(stderr), frame.get("exit_code"), bool(frame.get("timed_out")))
            elif frame.get("t") == "ch_error":
                raise LinkError(str(frame.get("code")), str(frame.get("message")))

    async def open_pty(
        self,
        cmd: str,
        cols: int = 80,
        rows: int = 24,
        term: str | None = "xterm-256color",
    ) -> PtyHandle:
        ws = self._require_ws()
        channel = next(self._counter)
        await ws.send(
            protocol.encode_control(
                "open", ch=channel, mode="pty", cmd=cmd, cols=cols, rows=rows, term=term,
            )
        )
        while True:
            kind, payload = await self._next_frame()
            if kind == "control":
                frame = payload  # type: ignore[assignment]
                if frame.get("ch") != channel:
                    continue
                if frame.get("t") == "opened":
                    if not frame.get("ok"):
                        raise LinkError(str(frame.get("code")), str(frame.get("message")))
                    return PtyHandle(ws, channel)
                if frame.get("t") == "ch_error":
                    raise LinkError(str(frame.get("code")), str(frame.get("message")))
