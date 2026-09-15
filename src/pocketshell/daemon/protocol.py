"""Length-prefixed JSON-RPC 2.0 wire framing for the daemon socket."""
from __future__ import annotations
import json
import socket
import struct
from typing import Any


# Length-prefix is a 4-byte unsigned big-endian integer. ``struct``
# format string lives once at module scope so the framing helpers do not
# drift apart.
_LENGTH_PREFIX_FORMAT = "!I"


_LENGTH_PREFIX_SIZE = struct.calcsize(_LENGTH_PREFIX_FORMAT)


# Cap each frame at 4 MiB. That is two orders of magnitude larger than
# the ``quse --json`` payload (~1.5 KB per provider) so we never trip in
# practice, but small enough that a malformed length prefix cannot trick
# us into allocating gigabytes.
_MAX_FRAME_BYTES = 4 * 1024 * 1024


class FramingError(RuntimeError):
    """Raised when a framed JSON-RPC message is malformed or truncated."""


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly ``n`` bytes from ``sock`` or raise :class:`FramingError`.

    ``socket.recv`` is allowed to return fewer bytes than requested, so
    we loop. Returning a short read here is the most common framing-
    error footgun; making the helper explicit keeps callers safe.
    """
    chunks: list[bytes] = []
    remaining = n
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise FramingError(
                f"socket closed after {n - remaining}/{n} bytes"
            )
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def send_frame(sock: socket.socket, payload: bytes) -> None:
    """Send a single length-prefixed frame on ``sock``.

    Raises :class:`FramingError` if the payload exceeds
    :data:`_MAX_FRAME_BYTES` so a misbehaving caller cannot wedge a
    16 MiB write into the socket before the peer notices.
    """
    if len(payload) > _MAX_FRAME_BYTES:
        raise FramingError(
            f"frame too large: {len(payload)} > {_MAX_FRAME_BYTES}"
        )
    header = struct.pack(_LENGTH_PREFIX_FORMAT, len(payload))
    sock.sendall(header + payload)


def recv_frame(sock: socket.socket) -> bytes:
    """Receive a single length-prefixed frame from ``sock``.

    Returns the raw payload bytes. Caller is responsible for JSON
    decoding so the framing layer is reusable for non-JSON future
    methods if any ever land.
    """
    header = _recv_exact(sock, _LENGTH_PREFIX_SIZE)
    (length,) = struct.unpack(_LENGTH_PREFIX_FORMAT, header)
    if length > _MAX_FRAME_BYTES:
        raise FramingError(
            f"frame too large: {length} > {_MAX_FRAME_BYTES}"
        )
    if length == 0:
        return b""
    return _recv_exact(sock, length)


def send_json(sock: socket.socket, obj: Any) -> None:
    """Convenience: encode ``obj`` as UTF-8 JSON and send one frame."""
    payload = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    send_frame(sock, payload)


def recv_json(sock: socket.socket) -> Any:
    """Convenience: receive one frame and decode it as UTF-8 JSON."""
    raw = recv_frame(sock)
    return json.loads(raw.decode("utf-8"))
