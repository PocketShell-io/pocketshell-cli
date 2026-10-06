"""Wire codec for the PocketShell link transport (protocol v1).

The link transport reaches hosts that have no inbound SSH: the host dials
OUT to a relay over WebSocket, clients dial the same relay, and the relay
pairs the legs by ``host_id``.  Control frames are JSON text messages
(``{"v":1,"t":"..."}``); channel data rides binary frames shaped
``u32BE channel-id | payload``.  This module is stdlib-only so the codec
stays testable and reusable without the ``websockets`` dependency.
"""

from __future__ import annotations

import json
import struct
from typing import Any

LINK_PROTO_VERSION = 1

# Stable error codes crossing every boundary (docs/link-transport.md).
AUTH_FAILED = "AUTH_FAILED"
HOST_OFFLINE = "HOST_OFFLINE"
PROTOCOL_ERROR = "PROTOCOL_ERROR"
NO_SUCH_CHANNEL = "NO_SUCH_CHANNEL"
EXEC_SPAWN_FAILED = "EXEC_SPAWN_FAILED"
PTY_OPEN_FAILED = "PTY_OPEN_FAILED"
UNSUPPORTED = "UNSUPPORTED"

_HEADER = struct.Struct(">I")


class ProtocolError(ValueError):
    """A frame that violates protocol v1."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def encode_frame(frame: dict[str, Any]) -> str:
    """Serialize a control frame, defaulting the protocol version.

    ``v`` and ``t`` are emitted first so wire dumps are deterministic.
    """
    body = dict(frame)
    if not isinstance(body.get("t"), str):
        raise ProtocolError(PROTOCOL_ERROR, "control frame needs a string 't'")
    ordered: dict[str, Any] = {"v": body.pop("v", LINK_PROTO_VERSION), "t": body.pop("t")}
    ordered.update(body)
    return json.dumps(ordered, separators=(",", ":"))


def encode_control(frame_type: str, **fields: Any) -> str:
    return encode_frame({"t": frame_type, **fields})


def decode_control(raw: str | bytes) -> dict[str, Any]:
    """Parse a control frame; raises :class:`ProtocolError` on any violation."""
    try:
        frame = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise ProtocolError(PROTOCOL_ERROR, f"control frame is not JSON: {exc}") from exc
    if not isinstance(frame, dict):
        raise ProtocolError(PROTOCOL_ERROR, "control frame must be a JSON object")
    if frame.get("v") != LINK_PROTO_VERSION:
        raise ProtocolError(PROTOCOL_ERROR, f"unsupported protocol version {frame.get('v')!r}")
    if not isinstance(frame.get("t"), str):
        raise ProtocolError(PROTOCOL_ERROR, "control frame needs a string 't'")
    return frame


def encode_data(channel: int, payload: bytes) -> bytes:
    if channel < 0 or channel > 0xFFFFFFFF:
        raise ProtocolError(PROTOCOL_ERROR, f"channel id out of range: {channel}")
    return _HEADER.pack(channel) + bytes(payload)


def decode_data(raw: bytes | bytearray | memoryview) -> tuple[int, bytes]:
    buf = bytes(raw)
    if len(buf) < _HEADER.size:
        raise ProtocolError(PROTOCOL_ERROR, "binary frame shorter than the channel header")
    return _HEADER.unpack_from(buf)[0], buf[_HEADER.size :]
