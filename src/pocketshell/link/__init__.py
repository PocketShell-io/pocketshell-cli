"""PocketShell link transport: reach hosts that have no inbound SSH.

The host runs :mod:`pocketshell.link.daemon` (``pocketshell link run``),
which dials OUT to a relay; clients reach the host through the relay's
client leg.  See ``docs/link-transport.md``.  Only ``protocol`` is
importable without the optional ``websockets`` dependency.
"""

from pocketshell.link.protocol import (
    LINK_PROTO_VERSION,
    ProtocolError,
    decode_control,
    decode_data,
    encode_control,
    encode_data,
    encode_frame,
)

__all__ = [
    "LINK_PROTO_VERSION",
    "ProtocolError",
    "decode_control",
    "decode_data",
    "encode_control",
    "encode_data",
    "encode_frame",
]
