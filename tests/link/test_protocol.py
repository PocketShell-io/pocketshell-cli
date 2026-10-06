"""Unit tests for the link protocol codec (stdlib-only, no websockets)."""

import pytest

from pocketshell.link import protocol


def test_control_roundtrip_preserves_fields():
    raw = protocol.encode_control("open", ch=7, mode="exec", cmd="ls", timeout_ms=15000)
    frame = protocol.decode_control(raw)
    assert frame["v"] == protocol.LINK_PROTO_VERSION
    assert frame["t"] == "open"
    assert frame["ch"] == 7
    assert frame["mode"] == "exec"
    assert frame["cmd"] == "ls"
    assert frame["timeout_ms"] == 15000


def test_encode_frame_defaults_version_and_compact_encodes():
    raw = protocol.encode_frame({"t": "ready"})
    assert raw == '{"v":1,"t":"ready"}'


def test_decode_rejects_non_json():
    with pytest.raises(protocol.ProtocolError) as excinfo:
        protocol.decode_control("not json{")
    assert excinfo.value.code == protocol.PROTOCOL_ERROR


def test_decode_rejects_non_object():
    with pytest.raises(protocol.ProtocolError):
        protocol.decode_control("[1,2,3]")


def test_decode_rejects_wrong_version():
    with pytest.raises(protocol.ProtocolError) as excinfo:
        protocol.decode_control('{"v":2,"t":"hello"}')
    assert excinfo.value.code == protocol.PROTOCOL_ERROR


def test_decode_rejects_missing_or_non_string_type():
    with pytest.raises(protocol.ProtocolError):
        protocol.decode_control('{"v":1}')
    with pytest.raises(protocol.ProtocolError):
        protocol.decode_control('{"v":1,"t":7}')


def test_data_roundtrip_with_empty_payload():
    raw = protocol.encode_data(0xDEADBEEF, b"")
    channel, payload = protocol.decode_data(raw)
    assert channel == 0xDEADBEEF
    assert payload == b""


def test_data_roundtrip_binary_payload_is_byte_exact():
    payload = bytes(range(256)) * 3
    channel, got = protocol.decode_data(protocol.encode_data(1, payload))
    assert channel == 1
    assert got == payload


def test_decode_data_rejects_short_frame():
    with pytest.raises(protocol.ProtocolError):
        protocol.decode_data(b"\x00\x00\x01")


def test_encode_data_rejects_out_of_range_channel():
    with pytest.raises(protocol.ProtocolError):
        protocol.encode_data(-1, b"x")
    with pytest.raises(protocol.ProtocolError):
        protocol.encode_data(1 << 32, b"x")
