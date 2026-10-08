"""Synthetic OpenSSH public-key blobs for the gateway client tests."""

from __future__ import annotations

import base64
import struct


def ssh_string(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def mpint(value: int) -> bytes:
    raw = value.to_bytes((value.bit_length() + 8) // 8, "big")  # sign bit room
    if len(raw) > 1 and raw[0] == 0 and not raw[1] & 0x80:
        raw = raw[1:]
    return ssh_string(raw)


def ed25519_blob(seed: int = 1) -> bytes:
    return ssh_string(b"ssh-ed25519") + ssh_string(bytes([seed % 256]) * 32)


def ecdsa_blob(curve: str = "nistp256", point_len: int = 65) -> bytes:
    return (
        ssh_string(f"ecdsa-sha2-{curve}".encode())
        + ssh_string(curve.encode())
        + ssh_string(b"\x04" + b"\x11" * (point_len - 1))
    )


def rsa_blob(bits: int = 2048, e: int = 65537) -> bytes:
    n = (1 << (bits - 1)) | 1 | (0x5A5A << 8)
    return ssh_string(b"ssh-rsa") + mpint(e) + mpint(n)


def line(key_type: str, blob: bytes) -> str:
    return f"{key_type} {base64.b64encode(blob).decode()}"


ED25519_LINE = line("ssh-ed25519", ed25519_blob(1))
ED25519_LINE_2 = line("ssh-ed25519", ed25519_blob(2))
