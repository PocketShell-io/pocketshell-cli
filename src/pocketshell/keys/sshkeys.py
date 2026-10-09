"""Inspect and generate SSH private keys without touching the disk.

Import keeps the key bytes exactly as given — an OpenSSH key with its own
passphrase stays encrypted with that passphrase inside the vault, and the
passphrase is asked for by ``ssh-add`` at connect time, never by us. What
we need from a key without decrypting it is its public half:

- ``openssh-key-v1`` (``-----BEGIN OPENSSH PRIVATE KEY-----``, every key
  ``ssh-keygen`` has written since OpenSSH 7.8): the public key blob sits in
  the unencrypted header, so it is read even from a passphrase-protected key;
- unencrypted PEM/PKCS#8 (RSA/EC/Ed25519): loaded with ``cryptography`` to
  compute the public key;
- encrypted legacy PEM: the public key cannot be computed without the
  passphrase, so the ``.pub`` next to it is required.

Generation happens in memory with ``cryptography`` and yields an OpenSSH
private key without a passphrase of its own (the vault's device password
protects it); a key that should ALSO carry an OpenSSH passphrase is made
with ``ssh-keygen`` and imported with ``keys add``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import struct
from dataclasses import dataclass
from typing import Optional

OPENSSH_BEGIN = b"-----BEGIN OPENSSH PRIVATE KEY-----"
OPENSSH_END = b"-----END OPENSSH PRIVATE KEY-----"
OPENSSH_MAGIC = b"openssh-key-v1\0"
MAX_KEY_FILE_BYTES = 16 * 1024

KEY_TYPES = (
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
)
_PEM_RE = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----")
_COMMENT_RE = re.compile(r"\A[\x20-\x7e]{0,200}\Z")


class KeyFormatError(ValueError):
    """Not a usable SSH private key. Message is safe to print (no key bytes)."""


@dataclass(frozen=True)
class PublicKey:
    key_type: str
    blob: bytes
    comment: str = ""

    @property
    def line(self) -> str:
        base = f"{self.key_type} {base64.b64encode(self.blob).decode('ascii')}"
        return f"{base} {self.comment}" if self.comment else base

    @property
    def fingerprint(self) -> str:
        digest = hashlib.sha256(self.blob).digest()
        return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


@dataclass(frozen=True)
class KeyInfo:
    public: PublicKey
    passphrase_protected: bool


def _read_string(buf: bytes, off: int) -> tuple[bytes, int]:
    if off + 4 > len(buf):
        raise KeyFormatError("truncated OpenSSH private key")
    (n,) = struct.unpack(">I", buf[off : off + 4])
    off += 4
    if n > len(buf) - off:
        raise KeyFormatError("truncated OpenSSH private key")
    return buf[off : off + n], off + n


def parse_public_line(text: str) -> PublicKey:
    """Parse a ``.pub`` line (``TYPE BASE64 [COMMENT]``)."""
    parts = text.strip().split(None, 2)
    if len(parts) < 2 or parts[0] not in KEY_TYPES:
        raise KeyFormatError("not an OpenSSH public key line")
    try:
        blob = base64.b64decode(parts[1].encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError):
        raise KeyFormatError("public key is not valid base64") from None
    inner, _ = _read_string(blob, 0)
    if inner.decode("ascii", "replace") != parts[0]:
        raise KeyFormatError("public key type does not match its blob")
    comment = parts[2] if len(parts) > 2 and _COMMENT_RE.match(parts[2]) else ""
    return PublicKey(parts[0], blob, comment)


def _openssh_info(data: bytes) -> KeyInfo:
    start = data.index(OPENSSH_BEGIN) + len(OPENSSH_BEGIN)
    end = data.find(OPENSSH_END, start)
    if end < 0:
        raise KeyFormatError("OpenSSH private key has no END line")
    body = b"".join(data[start:end].split())
    # Only the unencrypted header and the public key are needed; decode a
    # prefix big enough for both (a 16 kbit RSA public blob is ~2 KiB) so an
    # unprotected key's private half is not needlessly copied around.
    prefix = body[: min(len(body), 4096) // 4 * 4]
    try:
        raw = base64.b64decode(prefix, validate=True)
    except (binascii.Error, ValueError):
        raise KeyFormatError("OpenSSH private key is not valid base64") from None
    if not raw.startswith(OPENSSH_MAGIC):
        raise KeyFormatError("not an openssh-key-v1 private key")
    off = len(OPENSSH_MAGIC)
    cipher, off = _read_string(raw, off)
    _kdf, off = _read_string(raw, off)
    _kdfopts, off = _read_string(raw, off)
    if off + 4 > len(raw):
        raise KeyFormatError("truncated OpenSSH private key")
    (nkeys,) = struct.unpack(">I", raw[off : off + 4])
    off += 4
    if nkeys != 1:
        raise KeyFormatError(f"OpenSSH private key holds {nkeys} keys; exactly one is supported")
    blob, off = _read_string(raw, off)
    key_type, _ = _read_string(blob, 0)
    key_type_s = key_type.decode("ascii", "replace")
    if key_type_s not in KEY_TYPES:
        raise KeyFormatError(f"unsupported key type {key_type_s[:40]!r}")
    return KeyInfo(PublicKey(key_type_s, blob), passphrase_protected=cipher != b"none")


def inspect_private_key(data: bytes | bytearray, pub_line: Optional[str] = None) -> KeyInfo:
    """Public half + passphrase flag of a private key, without its passphrase.

    ``pub_line`` (the companion ``.pub``) is required only for an encrypted
    legacy PEM key and, when given for any other key, must match it.
    """
    data = bytes(data[: MAX_KEY_FILE_BYTES + 1])
    if len(data) > MAX_KEY_FILE_BYTES:
        raise KeyFormatError("file is too large to be an SSH private key")
    pub = parse_public_line(pub_line) if pub_line is not None else None
    if OPENSSH_BEGIN in data:
        info = _openssh_info(data)
    else:
        m = _PEM_RE.search(data)
        if m is None:
            if data.startswith(b"PuTTY-User-Key-File"):
                raise KeyFormatError(
                    "PuTTY .ppk keys are not supported; export an OpenSSH key "
                    "(puttygen KEY.ppk -O private-openssh-new -o KEY)"
                )
            raise KeyFormatError("not a PEM or OpenSSH private key")
        label = m.group(1).decode()
        if "PRIVATE KEY" not in label:
            raise KeyFormatError(f"not a private key (found {label!r})")
        encrypted = "ENCRYPTED" in label or b"Proc-Type: 4,ENCRYPTED" in data
        if encrypted:
            if pub is None:
                raise KeyFormatError(
                    "this passphrase-protected PEM key does not reveal its public key; "
                    "put its .pub next to it, or convert it to the OpenSSH format "
                    "with `ssh-keygen -p -f KEY` (which keeps the passphrase)"
                )
            info = KeyInfo(pub, passphrase_protected=True)
        else:
            info = KeyInfo(_pem_public(data), passphrase_protected=False)
    if pub is not None:
        if (pub.key_type, pub.blob) != (info.public.key_type, info.public.blob):
            raise KeyFormatError("the .pub file does not belong to this private key")
        info = KeyInfo(pub, info.passphrase_protected)
    return info


def _pem_public(data: bytes) -> PublicKey:
    from cryptography.hazmat.primitives import serialization

    try:
        key = serialization.load_pem_private_key(data, password=None)
        line = key.public_key().public_bytes(
            serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
        )
    except (ValueError, TypeError) as exc:
        raise KeyFormatError(f"unreadable PEM private key ({type(exc).__name__})") from None
    except Exception as exc:  # UnsupportedAlgorithm and friends
        raise KeyFormatError(f"unsupported PEM private key ({type(exc).__name__})") from None
    return parse_public_line(line.decode("ascii"))


GENERATE_TYPES = {
    "ed25519": None,
    "ecdsa": 256,
    "rsa": 4096,
}


def generate(key_type: str, comment: str) -> tuple[bytes, PublicKey]:
    """A new private key (OpenSSH format, no own passphrase) and its public half."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

    if key_type == "ed25519":
        key = ed25519.Ed25519PrivateKey.generate()
    elif key_type == "ecdsa":
        key = ec.generate_private_key(ec.SECP256R1())
    elif key_type == "rsa":
        key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    else:
        raise KeyFormatError(f"unsupported key type {key_type!r}")
    private = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    )
    public_line = key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    ).decode("ascii")
    pub = parse_public_line(public_line)
    if comment and not _COMMENT_RE.match(comment):
        raise KeyFormatError("comment must be printable ASCII (at most 200 characters)")
    return private, PublicKey(pub.key_type, pub.blob, comment)
