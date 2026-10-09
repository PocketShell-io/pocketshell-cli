"""Envelope crypto for the key vault: PBKDF2-SHA256 → AES-256-GCM.

Same family and parameters as the PocketShell web and desktop clients'
sync envelope (pocketshell-web ``src/shared/syncCrypto.ts``,
pocketshell-desktop ``src/main/sync/SyncCrypto.ts``)::

    {"v": 1, "kdf": "pbkdf2-sha256", "iter": 600000,
     "salt": "<b64 16B>", "iv": "<b64 12B>", "ct": "<b64 ciphertext+16B tag>"}

Fresh salt and IV for every encryption, so each entry is independent and
re-encrypting the same key never produces the same blob. One deliberate
addition: every envelope is bound to its vault entry with GCM associated
data (``AAD_PREFIX + name + NUL + public-key blob``), so a ciphertext moved
under another name, or paired with another public key, fails the tag
check. The web envelope has no AAD; vault entries are local-only and are
never handed to the web/desktop parsers.

Plaintext handling: decryption writes into a caller-visible ``bytearray``
(``update_into``) that the caller wipes with :func:`wipe` once the key has
been handed to ``ssh-add``. Python cannot guarantee that no other copy ever
existed (the password ``str``, the derived key ``bytes``), so this is best
effort — but the key itself is never materialised as an immutable object
on the ``gateway ssh`` path.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import secrets
from typing import Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

FORMAT_VERSION = 1
KDF_NAME = "pbkdf2-sha256"
KDF_ITERATIONS = 600_000
# The iteration count is read from the (attacker-writable) file and feeds the
# KDF loop: bounded before use, same bounds as the web/desktop parsers.
MAX_ITERATIONS = 10_000_000
SALT_BYTES = 16
IV_BYTES = 12
KEY_BYTES = 32
TAG_BYTES = 16
AAD_PREFIX = b"pocketshell-key-vault/v1\0"
# A private key is a few KiB; anything far larger is not ours.
MAX_PLAINTEXT_BYTES = 64 * 1024


class VaultCryptoError(Exception):
    """Malformed envelope or failed decryption. Message is safe to print."""


class WrongPassword(VaultCryptoError):
    """The GCM tag did not verify: wrong device password, or a tampered entry.

    GCM cannot tell the two apart and the message does not pretend to.
    """


def entry_aad(name: str, public_blob: bytes) -> bytes:
    return AAD_PREFIX + name.encode("utf-8") + b"\0" + public_blob


def wipe(buf: bytearray | memoryview | None) -> None:
    """Overwrite a mutable buffer with zeros (best effort secret hygiene)."""
    if buf is None:
        return
    view = buf if isinstance(buf, memoryview) else memoryview(buf)
    view[:] = bytes(len(view))


def _derive(password: str, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, KEY_BYTES)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(value: object, what: str) -> bytes:
    if not isinstance(value, str):
        raise VaultCryptoError(f"envelope {what} is missing")
    try:
        out = base64.b64decode(value.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError, ValueError):
        raise VaultCryptoError(f"envelope {what} is not valid base64") from None
    return out


def encrypt(plaintext: bytes | bytearray | memoryview, password: str, aad: bytes) -> dict:
    """Encrypt ``plaintext`` under ``password`` into an envelope dict."""
    if len(plaintext) > MAX_PLAINTEXT_BYTES:
        raise VaultCryptoError("key is too large for the vault")
    salt = secrets.token_bytes(SALT_BYTES)
    iv = secrets.token_bytes(IV_BYTES)
    key = _derive(password, salt, KDF_ITERATIONS)
    enc = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
    enc.authenticate_additional_data(aad)
    ct = enc.update(plaintext) + enc.finalize()
    return {
        "v": FORMAT_VERSION,
        "kdf": KDF_NAME,
        "iter": KDF_ITERATIONS,
        "salt": _b64(salt),
        "iv": _b64(iv),
        "ct": _b64(ct + enc.tag),
    }


def validate_envelope(env: object) -> tuple[int, bytes, bytes, bytes]:
    """Check an envelope's shape; return ``(iter, salt, iv, ct+tag)``."""
    if not isinstance(env, Mapping):
        raise VaultCryptoError("vault entry has no envelope")
    if env.get("v") != FORMAT_VERSION or env.get("kdf") != KDF_NAME:
        raise VaultCryptoError(
            f"vault entry uses a format this CLI cannot read "
            f"(v={env.get('v')!r:.20}, kdf={env.get('kdf')!r:.40})"
        )
    iterations = env.get("iter")
    if not isinstance(iterations, int) or isinstance(iterations, bool):
        raise VaultCryptoError("envelope iteration count is missing")
    if not 1 <= iterations <= MAX_ITERATIONS:
        raise VaultCryptoError("envelope iteration count is out of range")
    salt = _unb64(env.get("salt"), "salt")
    iv = _unb64(env.get("iv"), "iv")
    ct = _unb64(env.get("ct"), "ct")
    if len(salt) != SALT_BYTES:
        raise VaultCryptoError("envelope salt has the wrong length")
    if len(iv) != IV_BYTES:
        raise VaultCryptoError("envelope IV has the wrong length")
    if not TAG_BYTES < len(ct) <= MAX_PLAINTEXT_BYTES + TAG_BYTES:
        raise VaultCryptoError("envelope ciphertext has an impossible length")
    return iterations, salt, iv, ct


def decrypt_into(env: object, password: str, aad: bytes) -> bytearray:
    """Decrypt an envelope into a fresh ``bytearray`` the caller must :func:`wipe`.

    Raises :class:`WrongPassword` when the tag does not verify (the buffer
    is wiped first) and :class:`VaultCryptoError` for a malformed envelope.
    """
    iterations, salt, iv, blob = validate_envelope(env)
    ct, tag = blob[:-TAG_BYTES], blob[-TAG_BYTES:]
    key = _derive(password, salt, iterations)
    dec = Cipher(algorithms.AES(key), modes.GCM(iv, tag)).decryptor()
    dec.authenticate_additional_data(aad)
    # update_into needs block_size - 1 bytes of slack; the slack is trimmed
    # below by copying into an exactly-sized buffer, then wiped.
    scratch = bytearray(len(ct) + 15)
    try:
        n = dec.update_into(ct, scratch)
        dec.finalize()
    except InvalidTag:
        wipe(scratch)
        raise WrongPassword(
            "wrong device password (or the vault entry was modified)"
        ) from None
    with memoryview(scratch) as view:
        out = bytearray(view[:n])  # one copy, no intermediate slice object
    wipe(scratch)
    return out
