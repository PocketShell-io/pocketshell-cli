"""Vault envelope crypto: round trip, wrong password, tamper detection, format."""

from __future__ import annotations

import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pocketshell.keys import crypto

AAD = crypto.entry_aad("laptop", b"\x00\x00\x00\x0bssh-ed25519blob")
SECRET = b"-----BEGIN OPENSSH PRIVATE KEY-----\nnot-really-a-key\n"


def _flip(env: dict, field: str, index: int = 0) -> dict:
    raw = bytearray(base64.b64decode(env[field]))
    raw[index] ^= 0x01
    return {**env, field: base64.b64encode(bytes(raw)).decode()}


def test_round_trip_into_mutable_buffer():
    env = crypto.encrypt(SECRET, "correct horse", AAD)
    out = crypto.decrypt_into(env, "correct horse", AAD)
    assert isinstance(out, bytearray)
    assert out == SECRET
    crypto.wipe(out)
    assert out == bytearray(len(SECRET))


@pytest.mark.real_kdf
def test_envelope_matches_web_and_desktop_parameters():
    env = crypto.encrypt(SECRET, "pw-123456", AAD)
    # Same field set, KDF name and parameters as pocketshell-web
    # src/shared/syncCrypto.ts / pocketshell-desktop SyncCrypto.ts.
    assert set(env) == {"v", "kdf", "iter", "salt", "iv", "ct"}
    assert env["v"] == 1 and env["kdf"] == "pbkdf2-sha256" and env["iter"] == 600_000
    salt = base64.b64decode(env["salt"])
    iv = base64.b64decode(env["iv"])
    ct = base64.b64decode(env["ct"])
    assert len(salt) == 16 and len(iv) == 12 and len(ct) == len(SECRET) + 16
    # Independent decryption with the textbook construction: PBKDF2-SHA256
    # (600k, 32-byte key) → AES-256-GCM with ct||tag and the entry AAD.
    key = hashlib.pbkdf2_hmac("sha256", b"pw-123456", salt, 600_000, 32)
    assert AESGCM(key).decrypt(iv, ct, AAD) == SECRET


def test_fresh_salt_and_iv_every_time():
    a = crypto.encrypt(SECRET, "pw", AAD)
    b = crypto.encrypt(SECRET, "pw", AAD)
    assert a["salt"] != b["salt"] and a["iv"] != b["iv"] and a["ct"] != b["ct"]


def test_wrong_password_is_a_clear_error():
    env = crypto.encrypt(SECRET, "right", AAD)
    with pytest.raises(crypto.WrongPassword, match="wrong device password"):
        crypto.decrypt_into(env, "wrong", AAD)


@pytest.mark.parametrize("field", ["ct", "iv", "salt"])
def test_any_flipped_bit_fails_closed(field):
    env = crypto.encrypt(SECRET, "pw", AAD)
    with pytest.raises(crypto.WrongPassword):
        crypto.decrypt_into(_flip(env, field), "pw", AAD)


def test_tag_flip_fails_closed():
    env = crypto.encrypt(SECRET, "pw", AAD)
    last = len(base64.b64decode(env["ct"])) - 1
    with pytest.raises(crypto.WrongPassword):
        crypto.decrypt_into(_flip(env, "ct", last), "pw", AAD)


def test_entry_cannot_be_moved_to_another_name_or_public_key():
    env = crypto.encrypt(SECRET, "pw", AAD)
    with pytest.raises(crypto.WrongPassword):
        crypto.decrypt_into(env, "pw", crypto.entry_aad("other", b"\x00\x00\x00\x0bssh-ed25519blob"))
    with pytest.raises(crypto.WrongPassword):
        crypto.decrypt_into(env, "pw", crypto.entry_aad("laptop", b"another-public-key"))


def test_lowered_iteration_count_in_the_file_still_needs_the_password():
    env = crypto.encrypt(SECRET, "pw", AAD)
    with pytest.raises(crypto.WrongPassword):
        crypto.decrypt_into({**env, "iter": 1}, "pw", AAD)


@pytest.mark.parametrize(
    "patch, message",
    [
        ({"v": 2}, "cannot read"),
        ({"kdf": "scrypt"}, "cannot read"),
        ({"iter": 0}, "out of range"),
        ({"iter": 10_000_001}, "out of range"),
        ({"iter": True}, "missing"),
        ({"iter": "600000"}, "missing"),
        ({"salt": "!!!"}, "base64"),
        ({"salt": base64.b64encode(b"short").decode()}, "salt has the wrong length"),
        ({"iv": base64.b64encode(b"x" * 16).decode()}, "IV has the wrong length"),
        ({"ct": base64.b64encode(b"x" * 16).decode()}, "impossible length"),
        ({"ct": None}, "missing"),
    ],
)
def test_malformed_envelopes_are_refused_before_any_kdf(patch, message, monkeypatch):
    env = crypto.encrypt(SECRET, "pw", AAD)

    def no_kdf(*_a, **_k):
        raise AssertionError("KDF ran on a malformed envelope")

    monkeypatch.setattr(crypto, "_derive", no_kdf)
    with pytest.raises(crypto.VaultCryptoError, match=message):
        crypto.decrypt_into({**env, **patch}, "pw", AAD)


def test_envelope_is_plain_json():
    env = crypto.encrypt(SECRET, "pw", AAD)
    assert json.loads(json.dumps(env)) == env
    assert SECRET not in json.dumps(env).encode()


def test_oversized_plaintext_is_refused():
    with pytest.raises(crypto.VaultCryptoError, match="too large"):
        crypto.encrypt(b"x" * (crypto.MAX_PLAINTEXT_BYTES + 1), "pw", AAD)
