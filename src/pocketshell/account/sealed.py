"""Sealed broker transport for networks that intercept TLS.

Behind some managed sandboxes every HTTPS connection ends at a proxy that
re-signs it with its own CA, so TLS cannot protect ``device_code`` or the
``psc_`` session token from it. In *sealed mode* each broker request is
HPKE-sealed (RFC 9180, via ``pyhpke``) to a broker public key **pinned in this
release**, and the response is opened with the RFC 9458 §4.4 derivation. The
proxy carries ciphertext only. Wire format and rules: the broker repo's
``docs/SEALED-TRANSPORT.md``; client-side design: ``docs/account-intercepting-proxy.md``.

Rules (all fail closed, never a fallback to the plain path):

* opt-in only (``POCKETSHELL_BROKER_SEALED=1``) and only for the production
  broker, because the pinned keys belong to it;
* keys come from :data:`PINNED_KEYS` in this file, never from the environment,
  a file, or the network;
* the outer connection may use the environment proxy and CA bundle, but it
  carries only the envelope; the inner ``Authorization`` never leaves it in the
  clear and no ``Origin`` header is ever sent;
* redirects are refused, bodies are size-capped, and any decapsulation,
  key-id, shape or authentication failure aborts with a generic message.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time

from pyhpke import AEADId, CipherSuite, KDFId, KEMId

from pocketshell.account.errors import AccountError

ENV_SEALED = "POCKETSHELL_BROKER_SEALED"
VERSION = 1
REQ_INFO = b"pocketshell-sealed-v1 request"
RES_EXPORT = b"pocketshell-sealed-v1 response"
SEALED_PATH = "/sealed"
_NK, _NN = 16, 12

# kid (hex, first 4 bytes of SHA-256(public key)) -> base64url raw X25519 public key.
# The production broker key, provisioned 2026-11-27 per the broker's
# docs/SEALED-TRANSPORT.md "Operator runbook" (SSM
# /pocketshell-sync/sealed-transport-key, version 1). Keep exactly ONE entry:
# the broker accepts only its current key and seal() always uses the first
# kid, so pinning a second key before the broker accepts current+previous
# would break logins on one side of the swap.
PINNED_KEYS: dict[str, str] = {
    "575a6a86": "ORyrN6hRUdq2T2-mo14DB2mNpojLkP5xqW-YNetymiE",
}

_SUITE = CipherSuite.new(KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.AES128_GCM)


class SealedError(AccountError):
    """Sealed transport failure. Messages never include request or response data."""


def enabled() -> bool:
    return os.environ.get(ENV_SEALED, "") == "1"


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64u(text: object) -> bytes:
    if not isinstance(text, str) or not text.replace("-", "").replace("_", "").isalnum():
        raise SealedError("The sealed broker response was malformed.")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def key_id(public_key: bytes) -> str:
    return hashlib.sha256(public_key).digest()[:4].hex()


def _pins(pins: dict[str, str] | None) -> dict[str, bytes]:
    source = PINNED_KEYS if pins is None else pins
    out: dict[str, bytes] = {}
    for kid, value in source.items():
        raw = _unb64u(value)
        if len(raw) != 32 or key_id(raw) != kid:
            raise SealedError("A pinned broker key is inconsistent; refusing sealed mode.")
        out[kid] = raw
    if not out:
        raise SealedError(
            "Sealed mode is not available in this release: no broker key is pinned "
            "(see docs/account-intercepting-proxy.md)."
        )
    return out


class SealedRequest:
    """One sealed request and the context needed to open its response."""

    def __init__(self, body: bytes, ctx, enc: bytes) -> None:
        self.body = body
        self._ctx = ctx
        self._enc = enc

    def open(self, response_body: bytes) -> tuple[int, bytes]:
        """Authenticate and decrypt the response; returns (inner status, inner body)."""
        try:
            env = json.loads(response_body)
            if (
                not isinstance(env, dict)
                or set(env) != {"v", "nonce", "ct"}
                or env["v"] != VERSION
            ):
                raise ValueError
            nonce = _unb64u(env["nonce"])
            ct = _unb64u(env["ct"])
            if len(nonce) != 16 or len(ct) < 16:
                raise ValueError
            secret = self._ctx.export(RES_EXPORT, _NK)
            prk = hmac.new(self._enc + nonce, secret, hashlib.sha256).digest()
            key = hmac.new(prk, b"key\x01", hashlib.sha256).digest()[:_NK]
            iv = hmac.new(prk, b"nonce\x01", hashlib.sha256).digest()[:_NN]
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            plain = AESGCM(key).decrypt(iv, ct, b"")
            inner = json.loads(plain)
            if not isinstance(inner, dict) or set(inner) != {"s", "b"}:
                raise ValueError
            status, text = inner["s"], inner["b"]
            if not isinstance(status, int) or isinstance(status, bool) or not 100 <= status <= 599:
                raise ValueError
            if not isinstance(text, str):
                raise ValueError
        except SealedError:
            raise
        except Exception:  # noqa: BLE001 - any failure is one generic, data-free error
            raise SealedError(
                "The sealed broker response could not be authenticated; "
                "refusing to use it."
            ) from None
        return status, text.encode()


def seal(
    method: str,
    path: str,
    *,
    body: str | None,
    bearer: str | None,
    pins: dict[str, str] | None = None,
    kid: str | None = None,
    now: float | None = None,
    nonce: bytes | None = None,
    ephemeral=None,
) -> SealedRequest:
    keys = _pins(pins)
    use_kid = kid if kid is not None else sorted(keys)[0]
    if use_kid not in keys:
        raise SealedError("No pinned broker key matches; refusing sealed mode.")
    pk = _SUITE.kem.deserialize_public_key(keys[use_kid])
    kid_bytes = use_kid.encode()
    inner = {
        "m": method,
        "p": path,
        "a": None if bearer is None else f"Bearer {bearer}",
        "b": body,
        "t": int(time.time() if now is None else now),
        "n": _b64u(nonce if nonce is not None else secrets.token_bytes(16)),
    }
    enc, ctx = _SUITE.create_sender_context(
        pk, info=REQ_INFO + b"\x00" + kid_bytes, eks=ephemeral
    )
    ct = ctx.seal(json.dumps(inner, separators=(",", ":")).encode(), aad=kid_bytes)
    envelope = {"v": VERSION, "kid": use_kid, "enc": _b64u(enc), "ct": _b64u(ct)}
    return SealedRequest(json.dumps(envelope, separators=(",", ":")).encode(), ctx, enc)
