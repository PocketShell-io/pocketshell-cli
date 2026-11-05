"""Account vault v1, byte-compatible with pocketshell-core/keyVault.

Only ciphertext and the separate AUTH proof cross the broker boundary.
Plaintext private keys and the vault passphrase never leave this process.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import re
import secrets
import unicodedata
from datetime import datetime, timezone
from typing import Callable

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from pocketshell.account import broker, credentials
from pocketshell.account.errors import AccountError
from pocketshell.account.jsonutil import loads_strict

MAX_SLOT_BYTES = 8192
MAX_SAFE_INT = 2**53 - 1
PREFIX = "pocketshell-vault/v1/"
CHECK = b"pocketshell-vault-check-v1"
ACCOUNT_RE = re.compile(r"google:[A-Za-z0-9_-]{1,128}\Z")


class VaultError(AccountError):
    """Safe public error; never include server content or secret material."""


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def unb64(value: object, length: int | None = None) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise VaultError("The account vault contains malformed encoded data.")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if b64(raw) != value or (length is not None and len(raw) != length):
        raise VaultError("The account vault contains malformed encoded data.")
    return raw


def wire(value: object) -> str:
    # JSON.stringify: compact UTF-8, not Python's default ASCII escaping.
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def positive(value: object, maximum: int = MAX_SAFE_INT) -> bool:
    return type(value) is int and 1 <= value <= maximum


def parse(text: str) -> dict:
    try:
        value = loads_strict(text.encode("utf-8"))
        if isinstance(value, dict):
            return value
    except ValueError:
        pass
    raise VaultError("The account vault contains malformed JSON.")


def derive(passphrase: str, kdf: object) -> tuple[bytes, bytes]:
    if not isinstance(kdf, dict) or kdf.get("alg") != "argon2id" \
            or not all(type(kdf.get(k)) is int for k in ("m", "t", "p")) \
            or not 32768 <= kdf["m"] <= 262144 or not 3 <= kdf["t"] <= 10 \
            or not 1 <= kdf["p"] <= 8:
        raise VaultError("The account vault has unsupported Argon2id parameters.")
    salt = unb64(kdf.get("salt"), 16)
    mk = hash_secret_raw(unicodedata.normalize("NFKC", passphrase).encode("utf-8"), salt,
                         time_cost=kdf["t"], memory_cost=kdf["m"], parallelism=kdf["p"],
                         hash_len=32, type=Type.ID, version=19)
    def hkdf(label):
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"", info=(PREFIX + label).encode()).derive(mk)
    return hkdf("kek"), hkdf("auth")


def seal(key: bytes, plaintext: bytes, aad: str, nonce: bytes | None = None) -> dict:
    nonce = nonce if nonce is not None else secrets.token_bytes(12)
    if len(nonce) != 12 or len(key) != 32:
        raise VaultError("Invalid account vault encryption input.")
    return {"n": b64(nonce), "ct": b64(AESGCM(key).encrypt(nonce, plaintext, aad.encode("utf-8")))}


def opened(key: bytes, box: object, aad: str) -> bytes:
    if not isinstance(box, dict):
        raise VaultError("The account vault contains a malformed sealed value.")
    try:
        return AESGCM(key).decrypt(unb64(box.get("n"), 12), unb64(box.get("ct")), aad.encode("utf-8"))
    except (InvalidTag, ValueError):
        raise VaultError("The vault passphrase is wrong or the encrypted data was changed.") from None


def validate_header(header: dict) -> None:
    if set(header) != {"v", "vaultId", "kdf", "wrappedDek", "check", "index", "epoch", "updatedAt"} \
            or header.get("v") != 1 or type(header.get("v")) is not int or not positive(header.get("epoch")):
        raise VaultError("The account vault has an unsupported format or generation.")
    unb64(header.get("vaultId"), 16)
    if not isinstance(header.get("updatedAt"), str):
        raise VaultError("The account vault has no valid update timestamp.")


def validate_index(index: dict) -> None:
    if set(index) - {"keys", "hosts", "sync"} or not isinstance(index.get("keys"), list) \
            or not isinstance(index.get("hosts"), dict):
        raise VaultError("The account vault index is malformed or newer than this client.")
    ids = set()
    types = {"ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
             "ecdsa-sha2-nistp521", "password"}
    for item in index["keys"]:
        if not isinstance(item, dict) or set(item) - {"keyId", "name", "type", "fingerprint", "createdAt", "rotatedFrom"}:
            raise VaultError("The account vault contains an unsupported key entry.")
        unb64(item.get("keyId"), 16)
        if item["keyId"] in ids or item.get("type") not in types \
                or not isinstance(item.get("name"), str) or len(item["name"].encode("utf-16-le")) // 2 > 256 \
                or not isinstance(item.get("createdAt"), str):
            raise VaultError("The account vault contains a malformed key entry.")
        if item["type"] != "password" and not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", item.get("fingerprint", "")):
            raise VaultError("The account vault contains a malformed key fingerprint.")
        if "rotatedFrom" in item:
            unb64(item["rotatedFrom"], 16)
        ids.add(item["keyId"])
    for alias, binding in index["hosts"].items():
        if not alias or alias == "__proto__" or not isinstance(binding, dict) \
                or set(binding) != {"keyId", "gatewayAuth"} or binding["keyId"] not in ids \
                or binding["gatewayAuth"] not in ("host", "managed", "both"):
            raise VaultError("The account vault contains an unsupported host binding.")
    if "sync" in index and (not isinstance(index["sync"], dict) \
            or set(index["sync"]) != {"passphrase"} or not isinstance(index["sync"]["passphrase"], str)):
        raise VaultError("The account vault contains malformed sync settings.")


class SharedVault:
    """One explicit unlock; no passphrase, PEM or unsealed DEK on disk."""

    def __init__(self, creds: credentials.Credentials, *, request: Callable = broker.request):
        self.creds, self.request = creds, request
        self.account_id = self._identity()
        self.header: dict = {}
        self.index: dict = {}
        self.dek = bytearray()
        self.auth = bytearray()
        self.header_version = 0

    def __repr__(self):
        return "<SharedVault locked>" if not self.dek else "<SharedVault unlocked>"

    def close(self):
        self.dek[:] = bytes(len(self.dek))
        self.auth[:] = bytes(len(self.auth))
        self.dek.clear()
        self.auth.clear()
        self.index.clear()

    def call(self, method, path, body=None):
        return self.request(self.creds.broker_url, method, path, bearer=self.creds.access_token, body=body)

    def _identity(self):
        response = self.call("GET", "/cli/session")
        data = response.data or {}
        account = data.get("account_id")
        if response.status != 200 or not isinstance(account, str) or not ACCOUNT_RE.fullmatch(account) \
                or data.get("token_id") != self.creds.token_id or data.get("email") != self.creds.email:
            raise VaultError("The PocketShell login does not match this account or needs a broker update.")
        return account

    def check_identity(self):
        if self._identity() != self.account_id:
            raise VaultError("The signed-in account changed. Registration was stopped.")
        # A concurrent local login must not silently publish for the old account.
        current = credentials.load()
        if current.token_id != self.creds.token_id or current.broker_url != self.creds.broker_url:
            raise VaultError("The local PocketShell login changed. Registration was stopped.")

    def status(self) -> dict:
        resp = self.call("GET", "/cli/vault/status")
        if resp.status != 200 or not isinstance(resp.data, dict) or not positive(resp.data.get("epoch")):
            raise VaultError("The account vault status could not be read.")
        if type(resp.data.get("retryAfter")) is not int or resp.data["retryAfter"] != 0:
            raise VaultError("The vault is temporarily locked. Retry after the lockout expires.")
        return resp.data

    def pull(self, slot):
        resp = self.call("GET", "/cli/settings/" + slot)
        if resp.status == 404:
            return None, 0
        data = resp.data or {}
        if resp.status != 200 or not isinstance(data.get("data"), str) \
                or len(data["data"].encode("utf-8")) > MAX_SLOT_BYTES or not positive(data.get("version"), 1000001):
            raise VaultError("An account vault slot could not be read safely.")
        return data["data"], data["version"]

    def push(self, slot, value, version):
        text = wire(value)
        if len(text.encode("utf-8")) > MAX_SLOT_BYTES:
            raise VaultError("The account vault is full; no changes were authorized locally.")
        self.check_identity()
        response = self.call("PUT", "/cli/settings/" + slot, {"data": text, "version": version})
        if response.status == 409:
            raise VaultError("The vault changed on another device. Retry registration after refreshing it.")
        if response.status != 200 or (response.data or {}).get("version") != version + 1:
            raise VaultError("The encrypted vault upload was not confirmed; no new key was authorized locally.")
        return version + 1

    def unlock(self, passphrase: str, status: dict | None = None):
        status = status or self.status()
        if status.get("kdf") is None:
            raise VaultError("No account vault exists. Create it with a strong vault passphrase.")
        kek, auth = derive(passphrase, status["kdf"])
        if status.get("hasVerifier"):
            verified = self.call("POST", "/cli/vault/verify", {"auth": b64(auth)})
            if verified.status != 200 or (verified.data or {}).get("epoch") != status["epoch"]:
                raise VaultError("The vault passphrase was refused or its generation changed.")
        text, version = self.pull("vault")
        if text is None:
            raise VaultError("The account vault disappeared. Registration was stopped.")
        header = parse(text)
        validate_header(header)
        if header["kdf"] != status["kdf"] or header["epoch"] != status["epoch"]:
            raise VaultError("The account vault changed while unlocking. Try again.")
        vid = header["vaultId"]
        if opened(kek, header.get("check"), PREFIX + "check|" + vid) != CHECK:
            raise VaultError("The vault passphrase is wrong or the encrypted vault was changed.")
        dek = opened(kek, header.get("wrappedDek"), PREFIX + "dek|" + vid)
        if len(dek) != 32:
            raise VaultError("The account vault encryption key is malformed.")
        index = parse(opened(dek, header.get("index"), PREFIX + "index|" + vid).decode("utf-8"))
        validate_index(index)
        self.header, self.index, self.header_version = header, index, version
        self.dek, self.auth = bytearray(dek), bytearray(auth)
        self.check_identity()
        if not status.get("hasVerifier"):
            installed = self.call("POST", "/cli/vault/verifier", {"auth": b64(auth), "epoch": header["epoch"]})
            if installed.status != 200:
                self.close()
                raise VaultError("The existing vault verifier could not be installed; no SSH key was authorized.")
            verified = self.call("POST", "/cli/vault/verify", {"auth": b64(auth)})
            if verified.status != 200 or (verified.data or {}).get("epoch") != header["epoch"]:
                self.close()
                raise VaultError("The existing vault could not be verified; no SSH key was authorized.")

    def create(self, passphrase: str, status: dict | None = None):
        status = status or self.status()
        if status.get("kdf") is not None or status.get("hasVerifier"):
            raise VaultError("An account vault already exists; it must be unlocked, never replaced.")
        if len(passphrase) < 12 or passphrase.isdecimal() or not passphrase.strip():
            raise VaultError("Choose a strong vault passphrase of at least 12 characters, not a numeric PIN.")
        kdf = {"alg": "argon2id", "m": 65536, "t": 3, "p": 1, "salt": b64(secrets.token_bytes(16))}
        kek, auth = derive(passphrase, kdf)
        dek, vid = secrets.token_bytes(32), b64(secrets.token_bytes(16))
        index = {"keys": [], "hosts": {}}
        header = {"v": 1, "vaultId": vid, "kdf": kdf,
                  "wrappedDek": seal(kek, dek, PREFIX + "dek|" + vid),
                  "check": seal(kek, CHECK, PREFIX + "check|" + vid),
                  "index": seal(dek, wire(index).encode(), PREFIX + "index|" + vid),
                  "epoch": status["epoch"], "updatedAt": now_iso()}
        self.check_identity()
        initialized = self.call("POST", "/cli/vault/initialize",
                                {"data": wire(header), "auth": b64(auth), "epoch": status["epoch"]})
        if initialized.status != 201 or (initialized.data or {}).get("version") != 1 \
                or (initialized.data or {}).get("epoch") != status["epoch"]:
            raise VaultError("Vault creation was not confirmed. Retry by unlocking with the same passphrase; no key was authorized.")
        verified = self.call("POST", "/cli/vault/verify", {"auth": b64(auth)})
        if verified.status != 200 or (verified.data or {}).get("epoch") != status["epoch"]:
            raise VaultError("The encrypted vault was created but unlock was not confirmed; no key was authorized.")
        self.header_version = 1
        self.header, self.index = header, index
        self.dek, self.auth = bytearray(dek), bytearray(auth)

    def ensure_key(self, alias: str, *, before_bind: Callable | None = None):
        """Dedicated per-server key. Re-registration reuses the authenticated binding."""
        if not self.dek:
            raise VaultError("Unlock the account vault first.")
        if not alias or len(alias.encode("utf-16-le")) // 2 > 128 \
                or any(ord(c) < 32 for c in alias) or alias == "__proto__":
            raise VaultError("Choose a server name of 1–128 printable characters.")
        binding = self.index["hosts"].get(alias)
        if binding is not None:
            if binding["gatewayAuth"] != "managed":
                raise VaultError("This name uses a different SSH authorization policy; explicit migration is required.")
            kid = binding["keyId"]
            text, _ = self.pull("vk-" + kid)
            if text is None:
                raise VaultError("This server's existing encrypted key is missing. Refusing replacement.")
            blob = parse(text)
            if blob.get("v") != 1 or blob.get("vaultId") != self.header["vaultId"] or blob.get("keyId") != kid:
                raise VaultError("This server's encrypted key belongs to another vault or key.")
            public = opened(bytes(self.dek), blob.get("pub"), PREFIX + "pub|" + self.header["vaultId"] + "|" + kid).decode()
            pem = opened(bytes(self.dek), blob, PREFIX + "key|" + self.header["vaultId"] + "|" + kid)
            try:
                key = serialization.load_ssh_private_key(pem, password=None)
                derived_public = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
                if derived_public != public:
                    raise VaultError("The encrypted key's public and private halves do not match.")
            except (ValueError, TypeError):
                raise VaultError("This server's encrypted SSH key could not be used.") from None
            return kid, public
        key = Ed25519PrivateKey.generate()
        public = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
        ssh_blob = base64.b64decode(public.split()[1], validate=True)
        digest = hashlib.sha256(ssh_blob).digest()
        kid = b64(digest[:16])
        vid = self.header["vaultId"]
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption())
        blob = {"v": 1, "vaultId": vid, "keyId": kid,
                **seal(bytes(self.dek), pem, PREFIX + "key|" + vid + "|" + kid),
                "pub": seal(bytes(self.dek), public.encode(), PREFIX + "pub|" + vid + "|" + kid)}
        self.push("vk-" + kid, blob, 0)
        index = copy.deepcopy(self.index)
        index["keys"].append({"keyId": kid, "name": alias, "type": "ssh-ed25519",
                              "fingerprint": "SHA256:" + base64.b64encode(digest).decode().rstrip("="), "createdAt": now_iso()})
        index["hosts"][alias] = {"keyId": kid, "gatewayAuth": "managed"}
        header = copy.deepcopy(self.header)
        header["index"] = seal(bytes(self.dek), wire(index).encode(), PREFIX + "index|" + vid)
        header["updatedAt"] = now_iso()
        if before_bind is not None:
            before_bind(kid)
        self.header_version = self.push("vault", header, self.header_version)
        self.header, self.index = header, index
        return kid, public

    def confirm_binding(self, alias: str, key_id: str):
        """Re-read active generation/binding before changing local authorization."""
        status = self.status()
        text, _version = self.pull("vault")
        if text is None:
            raise VaultError("The vault disappeared before local authorization.")
        header = parse(text)
        validate_header(header)
        if header["vaultId"] != self.header["vaultId"] or header["epoch"] != self.header["epoch"] \
                or status["epoch"] != self.header["epoch"]:
            raise VaultError("The vault generation changed before local authorization.")
        index = parse(opened(bytes(self.dek), header["index"], PREFIX + "index|" + header["vaultId"]).decode())
        validate_index(index)
        if index["hosts"].get(alias) != {"keyId": key_id, "gatewayAuth": "managed"}:
            raise VaultError("The server's vault key binding changed before local authorization.")

    def read_descriptor_record(self, *, server: str, device: str):
        """Authenticate existing trust before any key or endpoint side effect."""
        slot = "th-" + b64(hashlib.sha256(wire([server, device]).encode()).digest()[:16])
        old, base = self.pull(slot)
        if old is not None:
            envelope = parse(old)
            expected = (self.account_id, self.header["vaultId"], self.header["epoch"], server, device)
            actual = tuple(envelope.get(k) for k in ("accountId", "vaultId", "epoch", "serverUrl", "deviceId"))
            if set(envelope) != {"v", "accountId", "vaultId", "epoch", "serverUrl", "deviceId", "revision", "n", "ct"} \
                    or type(envelope.get("v")) is not int or envelope.get("v") != 1 \
                    or type(envelope.get("epoch")) is not int or actual != expected \
                    or not positive(envelope.get("revision"), MAX_SAFE_INT - 1) \
                    or envelope["revision"] != base:
                raise VaultError("The server's trusted record belongs to another identity or generation.")
            aad = wire(["pocketshell-trusted-host/v1", *expected, envelope["revision"]])
            previous = parse(opened(bytes(self.dek), envelope, aad).decode())
            if set(previous) != {"hostAlias", "username", "keyId", "sshHostKey", "devicePublicKey", "status", "updatedAt"} \
                    or previous.get("status") not in ("active", "revoked"):
                raise VaultError("The server's trusted record has an unsupported shape.")
            binding = self.index["hosts"].get(previous.get("hostAlias"))
            if not binding or binding["keyId"] != previous["keyId"] or binding["gatewayAuth"] != "managed":
                raise VaultError("The server's trusted record does not match its vault key binding.")
            return slot, base, previous, envelope
        return slot, base, None, None

    def read_descriptor(self, *, server: str, device: str):
        slot, base, previous, _envelope = self.read_descriptor_record(server=server, device=device)
        return slot, base, previous

    def descriptor(self, *, server: str, device: str, values: dict):
        """Publish an authenticated descriptor. Never derive trust from a directory."""
        slot, base, previous = self.read_descriptor(server=server, device=device)
        if previous is not None:
            for name in ("sshHostKey", "devicePublicKey", "keyId", "hostAlias", "username"):
                if previous.get(name) != values.get(name):
                    raise VaultError("The server's trusted identity changed. Explicit rotation is required.")
            if previous.get("status") == "revoked" and values.get("status") != "revoked":
                raise VaultError("This server was revoked. Explicit re-registration is required.")
        revision = base + 1
        envelope = {"v": 1, "accountId": self.account_id, "vaultId": self.header["vaultId"],
                    "epoch": self.header["epoch"], "serverUrl": server, "deviceId": device, "revision": revision}
        aad = wire(["pocketshell-trusted-host/v1", self.account_id, self.header["vaultId"], self.header["epoch"], server, device, revision])
        envelope.update(seal(bytes(self.dek), wire({**values, "updatedAt": now_iso()}).encode(), aad))
        self.push(slot, envelope, base)
        return envelope
