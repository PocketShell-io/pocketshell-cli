"""Interoperability and hostile-storage tests for the real enrollment vault."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from pocketshell.account import broker, credentials
from pocketshell.account.shared_vault import (
    CHECK, PREFIX, SharedVault, VaultError, b64, derive, opened, parse, seal, unb64,
    validate_index, wire,
)

FIXTURES = Path(__file__).parent / "fixtures"
PASSPHRASE = "four invented words for testing"


class Store:
    def __init__(self):
        self.creds = credentials.Credentials("https://broker.example", "psc_" + "A" * 43,
                                             "fixture-token", "fixture@example.com", 2**35, "fixture")
        self.account = "google:fixture-subject"
        self.slots = {}
        self.auth = None
        self.epoch = 1
        self.requests = []
        self.conflict = None

    def __call__(self, base, method, path, *, bearer, body=None):
        assert base == self.creds.broker_url and bearer == self.creds.access_token
        self.requests.append((method, path, copy.deepcopy(body)))
        if path == "/cli/session":
            return broker.Response(200, {"account_id": self.account, "email": self.creds.email,
                                         "token_id": self.creds.token_id})
        if path == "/cli/vault/status":
            header = self.slots.get("vault")
            return broker.Response(200, {"epoch": self.epoch, "hasVerifier": self.auth is not None,
                                         "retryAfter": 0, "kdf": parse(header[0])["kdf"] if header else None})
        if path == "/cli/vault/initialize":
            if self.slots or self.auth:
                return broker.Response(409, {"error": "vault_exists"})
            self.auth = body["auth"]
            self.slots["vault"] = (body["data"], 1)
            return broker.Response(201, {"ok": True, "epoch": 1, "version": 1})
        if path == "/cli/vault/verify":
            return broker.Response(200 if body["auth"] == self.auth else 401, {"ok": True, "epoch": 1})
        if path == "/cli/vault/verifier":
            self.auth = body["auth"]
            return broker.Response(200, {"ok": True, "epoch": 1})
        slot = path.removeprefix("/cli/settings/")
        if method == "GET":
            if slot not in self.slots:
                return broker.Response(404, {"error": "not_found"})
            text, version = self.slots[slot]
            return broker.Response(200, {"data": text, "version": version, "slot": slot})
        if method == "PUT":
            base = self.slots.get(slot, (None, 0))[1]
            if slot == self.conflict or body["version"] != base:
                return broker.Response(409, {"error": "conflict"})
            self.slots[slot] = (body["data"], base + 1)
            return broker.Response(200, {"version": base + 1})
        raise AssertionError((method, path))


@pytest.fixture
def store(monkeypatch):
    result = Store()
    monkeypatch.setattr(credentials, "load", lambda: result.creds)
    return result


@pytest.fixture
def vault(store):
    result = SharedVault(store.creds, request=store)
    result.create(PASSPHRASE)
    yield result
    result.close()


def test_exact_core_vault_argon2_nfkc_hkdf_and_aead_vector():
    vector = json.loads((FIXTURES / "vault-v1-vectors.json").read_text(encoding="utf-8"))
    kek, auth = derive(vector["passphrase"], vector["kdf"])
    assert kek.hex() == vector["kekHex"] and auth.hex() == vector["authHex"]
    vid, header = vector["vaultId"], vector["header"]
    assert opened(kek, header["check"], PREFIX + "check|" + vid) == CHECK
    dek = opened(kek, header["wrappedDek"], PREFIX + "dek|" + vid)
    assert dek.hex() == vector["dekHex"]
    assert opened(dek, header["index"], PREFIX + "index|" + vid).decode() == vector["indexJson"]
    key = vector["sshKey"]
    assert opened(dek, key["blob"], PREFIX + "key|" + vid + "|" + key["keyId"]).decode() == key["plaintext"]


def test_exact_core_trusted_host_ciphertext_and_slot_vector():
    v = json.loads((FIXTURES / "trusted-host-v1-vector.json").read_text(encoding="utf-8"))
    key = bytes.fromhex(v["dekHex"])
    box = seal(key, wire(v["data"]).encode(), v["aad"], unb64(v["envelope"]["n"], 12))
    assert box["ct"] == v["envelope"]["ct"]
    assert opened(key, v["envelope"], v["aad"]).decode() == v["plaintext"]
    identity = v["identity"]
    assert "th-" + b64(hashlib.sha256(wire([identity["serverUrl"], identity["deviceId"]]).encode()).digest()[:16]) == v["slot"]


def test_create_is_atomic_and_uploads_no_plaintext(vault, store):
    kid, public = vault.ensure_key("fixture-server")
    assert public.startswith("ssh-ed25519 ")
    data = wire(store.requests)
    assert PASSPHRASE not in data and "PRIVATE KEY" not in data and public not in data
    assert "fixture-server" not in data  # name is in the encrypted index, not metadata
    assert vault.index["hosts"]["fixture-server"] == {"keyId": kid, "gatewayAuth": "managed"}
    methods = [(m, p) for m, p, _ in store.requests]
    assert ("POST", "/cli/vault/initialize") in methods
    assert methods.index(("POST", "/cli/vault/verify")) < methods.index(("PUT", "/cli/settings/vk-" + kid))


def test_existing_vault_unlock_reuses_key_and_preserves_other_data(vault, store):
    kid, public = vault.ensure_key("server")
    before = copy.deepcopy(store.slots)
    other = SharedVault(store.creds, request=store)
    other.unlock(PASSPHRASE)
    assert other.ensure_key("server") == (kid, public)
    assert store.slots == before
    other.close()


def test_wrong_passphrase_changes_no_slot(vault, store):
    before = copy.deepcopy(store.slots)
    other = SharedVault(store.creds, request=store)
    with pytest.raises(VaultError, match="refused"):
        other.unlock("wrong secret")
    assert store.slots == before and not other.dek


@pytest.mark.parametrize("part", ["wrappedDek", "index", "check"])
def test_tampered_existing_vault_never_unlocked(vault, store, part):
    header = parse(store.slots["vault"][0])
    cipher = bytearray(unb64(header[part]["ct"]))
    cipher[0] ^= 1
    header[part]["ct"] = b64(cipher)
    store.slots["vault"] = (wire(header), 1)
    other = SharedVault(store.creds, request=store)
    with pytest.raises(VaultError):
        other.unlock(PASSPHRASE)
    assert not other.dek


@pytest.mark.parametrize("changes", [{"m": 1}, {"m": 2**40}, {"t": 0}, {"p": True}, {"alg": "pbkdf2"}])
def test_hostile_kdf_costs_rejected_before_derivation(changes):
    kdf = {"alg": "argon2id", "m": 65536, "t": 3, "p": 1, "salt": b64(bytes(16)), **changes}
    with pytest.raises(VaultError, match="unsupported Argon2id"):
        derive(PASSPHRASE, kdf)


def descriptor_values(vault):
    kid, _ = vault.ensure_key("server")
    vector = json.loads((FIXTURES / "trusted-host-v1-vector.json").read_text())
    return {**vector["data"], "hostAlias": "server", "keyId": kid}


def test_authenticated_descriptor_and_tombstone_are_monotonic(vault, store):
    data = descriptor_values(vault)
    args = {"server": "wss://gateway.pocketshell.io", "device": "fixture-server"}
    one = vault.descriptor(**args, values=data)
    two = vault.descriptor(**args, values={**data, "status": "revoked"})
    assert (one["revision"], two["revision"]) == (1, 2)
    with pytest.raises(VaultError, match="revoked"):
        vault.descriptor(**args, values=data)


@pytest.mark.parametrize("field", ["accountId", "vaultId", "epoch", "serverUrl", "deviceId", "revision", "ct"])
def test_substituted_descriptor_identity_or_ciphertext_is_rejected(vault, store, field):
    data = descriptor_values(vault)
    args = {"server": "wss://gateway.pocketshell.io", "device": "fixture-server"}
    vault.descriptor(**args, values=data)
    slot = next(k for k in store.slots if k.startswith("th-"))
    changed = parse(store.slots[slot][0])
    changed[field] = changed[field] + 1 if isinstance(changed[field], int) else "substitution"
    store.slots[slot] = (wire(changed), 1)
    with pytest.raises(VaultError):
        vault.descriptor(**args, values=data)


@pytest.mark.parametrize("field", ["sshHostKey", "devicePublicKey", "username", "hostAlias", "keyId"])
def test_trusted_server_changes_require_explicit_rotation(vault, store, field):
    data = descriptor_values(vault)
    args = {"server": "wss://gateway.pocketshell.io", "device": "fixture-server"}
    vault.descriptor(**args, values=data)
    with pytest.raises(VaultError, match="identity changed"):
        vault.descriptor(**args, values={**data, field: "different"})


def test_concurrent_header_update_never_overwrites_or_binds_key(vault, store):
    previous = copy.deepcopy(store.slots["vault"])
    store.conflict = "vault"
    with pytest.raises(VaultError, match="changed on another device"):
        vault.ensure_key("server")
    assert store.slots["vault"] == previous and "server" not in vault.index["hosts"]


def test_account_or_local_session_change_refuses_writes(vault, store, monkeypatch):
    store.account = "google:other-account"
    with pytest.raises(VaultError, match="account changed"):
        vault.ensure_key("server")
    store.account = "google:fixture-subject"
    monkeypatch.setattr(credentials, "load", lambda: credentials.Credentials(
        store.creds.broker_url, store.creds.access_token, "different-token", store.creds.email, 2**35, "fixture"))
    with pytest.raises(VaultError, match="local PocketShell login changed"):
        vault.ensure_key("server")


def test_new_vault_never_replaces_existing_or_accepts_numeric_pin(vault, store):
    before = copy.deepcopy(store.slots)
    other = SharedVault(store.creds, request=store)
    with pytest.raises(VaultError, match="already exists"):
        other.create(PASSPHRASE)
    assert store.slots == before
    other = SharedVault(Store().creds, request=Store())
    with pytest.raises(VaultError, match="strong vault passphrase"):
        other.create("1234567890123456")


def test_unknown_index_fields_fail_closed_instead_of_being_dropped():
    with pytest.raises(VaultError):
        validate_index({"keys": [], "hosts": {}, "newTrust": {"secret": "unknown"}})


@pytest.mark.parametrize("text", ['{"v":1,"v":2}', '{"v":NaN}', '{"v":Infinity}'])
def test_ambiguous_json_is_rejected(text):
    with pytest.raises(VaultError, match="malformed JSON"):
        parse(text)


def test_descriptor_generation_boolean_is_not_an_integer(vault, store):
    values = descriptor_values(vault)
    args = {"server": "wss://gateway.pocketshell.io", "device": "fixture-server"}
    vault.descriptor(**args, values=values)
    slot = next(k for k in store.slots if k.startswith("th-"))
    envelope = parse(store.slots[slot][0])
    envelope["epoch"] = True
    store.slots[slot] = (wire(envelope), 1)
    with pytest.raises(VaultError):
        vault.read_descriptor(**args)
