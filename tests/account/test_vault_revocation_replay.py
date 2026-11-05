import copy
import pytest
from test_vault_enrollment import setup as shared_setup, publish  # noqa: F401
from test_shared_vault import PASSPHRASE
from pocketshell.account.shared_vault import SharedVault, VaultError
from pocketshell.account.shared_vault import opened, parse, seal, wire
from pocketshell.gateway import vault_enrollment as enrollment


@pytest.fixture
def setup(request):
    return request.getfixturevalue("shared_setup")


def restart(store):
    client = SharedVault(store.creds, request=store)
    client.unlock(PASSPHRASE)
    return client


def test_revoked_server_rejects_replayed_active_descriptor(setup):
    store, vault, journal, authorized, events = setup
    publish(vault)
    slot = next(s for s in store.slots if s.startswith('th-'))
    active = copy.deepcopy(store.slots[slot])
    publish(vault, revoke=True)
    assert not authorized
    store.slots[slot] = active
    fresh = restart(store)
    with pytest.raises(VaultError):
        publish(fresh)
    assert not authorized, 'replayed cloud state must not resurrect a revoked local key'


def test_failed_tombstone_upload_cannot_restore_removed_key_on_register(setup):
    store, vault, journal, authorized, events = setup
    publish(vault)
    slot = next(s for s in store.slots if s.startswith('th-'))
    store.conflict = slot
    with pytest.raises(VaultError):
        publish(vault, revoke=True)
    assert not authorized, 'local key removal happened before the failed tombstone upload'
    store.conflict = None
    fresh = restart(store)
    with pytest.raises(VaultError):
        publish(fresh)
    assert not authorized, 'ordinary register must not undo local revocation intent'


def test_deleted_accepted_record_never_resets_local_trust(setup):
    store, vault, journal, authorized, events = setup
    publish(vault)
    slot = next(s for s in store.slots if s.startswith("th-"))
    store.slots.pop(slot)
    with pytest.raises(VaultError, match="previously accepted.*missing"):
        publish(restart(store))
    assert events == ["authorize"]


def test_active_revision_floor_rejects_older_valid_active_record(setup):
    store, vault, journal, authorized, events = setup
    publish(vault)
    slot = next(s for s in store.slots if s.startswith("th-"))
    first = copy.deepcopy(store.slots[slot])
    publish(vault)
    store.slots[slot] = first
    with pytest.raises(VaultError, match="rolled back"):
        publish(restart(store))
    assert events == ["authorize", "authorize"]


def test_same_revision_different_valid_ciphertext_is_refused(setup):
    store, vault, journal, authorized, events = setup
    publish(vault)
    slot = next(s for s in store.slots if s.startswith("th-"))
    envelope = parse(store.slots[slot][0])
    aad = wire(["pocketshell-trusted-host/v1", *[envelope[k] for k in
                ("accountId", "vaultId", "epoch", "serverUrl", "deviceId", "revision")]])
    values = parse(opened(bytes(vault.dek), envelope, aad).decode())
    # Even a separately authenticated same-version record is not the record
    # this endpoint already accepted. No nonce/ciphertext substitution.
    envelope.update(seal(bytes(vault.dek), wire(values).encode(), aad))
    store.slots[slot] = (wire(envelope), 1)
    with pytest.raises(VaultError, match="rolled back or changed"):
        publish(restart(store))
    assert events == ["authorize"]


def test_revocation_intent_must_persist_before_actual_key_removal(setup, monkeypatch):
    store, vault, journal, authorized, events = setup
    publish(vault)
    before = set(authorized)
    def failed(*_args):
        raise OSError("invented disk failure")
    monkeypatch.setattr(enrollment, "write_trust", failed)
    with pytest.raises(OSError):
        publish(vault, revoke=True)
    assert authorized == before and events == ["authorize"]


def test_failed_revocation_can_retry_but_ordinary_registration_stays_revoked(setup):
    store, vault, journal, authorized, events = setup
    publish(vault)
    slot = next(s for s in store.slots if s.startswith("th-"))
    store.conflict = slot
    with pytest.raises(VaultError):
        publish(vault, revoke=True)
    assert not authorized
    store.conflict = None
    fresh = restart(store)
    with pytest.raises(VaultError, match="revoked locally"):
        publish(fresh)
    publish(fresh, revoke=True)
    assert not authorized and events == ["authorize", "remove", "remove"]


def test_old_pending_enrollment_metadata_cannot_replace_revocation_history(setup):
    store, vault, journal, authorized, events = setup
    publish(vault)
    previous_intent = copy.deepcopy(journal)
    slot = next(s for s in store.slots if s.startswith("th-"))
    active = copy.deepcopy(store.slots[slot])
    publish(vault, revoke=True)
    journal.clear()
    journal.update(previous_intent)
    store.slots[slot] = active
    with pytest.raises(VaultError, match="revoked locally"):
        publish(restart(store))
    assert not authorized


@pytest.mark.parametrize("field,value", [("accountId", "google:different"), ("vaultId", "different-vault"),
                                        ("epoch", 2), ("serverUrl", "wss://other.example"),
                                        ("deviceId", "other-device")])
def test_local_floor_is_scoped_and_preserves_other_account_generations(setup, field, value):
    store, vault, journal, authorized, events = setup
    publish(vault, revoke=False)
    expected = {**{k: v for k, v in journal.items() if k not in ("keyId", "phase")}, "v": 1}
    before = enrollment.read_trust(None)
    history, floor = enrollment.accepted_trust(None, {**expected, field: value})
    assert floor is None and history == before
    _history, original = enrollment.accepted_trust(None, expected)
    assert original["revision"] == 1 and original["state"] == "active"


@pytest.mark.parametrize("field", ["devicePublicKey", "sshHostKey", "hostAlias", "username"])
def test_same_scope_changed_local_identity_cannot_reuse_floor(setup, field):
    store, vault, journal, authorized, events = setup
    publish(vault)
    expected = {**{k: v for k, v in journal.items() if k not in ("keyId", "phase")}, "v": 1}
    with pytest.raises(VaultError, match="identity or name changed"):
        enrollment.accepted_trust(None, {**expected, field: "different"})


def test_legacy_identity_only_intent_cannot_bootstrap_after_unrecorded_revocation(setup):
    store, vault, journal, authorized, events = setup
    slot, _, _ = vault.read_descriptor(server="wss://gateway.pocketshell.io", device="fixture-linux")
    store.conflict = slot
    with pytest.raises(VaultError):
        publish(vault)
    assert journal["v"] == 2
    journal["v"] = 1
    journal.pop("phase")
    store.conflict = None
    with pytest.raises(VaultError, match="legacy metadata"):
        publish(restart(store))
    assert not authorized
