"""Real vault + registration orchestration, with local endpoint as an oracle."""
from __future__ import annotations

import copy
import json
from contextlib import nullcontext
from pathlib import Path

import pytest

from pocketshell.account import credentials
from pocketshell.account.errors import NotLoggedIn
from pocketshell.account.shared_vault import SharedVault, VaultError, parse, wire
from pocketshell.gateway import vault_enrollment as enrollment

from test_shared_vault import FIXTURES, PASSPHRASE, Store


@pytest.fixture
def setup(monkeypatch):
    store = Store()
    monkeypatch.setattr(credentials, "load", lambda: store.creds)
    vault = SharedVault(store.creds, request=store)
    vault.create(PASSPHRASE)
    vector = json.loads((FIXTURES / "trusted-host-v1-vector.json").read_text())
    identity = {"serverUrl": vector["identity"]["serverUrl"], "deviceId": "fixture-linux",
                "sshHostKey": vector["data"]["sshHostKey"], "devicePublicKey": vector["data"]["devicePublicKey"]}
    monkeypatch.setattr(enrollment, "local_identity", lambda _directory: copy.deepcopy(identity))
    monkeypatch.setattr(enrollment, "local_user", lambda: "orin")
    monkeypatch.setattr(enrollment, "registration_lock", lambda _directory: nullcontext())
    journal = {}
    monkeypatch.setattr(enrollment, "write_intent", lambda _directory, value: journal.update(value))
    monkeypatch.setattr(enrollment, "read_intent", lambda _directory: journal or None)
    trust = {"v": 1, "records": {}}
    monkeypatch.setattr(enrollment, "read_trust", lambda _directory: copy.deepcopy(trust))
    def persist_trust(_directory, record):
        trust.clear()
        trust.update(copy.deepcopy(record))
    monkeypatch.setattr(enrollment, "write_trust", persist_trust)
    authorized = set()
    events = []

    def authorize(_binary, _directory, key, *, revoke=False):
        # Independent local endpoint oracle. Authorization must follow a
        # successfully authenticated descriptor; revocation removes a real key.
        if revoke:
            authorized.discard(key)
        else:
            assert any(slot.startswith("th-") for slot in store.slots)
            authorized.add(key)
        events.append("remove" if revoke else "authorize")

    monkeypatch.setattr(enrollment, "authorize_public_key", authorize)
    yield store, vault, journal, authorized, events
    vault.close()


def publish(vault, **kwargs):
    return enrollment.publish(vault, binary="verified-helper", config_dir=Path("fixture"), **kwargs)


def test_registration_requires_no_public_key_or_pin_input(setup):
    store, vault, journal, authorized, events = setup
    result = publish(vault)
    assert result == {"server": "fixture-linux", "deviceId": "fixture-linux", "status": "active"}
    assert len(authorized) == 1 and events == ["authorize"]
    assert journal["accountId"] == "google:fixture-subject"
    assert journal["keyId"] == vault.index["hosts"]["fixture-linux"]["keyId"]
    assert "PRIVATE KEY" not in wire(journal) and PASSPHRASE not in wire(journal)


def test_descriptor_upload_failure_never_authorizes_and_retry_resumes_same_key(setup):
    store, vault, journal, authorized, events = setup
    slot, _, _ = vault.read_descriptor(server="wss://gateway.pocketshell.io", device="fixture-linux")
    store.conflict = slot
    with pytest.raises(VaultError, match="changed on another device"):
        publish(vault)
    kid = journal["keyId"]
    assert not authorized and not events
    # A fresh invocation unlocks the same vault and verifies protected local
    # intent; there is no manual key/pin recovery and no second key generation.
    retry = SharedVault(store.creds, request=store)
    retry.unlock(PASSPHRASE)
    store.conflict = None
    publish(retry)
    assert retry.index["hosts"]["fixture-linux"]["keyId"] == kid
    assert len([s for s in store.slots if s.startswith("vk-")]) == 1
    assert len(authorized) == 1
    retry.close()


def test_pending_enrollment_proof_cannot_be_reused_for_different_route_or_account(setup):
    store, vault, journal, authorized, events = setup
    slot, _, _ = vault.read_descriptor(server="wss://gateway.pocketshell.io", device="fixture-linux")
    store.conflict = slot
    with pytest.raises(VaultError):
        publish(vault)
    journal["accountId"] = "google:other"
    with pytest.raises(VaultError, match="pending enrollment identity changed"):
        publish(vault)
    assert not authorized


def test_authorization_failure_after_publication_can_retry_without_replacing_key(setup, monkeypatch):
    store, vault, journal, authorized, events = setup
    original = enrollment.authorize_public_key

    def refused(*args, **kwargs):
        raise VaultError("private endpoint refused")

    monkeypatch.setattr(enrollment, "authorize_public_key", refused)
    with pytest.raises(VaultError, match="private endpoint refused"):
        publish(vault)
    kid = journal["keyId"]
    assert not authorized and any(s.startswith("th-") for s in store.slots)
    monkeypatch.setattr(enrollment, "authorize_public_key", original)
    publish(vault)
    assert vault.index["hosts"]["fixture-linux"]["keyId"] == kid and len(authorized) == 1
    assert len([s for s in store.slots if s.startswith("vk-")]) == 1


def test_wrong_name_revoke_never_removes_another_servers_key(setup):
    store, vault, journal, authorized, events = setup
    publish(vault)
    before = set(authorized)
    vault.ensure_key("other-server")
    snapshot = copy.deepcopy(store.slots)
    with pytest.raises(VaultError, match="identity or name changed"):
        publish(vault, name="other-server", revoke=True)
    assert authorized == before and events == ["authorize"]
    assert store.slots == snapshot


def test_revocation_removes_actual_key_and_publishes_tombstone(setup):
    store, vault, journal, authorized, events = setup
    publish(vault)
    result = publish(vault, revoke=True)
    assert result["status"] == "revoked" and not authorized and events == ["authorize", "remove"]
    with pytest.raises(VaultError, match="was revoked"):
        publish(vault)
    assert not authorized


def test_tampered_trust_record_blocks_registration_and_revocation_side_effects(setup):
    store, vault, journal, authorized, events = setup
    publish(vault)
    slot = next(s for s in store.slots if s.startswith("th-"))
    envelope = parse(store.slots[slot][0])
    envelope["deviceId"] = "attacker"
    store.slots[slot] = (wire(envelope), 1)
    before = set(authorized)
    for revoke in (True, False):
        with pytest.raises(VaultError):
            publish(vault, revoke=revoke)
    assert authorized == before and events == ["authorize"]


def test_cloud_alias_collision_without_local_intent_fails_closed(setup):
    store, vault, journal, authorized, events = setup
    vault.ensure_key("fixture-linux")
    before = copy.deepcopy(store.slots)
    with pytest.raises(VaultError, match="already has a vault key"):
        publish(vault)
    assert store.slots == before and not authorized


def test_cancelled_or_mismatched_passphrase_never_creates_or_authorizes(setup):
    store, vault, journal, authorized, events = setup
    def factory(creds):
        return SharedVault(creds, request=store)
    before = copy.deepcopy(store.slots)
    with pytest.raises(VaultError, match="cancelled"):
        enrollment.unlock_for_registration(prompt=lambda _: None, vault_factory=factory)
    assert store.slots == before and not authorized


def test_registration_automatically_starts_device_flow_and_continues(monkeypatch):
    from pocketshell.account import device
    monkeypatch.setattr(credentials, "require_session", lambda: (_ for _ in ()).throw(NotLoggedIn("missing")))
    expected, calls = object(), []
    monkeypatch.setattr(device, "login", lambda base, **kwargs: calls.append((base, kwargs)) or expected)
    assert enrollment.ensure_login() is expected
    assert len(calls) == 1 and calls[0][0].startswith("https://")


def test_vault_epoch_change_before_endpoint_authorization_fails_closed(setup, monkeypatch):
    store, vault, journal, authorized, events = setup
    original = vault.descriptor
    def reset_after_descriptor(**kwargs):
        result = original(**kwargs)
        store.epoch = 2
        return result
    monkeypatch.setattr(vault, "descriptor", reset_after_descriptor)
    with pytest.raises(VaultError, match="generation changed"):
        publish(vault)
    assert not authorized and not events


def test_native_registration_mutex_excludes_other_windows_process(tmp_path):
    import subprocess
    import sys
    if sys.platform != "win32":
        pytest.skip("Windows cross-process registration mutex")
    directory = tmp_path / "fixture-enrollment"
    with enrollment.registration_lock(directory):
        program = "from pathlib import Path; from pocketshell.gateway.vault_enrollment import registration_lock; " \
                  "lock=registration_lock(Path(__import__('sys').argv[1])); lock.__enter__()"
        proc = subprocess.run([sys.executable, "-c", program, str(directory)], capture_output=True, timeout=10)
        assert proc.returncode != 0 and b"Another registration" in proc.stderr
    with enrollment.registration_lock(directory):
        pass


def test_linux_existing_daemon_is_enabled_started_without_rewrite_or_restart(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from pocketshell.gateway import service_linux as service
    from pocketshell.gateway.service_common import ChildResult
    monkeypatch.setattr(enrollment, "sys", SimpleNamespace(platform="linux"))
    state = SimpleNamespace(installed=True, managed=True, config_dir=str(tmp_path),
                            helper="existing-verified-helper", running=True)
    monkeypatch.setattr(service, "status", lambda: state)
    monkeypatch.setattr(service, "resolve_helper", lambda helper: helper)
    monkeypatch.setattr(service, "plan_install", lambda *a, **kw: pytest.fail("must not rewrite existing unit"))
    calls = []
    monkeypatch.setattr(service, "run_child", lambda args: calls.append(args) or ChildResult(0, b"", b""))
    enrollment.start_registered_daemon("new-helper", tmp_path)
    assert [args[2] for args in calls] == ["enable", "start"]


def test_linux_registration_never_replaces_unrelated_user_service(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from pocketshell.gateway import service_linux as service
    monkeypatch.setattr(enrollment, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(service, "status", lambda: SimpleNamespace(
        installed=True, managed=True, config_dir=str(tmp_path / "different"), helper="other"))
    monkeypatch.setattr(service, "run_child", lambda *a: pytest.fail("unrelated daemon was touched"))
    with pytest.raises(VaultError, match="different enrollment"):
        enrollment.start_registered_daemon("new-helper", tmp_path)


def test_linux_first_registration_installs_supported_service_and_confirms_running(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from pocketshell.gateway import service_linux as service
    monkeypatch.setattr(enrollment, "sys", SimpleNamespace(platform="linux"))
    states = iter([SimpleNamespace(installed=False), SimpleNamespace(running=True)])
    monkeypatch.setattr(service, "status", lambda: next(states))
    calls = []
    plan = object()
    def planned(binary, directory, **kwargs):
        calls.append((binary, directory, kwargs))
        return plan
    monkeypatch.setattr(service, "plan_install", planned)
    monkeypatch.setattr(service, "apply_install", lambda p: calls.append(p))
    enrollment.start_registered_daemon("verified-helper", tmp_path)
    assert calls == [("verified-helper", str(tmp_path), {"force": False, "start": True}), plan]


def test_container_foreground_starts_only_after_vault_is_closed(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from click.testing import CliRunner
    from pocketshell.cli import cli
    from pocketshell.gateway import cli as gateway_cli, helper
    monkeypatch.setattr(enrollment, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(enrollment, "ensure_login", lambda: None)
    monkeypatch.setattr(gateway_cli, "_verified_helper", lambda ctx: "verified-helper")
    events = []
    vault = SimpleNamespace(close=lambda: events.append("locked"))
    monkeypatch.setattr(enrollment, "unlock_for_registration", lambda **kwargs: vault)
    (tmp_path / "config.json").write_text("{}")
    monkeypatch.setattr(enrollment, "publish", lambda *a, **kw: events.append("registered") or {"server": "fixture"})
    def run(binary, args):
        assert events == ["registered", "locked"]
        events.append((binary, args))
    monkeypatch.setattr(helper, "exec_helper", run)
    monkeypatch.setattr(enrollment, "start_registered_daemon", lambda *a: pytest.fail("no systemd in container"))
    result = CliRunner().invoke(cli, ["gateway", "register", "--config-dir", str(tmp_path), "--foreground"])
    assert result.exit_code == 0, result.output
    assert events[-1] == ("verified-helper", ["run", "--config-dir", str(tmp_path)])
