"""Durable local replay floor: native private storage and fresh process proof."""
from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

from pocketshell.account.shared_vault import VaultError
from pocketshell.gateway import vault_enrollment as enrollment

from test_vault_enrollment import setup as shared_setup  # noqa: F401

READ_TRUST = enrollment.read_trust
WRITE_TRUST = enrollment.write_trust


@pytest.fixture
def setup(request):
    return request.getfixturevalue("shared_setup")


@pytest.fixture
def private_directory(tmp_path):
    path = tmp_path / "private-endpoint"
    if sys.platform == "win32":
        from pocketshell import windows_security
        with windows_security._directory(path, create=True):
            pass
    else:
        path.mkdir(mode=0o700)
    return path


@pytest.mark.parametrize("failed_upload", [False, True])
def test_fresh_process_rejects_cloud_replay_after_durable_revocation(
        setup, private_directory, monkeypatch, tmp_path, failed_upload):
    store, vault, journal, authorized, events = setup
    monkeypatch.setattr(enrollment, "read_trust", READ_TRUST)
    monkeypatch.setattr(enrollment, "write_trust", WRITE_TRUST)
    args = {"binary": "verified-helper", "config_dir": private_directory}
    enrollment.publish(vault, **args)
    slot = next(s for s in store.slots if s.startswith("th-"))
    active = copy.deepcopy(store.slots[slot])
    if failed_upload:
        store.conflict = slot
        with pytest.raises(VaultError):
            enrollment.publish(vault, revoke=True, **args)
    else:
        enrollment.publish(vault, revoke=True, **args)
    assert not authorized
    saved = READ_TRUST(private_directory)
    assert next(iter(saved["records"].values()))["state"] == ("revoking" if failed_upload else "revoked")
    store.slots[slot] = active
    # New OS process, new SharedVault, real local private storage. Only
    # invented encrypted test fixtures are serialized, never live credentials.
    cloud = tmp_path / "invented-cloud.json"
    cloud.write_text(json.dumps(store.slots))
    program = r'''
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[3])
from test_shared_vault import Store, PASSPHRASE
from pocketshell.account import credentials
from pocketshell.account.shared_vault import SharedVault, VaultError
from pocketshell.gateway import vault_enrollment as e
import json
store = Store()
store.slots = json.loads(Path(sys.argv[2]).read_text())
store.auth = __import__('pocketshell.account.shared_vault', fromlist=['derive']).b64(
    __import__('pocketshell.account.shared_vault', fromlist=['derive']).derive(
        PASSPHRASE, json.loads(store.slots['vault'][0])['kdf'])[1])
credentials.load = lambda: store.creds
vault = SharedVault(store.creds, request=store)
vault.unlock(PASSPHRASE)
history = e.read_trust(Path(sys.argv[1]))
record = next(iter(history['records'].values()))
e.local_identity = lambda _: {k: record[k] for k in ('serverUrl','deviceId','sshHostKey','devicePublicKey')}
e.local_user = lambda: record['username']
def unauthorized(*a, **kw):
    raise AssertionError('REPLAY REAUTHORIZED A REMOVED KEY')
e.authorize_public_key = unauthorized
try:
    e.publish(vault, binary='fixture-helper', config_dir=Path(sys.argv[1]))
except VaultError:
    print('durable replay refused')
else:
    raise AssertionError('valid old cloud ciphertext revived registration')
'''
    child = subprocess.run([sys.executable, "-c", program, str(private_directory), str(cloud),
                            str(Path(__file__).parent)], capture_output=True, text=True, timeout=20)
    assert child.returncode == 0, child.stdout + child.stderr
    assert child.stdout.strip() == "durable replay refused"
    assert READ_TRUST(private_directory) == saved


def test_old_or_malformed_local_history_is_never_reset(private_directory):
    enrollment.write_private_record(private_directory, "vault-enrollment-trust.json", {"v": 0, "records": {}})
    before = (private_directory / "vault-enrollment-trust.json").read_bytes()
    with pytest.raises(VaultError, match="unsupported"):
        READ_TRUST(private_directory)
    assert (private_directory / "vault-enrollment-trust.json").read_bytes() == before


def test_trust_store_refuses_symlink_without_changing_target(private_directory, tmp_path):
    target = tmp_path / "unrelated.txt"
    target.write_text("unrelated public fixture")
    path = private_directory / "vault-enrollment-trust.json"
    try:
        path.symlink_to(target)
    except OSError:
        pytest.skip("creating symbolic links is unavailable to this Windows token")
    with pytest.raises((OSError, VaultError)):
        READ_TRUST(private_directory)
    with pytest.raises((OSError, VaultError)):
        WRITE_TRUST(private_directory, {"v": 1, "records": {}})
    assert target.read_text() == "unrelated public fixture" and path.is_symlink()


def test_trust_store_refuses_unsafe_permissions(private_directory):
    path = private_directory / "vault-enrollment-trust.json"
    if sys.platform == "win32":
        # Ordinary inherited ACL is deliberately not the protected owner-only
        # descriptor required by Windows private storage.
        path.write_text('{"v":1,"records":{}}')
    else:
        WRITE_TRUST(private_directory, {"v": 1, "records": {}})
        path.chmod(0o644)
    with pytest.raises((OSError, VaultError)):
        READ_TRUST(private_directory)
    with pytest.raises((OSError, VaultError)):
        WRITE_TRUST(private_directory, {"v": 1, "records": {}})


def test_concurrent_process_cannot_write_around_registration_lock(private_directory):
    program = r'''
import sys
from pathlib import Path
from pocketshell.gateway.vault_enrollment import registration_lock, write_trust
with registration_lock(Path(sys.argv[1])):
    write_trust(Path(sys.argv[1]), {'v':1,'records':{}})
'''
    with enrollment.registration_lock(private_directory):
        child = subprocess.run([sys.executable, "-c", program, str(private_directory)],
                               capture_output=True, timeout=10)
        assert child.returncode != 0 and b"Another registration" in child.stderr
    assert not (private_directory / "vault-enrollment-trust.json").exists()
