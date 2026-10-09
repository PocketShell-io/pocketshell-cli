"""Vault file: permissions, ownership, symlinks, atomic writes, locking."""

from __future__ import annotations

import json
import os
import stat
import threading

import pytest

from pocketshell.keys import crypto, sshkeys, store


def _add(name: str, password: str = "device-pw", key_type: str = "ed25519"):
    private, public = sshkeys.generate(key_type, name)
    with store.locked() as txn:
        txn.vault.entries[name] = store.new_entry(name, public, False, private, password)
        txn.commit()
    return private, public


def test_missing_vault_is_empty_and_creates_nothing(xdg):
    assert store.load().entries == {}
    assert not (xdg / "pocketshell").exists()


def test_write_creates_0700_dir_and_0600_file(xdg):
    _add("a")
    d = xdg / "pocketshell"
    assert stat.S_IMODE(d.stat().st_mode) == 0o700
    st = (d / store.FILE_NAME).stat()
    assert stat.S_IMODE(st.st_mode) == 0o600 and st.st_uid == os.geteuid()
    assert [p.name for p in d.iterdir() if p.name.endswith(".tmp")] == []


def test_existing_lax_dir_is_tightened_on_write(xdg):
    d = xdg / "pocketshell"
    d.mkdir(mode=0o755)
    os.chmod(d, 0o755)
    _add("a")
    assert stat.S_IMODE(d.stat().st_mode) == 0o700


def test_round_trip_and_metadata(xdg):
    private, public = _add("laptop")
    vault = store.load()
    entry = vault.get("laptop")
    assert entry.public.blob == public.blob
    assert entry.public.fingerprint.startswith("SHA256:")
    plain = crypto.decrypt_into(entry.envelope, "device-pw", entry.aad)
    assert bytes(plain) == private
    with pytest.raises(crypto.WrongPassword):
        store.verify_password(vault, "nope")
    store.verify_password(vault, "device-pw")


def test_file_mode_leak_is_refused(xdg):
    _add("a")
    path = xdg / "pocketshell" / store.FILE_NAME
    os.chmod(path, 0o644)
    with pytest.raises(store.VaultError, match="accessible by other users"):
        store.load()
    with pytest.raises(store.VaultError, match="accessible by other users"):
        with store.locked():
            pass


def test_group_writable_dir_is_refused(xdg):
    _add("a")
    os.chmod(xdg / "pocketshell", 0o770)
    with pytest.raises(store.VaultError, match="writable by others"):
        store.load()


def test_symlinked_vault_is_refused(xdg, tmp_path):
    _add("a")
    path = xdg / "pocketshell" / store.FILE_NAME
    real = tmp_path / "elsewhere.json"
    os.replace(path, real)
    os.symlink(real, path)
    with pytest.raises(store.VaultError, match="symlink"):
        store.load()


def test_non_regular_vault_is_refused(xdg):
    d = xdg / "pocketshell"
    d.mkdir(mode=0o700)
    os.mkfifo(d / store.FILE_NAME, 0o600)
    with pytest.raises(store.VaultError, match="not a regular file"):
        store.load()


def test_foreign_owner_is_refused(xdg, monkeypatch):
    _add("a")
    real = os.geteuid()
    monkeypatch.setattr(os, "geteuid", lambda: real + 1)
    with pytest.raises(store.VaultError, match="not owned by you"):
        store.load()
    with pytest.raises(store.VaultError, match="not owned by you"):
        with store.locked():
            pass


@pytest.mark.parametrize(
    "content",
    [b"", b"{", b"[]", b'{"version": 2, "keys": {}}', b'{"version": 1, "keys": []}',
     b'{"version": 1, "keys": {"bad name": {}}}',
     b'{"version": 1, "keys": {"a": {"public_key": "nope"}}}'],
)
def test_corrupt_vault_is_refused(xdg, content):
    d = xdg / "pocketshell"
    d.mkdir(mode=0o700)
    fd = os.open(d / store.FILE_NAME, os.O_WRONLY | os.O_CREAT, 0o600)
    os.write(fd, content)
    os.close(fd)
    with pytest.raises(store.VaultError):
        store.load()


def test_failed_write_leaves_previous_vault_and_no_temp(xdg, monkeypatch):
    _add("a")
    path = xdg / "pocketshell" / store.FILE_NAME
    before = path.read_bytes()

    def boom(*_a, **_k):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(store.os, "replace", boom)
    with pytest.raises(store.VaultError, match="could not write"):
        _add("b")
    assert path.read_bytes() == before
    assert [p.name for p in path.parent.iterdir() if p.name.endswith(".tmp")] == []
    assert list(store.load().entries) == ["a"]


def test_concurrent_writers_do_not_lose_entries(xdg):
    errors = []

    def worker(i):
        try:
            _add(f"k{i}")
        except Exception as exc:  # pragma: no cover - surfaced below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert sorted(store.load().entries) == [f"k{i}" for i in range(6)]


def test_entry_swapped_between_names_fails_closed(xdg):
    _add("a")
    _add("b")
    path = xdg / "pocketshell" / store.FILE_NAME
    doc = json.loads(path.read_text())
    doc["keys"]["a"]["envelope"], doc["keys"]["b"]["envelope"] = (
        doc["keys"]["b"]["envelope"], doc["keys"]["a"]["envelope"],
    )
    path.write_text(json.dumps(doc))
    entry = store.load().get("a")
    with pytest.raises(crypto.WrongPassword):
        crypto.decrypt_into(entry.envelope, "device-pw", entry.aad)


def test_rewrap_changes_password(xdg):
    private, _ = _add("a", password="old-password")
    entry = store.load().get("a")
    new = store.rewrap(entry, "old-password", "new-password")
    with pytest.raises(crypto.WrongPassword):
        crypto.decrypt_into(new.envelope, "old-password", new.aad)
    assert bytes(crypto.decrypt_into(new.envelope, "new-password", new.aad)) == private


@pytest.mark.parametrize("name", ["", "-x", ".x", "a b", "a/b", "x" * 65, "é"])
def test_invalid_names(name):
    with pytest.raises(store.VaultError, match="invalid key name"):
        store.validate_name(name)
