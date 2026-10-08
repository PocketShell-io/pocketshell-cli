"""Credentials store: atomic 0600 create, and refusal of unsafe files."""

from __future__ import annotations

import json
import os
import stat
import time

import pytest

from pocketshell.account import AccountError, NotLoggedIn
from pocketshell.account import credentials as store
from pocketshell.account.errors import CredentialsUnsafe

TOKEN = "psc_" + "A" * 43


def _creds(**over) -> store.Credentials:
    base = dict(
        broker_url="https://broker.example.com",
        access_token=TOKEN,
        token_id="tok_1",
        email="me@example.com",
        expires_at=int(time.time()) + 3600,
        label="me@laptop",
    )
    base.update(over)
    return store.Credentials(**base)


def _mode(path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


def test_path_honours_xdg_config_home(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    assert store.credentials_path() == tmp_path / "xdg" / "pocketshell" / "credentials.json"
    monkeypatch.setenv("XDG_CONFIG_HOME", "relative/ignored")
    assert store.credentials_path() == store.Path.home() / ".config/pocketshell/credentials.json"


def test_save_then_load_round_trips_with_strict_modes() -> None:
    path = store.save(_creds())
    assert _mode(path) == 0o600
    assert _mode(path.parent) == 0o700
    loaded = store.load()
    assert loaded == _creds(expires_at=loaded.expires_at)
    data = json.loads(path.read_text())
    assert data["version"] == 1
    assert set(data) == {
        "version", "broker_url", "access_token", "token_id", "email", "expires_at", "label"
    }
    # No temp files left behind.
    assert os.listdir(path.parent) == ["credentials.json"]


def test_save_is_0600_even_with_a_permissive_umask() -> None:
    old = os.umask(0)
    try:
        path = store.save(_creds())
    finally:
        os.umask(old)
    assert _mode(path) == 0o600
    assert _mode(path.parent) == 0o700


def test_save_creates_the_temp_file_0600_exclusively(monkeypatch) -> None:
    """The secret never exists on disk with a broader mode (no chmod-after-write)."""
    calls = []
    real_open = os.open

    def spy(path, flags, mode=0o777, *, dir_fd=None):
        calls.append((str(path), flags, mode))
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(store.os, "open", spy)
    store.save(_creds())
    creates = [c for c in calls if c[1] & os.O_CREAT]
    assert len(creates) == 1
    name, flags, mode = creates[0]
    assert name.endswith(".tmp") and name.startswith(".credentials.json.")
    assert flags & os.O_EXCL and flags & os.O_NOFOLLOW
    assert mode == 0o600


def test_save_tightens_an_existing_shared_config_dir() -> None:
    directory = store.config_dir()
    directory.mkdir(parents=True)
    os.chmod(directory, 0o755)
    (directory / "profiles.yaml").write_text("x: 1\n")
    store.save(_creds())
    assert _mode(directory) == 0o700
    assert (directory / "profiles.yaml").read_text() == "x: 1\n"


def test_save_replaces_a_planted_symlink_without_following_it(tmp_path) -> None:
    target = tmp_path / "victim"
    target.write_text("untouched")
    directory = store.config_dir()
    directory.mkdir(parents=True, mode=0o700)
    (directory / "credentials.json").symlink_to(target)
    store.save(_creds())
    assert target.read_text() == "untouched"
    assert not os.path.islink(directory / "credentials.json")
    assert _mode(directory / "credentials.json") == 0o600


def test_missing_file_is_not_logged_in() -> None:
    with pytest.raises(NotLoggedIn, match="pocketshell login") as info:
        store.load()
    assert not isinstance(info.value, CredentialsUnsafe)


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o644, 0o660, 0o606])
def test_group_or_world_accessible_file_is_refused(mode) -> None:
    path = store.save(_creds())
    os.chmod(path, mode)
    with pytest.raises(CredentialsUnsafe, match="accessible by other users") as info:
        store.load()
    assert TOKEN not in str(info.value)


def test_symlinked_credentials_file_is_refused(tmp_path) -> None:
    path = store.save(_creds())
    real = tmp_path / "real.json"
    os.replace(path, real)
    path.symlink_to(real)
    with pytest.raises(CredentialsUnsafe, match="symlink"):
        store.load()


def test_file_not_owned_by_user_is_refused(monkeypatch) -> None:
    store.save(_creds())
    real_fstat = os.fstat

    def fake_fstat(fd):
        st = real_fstat(fd)
        if stat.S_ISREG(st.st_mode):
            values = list(st)
            values[stat.ST_UID] = st.st_uid + 1
            return os.stat_result(values)
        return st

    monkeypatch.setattr(store.os, "fstat", fake_fstat)
    with pytest.raises(CredentialsUnsafe, match="not owned by you"):
        store.load()


def test_config_dir_writable_by_others_is_refused() -> None:
    path = store.save(_creds())
    os.chmod(path.parent, 0o777)
    try:
        with pytest.raises(CredentialsUnsafe, match="writable by others"):
            store.load()
    finally:
        os.chmod(path.parent, 0o700)


def test_fifo_is_refused_without_blocking() -> None:
    directory = store.config_dir()
    directory.mkdir(parents=True, mode=0o700)
    os.mkfifo(directory / "credentials.json", 0o600)
    with pytest.raises(CredentialsUnsafe, match="not a regular file"):
        store.load()


@pytest.mark.parametrize(
    "content",
    [
        b"not json",
        b'{"version": 2}',
        b"[]",
        # duplicate keys: strict parser refuses
        json.dumps({"version": 1}).encode()[:-1] + b', "version": 1}',
        json.dumps(
            {"version": 1, "broker_url": "https://b", "access_token": "nope " + TOKEN,
             "token_id": "t", "email": "e", "expires_at": 1, "label": "l"}
        ).encode(),
        json.dumps(
            {"version": 1, "broker_url": "https://b", "access_token": TOKEN,
             "token_id": "t", "email": "e", "expires_at": True, "label": "l"}
        ).encode(),
    ],
)
def test_corrupt_file_is_not_logged_in_and_never_echoed(content) -> None:
    directory = store.config_dir()
    directory.mkdir(parents=True, mode=0o700)
    fd = os.open(directory / "credentials.json", os.O_WRONLY | os.O_CREAT, 0o600)
    os.write(fd, content)
    os.close(fd)
    with pytest.raises(NotLoggedIn, match="corrupt") as info:
        store.load()
    assert TOKEN not in str(info.value)


def test_require_session_rejects_expired() -> None:
    store.save(_creds(expires_at=int(time.time()) - 1))
    assert store.load().expired()
    with pytest.raises(NotLoggedIn, match="expired"):
        store.require_session()


def test_credentials_repr_redacts_token() -> None:
    assert TOKEN not in repr(_creds())
    assert TOKEN not in str(_creds())


def test_save_refuses_malformed_token() -> None:
    with pytest.raises(AccountError):
        store.save(_creds(access_token="psc_short"))


def test_delete_removes_symlink_not_target(tmp_path) -> None:
    target = tmp_path / "victim"
    target.write_text("keep")
    directory = store.config_dir()
    directory.mkdir(parents=True, mode=0o700)
    (directory / "credentials.json").symlink_to(target)
    assert store.exists()
    assert store.delete() is True
    assert target.read_text() == "keep"
    assert not store.exists()
    assert store.delete() is False


def test_lax_config_dir_without_credentials_is_plain_not_logged_in() -> None:
    directory = store.config_dir()
    directory.mkdir(parents=True)
    os.chmod(directory, 0o775)
    with pytest.raises(NotLoggedIn, match="^Not logged in") as info:
        store.load()
    assert not isinstance(info.value, CredentialsUnsafe)
