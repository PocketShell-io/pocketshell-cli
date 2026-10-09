"""The key vault file: ``${XDG_CONFIG_HOME:-~/.config}/pocketshell/key-vault.json``.

Same on-disk discipline as the CLI session file
(:mod:`pocketshell.account.credentials`): a 0700 directory we own, a 0600
regular file we own (``O_NOFOLLOW``: never a symlink), written to a fresh
``O_EXCL`` temp name, fsynced, ``os.replace``d over the final name, and the
directory fsynced. Every file operation is relative to a directory fd.
Read-modify-write cycles hold an exclusive ``flock`` on a sibling lock
file, so two concurrent ``pocketshell keys`` invocations cannot lose an
entry.

The file holds only public metadata in the clear (name, public key,
fingerprint, whether the key has its own passphrase) and one encrypted
envelope per key (:mod:`pocketshell.keys.crypto`). The device password is
never stored, in any form: a wrong password is detected by the AEAD tag of
the envelope it fails to open.
"""

from __future__ import annotations

import contextlib
import errno
import json
import os
import re
import secrets
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional

from pocketshell.keys import crypto
from pocketshell.keys.sshkeys import KeyFormatError, PublicKey, parse_public_line

FILE_NAME = "key-vault.json"
LOCK_NAME = ".key-vault.lock"
FORMAT_VERSION = 1
MAX_FILE_BYTES = 1024 * 1024
MAX_KEYS = 256
NAME_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")


class VaultError(Exception):
    """Unusable vault (unsafe permissions, corrupt file, bad name …). Safe to print."""


@dataclass(frozen=True)
class VaultEntry:
    name: str
    public: PublicKey
    passphrase_protected: bool
    created_at: int
    envelope: dict

    @property
    def aad(self) -> bytes:
        return crypto.entry_aad(self.name, self.public.blob)

    def to_json(self) -> dict:
        return {
            "public_key": self.public.line,
            "fingerprint": self.public.fingerprint,
            "passphrase_protected": self.passphrase_protected,
            "created_at": self.created_at,
            "envelope": self.envelope,
        }


@dataclass
class Vault:
    entries: dict[str, VaultEntry] = field(default_factory=dict)

    def get(self, name: str) -> VaultEntry:
        validate_name(name)
        try:
            return self.entries[name]
        except KeyError:
            raise VaultError(
                f"no key named {name!r} in the vault (see `pocketshell keys list`)"
            ) from None

    def to_json(self) -> dict:
        return {
            "version": FORMAT_VERSION,
            "keys": {n: e.to_json() for n, e in sorted(self.entries.items())},
        }


def validate_name(name: str) -> str:
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise VaultError(
            f"invalid key name {ascii(name)[:80]}: use 1-64 letters, digits, '.', '_' "
            "or '-', starting with a letter or digit"
        )
    return name


def config_dir() -> Path:
    # Same resolution as the CLI session file, so all client state lives together.
    from pocketshell.account.credentials import config_dir as _account_config_dir

    return _account_config_dir()


def vault_path() -> Path:
    return config_dir() / FILE_NAME


def _mode(st: os.stat_result) -> str:
    return oct(stat.S_IMODE(st.st_mode))


def _require_posix() -> None:
    if os.name != "posix":
        raise VaultError("the PocketShell key vault is not supported on this platform yet")


# --- reading -----------------------------------------------------------------


def _open_dir_for_read(directory: Path) -> Optional[int]:
    try:
        dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except FileNotFoundError:
        return None
    except NotADirectoryError:
        raise VaultError(f"{directory} is not a directory; refusing to use the key vault") from None
    except OSError as exc:
        raise VaultError(f"cannot open {directory} ({os.strerror(exc.errno or 0)})") from None
    st = os.fstat(dfd)
    if st.st_uid != os.geteuid() or st.st_mode & 0o022:
        os.close(dfd)
        raise VaultError(
            f"{directory} is not owned by you or is writable by others "
            f"(mode {_mode(st)}); refusing to use the key vault. "
            f"Fix it with `chmod 700 {directory}`."
        )
    return dfd


def _read_file(dfd: int, path: Path) -> Optional[bytes]:
    try:
        fd = os.open(
            FILE_NAME, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=dfd
        )
    except FileNotFoundError:
        return None
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise VaultError(f"{path} is a symlink; refusing to read it") from None
        raise VaultError(f"cannot open {path} ({os.strerror(exc.errno or 0)})") from None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise VaultError(f"{path} is not a regular file; refusing to read it")
        if st.st_uid != os.geteuid():
            raise VaultError(f"{path} is not owned by you; refusing to read it")
        if st.st_mode & 0o077:
            raise VaultError(
                f"{path} is accessible by other users (mode {_mode(st)}); refusing to use it. "
                f"The keys inside are still encrypted with your device password, but "
                f"fix the mode with `chmod 600 {path}` and consider rotating them."
            )
        if st.st_size > MAX_FILE_BYTES:
            raise VaultError(f"{path} is too large to be a key vault")
        chunks = []
        remaining = MAX_FILE_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
    finally:
        os.close(fd)
    if len(raw) > MAX_FILE_BYTES:
        raise VaultError(f"{path} is too large to be a key vault")
    return raw


def _parse(raw: bytes, path: Path) -> Vault:
    bad = f"{path} is corrupt or from an unsupported version"
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise VaultError(bad) from None
    if not isinstance(data, dict) or data.get("version") != FORMAT_VERSION:
        raise VaultError(bad)
    keys = data.get("keys")
    if not isinstance(keys, dict) or len(keys) > MAX_KEYS:
        raise VaultError(bad)
    vault = Vault()
    for name, item in keys.items():
        if not isinstance(name, str) or not NAME_RE.match(name) or not isinstance(item, dict):
            raise VaultError(f"{bad} (bad entry {ascii(name)[:40]})")
        try:
            public = parse_public_line(item["public_key"])
        except (KeyError, TypeError, AttributeError, KeyFormatError):
            raise VaultError(f"{bad} (entry {name!r} has no valid public key)") from None
        protected = item.get("passphrase_protected")
        created = item.get("created_at")
        if not isinstance(protected, bool) or not isinstance(created, int):
            raise VaultError(f"{bad} (entry {name!r} is incomplete)")
        try:
            crypto.validate_envelope(item.get("envelope"))
        except crypto.VaultCryptoError as exc:
            raise VaultError(f"{path}: entry {name!r}: {exc}") from None
        vault.entries[name] = VaultEntry(
            name=name,
            public=public,
            passphrase_protected=protected,
            created_at=created,
            envelope=dict(item["envelope"]),
        )
    return vault


def load() -> Vault:
    """The vault (empty when no file exists yet). Never needs the password."""
    _require_posix()
    directory = config_dir()
    dfd = _open_dir_for_read(directory)
    if dfd is None:
        return Vault()
    try:
        raw = _read_file(dfd, directory / FILE_NAME)
    finally:
        os.close(dfd)
    return Vault() if raw is None else _parse(raw, directory / FILE_NAME)


# --- writing -----------------------------------------------------------------


def _open_dir_for_write(directory: Path) -> int:
    try:
        directory.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.mkdir(directory, 0o700)
        except FileExistsError:
            pass
        dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError as exc:
        raise VaultError(f"cannot create {directory} ({os.strerror(exc.errno or 0)})") from None
    st = os.fstat(dfd)
    if st.st_uid != os.geteuid():
        os.close(dfd)
        raise VaultError(f"{directory} is not owned by you; refusing to store keys there")
    if stat.S_IMODE(st.st_mode) != 0o700:
        os.fchmod(dfd, 0o700)
    return dfd


def _write_atomically(dfd: int, payload: bytes) -> None:
    tmp = f".{FILE_NAME}.{secrets.token_hex(8)}.tmp"
    fd = os.open(
        tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
        dir_fd=dfd,
    )
    try:
        try:
            os.fchmod(fd, 0o600)
            view = memoryview(payload)
            while view:
                view = view[os.write(fd, view) :]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, FILE_NAME, src_dir_fd=dfd, dst_dir_fd=dfd)
        tmp = ""
        os.fsync(dfd)
    finally:
        if tmp:
            with contextlib.suppress(OSError):
                os.unlink(tmp, dir_fd=dfd)


@contextlib.contextmanager
def locked() -> Iterator["_Txn"]:
    """Exclusive read-modify-write transaction on the vault.

    Yields a :class:`_Txn` whose ``vault`` is the current contents; call
    ``txn.commit()`` to atomically replace the file with ``txn.vault``.
    """
    _require_posix()
    import fcntl

    directory = config_dir()
    dfd = _open_dir_for_write(directory)
    try:
        try:
            lfd = os.open(
                LOCK_NAME, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                dir_fd=dfd,
            )
        except OSError as exc:
            raise VaultError(
                f"cannot open the vault lock in {directory} ({os.strerror(exc.errno or 0)})"
            ) from None
        try:
            fcntl.flock(lfd, fcntl.LOCK_EX)
            raw = _read_file(dfd, directory / FILE_NAME)
            vault = Vault() if raw is None else _parse(raw, directory / FILE_NAME)
            yield _Txn(dfd, directory, vault)
        finally:
            os.close(lfd)  # releases the flock
    finally:
        os.close(dfd)


class _Txn:
    def __init__(self, dfd: int, directory: Path, vault: Vault) -> None:
        self._dfd = dfd
        self.directory = directory
        self.vault = vault

    def commit(self) -> Path:
        if len(self.vault.entries) > MAX_KEYS:
            raise VaultError(f"the vault holds at most {MAX_KEYS} keys")
        payload = (json.dumps(self.vault.to_json(), indent=2, sort_keys=True) + "\n").encode()
        try:
            _write_atomically(self._dfd, payload)
        except OSError as exc:
            raise VaultError(
                f"could not write {self.directory / FILE_NAME} ({os.strerror(exc.errno or 0)})"
            ) from None
        return self.directory / FILE_NAME


def new_entry(
    name: str, public: PublicKey, passphrase_protected: bool, private: bytes | bytearray,
    password: str,
) -> VaultEntry:
    validate_name(name)
    envelope = crypto.encrypt(private, password, crypto.entry_aad(name, public.blob))
    return VaultEntry(
        name=name,
        public=public,
        passphrase_protected=passphrase_protected,
        created_at=int(time.time()),
        envelope=envelope,
    )


def rewrap(entry: VaultEntry, old_password: str, new_password: str) -> VaultEntry:
    """The same entry with its envelope re-encrypted under ``new_password``."""
    plain = crypto.decrypt_into(entry.envelope, old_password, entry.aad)
    try:
        envelope = crypto.encrypt(plain, new_password, entry.aad)
    finally:
        crypto.wipe(plain)
    return VaultEntry(
        name=entry.name,
        public=entry.public,
        passphrase_protected=entry.passphrase_protected,
        created_at=entry.created_at,
        envelope=envelope,
    )


def verify_password(vault: Vault, password: str) -> None:
    """Raise :class:`crypto.WrongPassword` unless ``password`` opens the vault.

    Checked against one existing entry (all entries share the password);
    an empty vault has no password yet and accepts any.
    """
    for entry in vault.entries.values():
        crypto.wipe(crypto.decrypt_into(entry.envelope, password, entry.aad))
        return
