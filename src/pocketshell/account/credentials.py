"""The on-disk CLI session: ``${XDG_CONFIG_HOME:-~/.config}/pocketshell/credentials.json``.

Write path (no chmod-after-write window): the directory is created 0700 (an
existing one we own is tightened to 0700), then the JSON is written to a
fresh temp name opened ``O_CREAT|O_EXCL|O_NOFOLLOW`` with mode 0600, fsynced,
and ``os.replace``d over the final name; the directory is fsynced last. All
file operations are relative to an fd of the directory, so swapping a path
component mid-way cannot redirect them.

Read path: the file must be a regular file (``O_NOFOLLOW``: a symlink is
refused), owned by the effective uid, with no group/other permission bits,
inside a directory we own that nobody else can write. Anything else is
reported as :class:`CredentialsUnsafe` — a :class:`NotLoggedIn` — with a
message that says how to fix it and never echoes the file's contents.
"""

from __future__ import annotations

import errno
import json
import os
import re
import secrets
import stat
import time
from dataclasses import dataclass
from pathlib import Path

from pocketshell.account.errors import AccountError, CredentialsUnsafe, NotLoggedIn
from pocketshell.account.jsonutil import StrictJSONError, loads_strict

FILE_NAME = "credentials.json"
FORMAT_VERSION = 1
MAX_FILE_BYTES = 16 * 1024

# Contract: `psc_` + 43 base64url chars. Accept a bounded range so a broker
# that lengthens the token does not brick every client, while the charset
# alone keeps the value safe to place in an HTTP header.
SESSION_TOKEN_RE = re.compile(r"^psc_[A-Za-z0-9_-]{32,128}$")

_LOGIN_HINT = "run `pocketshell login`"


@dataclass(frozen=True)
class Credentials:
    broker_url: str
    access_token: str
    token_id: str
    email: str
    expires_at: int
    label: str

    def __repr__(self) -> str:
        return (
            f"Credentials(broker_url={self.broker_url!r}, access_token='<redacted>', "
            f"token_id={self.token_id!r}, email={self.email!r}, "
            f"expires_at={self.expires_at}, label={self.label!r})"
        )

    __str__ = __repr__

    def expired(self, now: float | None = None) -> bool:
        return self.expires_at <= (time.time() if now is None else now)

    def to_json(self) -> dict:
        return {
            "version": FORMAT_VERSION,
            "broker_url": self.broker_url,
            "access_token": self.access_token,
            "token_id": self.token_id,
            "email": self.email,
            "expires_at": self.expires_at,
            "label": self.label,
        }


def config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or ""
    root = Path(base) if base and os.path.isabs(base) else Path.home() / ".config"
    return root / "pocketshell"


def credentials_path() -> Path:
    return config_dir() / FILE_NAME


def _mode(st: os.stat_result) -> str:
    return oct(stat.S_IMODE(st.st_mode))


def _open_dir_for_read(directory: Path) -> int:
    """Open the config dir and check it is ours and not writable by others."""
    try:
        dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except FileNotFoundError:
        raise NotLoggedIn(f"Not logged in; {_LOGIN_HINT}.") from None
    except NotADirectoryError:
        raise CredentialsUnsafe(
            f"{directory} is not a directory; refusing to read credentials. "
            f"Remove it and {_LOGIN_HINT}."
        ) from None
    except OSError as exc:
        raise NotLoggedIn(
            f"Cannot open {directory} ({os.strerror(exc.errno or 0)}); {_LOGIN_HINT}."
        ) from None
    st = os.fstat(dfd)
    if st.st_uid != os.geteuid() or st.st_mode & 0o022:
        try:
            os.lstat(FILE_NAME, dir_fd=dfd)
        except FileNotFoundError:
            # Nothing to refuse: a lax shared config dir alone is just "not
            # logged in" (login tightens it to 0700 when it writes).
            raise NotLoggedIn(f"Not logged in; {_LOGIN_HINT}.") from None
        except OSError:
            pass
        finally:
            os.close(dfd)
        raise CredentialsUnsafe(
            f"{directory} is not owned by you or is writable by others "
            f"(mode {_mode(st)}); refusing to read credentials. "
            f"Fix it with `chmod 700 {directory}` and {_LOGIN_HINT}."
        )
    return dfd


def load(*, allow_shared_mode: bool = False) -> Credentials:
    """Return the stored session (possibly expired) or raise :class:`NotLoggedIn`.

    ``allow_shared_mode`` is for ``logout`` only: a file we own whose mode
    leaked it to other users still holds *our* token, and revoking it is
    exactly what should happen next. Symlinks and foreign-owned files are
    refused regardless — their contents are not ours to trust.
    """
    directory = config_dir()
    path = directory / FILE_NAME
    dfd = _open_dir_for_read(directory)
    try:
        try:
            fd = os.open(
                FILE_NAME,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                dir_fd=dfd,
            )
        except FileNotFoundError:
            raise NotLoggedIn(f"Not logged in; {_LOGIN_HINT}.") from None
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise CredentialsUnsafe(
                    f"{path} is a symlink; refusing to read it. Remove it and {_LOGIN_HINT}."
                ) from None
            raise NotLoggedIn(
                f"Cannot open {path} ({os.strerror(exc.errno or 0)}); {_LOGIN_HINT}."
            ) from None
    finally:
        os.close(dfd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise CredentialsUnsafe(
                f"{path} is not a regular file; refusing to read it. "
                f"Remove it and {_LOGIN_HINT}."
            )
        if st.st_uid != os.geteuid():
            raise CredentialsUnsafe(
                f"{path} is not owned by you; refusing to read it. "
                f"Remove it and {_LOGIN_HINT}."
            )
        if st.st_mode & 0o077 and not allow_shared_mode:
            raise CredentialsUnsafe(
                f"{path} is accessible by other users (mode {_mode(st)}); refusing to "
                f"use it. Treat the session as leaked: run `pocketshell logout` to revoke "
                f"it, then `pocketshell login`."
            )
        if st.st_size > MAX_FILE_BYTES:
            raise NotLoggedIn(f"{path} is too large to be a credentials file; {_LOGIN_HINT}.")
        raw = os.read(fd, MAX_FILE_BYTES + 1)
    finally:
        os.close(fd)
    return _parse(raw, path)


def _parse(raw: bytes, path: Path) -> Credentials:
    bad = NotLoggedIn(f"{path} is corrupt or from an unsupported version; {_LOGIN_HINT}.")
    try:
        data = loads_strict(raw)
    except StrictJSONError:
        raise bad from None
    if not isinstance(data, dict) or data.get("version") != FORMAT_VERSION:
        raise bad
    strings = ("broker_url", "access_token", "token_id", "email", "label")
    if not all(isinstance(data.get(k), str) for k in strings):
        raise bad
    expires_at = data.get("expires_at")
    if not isinstance(expires_at, int) or isinstance(expires_at, bool):
        raise bad
    if not SESSION_TOKEN_RE.match(data["access_token"]):
        raise bad
    return Credentials(
        broker_url=data["broker_url"],
        access_token=data["access_token"],
        token_id=data["token_id"],
        email=data["email"],
        expires_at=expires_at,
        label=data["label"],
    )


def require_session() -> Credentials:
    """The stored session if present, safe and unexpired; else :class:`NotLoggedIn`."""
    creds = load()
    if creds.expired():
        raise NotLoggedIn(f"Your PocketShell login has expired; {_LOGIN_HINT}.")
    return creds


def _open_dir_for_write(directory: Path) -> int:
    try:
        directory.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.mkdir(directory, 0o700)
        except FileExistsError:
            pass
        dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError as exc:
        raise AccountError(
            f"Cannot create {directory} ({os.strerror(exc.errno or 0)}); credentials not saved."
        ) from None
    st = os.fstat(dfd)
    if st.st_uid != os.geteuid():
        os.close(dfd)
        raise AccountError(f"{directory} is not owned by you; refusing to store credentials there.")
    if stat.S_IMODE(st.st_mode) != 0o700:
        os.fchmod(dfd, 0o700)
    return dfd


def save(creds: Credentials) -> Path:
    """Atomically write ``creds`` as a 0600 file in a 0700 directory."""
    if not SESSION_TOKEN_RE.match(creds.access_token):
        raise AccountError("refusing to store a malformed session token")
    directory = config_dir()
    payload = (json.dumps(creds.to_json(), indent=2, sort_keys=True) + "\n").encode()
    dfd = _open_dir_for_write(directory)
    tmp = f".{FILE_NAME}.{secrets.token_hex(8)}.tmp"
    try:
        _write_atomically(dfd, tmp, payload)
        tmp = ""
    except OSError as exc:
        raise AccountError(
            f"Could not write {directory / FILE_NAME} ({os.strerror(exc.errno or 0)})."
        ) from None
    finally:
        if tmp:
            try:
                os.unlink(tmp, dir_fd=dfd)
            except OSError:
                pass
        os.close(dfd)
    return directory / FILE_NAME


def _write_atomically(dfd: int, tmp: str, payload: bytes) -> None:
    fd = os.open(
        tmp,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
        dir_fd=dfd,
    )
    try:
        os.fchmod(fd, 0o600)  # exact mode regardless of umask quirks
        view = memoryview(payload)
        while view:
            view = view[os.write(fd, view) :]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, FILE_NAME, src_dir_fd=dfd, dst_dir_fd=dfd)
    os.fsync(dfd)


def exists() -> bool:
    """Whether *anything* (file, symlink, ...) sits at the credentials path."""
    return os.path.lexists(credentials_path())


def delete() -> bool:
    """Remove the credentials entry (never following a symlink). True if removed."""
    directory = config_dir()
    try:
        dfd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except (FileNotFoundError, NotADirectoryError):
        return False
    try:
        os.unlink(FILE_NAME, dir_fd=dfd)
        os.fsync(dfd)
        return True
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise AccountError(
            f"Could not remove {directory / FILE_NAME} ({os.strerror(exc.errno or 0)})."
        ) from None
    finally:
        os.close(dfd)
