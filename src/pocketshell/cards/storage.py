"""Durable, private (0600) file writes and per-session locks."""
from __future__ import annotations
import os
import base64
import errno
import fcntl
import logging
import tempfile
from contextlib import contextmanager
from pathlib import Path


# Permissions for the per-session card file (owner-only, matches tree.py).
NEW_FILE_MODE = 0o600


_LOGGER = logging.getLogger(__name__)


_UNSUPPORTED_SYNC_ERRNOS = {errno.EINVAL, errno.ENOTSUP}


if hasattr(errno, "EOPNOTSUPP"):
    _UNSUPPORTED_SYNC_ERRNOS.add(errno.EOPNOTSUPP)


def _encode_session(session: str) -> str:
    """Reversibly encode a session as one safe path segment."""
    encoded = base64.urlsafe_b64encode(session.encode("utf-8")).decode("ascii")
    return "s-" + encoded.rstrip("=")


def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except (PermissionError, FileNotFoundError):
        pass


def _durability_barrier(fd: int, *, path: Path, kind: str) -> bool:
    """Fsync one file or directory, tolerating only unsupported barriers."""
    while True:
        try:
            os.fsync(fd)
            return True
        except OSError as error:
            if error.errno == errno.EINTR:
                continue
            if error.errno in _UNSUPPORTED_SYNC_ERRNOS:
                _LOGGER.warning(
                    "durability barrier unavailable for %s %s: %s; "
                    "continuing with atomic publication",
                    kind,
                    path,
                    error,
                )
                return False
            raise


def _fsync_directory(path: Path) -> bool:
    """Fsync a directory after rename when the filesystem supports it."""
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        fd = os.open(str(path), flags)
    except OSError as error:
        if error.errno in _UNSUPPORTED_SYNC_ERRNOS:
            _LOGGER.warning(
                "durability barrier unavailable for directory %s: %s; "
                "continuing with atomic publication",
                path,
                error,
            )
            return False
        raise
    try:
        return _durability_barrier(fd, path=path, kind="directory")
    finally:
        os.close(fd)


def _write_private(path: Path, text: str) -> None:
    """Publish ``text`` atomically with file and directory durability barriers."""
    _ensure_dir(path.parent)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    tmp = Path(tmp_name)
    open_fd = fd
    try:
        with os.fdopen(fd, "wb") as handle:
            open_fd = -1
            handle.write(text.encode("utf-8"))
            handle.flush()
            os.chmod(tmp, NEW_FILE_MODE)
            _durability_barrier(handle.fileno(), path=tmp, kind="file")
        os.replace(tmp, path)
        _fsync_directory(path.parent)
    except BaseException:
        if open_fd >= 0:
            try:
                os.close(open_fd)
            except OSError:
                pass
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
        except OSError:
            pass
        raise


@contextmanager
def _session_lock(path: Path):
    """Hold the cross-process advisory lock for one session document."""
    _ensure_dir(path.parent)
    lock_path = path.with_suffix(path.suffix + ".lock")
    fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, NEW_FILE_MODE)
    with os.fdopen(fd, "a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)
