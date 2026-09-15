"""Private (0600), fsync-guarded durable file writes."""
from __future__ import annotations
import errno
import logging
import os
import tempfile
from pathlib import Path
# --- sibling modules ---
from pocketshell.usage.capture.paths import NEW_FILE_MODE, _ensure_dir


_LOGGER = logging.getLogger(__name__)


_UNSUPPORTED_SYNC_ERRNOS = frozenset(
    {
        errno.EINVAL,
        errno.ENOTSUP,
        errno.EOPNOTSUPP,
        errno.ENOSYS,
        errno.EISDIR,
    }
)


def _is_unsupported_sync_error(error: OSError) -> bool:
    return error.errno in _UNSUPPORTED_SYNC_ERRNOS


def _durability_barrier(fd: int, *, path: Path, kind: str) -> bool:
    """Apply an fsync barrier, reporting supported-but-unavailable cases.

    Linux filesystems normally support both regular-file and directory fsync,
    but some network, virtual, or non-POSIX filesystems reject one of them
    with ``EINVAL``/``ENOTSUP``. Those filesystems still get atomic publication
    and a warning that durability is best-effort; unexpected I/O errors remain
    fatal so a real storage failure cannot be mistaken for a durable write.
    """
    while True:
        try:
            os.fsync(fd)
            return True
        except OSError as error:
            if error.errno == errno.EINTR:
                continue
            if _is_unsupported_sync_error(error):
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
    """Fsync a parent directory after rename when the filesystem permits it."""
    flags = os.O_RDONLY
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    try:
        fd = os.open(str(path), flags | directory_flag)
    except OSError as error:
        if _is_unsupported_sync_error(error):
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


def _discard_temp(tmp: Path, open_fd: int) -> None:
    """Close an untransferred fd and unlink the temp after any failure."""
    if open_fd >= 0:
        try:
            os.close(open_fd)
        except OSError:
            pass
    try:
        tmp.unlink()
    except (FileNotFoundError, OSError):
        pass


def _write_private(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` atomically and as durably as possible.

    The temp is ``mkstemp``'d in the destination directory (unique across
    concurrent writers; ``os.replace`` stays one-filesystem atomic) and
    fsync'd before publication; the parent directory is fsync'd after the
    rename. A filesystem lacking a barrier is logged and still gets the
    atomic write; unexpected storage errors fail closed.
    """
    _ensure_dir(path.parent)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
    )
    tmp = Path(tmp_name)
    open_fd = fd
    try:
        with os.fdopen(fd, "wb") as handle:
            # Ownership of the descriptor has transferred to `handle`.
            open_fd = -1
            handle.write(text.encode("utf-8"))
            handle.flush()
            os.chmod(tmp, NEW_FILE_MODE)
            _durability_barrier(handle.fileno(), path=tmp, kind="file")
        os.replace(tmp, path)
        _fsync_directory(path.parent)
    except BaseException:
        _discard_temp(tmp, open_fd)
        raise
