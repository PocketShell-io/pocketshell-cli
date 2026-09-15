"""Durable, private (0600) registry reads/writes under a lock."""
from __future__ import annotations
import json
import fcntl
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Mapping
# --- sibling modules ---
from pocketshell.tree.paths import NEW_FILE_MODE, TreePaths


def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except PermissionError:
        pass


def _set_private_mode(path: Path) -> None:
    """Best-effort chmod to the private mode (missing file is fine)."""
    try:
        os.chmod(path, NEW_FILE_MODE)
    except FileNotFoundError:
        pass


def _sync_parent_directory(path: Path) -> None:
    """fsync the parent directory so the rename itself is durable."""
    directory_fd = os.open(
        str(path.parent), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    )
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _write_private(path: Path, text: str) -> None:
    """Write ``text`` to ``path`` atomically with mode 0600.

    Temp file + ``os.replace`` so a concurrent reader (the app's SSH ``tree.get``
    racing a ``tree.upsert``) never sees a half-written registry. Copied from
    :func:`pocketshell.usage.capture._write_private`.
    """
    _ensure_dir(path.parent)
    fd, raw_tmp = tempfile.mkstemp(
        prefix=path.name + ".", suffix=".tmp", dir=path.parent
    )
    tmp = Path(raw_tmp)
    os.fchmod(fd, NEW_FILE_MODE)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        _set_private_mode(path)
        _sync_parent_directory(path)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


@contextmanager
def _registry_lock(paths: TreePaths, *, exclusive: bool):
    """One cross-process lock shared by daemon and CLI fallback writers."""
    _ensure_dir(paths.tree_dir)
    fd = os.open(str(paths.lock_file), os.O_RDWR | os.O_CREAT, NEW_FILE_MODE)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def _read_registry(paths: TreePaths) -> dict[str, Any]:
    """Read the whole registry document, returning an empty doc on any miss.

    A missing file, an empty file, or an unparseable file all degrade to an
    empty registry — the client treats "no registry yet" as a valid fresh-seed
    state, and a corrupt file must never wedge a cold start (it is rewritten on
    the next upsert).
    """
    try:
        raw = paths.registry_file.read_text(encoding="utf-8")
    except (FileNotFoundError, IsADirectoryError, PermissionError):
        return {"hosts": {}}
    if not raw.strip():
        return {"hosts": {}}
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError:
        return {"hosts": {}}
    if not isinstance(doc, dict):
        return {"hosts": {}}
    hosts = doc.get("hosts")
    if not isinstance(hosts, dict):
        doc["hosts"] = {}
    return doc


def _write_registry(paths: TreePaths, doc: Mapping[str, Any]) -> None:
    _write_private(
        paths.registry_file,
        json.dumps(doc, sort_keys=True) + "\n",
    )
