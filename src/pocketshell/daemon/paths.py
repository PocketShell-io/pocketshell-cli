"""Daemon socket/PID/lock path resolution and the per-daemon lifecycle files."""
from __future__ import annotations
import os
from pathlib import Path
from typing import Optional


def resolve_socket_path() -> Path:
    """Return the Unix socket path the daemon binds and the CLI connects to.

    Resolution order matches the spike:

    1. ``$POCKETSHELL_DAEMON_SOCKET`` if set (test/dev override).
    2. ``$XDG_RUNTIME_DIR/pocketshell/daemon.sock`` if XDG is defined.
    3. ``~/.cache/pocketshell/daemon.sock`` fallback for hosts without
       XDG (macOS user sessions, minimal Alpine, Docker containers).

    The parent directory is created with mode ``0700`` so a sibling user
    on a shared box cannot read or write the socket. The socket itself
    inherits mode ``0600`` via :func:`os.umask` set in :meth:`Daemon.serve`.
    """
    override = os.environ.get("POCKETSHELL_DAEMON_SOCKET")
    if override:
        return Path(override)

    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if xdg:
        return Path(xdg) / "pocketshell" / "daemon.sock"

    return Path.home() / ".cache" / "pocketshell" / "daemon.sock"


def resolve_pid_path(socket_path: Optional[Path] = None) -> Path:
    """Return the PID file path sitting next to the socket.

    Kept next to the socket so a single ``rm -rf`` (or
    ``XDG_RUNTIME_DIR`` auto-clean on logout) takes both files out
    together. Tests can override via ``socket_path`` to keep their
    fixtures contained to a tmpdir.
    """
    if socket_path is None:
        socket_path = resolve_socket_path()
    return socket_path.with_suffix(".pid")


def resolve_lock_path(socket_path: Optional[Path] = None) -> Path:
    """Return the lifetime-ownership lock beside the daemon socket."""
    if socket_path is None:
        socket_path = resolve_socket_path()
    return socket_path.with_suffix(".lock")


def _ensure_socket_dir(socket_path: Path) -> None:
    """Create the socket's parent dir with mode 0700 if missing."""
    parent = socket_path.parent
    parent.mkdir(parents=True, exist_ok=True)
    # ``mkdir(mode=)`` is masked by the process umask; chmod afterwards
    # so we land on 0700 regardless of the inherited umask.
    try:
        os.chmod(parent, 0o700)
    except PermissionError:
        # Shared-mount edge cases on macOS-over-NFS etc. We still want
        # to try to serve; the socket itself is the authoritative ACL.
        pass


def read_pid(pid_path: Optional[Path] = None) -> Optional[int]:
    """Read the daemon's PID file, returning ``None`` if absent/invalid."""
    pid_path = pid_path or resolve_pid_path()
    try:
        return int(pid_path.read_text().strip())
    except (FileNotFoundError, ValueError):
        return None
