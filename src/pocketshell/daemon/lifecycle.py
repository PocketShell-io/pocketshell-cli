"""Daemon process lifecycle: status probe, lazy spawn, stop, foreground serve.

The gpg-agent pattern: ``pocketshell daemon start`` spawns a detached
``pocketshell daemon _serve`` child (session leader reparented to PID 1),
the CLI polls :func:`is_daemon_running` for readiness, and
``pocketshell daemon stop`` shuts it down over RPC. A stale socket is never
trusted as "running" — only a daemon that answers ``daemon.ping`` is.
"""

from __future__ import annotations

import fcntl
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from pocketshell.daemon.client import call
from pocketshell.daemon.failures import DaemonClientError
from pocketshell.daemon.paths import (
    _ensure_socket_dir,
    resolve_lock_path,
    resolve_pid_path,
    resolve_socket_path,
)
from pocketshell.daemon.server import DEFAULT_IDLE_TIMEOUT_SECS, Daemon


def is_daemon_running(socket_path: Optional[Path] = None) -> bool:
    """Return True if a daemon answers ``daemon.ping`` on the socket.

    Used by ``pocketshell daemon status`` and by the lazy-spawn logic
    in the CLI to decide whether to fall through to subprocess. A bare
    ``socket.exists()`` is not sufficient — a stale socket from a
    crashed daemon would falsely report "running".
    """
    socket_path = socket_path or resolve_socket_path()
    if not socket_path.exists():
        return False
    try:
        result = call("daemon.ping", socket_path=socket_path, timeout=1.0)
    except (DaemonClientError, RuntimeError, OSError):
        return False
    return bool(result and result.get("ok"))


def _detached_child_env(
    socket_path: Optional[Path], idle_timeout: Optional[float]
) -> dict[str, str]:
    """Environment for the detached daemon child: socket + idle overrides."""
    env = dict(os.environ)
    if socket_path is not None:
        env["POCKETSHELL_DAEMON_SOCKET"] = str(socket_path)
    if idle_timeout is not None:
        env["POCKETSHELL_DAEMON_IDLE_SECS"] = str(idle_timeout)
    return env


def spawn_detached(
    *,
    socket_path: Optional[Path] = None,
    idle_timeout: Optional[float] = None,
    python_executable: Optional[str] = None,
) -> int:
    """Spawn ``pocketshell daemon start`` detached (gpg-agent pattern).

    One ``subprocess.Popen`` with ``start_new_session=True``: the child
    becomes a session leader reparented to PID 1 when this process exits.
    Returns the spawned PID; poll :func:`is_daemon_running` for readiness.
    """
    python_executable = python_executable or sys.executable
    cmd = [python_executable, "-m", "pocketshell", "daemon", "_serve"]
    env = _detached_child_env(socket_path, idle_timeout)
    # DEVNULL stdio + start_new_session (setsid) cut the child loose from
    # this terminal entirely, so the parent can exit immediately.
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
        env=env,
        close_fds=True,
    )
    return proc.pid


def wait_until_ready(
    *,
    socket_path: Optional[Path] = None,
    deadline: float = 5.0,
    poll_interval: float = 0.05,
) -> bool:
    """Poll the socket until :func:`is_daemon_running` succeeds or timeout.

    50 ms polling matches the spike's "50 ms x 20 ≈ 1 s ceiling".
    Default deadline 5 s gives slow Python imports headroom on cold
    cache (the typical real-world worst case is ~1.5 s on the dev
    box).
    """
    socket_path = socket_path or resolve_socket_path()
    deadline_at = time.monotonic() + deadline
    while time.monotonic() < deadline_at:
        if is_daemon_running(socket_path):
            return True
        time.sleep(poll_interval)
    return False


def _await_socket_removal(socket_path: Path, timeout: float) -> None:
    """Give a proven-live daemon time to remove its owned socket.

    A stale, unresponsive socket has nobody to wait for and proceeds
    directly to ownership-locked cleanup.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not socket_path.exists():
            break
        time.sleep(0.05)


def _reap_stale_paths(socket_path: Path, pid_path: Path) -> None:
    """Remove stale socket/pid files when no daemon owns the lifecycle lock.

    Re-probes after acquiring the lock so a concurrent startup cannot be
    mistaken for a stale daemon.
    """
    _ensure_socket_dir(socket_path)
    lock_fd = os.open(str(resolve_lock_path(socket_path)), os.O_RDWR | os.O_CREAT, 0o600)
    lock = os.fdopen(lock_fd, "a+")
    try:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        if not is_daemon_running(socket_path):
            for path in (socket_path, pid_path):
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
    finally:
        lock.close()


def stop_daemon(
    *,
    socket_path: Optional[Path] = None,
    timeout: float = 5.0,
) -> bool:
    """Stop a running daemon and remove its socket.

    A responsive socket proves daemon identity, so shutdown always goes over
    RPC. A numeric PID file alone is never trusted: the OS may have reused a
    stale PID for an unrelated process. Stale paths are removed only while
    holding the same exclusive lifetime lock used by startup.

    Returns ``True`` if a daemon was running and is now stopped,
    ``False`` if no daemon was running.
    """
    socket_path = socket_path or resolve_socket_path()
    was_running = is_daemon_running(socket_path)
    if was_running:
        try:
            call("daemon.shutdown", socket_path=socket_path, timeout=timeout)
        except (DaemonClientError, RuntimeError, OSError):
            pass
        _await_socket_removal(socket_path, timeout)
    _reap_stale_paths(socket_path, resolve_pid_path(socket_path))
    return was_running


def _resolve_idle_timeout(idle_timeout: Optional[float]) -> float:
    """Fall back to the env override, then the default idle timeout."""
    if idle_timeout is not None:
        return idle_timeout
    env_value = os.environ.get("POCKETSHELL_DAEMON_IDLE_SECS")
    if env_value is None:
        return DEFAULT_IDLE_TIMEOUT_SECS
    try:
        return float(env_value)
    except ValueError:
        return DEFAULT_IDLE_TIMEOUT_SECS


def serve_foreground(
    *,
    socket_path: Optional[Path] = None,
    idle_timeout: Optional[float] = None,
) -> int:
    """Run the daemon in the foreground until idle or shutdown.

    Used by both ``pocketshell daemon start`` (after the parent
    spawn-detaches) and by the hidden ``pocketshell daemon _serve``
    entrypoint that the lazy-spawn path execs. Returns the process
    exit code (0 = clean shutdown).
    """
    if socket_path is None:
        socket_path = resolve_socket_path()
    idle_timeout = _resolve_idle_timeout(idle_timeout)
    # Abort cleanly if another daemon is already serving the socket.
    # The lazy-spawn code path checks this too, but a manual
    # ``pocketshell daemon start`` race can still land here.
    if is_daemon_running(socket_path):
        return 0
    daemon = Daemon(socket_path=socket_path, idle_timeout=idle_timeout)
    daemon.serve()
    return 0
