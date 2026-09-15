"""The ``Daemon`` accept loop: socket binding, lifecycle, shutdown.

Request handling (validation, registry, cache, responses) lives in
:class:`pocketshell.daemon.dispatch.RequestDispatcher`; this module owns the
Unix-socket transport and the process lifecycle around it — lifetime lock,
stale-socket replacement, PID file, idle timeout, and signal-driven
shutdown.
"""

from __future__ import annotations

import fcntl
import os
import signal
import socket
import threading
import time
from pathlib import Path
from typing import Any, Callable, Mapping, Optional

from pocketshell.daemon.cache import _Cache
from pocketshell.daemon.dispatch import RequestDispatcher
from pocketshell.daemon.failures import DaemonFailureReason, _installed_cli_version, _safe_version
from pocketshell.daemon.methods import DEFAULT_METHODS, RpcHandler
from pocketshell.daemon.paths import _ensure_socket_dir, resolve_lock_path, resolve_pid_path


# Public so the CLI module and tests can reuse without duplicating the
# default. Override via env var ``POCKETSHELL_DAEMON_IDLE_SECS`` for
# tests that want to assert idle shutdown without waiting two minutes.
DEFAULT_IDLE_TIMEOUT_SECS = 120.0


class _DaemonAlreadyOwned(Exception):
    """Another daemon holds the socket's lifetime lock."""


class Daemon:
    """Unix-socket JSON-RPC 2.0 server for ``pocketshell`` subcommands.

    Single-threaded for now: handler calls (especially ``usage.fetch``)
    are dominated by the ``quse`` subprocess, and serialising them
    keeps the cache logic simple. Concurrent reads of a cache hit are
    not a hot enough path to justify a thread pool — the cache hit
    returns in microseconds; queueing behind a single accept loop is
    fine. Tests for the "two concurrent clients" scenario rely on the
    accept loop draining quickly between handler invocations.
    """

    def __init__(
        self,
        socket_path: Path,
        *,
        idle_timeout: float = DEFAULT_IDLE_TIMEOUT_SECS,
        methods: Optional[Mapping[str, RpcHandler]] = None,
        pid_path: Optional[Path] = None,
        clock: Callable[[], float] = time.monotonic,
        daemon_version: Optional[str] = None,
    ) -> None:
        self.socket_path = socket_path
        self.pid_path = pid_path or resolve_pid_path(socket_path)
        self.idle_timeout = idle_timeout
        self.daemon_version = _safe_version(daemon_version) or _installed_cli_version()
        self._cache = _Cache(clock=clock)
        self._clock = clock
        self._server_sock: Optional[socket.socket] = None
        self._lifecycle_lock: Optional[Any] = None
        self._stop_event = threading.Event()
        self._last_activity = self._clock()
        self._dispatcher = RequestDispatcher(
            cache=self._cache,
            daemon_version_fn=lambda: self.daemon_version,
            shutdown_fn=self.shutdown,
            methods=methods if methods is not None else DEFAULT_METHODS,
        )

    # -- registration ----------------------------------------------------

    def register_method(self, name: str, handler: RpcHandler) -> None:
        self._dispatcher.register_method(name, handler)

    # -- lifecycle -------------------------------------------------------

    def _acquire_lifecycle_lock(self) -> None:
        """Take the socket's exclusive lifetime lock or raise if owned."""
        lock_path = resolve_lock_path(self.socket_path)
        lock_fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o600)
        lock = os.fdopen(lock_fd, "a+")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            lock.close()
            raise _DaemonAlreadyOwned
        self._lifecycle_lock = lock

    def _create_listener_socket(self) -> socket.socket:
        """Replace any stale endpoint with a fresh, user-only listener."""
        # Only the lifetime-lock owner may replace a proven stale endpoint.
        try:
            os.unlink(self.socket_path)
        except FileNotFoundError:
            pass

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        # Restrict the socket file to user-only. We set umask before
        # bind() because Linux derives the socket file mode from the
        # process umask (no fchmod hook on AF_UNIX at bind time).
        old_umask = os.umask(0o077)
        try:
            sock.bind(str(self.socket_path))
        finally:
            os.umask(old_umask)
        sock.listen(8)
        # Defence in depth: chmod the socket explicitly in case some
        # platform ignored the umask.
        try:
            os.chmod(self.socket_path, 0o600)
        except FileNotFoundError:
            pass
        return sock

    def _bind(self) -> socket.socket:
        _ensure_socket_dir(self.socket_path)
        self._acquire_lifecycle_lock()
        try:
            return self._create_listener_socket()
        except BaseException:
            self._release_lifecycle_lock()
            raise

    def _write_pid_file(self) -> None:
        try:
            self.pid_path.write_text(f"{os.getpid()}\n")
        except OSError:
            # Best-effort. Missing PID file means ``daemon status``
            # falls back to socket-probe semantics.
            pass

    def _remove_pid_file(self) -> None:
        try:
            self.pid_path.unlink()
        except FileNotFoundError:
            pass

    def _remove_socket_file(self) -> None:
        try:
            os.unlink(self.socket_path)
        except FileNotFoundError:
            pass

    def _idle_expired(self) -> bool:
        # Checked BEFORE the accept call so a daemon idle past its limit
        # exits without blocking on the kernel for another full slice.
        return (
            self.idle_timeout > 0
            and self._clock() - self._last_activity >= self.idle_timeout
        )

    def _accept_loop(self) -> None:
        """Accept one short-lived connection at a time until stop/idle."""
        self._server_sock.settimeout(1.0)
        while not self._stop_event.is_set():
            if self._idle_expired():
                break
            try:
                client_sock, _ = self._server_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                # Server socket closed by `shutdown`.
                break
            self._last_activity = self._clock()
            try:
                self._dispatcher.handle_one(client_sock)
            finally:
                try:
                    client_sock.close()
                except OSError:
                    pass

    def serve(self) -> None:
        """Run the accept loop until idle timeout or :meth:`shutdown`.

        One request frame per connection, response written, socket closed
        (the CLI opens a fresh socket per call). Idle timeout 0 disables
        the idle exit (future systemd ``Type=simple`` always-on mode).
        """
        try:
            self._server_sock = self._bind()
        except _DaemonAlreadyOwned:
            return
        self._write_pid_file()
        self._last_activity = self._clock()
        # Trap SIGTERM so `daemon stop` (and systemd Stop) shuts us
        # down cleanly with the atexit-equivalent path.
        signal.signal(signal.SIGTERM, self._on_signal)
        signal.signal(signal.SIGINT, self._on_signal)
        try:
            self._accept_loop()
        finally:
            self._cleanup()

    def shutdown(self) -> None:
        """Request a clean exit from the accept loop."""
        self._stop_event.set()
        sock = self._server_sock
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass

    def _on_signal(self, _signum: int, _frame: Any) -> None:
        self.shutdown()

    def _cleanup(self) -> None:
        if self._server_sock is not None:
            try:
                self._server_sock.close()
            except OSError:
                pass
            self._server_sock = None
        self._remove_socket_file()
        self._remove_pid_file()
        self._release_lifecycle_lock()

    def _release_lifecycle_lock(self) -> None:
        lock = self._lifecycle_lock
        if lock is None:
            return
        self._lifecycle_lock = None
        try:
            fcntl.flock(lock, fcntl.LOCK_UN)
        finally:
            lock.close()

    # -- request handling (delegated to the dispatcher) --------------------

    def _handle_one(self, client_sock: socket.socket) -> None:
        """Read one JSON-RPC request, dispatch, write the response."""
        self._dispatcher.handle_one(client_sock)

    def _failure_data(
        self,
        reason: DaemonFailureReason,
        client_version: Optional[str],
    ) -> dict[str, str]:
        """Return safe classification metadata for an RPC error envelope."""
        return self._dispatcher.failure_data(reason, client_version)
