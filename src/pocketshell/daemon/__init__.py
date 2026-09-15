"""`pocketshell daemon` — Unix-socket JSON-RPC 2.0 server.

The daemon provides the long-lived RPC path for the host-side wrappers. It is
an optimisation, not a dependency: wrappers may run their documented local
implementation only when this module classifies the daemon as absent,
unavailable, or explicitly incompatible by method. A timeout or daemon
internal/protocol failure is surfaced so a mutating call is never duplicated
or silently reported as successful.

Why this exists
---------------

Each ``pocketshell usage`` call today re-imports Python and re-runs the
``quse`` provider scan, which costs ~150-400 ms of interpreter cold-start
before any real work happens. A long-lived daemon process eliminates the
interpreter import cost on every call, and the in-memory cache short-
circuits the second-and-later calls within a TTL window.

Design choices (verbatim from the spike)
----------------------------------------

- **Transport**: Unix domain socket carrying 4-byte big-endian
  length-prefixed UTF-8 JSON-RPC 2.0 frames. Filesystem ACL is the
  security boundary (``chmod 0600`` socket, ``chmod 0700`` parent dir).
  Reject :mod:`multiprocessing.connection` because its default authkey
  uses :mod:`pickle`, an RCE footgun.
- **Socket path**: ``$POCKETSHELL_DAEMON_SOCKET`` override (test/dev),
  then ``$XDG_RUNTIME_DIR/pocketshell/daemon.sock``, then
  ``~/.cache/pocketshell/daemon.sock`` fallback for hosts without XDG
  (macOS, minimal containers).
- **Lifecycle**: gpg-agent pattern. ``pocketshell daemon start`` forks
  once via :func:`subprocess.Popen` with ``start_new_session=True`` so
  the child is reparented to PID 1. No double-fork (PEP-3143 /
  ``python-daemon`` is over-engineered for this case).
- **Idle timeout**: 120 s default; configurable via
  ``POCKETSHELL_DAEMON_IDLE_SECS``. Setting it to 0 disables idle
  shutdown (used by the future systemd ``Type=simple`` always-on mode).
- **Cache**: in-memory ``{(method, frozen_args): (timestamp, value)}``
  with per-method TTL. ``usage.fetch`` TTL is 30 s. Failures (non-zero
  exit) are NOT cached so a transient ``quse`` hiccup does not pin a
  bad result for 30 s. ``--no-cache`` propagates as a JSON-RPC param.
- **Stale-socket recovery**: the daemon ``os.unlink``-s the socket path
  before ``bind()`` and again on shutdown via an atexit handler. The
  CLI probes the socket with ``connect()``; ``ECONNREFUSED`` /
  ``ENOENT`` is classified as absent/unavailable and falls through to
  either spawning a fresh daemon or running the one-shot subprocess path.
  A method-not-found response is the explicitly supported version-skew
  fallback. Timeouts, malformed responses, and daemon errors remain visible.

The daemon is a pure optimisation; the CLI path falls through cleanly only
for the two approved fallback reasons. Every classified attempt emits the
``pocketshell.daemon_call`` telemetry fields (including safe CLI/daemon
versions when available) without RPC parameters or command output.
"""
from __future__ import annotations

from pocketshell.daemon.cache import (
    METHOD_TTLS,
)
from pocketshell.daemon.client import (
    call_outcome,
    call,
    try_call,
    is_command_envelope,
    is_daemon_running,
    spawn_detached,
    wait_until_ready,
    stop_daemon,
    serve_foreground,
)
from pocketshell.daemon.failures import (
    JSONRPC_PARSE_ERROR,
    JSONRPC_INVALID_REQUEST,
    JSONRPC_METHOD_NOT_FOUND,
    JSONRPC_INVALID_PARAMS,
    JSONRPC_INTERNAL_ERROR,
    DaemonFailureReason,
    LOCAL_FALLBACK_REASONS,
    DaemonFailure,
    DaemonCallOutcome,
    DaemonClientError,
)
from pocketshell.daemon.methods import (
    RpcHandler,
    DEFAULT_METHODS,
    METHOD_CACHE_INVALIDATIONS,
)
from pocketshell.daemon.paths import (
    resolve_socket_path,
    resolve_pid_path,
    resolve_lock_path,
    read_pid,
)
from pocketshell.daemon.protocol import (
    FramingError,
    send_frame,
    recv_frame,
    send_json,
    recv_json,
)
from pocketshell.daemon.server import (
    DEFAULT_IDLE_TIMEOUT_SECS,
    Daemon,
)

__all__ = [
    "DEFAULT_IDLE_TIMEOUT_SECS",
    "METHOD_TTLS",
    "JSONRPC_PARSE_ERROR",
    "JSONRPC_INVALID_REQUEST",
    "JSONRPC_METHOD_NOT_FOUND",
    "JSONRPC_INVALID_PARAMS",
    "JSONRPC_INTERNAL_ERROR",
    "DaemonFailureReason",
    "LOCAL_FALLBACK_REASONS",
    "DaemonFailure",
    "DaemonCallOutcome",
    "resolve_socket_path",
    "resolve_pid_path",
    "resolve_lock_path",
    "read_pid",
    "FramingError",
    "send_frame",
    "recv_frame",
    "send_json",
    "recv_json",
    "RpcHandler",
    "DEFAULT_METHODS",
    "METHOD_CACHE_INVALIDATIONS",
    "Daemon",
    "DaemonClientError",
    "call_outcome",
    "call",
    "try_call",
    "is_command_envelope",
    "is_daemon_running",
    "spawn_detached",
    "wait_until_ready",
    "stop_daemon",
    "serve_foreground",
]
