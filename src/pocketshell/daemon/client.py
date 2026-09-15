"""Client-side daemon RPC: connect, exchange frames, classify failures."""
from __future__ import annotations
import json
import socket
from pathlib import Path
from typing import Any, Callable, Mapping, Optional
# --- sibling modules ---
from pocketshell.daemon.failures import DaemonCallOutcome, DaemonClientError, DaemonFailureReason, JSONRPC_METHOD_NOT_FOUND, _failure, _installed_cli_version, _log_failure, _safe_error_data, _safe_version
from pocketshell.daemon.paths import resolve_socket_path
from pocketshell.daemon.protocol import FramingError, recv_json, send_json


def _connect(socket_path: Path, *, timeout: float = 1.0) -> socket.socket:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect(str(socket_path))
    except BaseException:
        # A failed connect does not transfer ownership to the caller.
        try:
            sock.close()
        except OSError:
            pass
        raise
    return sock


_CONNECT_TIMEOUT_ERRORS = (socket.timeout, TimeoutError)


def _phase_failure(
    reason: DaemonFailureReason,
    method: str,
    cli_version: Optional[str],
    phase: str,
    **extra: Any,
) -> DaemonCallOutcome[Any]:
    """Build and log one classified failure outcome."""
    failure = _failure(reason, method, cli_version=cli_version, phase=phase, **extra)
    _log_failure(failure)
    return DaemonCallOutcome(failure=failure)


def _probe(
    socket_path: Path, method: str, cli_version: Optional[str]
) -> Optional[DaemonCallOutcome[Any]]:
    """Classify a missing daemon socket as absent/unavailable."""
    if socket_path.exists():
        return None
    return _phase_failure(
        DaemonFailureReason.ABSENT_OR_UNAVAILABLE,
        method,
        cli_version,
        phase="probe",
    )


def _dial(
    socket_path: Path, method: str, cli_version: Optional[str], timeout: float
) -> tuple[Optional[socket.socket], Optional[DaemonCallOutcome[Any]]]:
    """Connect to the daemon. Only this phase may report it absent."""
    try:
        return _connect(socket_path, timeout=timeout), None
    except _CONNECT_TIMEOUT_ERRORS:
        return None, _phase_failure(
            DaemonFailureReason.TRANSPORT_TIMEOUT, method, cli_version, phase="connect"
        )
    except OSError:
        # ECONNREFUSED/ENOENT and permission/socket availability errors all
        # mean the daemon cannot be used for this attempt. Do not expose the
        # OS error text: it can contain a private socket path.
        return None, _phase_failure(
            DaemonFailureReason.ABSENT_OR_UNAVAILABLE, method, cli_version, phase="connect"
        )


def _request(
    method: str, params: Optional[Mapping[str, Any]], cli_version: Optional[str]
) -> dict[str, Any]:
    request: dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": dict(params or {}),
    }
    if cli_version is not None:
        # Top-level metadata is outside method params, so it cannot alter
        # handler contracts or cache keys. The server sanitizes it again.
        request["client_version"] = cli_version
    return request


def _setup(sock: socket.socket, method: str, cli_version: Optional[str], timeout: float) -> Optional[DaemonCallOutcome[Any]]:
    try:
        sock.settimeout(timeout)
    except _CONNECT_TIMEOUT_ERRORS:
        return _phase_failure(
            DaemonFailureReason.TRANSPORT_TIMEOUT, method, cli_version, phase="setup"
        )
    except OSError:
        return _phase_failure(
            DaemonFailureReason.DAEMON_INTERNAL_ERROR, method, cli_version, phase="setup"
        )
    return None


def _send(
    sock: socket.socket, request: dict[str, Any], method: str, cli_version: Optional[str]
) -> Optional[DaemonCallOutcome[Any]]:
    try:
        send_json(sock, request)
    except _CONNECT_TIMEOUT_ERRORS:
        return _phase_failure(
            DaemonFailureReason.TRANSPORT_TIMEOUT, method, cli_version, phase="write"
        )
    except (FramingError, OSError):
        # The peer accepted the connection. A write-side disconnect could
        # follow a successfully applied mutation, so it is not safe to
        # retry the operation locally.
        return _phase_failure(
            DaemonFailureReason.DAEMON_INTERNAL_ERROR, method, cli_version, phase="write"
        )
    return None


def _receive(
    sock: socket.socket, method: str, cli_version: Optional[str]
) -> tuple[Optional[Any], Optional[DaemonCallOutcome[Any]]]:
    try:
        return recv_json(sock), None
    except _CONNECT_TIMEOUT_ERRORS:
        return None, _phase_failure(
            DaemonFailureReason.TRANSPORT_TIMEOUT, method, cli_version, phase="read"
        )
    except (FramingError, json.JSONDecodeError, UnicodeDecodeError, OSError):
        # A connected peer sent no usable response. Treat it as an
        # unhealthy daemon rather than an absent one; local retry could
        # duplicate a side effect whose response was lost.
        return None, _phase_failure(
            DaemonFailureReason.DAEMON_INTERNAL_ERROR, method, cli_version, phase="read"
        )


def _exchange(
    sock: socket.socket, request: dict[str, Any], method: str,
    cli_version: Optional[str], timeout: float,
) -> tuple[Optional[Any], Optional[DaemonCallOutcome[Any]]]:
    """Run one request/response cycle, always closing ``sock``."""
    outcome = _setup(sock, method, cli_version, timeout)
    response: Optional[Any] = None
    if outcome is None:
        outcome = _send(sock, request, method, cli_version)
    if outcome is None:
        response, outcome = _receive(sock, method, cli_version)
    try:
        sock.close()
    except OSError:
        pass
    return response, outcome


def _rpc_error_outcome(
    err: Any, method: str, cli_version: Optional[str]
) -> DaemonCallOutcome[Any]:
    """Classify a JSON-RPC error envelope (skew vs internal)."""
    code = err.get("code") if isinstance(err, dict) else None
    safe_data = _safe_error_data(err.get("data")) if isinstance(err, dict) else None
    daemon_version = (
        _safe_version(safe_data.get("daemon_version")) if safe_data is not None else None
    )
    reason = (
        DaemonFailureReason.SUPPORTED_SKEW
        if code == JSONRPC_METHOD_NOT_FOUND
        else DaemonFailureReason.DAEMON_INTERNAL_ERROR
    )
    return _phase_failure(
        reason,
        method,
        cli_version,
        daemon_version=daemon_version,
        rpc_code=code if isinstance(code, int) else None,
        phase="rpc",
    )


def _response_outcome(
    response: Optional[Any], method: str, cli_version: Optional[str]
) -> tuple[Optional[Any], Optional[DaemonCallOutcome[Any]]]:
    """Validate the reply envelope; return ``(result, failure_outcome)``."""
    if not isinstance(response, dict):
        return None, _phase_failure(
            DaemonFailureReason.DAEMON_INTERNAL_ERROR, method, cli_version, phase="response"
        )
    if response.get("error") is not None:
        return None, _rpc_error_outcome(response["error"], method, cli_version)
    if "result" not in response:
        return None, _phase_failure(
            DaemonFailureReason.DAEMON_INTERNAL_ERROR, method, cli_version, phase="response"
        )
    return response["result"], None


def call_outcome(
    method: str,
    params: Optional[Mapping[str, Any]] = None,
    *,
    socket_path: Optional[Path] = None,
    timeout: float = 5.0,
) -> DaemonCallOutcome[Any]:
    """Send one JSON-RPC request and classify every unsuccessful attempt.

    The initial socket probe/connect is the only phase classified as
    ``ABSENT_OR_UNAVAILABLE``. Once a peer accepted the request, a timeout,
    broken frame, or closed connection is non-fallback: a mutation may have
    reached the daemon even if its reply did not. JSON-RPC method-not-found is
    the one explicitly supported compatibility/skew case.
    """
    socket_path = socket_path or resolve_socket_path()
    cli_version = _installed_cli_version()
    outcome = _probe(socket_path, method, cli_version)
    sock = None
    if outcome is None:
        sock, outcome = _dial(socket_path, method, cli_version, timeout)
    response: Optional[Any] = None
    if outcome is None and sock is not None:
        request = _request(method, params, cli_version)
        response, outcome = _exchange(sock, request, method, cli_version, timeout)
    if outcome is None:
        result, outcome = _response_outcome(response, method, cli_version)
        if outcome is None:
            return DaemonCallOutcome(result=result)
    return outcome


def call(
    method: str,
    params: Optional[Mapping[str, Any]] = None,
    *,
    socket_path: Optional[Path] = None,
    timeout: float = 5.0,
) -> Any:
    """Send one JSON-RPC request and return its result or a typed error."""
    outcome = call_outcome(
        method,
        params=params,
        socket_path=socket_path,
        timeout=timeout,
    )
    if outcome.failure is not None:
        raise DaemonClientError(outcome.failure)
    return outcome.result


def try_call(
    method: str,
    params: Optional[Mapping[str, Any]] = None,
    *,
    socket_path: Optional[Path] = None,
    timeout: float = 5.0,
    result_validator: Optional[Callable[[Any], bool]] = None,
) -> Any:
    """Call the daemon; return ``None`` only for approved local fallback.

    Wrappers use this shared boundary and run their own local implementation
    when it returns ``None``. A validator turns a malformed successful RPC
    response into a visible daemon-internal failure, not silent fallback.
    """
    outcome = call_outcome(method, params=params, socket_path=socket_path, timeout=timeout)
    if outcome.failure is not None:
        if outcome.failure.fallback_allowed:
            return None
        raise DaemonClientError(outcome.failure)
    if result_validator is not None and not result_validator(outcome.result):
        raise DaemonClientError(
            _phase_failure(
                DaemonFailureReason.DAEMON_INTERNAL_ERROR,
                method,
                _installed_cli_version(),
                phase="validate",
            ).failure
        )
    return outcome.result


def is_command_envelope(value: Any) -> bool:
    """Return whether ``value`` is a complete subprocess proxy envelope."""
    return (
        isinstance(value, dict)
        and isinstance(value.get("stdout"), str)
        and isinstance(value.get("stderr"), str)
        and type(value.get("returncode")) is int
    )


# --- lifecycle API ------------------------------------------------------
# Spawn / stop / status / foreground-serve live in ``lifecycle.py``; they
# are re-exported here so ``pocketshell.daemon.client`` remains the one
# import surface for everything a CLI wrapper needs against the daemon.
from pocketshell.daemon.lifecycle import (  # noqa: E402
    is_daemon_running as is_daemon_running,
    serve_foreground as serve_foreground,
    spawn_detached as spawn_detached,
    stop_daemon as stop_daemon,
    wait_until_ready as wait_until_ready,
)
