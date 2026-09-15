"""Typed daemon RPC failure classification, sanitisation, and error types."""
from __future__ import annotations
import logging
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Generic, Mapping, Optional, TypeVar
import click


# JSON-RPC 2.0 error codes (the standard ones we actually emit).
JSONRPC_PARSE_ERROR = -32700


JSONRPC_INVALID_REQUEST = -32600


JSONRPC_METHOD_NOT_FOUND = -32601


JSONRPC_INVALID_PARAMS = -32602


JSONRPC_INTERNAL_ERROR = -32603


_LOGGER = logging.getLogger(__name__)


class DaemonFailureReason(str, Enum):
    """Stable classification for a failed daemon RPC attempt.

    The CLI wrappers deliberately fall back only for the first two reasons.
    A timeout can mean the daemon accepted a mutating request but lost its
    reply, and an internal/protocol error means the daemon is present but
    unhealthy; retrying either locally would hide the real failure (and can
    duplicate a side effect).
    """

    ABSENT_OR_UNAVAILABLE = "absent_or_unavailable"
    SUPPORTED_SKEW = "supported_skew"
    TRANSPORT_TIMEOUT = "transport_timeout"
    DAEMON_INTERNAL_ERROR = "daemon_internal_error"


LOCAL_FALLBACK_REASONS: frozenset[DaemonFailureReason] = frozenset(
    {
        DaemonFailureReason.ABSENT_OR_UNAVAILABLE,
        DaemonFailureReason.SUPPORTED_SKEW,
    }
)


_SAFE_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")


_SAFE_METHOD_RE = re.compile(r"^[A-Za-z0-9_.-]{1,96}$")


def _safe_version(value: Any) -> Optional[str]:
    """Return a version token safe to include in telemetry or an error."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value if _SAFE_VERSION_RE.fullmatch(value) else None


def _safe_method(value: Any) -> str:
    """Return a protocol method suitable for user-facing diagnostics.

    Method names are not user prompt data in normal operation, but the daemon
    socket is a protocol boundary. Redacting an unexpected token keeps a
    malformed request from turning the error/log channel into a data echo.
    """
    if isinstance(value, str) and _SAFE_METHOD_RE.fullmatch(value):
        return value
    return "<redacted>"


def _installed_cli_version() -> Optional[str]:
    """Read the running PocketShell version without making it a hard failure."""
    try:
        from pocketshell import __version__

        return _safe_version(__version__)
    except Exception:  # pragma: no cover - defensive metadata path
        return None


@dataclass(frozen=True)
class DaemonFailure:
    """Structured, sanitized description of one failed daemon call."""

    reason: DaemonFailureReason
    method: str
    cli_version: Optional[str] = None
    daemon_version: Optional[str] = None
    rpc_code: Optional[int] = None
    phase: str = "rpc"

    @property
    def fallback_allowed(self) -> bool:
        """Whether a wrapper may run its documented local implementation."""
        return self.reason in LOCAL_FALLBACK_REASONS

    def telemetry(self) -> dict[str, Any]:
        """Return fields safe for structured logging; never include params."""
        return {
            "event": "pocketshell.daemon_call",
            "reason": self.reason.value,
            "method": _safe_method(self.method),
            "phase": self.phase,
            "rpc_code": self.rpc_code,
            "cli_version": self.cli_version,
            "daemon_version": self.daemon_version,
        }

    def user_message(self) -> str:
        """Render a detail-free message for a CLI error or exception string."""
        labels = {
            DaemonFailureReason.ABSENT_OR_UNAVAILABLE: "daemon is absent or unavailable",
            DaemonFailureReason.SUPPORTED_SKEW: "daemon does not support this method",
            DaemonFailureReason.TRANSPORT_TIMEOUT: "daemon transport timed out",
            DaemonFailureReason.DAEMON_INTERNAL_ERROR: "daemon returned an internal error",
        }
        label = labels[self.reason]
        if self.rpc_code == JSONRPC_INVALID_PARAMS:
            # Keep the existing actionable shape hint without echoing the
            # daemon's arbitrary error string, which could contain a prompt,
            # token, or another value copied from RPC params.
            label = "daemon rejected invalid parameters (must be a list or object as required)"
        fields = [
            f"method={_safe_method(self.method)}",
            f"reason={self.reason.value}",
        ]
        if self.rpc_code is not None:
            fields.append(f"rpc_code={self.rpc_code}")
        fields.append(f"cli_version={self.cli_version or 'unknown'}")
        fields.append(f"daemon_version={self.daemon_version or 'unknown'}")
        return f"{label} ({', '.join(fields)})"


_OutcomeT = TypeVar("_OutcomeT")


@dataclass(frozen=True)
class DaemonCallOutcome(Generic[_OutcomeT]):
    """Result-or-classification value used by CLI-facing daemon helpers."""

    result: Optional[_OutcomeT] = None
    failure: Optional[DaemonFailure] = None

    @property
    def succeeded(self) -> bool:
        return self.failure is None


def _safe_error_data(data: Any) -> Optional[dict[str, Any]]:
    """Keep only non-sensitive classification metadata in an RPC error."""
    if not isinstance(data, Mapping):
        return None
    safe: dict[str, Any] = {}
    raw_reason = data.get("failure_reason")
    if isinstance(raw_reason, str) and raw_reason in {
        reason.value for reason in DaemonFailureReason
    }:
        safe["failure_reason"] = raw_reason
    for key in ("cli_version", "client_version", "daemon_version"):
        version = _safe_version(data.get(key))
        if version is not None:
            safe[key] = version
    return safe or None


def _failure(
    reason: DaemonFailureReason,
    method: str,
    *,
    cli_version: Optional[str],
    daemon_version: Optional[str] = None,
    rpc_code: Optional[int] = None,
    phase: str,
) -> DaemonFailure:
    """Build a failure with all externally sourced metadata sanitized."""
    safe_code = rpc_code if isinstance(rpc_code, int) else None
    return DaemonFailure(
        reason=reason,
        method=method,
        cli_version=_safe_version(cli_version),
        daemon_version=_safe_version(daemon_version),
        rpc_code=safe_code,
        phase=phase,
    )


def _log_failure(failure: DaemonFailure) -> None:
    """Emit safe structured telemetry for a classified daemon failure.

    Expected local fallback is informational; actionable skew and failures are
    visible at warning/error level. The telemetry intentionally contains no
    RPC params, exception text, stdout, stderr, prompt, or secret material.
    """
    if failure.reason == DaemonFailureReason.ABSENT_OR_UNAVAILABLE:
        level = logging.INFO
    elif failure.reason == DaemonFailureReason.SUPPORTED_SKEW:
        level = logging.WARNING
    else:
        level = logging.ERROR
    _LOGGER.log(level, "daemon RPC classification: %s", failure.telemetry())


class DaemonClientError(click.ClickException, RuntimeError):
    """A safe, typed failure from one daemon RPC attempt.

    ``ClickException`` makes a fatal daemon failure user-visible without a
    traceback at the CLI boundary. ``RuntimeError`` preserves the historical
    API for callers that handled daemon errors directly. The structured reason
    is the only signal wrappers use to decide whether local fallback is safe.
    """

    def __init__(self, failure: DaemonFailure) -> None:
        self.failure = failure
        message = failure.user_message()
        click.ClickException.__init__(self, message)
        RuntimeError.__init__(self, message)


class _RpcError(Exception):
    """Internal helper carrying JSON-RPC error code + message."""

    def __init__(self, code: int, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data
