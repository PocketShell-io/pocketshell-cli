"""Daemon method handlers and the daemon-first call helper."""
from __future__ import annotations
import json
import sys
from typing import Any, Mapping, Optional
import click
# --- sibling modules ---
from pocketshell.tree.model import get_tree, reconcile_tree, upsert_tree
from pocketshell.tree.workspaces.membership import get_workspace, upsert_workspace


def daemon_handler_get(params: Mapping[str, Any]) -> dict[str, Any]:
    """JSON-RPC handler for ``tree.get``."""
    return get_tree(params)


def daemon_handler_upsert(params: Mapping[str, Any]) -> dict[str, Any]:
    """JSON-RPC handler for ``tree.upsert``."""
    return upsert_tree(params)


def daemon_handler_reconcile(params: Mapping[str, Any]) -> dict[str, Any]:
    """JSON-RPC handler for ``tree.reconcile``."""
    return reconcile_tree(params)


def daemon_handler_workspace_get(params: Mapping[str, Any]) -> dict[str, Any]:
    """JSON-RPC handler for ``tree.workspace.get``."""
    return get_workspace(params)


def daemon_handler_workspace_upsert(params: Mapping[str, Any]) -> dict[str, Any]:
    """JSON-RPC handler for ``tree.workspace.upsert``."""
    return upsert_workspace(params)


def _read_stdin_params() -> dict[str, Any]:
    """Read the request params as a JSON object from stdin (empty -> ``{}``)."""
    if sys.stdin is None or sys.stdin.isatty():
        return {}
    raw = sys.stdin.read()
    if not raw.strip():
        return {}
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise click.ClickException(f"tree: stdin is not valid JSON: {exc}") from exc
    if not isinstance(doc, Mapping):
        raise click.ClickException("tree: stdin JSON must be an object")
    return dict(doc)


def _try_daemon_call(method: str, params: Mapping[str, Any]) -> Optional[Any]:
    """Dispatch ``method`` through the shared typed daemon boundary.

    ``None`` means only an absent/unavailable daemon or an explicitly
    supported method skew. Timeouts, protocol failures, daemon errors, and
    malformed result shapes raise a safe user-visible daemon error.
    """
    from pocketshell import daemon as _daemon

    socket_path = _daemon.resolve_socket_path()
    return _daemon.try_call(
        method,
        params=dict(params),
        socket_path=socket_path,
        timeout=5.0,
        result_validator=lambda result: _is_daemon_result(method, result),
    )


def _valid_tree_result(method: str, result: dict[str, Any]) -> bool:
    """Shape checks for the three tree RPC envelopes."""
    if method == "tree.get":
        return isinstance(result.get("nodes"), list) and isinstance(
            result.get("version"), int
        )
    if method == "tree.upsert":
        return isinstance(result.get("status"), str) and isinstance(
            result.get("version"), int
        )
    if method == "tree.reconcile":
        return all(
            isinstance(result.get(key), list) for key in ("alive", "gone", "added")
        )
    return False


def _valid_workspace_result(method: str, result: dict[str, Any]) -> bool:
    """Shape checks for the two file-workspace RPC envelopes."""
    if method == "tree.workspace.get":
        return isinstance(result.get("tabs"), list) and (
            result.get("active_path") is None
            or isinstance(result.get("active_path"), str)
        )
    if method == "tree.workspace.upsert":
        return (
            isinstance(result.get("status"), str)
            and isinstance(result.get("tabs"), list)
            and (
                result.get("active_path") is None
                or isinstance(result.get("active_path"), str)
            )
        )
    return False


def _is_daemon_result(method: str, result: Any) -> bool:
    """Validate the result shape for each tree RPC before using it.

    A successful JSON-RPC response with the wrong object shape is a daemon
    failure, not evidence that the daemon is absent. Keeping this validation
    beside the wrapper prevents malformed responses from reaching the local
    fallback branch (or being emitted as a false successful CLI response).
    """
    if not isinstance(result, dict):
        return False
    return _valid_tree_result(method, result) or _valid_workspace_result(
        method, result
    )
