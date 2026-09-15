"""Schema-3 sessions list envelope (daemon-first)."""
from __future__ import annotations
import json
import sys
from typing import Any, Mapping, Optional
import click
from pocketshell.runtime import sessions as _session_enum
# --- sibling modules ---
from pocketshell.sessions.cli import sessions_group
from pocketshell.sessions.create import CREATE_SCHEMA_VERSION


def _emit_envelope(ctx: click.Context, envelope: Mapping[str, Any]) -> None:
    if envelope.get("stdout"):
        sys.stdout.write(str(envelope["stdout"]))
    if envelope.get("stderr"):
        sys.stderr.write(str(envelope["stderr"]))
    exit_code = int(envelope.get("returncode", 0))
    if exit_code:
        ctx.exit(exit_code)


def _is_schema3_list_envelope(value: Any) -> bool:
    """Validate a daemon ``sessions.list`` reply at the current schema."""
    from pocketshell import daemon as _daemon

    if not _daemon.is_command_envelope(value):
        return False
    try:
        payload = json.loads(str(value.get("stdout") or ""))
    except ValueError:
        return False
    return (
        isinstance(payload, dict)
        and payload.get("schema") == CREATE_SCHEMA_VERSION
        and isinstance(payload.get("sessions"), list)
        and isinstance(payload.get("errors"), list)
    )


def _try_daemon_sessions_list(*, as_json: bool = False) -> Optional[dict[str, Any]]:
    """Use the shared daemon boundary when one is already running."""
    from pocketshell import daemon as _daemon

    return _daemon.try_call(
        "sessions.list",
        params={"as_json": as_json},
        socket_path=_daemon.resolve_socket_path(),
        timeout=5.0,
        result_validator=_is_schema3_list_envelope if as_json else _daemon.is_command_envelope,
    )


def _list_envelope(*, as_json: bool) -> dict[str, Any]:
    sessions, errors = _session_enum.enumerate_live_sessions()
    if as_json:
        stdout = json.dumps(_session_enum.json_payload(sessions, errors), indent=2) + "\n"
    else:
        stdout = _session_enum.format_aplexer_table(sessions)

    if errors:
        detail = "; ".join(str(error.get("message") or "session enumeration failed") for error in errors)
        return {
            "stdout": stdout,
            "stderr": f"pocketshell: {detail}\n",
            "returncode": 127,
        }
    return {"stdout": stdout, "stderr": "", "returncode": 0}


def daemon_handler_list(params: dict[str, Any]) -> dict[str, Any]:
    """JSON-RPC handler for the aplexer-only session listing."""
    return _list_envelope(as_json=bool(params.get("as_json")))


@sessions_group.command("list", context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    default=False,
    help="Emit the schema-3 session list contract.",
)
@click.pass_context
def sessions_list(ctx: click.Context, as_json: bool) -> None:
    """List live aplexer sessions."""
    envelope = _try_daemon_sessions_list(as_json=as_json)
    if envelope is None:
        envelope = _list_envelope(as_json=as_json)
    _emit_envelope(ctx, envelope)
