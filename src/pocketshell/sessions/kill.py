"""Stop a live session through aplexer and adapt its result for the client."""
from __future__ import annotations
import json
import subprocess
from typing import Any, Optional
import click
# --- sibling modules ---
from pocketshell.sessions.attach import ATTACH_EXIT_AMBIGUOUS, ATTACH_EXIT_NOT_FOUND, ATTACH_EXIT_NO_BINARY, _attach_live_rows, _match_attach_target
from pocketshell.sessions.cli import sessions_group
from pocketshell.sessions.create import CREATE_SCHEMA_VERSION, _aplexer_unresolved_message, _resolve_aplexer
from pocketshell.sessions.reap import _run_session_command


KILL_SCHEMA_VERSION = CREATE_SCHEMA_VERSION


def _emit_kill_failure(
    ctx: click.Context, message: str, *, exit_code: int, as_json: bool
) -> None:
    if as_json:
        click.echo(json.dumps({"schema": KILL_SCHEMA_VERSION, "error": message}, indent=2))
    else:
        click.echo(message, err=True)
    ctx.exit(exit_code or 1)


def _resolve_kill_target(
    ctx: click.Context, name: str, *, as_json: bool
) -> Optional[Any]:
    """Validate live rows and a unique name match; emit failure and return None."""
    rows, errors = _attach_live_rows()
    if errors:
        _emit_kill_failure(
            ctx,
            "; ".join(error["message"] for error in errors),
            exit_code=ATTACH_EXIT_NO_BINARY,
            as_json=as_json,
        )
        return None
    matches = _match_attach_target(rows, name)
    if not matches:
        _emit_kill_failure(
            ctx, f"no session named {name!r}",
            exit_code=ATTACH_EXIT_NOT_FOUND, as_json=as_json,
        )
        return None
    if len(matches) > 1:
        _emit_kill_failure(
            ctx, f"ambiguous session name {name!r}",
            exit_code=ATTACH_EXIT_AMBIGUOUS, as_json=as_json,
        )
        return None
    return matches[0]


def _kill_aplexer_path(
    ctx: click.Context, row: Any, *, as_json: bool
) -> Optional[str]:
    """Resolve the ``a`` binary and the record id, emitting failures."""
    resolution = _resolve_aplexer()
    if resolution.path is None:
        _emit_kill_failure(
            ctx,
            _aplexer_unresolved_message(
                resolution, action=f"cannot stop {row.name!r}"
            ),
            exit_code=ATTACH_EXIT_NO_BINARY,
            as_json=as_json,
        )
        return None
    if not row.aplexer_id:
        _emit_kill_failure(
            ctx, f"pocketshell: session {row.name!r} has no aplexer id.",
            exit_code=ATTACH_EXIT_NOT_FOUND, as_json=as_json,
        )
        return None
    return resolution.path


def _run_kill_command(
    ctx: click.Context, row: Any, aplexer_path: str, *, as_json: bool
) -> Optional[Any]:
    """Run ``a --json kill <id>``, mapping failures to kill failures."""
    try:
        return _run_session_command(
            [aplexer_path, "--json", "kill", str(row.aplexer_id)]
        )
    except subprocess.TimeoutExpired:
        _emit_kill_failure(
            ctx, f"pocketshell: `a kill {row.aplexer_id}` timed out.",
            exit_code=1, as_json=as_json,
        )
    except OSError as exc:
        _emit_kill_failure(
            ctx, f"pocketshell: could not stop {row.name!r}: {exc}",
            exit_code=ATTACH_EXIT_NO_BINARY, as_json=as_json,
        )
    return None


def _emit_nonzero_kill(
    ctx: click.Context, row: Any, completed: Any, *, as_json: bool
) -> bool:
    """Emit the failure envelope for a non-zero ``a kill`` exit."""
    if completed.returncode == 0:
        return False
    detail = str(completed.stderr or "").strip() or f"exit {completed.returncode}"
    _emit_kill_failure(
        ctx, f"pocketshell: could not stop {row.name!r}: {detail}",
        exit_code=completed.returncode, as_json=as_json,
    )
    return True


def _emit_kill_result(
    ctx: click.Context, row: Any, completed: Any, *, as_json: bool
) -> None:
    """Adapt aplexer's structured record-removal result without re-forgetting."""
    try:
        payload = json.loads(completed.stdout or "")
    except (TypeError, ValueError):
        payload = {}
    reaped = isinstance(payload, dict) and payload.get("record_removed") is True
    if not reaped:
        click.echo(
            f"pocketshell: stopped {row.name!r}, but its aplexer record could "
            "not be removed; inspect it with `a status` before taking any "
            "further recovery action.",
            err=True,
        )
    if as_json:
        click.echo(
            json.dumps(
                {
                    "schema": KILL_SCHEMA_VERSION,
                    "name": row.name,
                    "id": row.aplexer_id,
                    "killed": True,
                    "reaped": reaped,
                },
                indent=2,
            )
        )


@sessions_group.command("kill", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("name")
@click.option("--json", "as_json", is_flag=True, default=False, help="Emit the schema-3 kill envelope.")
@click.pass_context
def sessions_kill(ctx: click.Context, name: str, as_json: bool) -> None:
    """Stop a live aplexer session and reap its record."""
    row = _resolve_kill_target(ctx, name, as_json=as_json)
    if row is None:
        return
    aplexer_path = _kill_aplexer_path(ctx, row, as_json=as_json)
    if aplexer_path is None:
        return
    completed = _run_kill_command(ctx, row, aplexer_path, as_json=as_json)
    if completed is None:
        return
    if _emit_nonzero_kill(ctx, row, completed, as_json=as_json):
        return
    _emit_kill_result(ctx, row, completed, as_json=as_json)
