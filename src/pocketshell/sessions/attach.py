"""Resolve a session by name/prefix and exec the multiplexer."""
from __future__ import annotations
import os
from typing import Sequence
import click
from pocketshell.runtime import sessions as _session_enum
# --- sibling modules ---
from pocketshell.sessions.cli import sessions_group
from pocketshell.sessions.create import _aplexer_snapshot, _aplexer_unresolved_message, _resolve_aplexer


ATTACH_EXIT_NOT_FOUND = 3


ATTACH_EXIT_AMBIGUOUS = 4


ATTACH_EXIT_NO_BINARY = 127


APLEXER_ID_PREFIX_MIN = 8


def _exec(argv: list[str]) -> None:
    """Replace this process with the already resolved executable."""
    os.execv(argv[0], argv)


def _match_attach_target(
    rows: Sequence[_session_enum.LiveSession], name: str
) -> list[_session_enum.LiveSession]:
    exact = [row for row in rows if row.name == name]
    if exact:
        return exact
    if len(name) < APLEXER_ID_PREFIX_MIN:
        return []
    return [row for row in rows if row.aplexer_id and row.aplexer_id.startswith(name)]


def _attach_live_rows() -> tuple[list[_session_enum.LiveSession], list[dict[str, str]]]:
    return _session_enum.enumerate_live_sessions()


def _dead_row_detail(row: _session_enum.LiveSession) -> str:
    phase = row.phase or "unknown"
    if phase == "exited":
        return f"it has already exited (aplexer phase: {phase})"
    if phase == "failed":
        return f"it failed to start (aplexer phase: {phase})"
    return f"it has no live worker (aplexer phase: {phase}, worker_alive: false)"


def _not_attachable_message(name: str) -> str:
    dead = _session_enum.dead_sessions_from_aplexer_snapshot(_aplexer_snapshot())
    for row in _match_attach_target(dead, name):
        return (
            f"pocketshell: aplexer session {row.name!r} is no longer running: "
            f"{_dead_row_detail(row)}. It cannot be attached; run "
            "`pocketshell sessions list` for the live ones."
        )
    return f"no session named {name!r}"


def _describe_candidate(row: _session_enum.LiveSession) -> str:
    if row.aplexer_id:
        return f"  {row.name}  (aplexer {row.aplexer_id})"
    return f"  {row.name}"


def _validated_attach_target(
    ctx: click.Context, name: str
) -> _session_enum.LiveSession:
    """Resolve a unique live session for ``name``, exiting the CLI on failure."""
    rows, errors = _attach_live_rows()
    if errors:
        click.echo(
            "pocketshell: " + "; ".join(error["message"] for error in errors),
            err=True,
        )
        ctx.exit(ATTACH_EXIT_NO_BINARY)
    matches = _match_attach_target(rows, name)
    if not matches:
        click.echo(_not_attachable_message(name), err=True)
        ctx.exit(ATTACH_EXIT_NOT_FOUND)
    if len(matches) > 1:
        click.echo(f"ambiguous session name {name!r}; candidates:", err=True)
        for row in matches:
            click.echo(_describe_candidate(row), err=True)
        ctx.exit(ATTACH_EXIT_AMBIGUOUS)
    return matches[0]


def _exec_attach(ctx: click.Context, row: _session_enum.LiveSession) -> None:
    """Resolve ``a`` and replace this process with the attach relay."""
    resolution = _resolve_aplexer()
    if resolution.path is None:
        click.echo(
            _aplexer_unresolved_message(
                resolution, action=f"cannot attach to {row.name!r}"
            ),
            err=True,
        )
        ctx.exit(ATTACH_EXIT_NO_BINARY)
    if not row.aplexer_id:
        click.echo(f"pocketshell: session {row.name!r} has no aplexer id.", err=True)
        ctx.exit(ATTACH_EXIT_NOT_FOUND)
    # PocketShell owns the session header, status and controls. Ask aplexer
    # for its plain full-screen relay so its terminal attach UI cannot leak
    # Multiplexer chrome into the Android terminal.
    _exec([resolution.path, "attach", "--no-status", str(row.aplexer_id)])


@sessions_group.command("attach", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("name")
@click.pass_context
def sessions_attach(ctx: click.Context, name: str) -> None:
    """Attach to a live session by display name or id prefix."""
    row = _validated_attach_target(ctx, name)
    _exec_attach(ctx, row)
