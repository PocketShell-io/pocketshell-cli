"""Rename a live aplexer session through aplexer and adapt its result.

Issue #9. The tag is the session's identity in the tree
(``<workspace-basename>:<tag>``), so renaming re-keys the row mid-flight;
this module only plumbs the verb: target resolution and exit codes are
exactly ``attach``/``kill``'s, tag rules are aplexer's own (never a second
validator — D22), and aplexer's error text is surfaced faithfully rather
than pre-empted (including the known dead-record claim-check gap,
aplexer#13 — report it, do not paper over it).
"""

from __future__ import annotations

import json
import subprocess
from typing import Any, Optional

import click

from pocketshell.runtime import sessions as _session_enum
from pocketshell.sessions.attach import (
    ATTACH_EXIT_AMBIGUOUS,
    ATTACH_EXIT_NOT_FOUND,
    ATTACH_EXIT_NO_BINARY,
    _attach_live_rows,
    _match_attach_target,
)
from pocketshell.sessions.cli import sessions_group
from pocketshell.sessions.create import (
    CREATE_SCHEMA_VERSION,
    _aplexer_unresolved_message,
    _resolve_aplexer,
)
from pocketshell.sessions.kill import _run_session_command

RENAME_SCHEMA_VERSION = CREATE_SCHEMA_VERSION


def _emit_rename_failure(
    ctx: click.Context, message: str, *, exit_code: int, as_json: bool
) -> None:
    if as_json:
        click.echo(
            json.dumps(
                {"schema": RENAME_SCHEMA_VERSION, "error": message}, indent=2
            )
        )
    else:
        click.echo(message, err=True)
    ctx.exit(exit_code or 1)


def _resolve_rename_target(
    ctx: click.Context, name: str, *, as_json: bool
) -> Optional[Any]:
    """Validate live rows and a unique name match; emit failure and return None."""
    rows, errors = _attach_live_rows()
    if errors:
        _emit_rename_failure(
            ctx,
            "; ".join(error["message"] for error in errors),
            exit_code=ATTACH_EXIT_NO_BINARY,
            as_json=as_json,
        )
        return None
    matches = _match_attach_target(rows, name)
    if not matches:
        _emit_rename_failure(
            ctx, f"no session named {name!r}",
            exit_code=ATTACH_EXIT_NOT_FOUND, as_json=as_json,
        )
        return None
    if len(matches) > 1:
        _emit_rename_failure(
            ctx, f"ambiguous session name {name!r}",
            exit_code=ATTACH_EXIT_AMBIGUOUS, as_json=as_json,
        )
        return None
    return matches[0]


def _rename_aplexer_path(
    ctx: click.Context, row: Any, *, as_json: bool
) -> Optional[str]:
    """Resolve the ``a`` binary and the record id, emitting failures."""
    resolution = _resolve_aplexer()
    if resolution.path is None:
        _emit_rename_failure(
            ctx,
            _aplexer_unresolved_message(
                resolution, action=f"cannot rename {row.name!r}"
            ),
            exit_code=ATTACH_EXIT_NO_BINARY,
            as_json=as_json,
        )
        return None
    if not row.aplexer_id:
        _emit_rename_failure(
            ctx,
            f"pocketshell: session {row.name!r} has no aplexer id and "
            "cannot be renamed.",
            exit_code=ATTACH_EXIT_NOT_FOUND,
            as_json=as_json,
        )
        return None
    return resolution.path


def _run_rename_command(
    ctx: click.Context, row: Any, aplexer_path: str, new_tag: str, *, as_json: bool
) -> Optional[Any]:
    """Run ``a --json rename <id> --tag <new_tag>``, mapping spawn failures."""
    try:
        return _run_session_command(
            [
                aplexer_path, "--json", "rename",
                str(row.aplexer_id), "--tag", new_tag,
            ]
        )
    except subprocess.TimeoutExpired:
        _emit_rename_failure(
            ctx, f"pocketshell: renaming {row.name!r} timed out.",
            exit_code=1, as_json=as_json,
        )
    except OSError as exc:
        _emit_rename_failure(
            ctx, f"pocketshell: could not rename {row.name!r}: {exc}",
            exit_code=ATTACH_EXIT_NO_BINARY, as_json=as_json,
        )
    return None


def _emit_nonzero_rename(
    ctx: click.Context, row: Any, completed: Any, *, as_json: bool
) -> bool:
    """Surface aplexer's own rejection verbatim — including aplexer#13's
    ``already belongs to session <uuid>`` for a claim held by a DEAD record:
    the message names a session the user cannot see, which is aplexer's gap
    to fix, not ours to retry or reap around (issue #9)."""
    if completed.returncode == 0:
        return False
    detail = str(completed.stderr or "").strip() or f"exit {completed.returncode}"
    _emit_rename_failure(
        ctx, f"pocketshell: could not rename {row.name!r}: {detail}",
        exit_code=completed.returncode, as_json=as_json,
    )
    return True


def _emit_rename_result(
    ctx: click.Context, row: Any, new_tag: str, *, renamed: bool, as_json: bool
) -> None:
    """Emit the schema-3 rename envelope; the row re-keys to its new name."""
    name = _session_enum.aplexer_display_name(
        {"workspace": row.workspace, "tag": new_tag}
    ) or new_tag
    if as_json:
        click.echo(
            json.dumps(
                {
                    "schema": RENAME_SCHEMA_VERSION,
                    "name": name,
                    "id": row.aplexer_id,
                    "renamed": renamed,
                    "tag": new_tag,
                },
                indent=2,
            )
        )
    ctx.exit()


@sessions_group.command(
    "rename", context_settings={"help_option_names": ["-h", "--help"]}
)
@click.argument("name")
@click.argument("new_tag")
@click.option(
    "--json", "as_json", is_flag=True, default=False,
    help="Emit the schema-3 rename envelope.",
)
@click.pass_context
def sessions_rename(
    ctx: click.Context, name: str, new_tag: str, as_json: bool
) -> None:
    """Rename a live aplexer session to NEW_TAG."""
    row = _resolve_rename_target(ctx, name, as_json=as_json)
    if row is None:
        return
    if (row.tag or "") == new_tag:
        # A no-op success, NOT an error: aplexer's own claim check would
        # reject the pair it already holds ("already belongs to session
        # <uuid>", aplexer#13), and a self-rename must not read as broken.
        if not as_json:
            click.echo(f"pocketshell: session {row.name!r} is already named {new_tag!r}.")
        _emit_rename_result(ctx, row, new_tag, renamed=False, as_json=as_json)
        return
    aplexer_path = _rename_aplexer_path(ctx, row, as_json=as_json)
    if aplexer_path is None:
        return
    completed = _run_rename_command(
        ctx, row, aplexer_path, new_tag, as_json=as_json
    )
    if completed is None:
        return
    if _emit_nonzero_rename(ctx, row, completed, as_json=as_json):
        return
    _emit_rename_result(ctx, row, new_tag, renamed=True, as_json=as_json)
