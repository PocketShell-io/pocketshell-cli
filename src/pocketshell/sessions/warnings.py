"""Ack-gated crash/OOM warnings surfaced from aplexer (issue #18).

aplexer keeps a durable warning when a session is OOM-killed, dies without
recording an exit, or finalizes with a fatal error. The warning shows in
every ``a`` listing and survives ``a prune`` until an explicit ``a ack`` —
this module mirrors both verbs for pocketshell users:

- ``pocketshell sessions warnings [--json]`` — the unacknowledged list
  (a pass-through of ``a --json warnings``, whose array shape is the
  machine contract; do not scrape human output).
- ``pocketshell sessions ack [SESSION] [--json]`` — acknowledge one warning
  by selector (``ws:tag``, UUID/prefix, or a tag in the current workspace)
  or, bare, everything — exactly ``a ack``'s semantics.

The sessions ``list`` banner renders the same facts for humans; the schema-3
``list --json`` document is untouched. The standalone ``warnings`` command
fails loud on a broken probe (a silent "no warnings" could hide a crash),
while the ``list`` banner degrades quietly — a listing must not fail over
warnings it cannot fetch (an aplexer build without the subcommand, kill
switches, an unresolved binary).
"""
from __future__ import annotations

import json
import os
import time
from typing import Any, Optional

import click
from pocketshell.runtime.aplexer import AplexerFailure, run_json_reported
# --- sibling modules ---
from pocketshell.sessions.cli import sessions_group

WARNINGS_SCHEMA_VERSION = 1


def fetch_warnings_reported(
    *,
    env: Optional[dict[str, str]] = None,
) -> tuple[Optional[list[dict[str, Any]]], Optional[AplexerFailure]]:
    """``a --json warnings`` as ``(rows, failure)`` — exactly one is ``None``."""
    payload, failure = run_json_reported(["warnings"], env=env, feature="sessions")
    if failure is not None:
        return None, failure
    if not isinstance(payload, list):
        return None, AplexerFailure("decode", "warnings reply was not a list")
    return [row for row in payload if isinstance(row, dict)], None


def fetch_warnings() -> Optional[list[dict[str, Any]]]:
    """The unacknowledged warnings, or ``None`` when the probe failed."""
    return fetch_warnings_reported()[0]


def ack_warnings(
    selector: Optional[str] = None,
    *,
    env: Optional[dict[str, str]] = None,
) -> tuple[Optional[list[dict[str, Any]]], Optional[AplexerFailure]]:
    """``a --json ack [SELECTOR]``; bare acknowledges every warning."""
    args = ["ack"] + ([selector] if selector else [])
    payload, failure = run_json_reported(args, env=env, feature="sessions")
    if failure is not None:
        return None, failure
    if not isinstance(payload, dict) or not isinstance(payload.get("acknowledged"), list):
        return None, AplexerFailure("decode", "ack reply lacked an `acknowledged` list")
    return [row for row in payload["acknowledged"] if isinstance(row, dict)], None


def human_age_phrase(created_at_ms: int, *, now_ms: Optional[int] = None) -> str:
    """Compact age for one warning, matching ``a list``'s banner phrasing."""
    now = int(time.time() * 1000) if now_ms is None else now_ms
    seconds = max(0, (now - int(created_at_ms)) // 1000)
    if seconds < 60:
        return "just now"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m ago"
    hours = minutes // 60
    if hours < 24:
        return f"{hours}h ago"
    return f"{hours // 24}d ago"


def _display_selector(warning: dict[str, Any]) -> str:
    """``workspace:tag`` for humans, with ``$HOME`` shortened to ``~``."""
    workspace = os.path.expanduser(str(warning.get("workspace") or ""))
    home = os.path.expanduser("~")
    if workspace.startswith(home + os.sep):
        workspace = "~" + workspace[len(home):]
    return f"{workspace}:{warning.get('tag') or ''}"


def format_warnings_banner(warnings: list[dict[str, Any]]) -> str:
    """The human banner: one line per warning, newest first (aplexer's order)."""
    if not warnings:
        return ""
    plural = "warning" if len(warnings) == 1 else "warnings"
    lines = [
        f"⚠ {len(warnings)} unacknowledged crash {plural} "
        "(cleared by `pocketshell sessions ack`):"
    ]
    for warning in warnings:
        kind = "oom" if warning.get("kind") == "oom" else "crashed"
        detail = str(warning.get("detail") or "")
        age = human_age_phrase(int(warning.get("created_at_ms") or 0))
        lines.append(f"  ⚠ {kind} {_display_selector(warning)} — {detail} · {age}")
    return "\n".join(lines) + "\n"


@sessions_group.command("warnings", context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    default=False,
    help="Emit aplexer's warning array unchanged (the machine contract).",
)
@click.pass_context
def sessions_warnings(ctx: click.Context, as_json: bool) -> None:
    """List unacknowledged crash/OOM warnings from aplexer."""
    warnings, failure = fetch_warnings_reported()
    if failure is not None:
        click.echo(f"pocketshell: could not list crash warnings: {failure}", err=True)
        ctx.exit(1)
        return
    if as_json:
        click.echo(json.dumps(warnings, indent=2))
        return
    if not warnings:
        click.echo("no unacknowledged warnings")
        return
    click.echo(format_warnings_banner(warnings), nl=False)
    click.echo()
    click.echo(
        "Acknowledge: pocketshell sessions ack (everything) · "
        "pocketshell sessions ack SESSION (one)"
    )


@sessions_group.command("ack", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("selector", required=False)
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    default=False,
    help="Emit the warnings ack envelope.",
)
@click.pass_context
def sessions_ack(ctx: click.Context, selector: Optional[str], as_json: bool) -> None:
    """Acknowledge crash warnings: SELECTOR, or everything when omitted."""
    acknowledged, failure = ack_warnings(selector)
    if failure is not None:
        if as_json:
            click.echo(
                json.dumps(
                    {"schema": WARNINGS_SCHEMA_VERSION, "error": str(failure)},
                    indent=2,
                )
            )
        else:
            click.echo(f"pocketshell: could not acknowledge crash warnings: {failure}", err=True)
        ctx.exit(1)
        return
    if as_json:
        click.echo(
            json.dumps(
                {"schema": WARNINGS_SCHEMA_VERSION, "acknowledged": acknowledged},
                indent=2,
            )
        )
        return
    if not acknowledged:
        click.echo(
            "no warnings to acknowledge"
            if selector is None
            else "no matching unacknowledged warning"
        )
        return
    for warning in acknowledged:
        click.echo(
            f"acknowledged {_display_selector(warning)} ({warning.get('kind')}) — "
            f"{warning.get('detail')}"
        )
    click.echo(f"acknowledged {len(acknowledged)} warning(s)")
