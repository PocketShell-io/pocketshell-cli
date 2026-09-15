"""The `pocketshell logs` click command group."""
from __future__ import annotations
import json
import sys
from datetime import datetime, timezone
from typing import Optional
import click
# --- sibling modules ---
from pocketshell.logs.events import ingest_event, read_records
from pocketshell.logs.hooks import import_hooks
from pocketshell.logs.paths import resolve_paths


_KIND_OPTION = click.option(
    "--kind",
    "family",
    type=click.Choice(["agent", "app"]),
    default="agent",
    show_default=True,
    help="Which log family to act on (agent = action/engine events; app = app_log/crash).",
)


@click.group(
    name="logs",
    context_settings={"help_option_names": ["-h", "--help"]},
    help=(
        "Canonical server-side sink for assistant action traces, app/crash "
        "logs, and coding-agent engine events.\n\n"
        "`ingest` reads ONE JSON event from stdin, aggressively redacts "
        "secrets, stamps `ts`, and appends to a dated JSONL under "
        "`$XDG_STATE_HOME/pocketshell/logs` (0600). `tail` and `path` let "
        "the orchestrator read/grep the record directly. `import-hooks` "
        "mirrors the #267 hooks bus in as `engine_event`s (idempotent). "
        "Tier 1: single canonical host, no cloud. See D27 in "
        "docs/decisions.md."
    ),
)
def logs_group() -> None:
    """Top-level group registered onto the root `pocketshell` CLI."""


@logs_group.command(
    "ingest",
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.option(
    "--json",
    "json_output",
    is_flag=True,
    help="Echo the normalized (redacted) record that was written.",
)
@click.pass_context
def logs_ingest(ctx: click.Context, json_output: bool) -> None:
    """Append ONE JSON event (read from stdin) to the canonical log.

    The event is normalized (schema/ts stamped, kind/source defaulted)
    and aggressively redacted before any byte hits disk: secret-named
    keys, token-shaped strings, and inline `KEY=value` secret
    assignments never persist. Secret values are NEVER echoed even with
    `--json` (the echoed record is the redacted one).
    """
    raw = sys.stdin.read()
    if not raw.strip():
        click.echo("pocketshell logs ingest: no JSON on stdin", err=True)
        ctx.exit(2)
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        click.echo(f"pocketshell logs ingest: invalid JSON on stdin: {exc}", err=True)
        ctx.exit(2)
    if not isinstance(payload, dict):
        click.echo("pocketshell logs ingest: stdin JSON must be an object", err=True)
        ctx.exit(2)
    paths = resolve_paths()
    record = ingest_event(paths, payload)
    if json_output:
        click.echo(json.dumps(record, sort_keys=True))


@logs_group.command(
    "tail",
    context_settings={"help_option_names": ["-h", "--help"]},
)
@_KIND_OPTION
@click.option(
    "-n",
    "--lines",
    "count",
    type=int,
    default=20,
    show_default=True,
    help="Number of most-recent records to print.",
)
@click.option(
    "--json",
    "json_output",
    is_flag=True,
    help="Emit a JSON array of records instead of one JSON line per record.",
)
def logs_tail(family: str, count: int, json_output: bool) -> None:
    """Print the most-recent records for a log family."""
    paths = resolve_paths()
    records = read_records(paths, family, limit=count)
    if json_output:
        click.echo(json.dumps(records, indent=2, sort_keys=True))
        return
    for record in records:
        click.echo(json.dumps(record, sort_keys=True))


@logs_group.command(
    "path",
    context_settings={"help_option_names": ["-h", "--help"]},
)
@_KIND_OPTION
def logs_path(family: str) -> None:
    """Print today's log file path for a family so it can be grepped.

    Prints the dated path for the current UTC day. The directory and
    file may not yet exist (nothing has been ingested today); the path
    is still where today's records would land.
    """
    paths = resolve_paths()
    day = datetime.now(timezone.utc).strftime("%Y%m%d")
    if family == "app":
        click.echo(str(paths.app_file(day)))
    else:
        click.echo(str(paths.agent_file(day)))


@logs_group.command(
    "import-hooks",
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.option(
    "--target-host",
    "target_host",
    type=str,
    default=None,
    help="Canonical host name to stamp on each forwarded engine event.",
)
def logs_import_hooks(target_host: Optional[str]) -> None:
    """Mirror new #267 hooks-bus events into the canonical log.

    Forwards every new coding-agent stop/idle/waiting event as
    `kind=engine_event`. Idempotent via a byte cursor: re-running with
    no new bus activity forwards nothing (no duplicates).
    """
    paths = resolve_paths()
    forwarded = import_hooks(paths, target_host=target_host)
    click.echo(f"forwarded {forwarded} engine event(s)")
