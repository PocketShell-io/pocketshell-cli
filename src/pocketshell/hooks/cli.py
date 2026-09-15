"""The `pocketshell hooks` click command group."""
from __future__ import annotations
import json
from typing import Optional
import click
# --- sibling modules ---
from pocketshell.hooks.installers import install_engines, uninstall_engines
from pocketshell.hooks.paths import ENGINES, resolve_paths
from pocketshell.hooks.status import _resolve_engines, engine_status, read_events


@click.group(
    name="hooks",
    context_settings={"help_option_names": ["-h", "--help"]},
    help=(
        "Install / uninstall agent stop-idle detection hooks and read the "
        "normalized event bus.\n\n"
        "``install`` merges our Stop/idle hooks into each engine's config "
        "without clobbering existing settings (Claude ``settings.json`` "
        "hooks, Codex ``notify`` program, OpenCode plugin). ``uninstall`` "
        "removes only our entries. ``status`` reports per-engine install "
        "state; ``events`` reads the JSONL bus. Integration only — no "
        "continue/stop action. See issue #267 and D26."
    ),
)
def hooks_group() -> None:
    """Top-level group registered onto the root `pocketshell` CLI."""


_ENGINE_OPTION = click.option(
    "--engine",
    type=click.Choice([*ENGINES, "all"]),
    default="all",
    show_default=True,
    help="Which engine to act on (default: all).",
)


@hooks_group.command("install")
@_ENGINE_OPTION
def hooks_install(engine: str) -> None:
    """Install stop/idle hooks (merge into existing config, never clobber)."""
    paths = resolve_paths()
    results = install_engines(_resolve_engines(engine), paths)
    for result in results:
        stream = "err" if result.status == "skipped" else "out"
        line = f"{result.engine}: {result.status} — {result.message}"
        click.echo(line, err=(stream == "err"))


@hooks_group.command("uninstall")
@_ENGINE_OPTION
def hooks_uninstall(engine: str) -> None:
    """Remove only the entries pocketshell installed (idempotent)."""
    paths = resolve_paths()
    results = uninstall_engines(_resolve_engines(engine), paths)
    for result in results:
        click.echo(f"{result.engine}: {result.status} — {result.message}")


@hooks_group.command("status")
@_ENGINE_OPTION
@click.option(
    "--json",
    "json_output",
    is_flag=True,
    help="Emit JSON instead of a human-readable summary.",
)
@click.option(
    "--last",
    "last",
    type=int,
    default=5,
    show_default=True,
    help="Include the last N bus events in the report.",
)
def hooks_status(engine: str, json_output: bool, last: int) -> None:
    """Report per-engine install state + the tail of the event bus."""
    paths = resolve_paths()
    engines = _resolve_engines(engine)
    statuses = [engine_status(eng, paths) for eng in engines]
    events = read_events(paths, limit=last)
    if json_output:
        payload = {
            "bus_path": str(paths.events_file),
            "engines": statuses,
            "recent_events": events,
        }
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
        return
    click.echo(f"bus: {paths.events_file}")
    for status in statuses:
        mark = "installed" if status["installed"] else "not installed"
        click.echo(f"  {status['engine']:<9} {mark}  ({status['config_path']})")
    if events:
        click.echo(f"recent events (last {len(events)}):")
        for event in events:
            click.echo(
                f"  {event.get('ts', '?')}  {event.get('engine', '?')}  "
                f"{event.get('state', '?')}"
            )


@hooks_group.command("events")
@click.option(
    "--json",
    "json_output",
    is_flag=True,
    help="Emit a JSON array of records instead of one JSON line per record.",
)
@click.option(
    "--since",
    "since",
    type=str,
    default=None,
    help="Only show records whose ts is strictly after this ISO-8601 value.",
)
@click.option(
    "--limit",
    "limit",
    type=int,
    default=None,
    help="Show only the last N records.",
)
def hooks_events(json_output: bool, since: Optional[str], limit: Optional[int]) -> None:
    """Read the normalized JSONL event bus."""
    paths = resolve_paths()
    records = read_events(paths, limit=limit, since=since)
    if json_output:
        click.echo(json.dumps(records, indent=2, sort_keys=True))
        return
    for record in records:
        click.echo(json.dumps(record, sort_keys=True))
