"""The `pocketshell prune-attachments` Click command and its rendering."""

from __future__ import annotations

import json
from pathlib import Path

import click

from pocketshell.attachments.prune import (
    DEFAULT_MAX_TOTAL_BYTES,
    DEFAULT_TTL_DAYS,
    PROTECT_NEWEST_HOURS,
    PruneResult,
    prune_attachments,
    resolve_attachments_root,
)


@click.command(
    name="prune-attachments",
    context_settings={"help_option_names": ["-h", "--help"]},
    help=(
        "Prune the ~/.pocketshell/attachments/ tree on this host.\n\n"
        "Server-side retention backstop for prompt attachments uploaded by "
        "the PocketShell composer (issue #547). Deletes regular files older "
        "than the TTL, then trims the oldest survivors if the tree still "
        "exceeds the size cap. Only touches files inside the attachments "
        "directory; never the user's own files. Best-effort: per-file "
        "errors are reported, not raised."
    ),
)
@click.option(
    "--ttl-days",
    type=click.IntRange(min=0),
    default=DEFAULT_TTL_DAYS,
    show_default=True,
    help="Delete attachments strictly older than this many days.",
)
@click.option(
    "--max-total-mib",
    type=click.IntRange(min=0),
    default=DEFAULT_MAX_TOTAL_BYTES // (1024 * 1024),
    show_default=True,
    help=(
        "After the TTL pass, trim oldest survivors until the tree is under "
        "this size (MiB). Files younger than the protect window are spared."
    ),
)
@click.option(
    "--protect-newest-hours",
    type=click.IntRange(min=0),
    default=PROTECT_NEWEST_HOURS,
    show_default=True,
    help="Never let the size cap delete files younger than this.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Report what would be deleted without deleting anything.",
)
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Emit the prune summary as JSON.",
)
def prune_attachments_command(
    ttl_days: int,
    max_total_mib: int,
    protect_newest_hours: int,
    dry_run: bool,
    as_json: bool,
) -> None:
    """CLI entrypoint for ``pocketshell prune-attachments``."""
    root = _resolved_prune_root()
    result = _run_prune(
        root,
        ttl_days=ttl_days,
        max_total_mib=max_total_mib,
        protect_newest_hours=protect_newest_hours,
        dry_run=dry_run,
    )
    _emit_prune_result(root, result, dry_run=dry_run, as_json=as_json)


def _resolved_prune_root() -> Path:
    """Resolve the attachments root, refusing anything outside ``$HOME``.

    Belt-and-braces containment check against a tampered ``$HOME``.
    Raises :class:`click.ClickException` otherwise.
    """
    home = Path.home().resolve()
    root = resolve_attachments_root(home)
    if not _is_within(root, home):
        raise click.ClickException(
            f"refusing to prune {root}: not inside $HOME ({home})"
        )
    return root


def _run_prune(
    root: Path,
    *,
    ttl_days: int,
    max_total_mib: int,
    protect_newest_hours: int,
    dry_run: bool,
) -> PruneResult:
    """Run one prune pass with CLI-shaped arguments."""
    import time

    return prune_attachments(
        root,
        now=time.time(),
        ttl_days=ttl_days,
        max_total_bytes=max_total_mib * 1024 * 1024,
        protect_newest_hours=protect_newest_hours,
        dry_run=dry_run,
    )


def _emit_prune_result(root: Path, result: PruneResult, *, dry_run: bool, as_json: bool) -> None:
    """Render the prune summary as JSON or as human text."""
    if as_json:
        click.echo(json.dumps(result.to_dict(), indent=2))
        return

    if result.skipped_root_missing:
        click.echo(f"no attachments directory at {root}; nothing to prune.")
        return

    verb = "would delete" if dry_run else "deleted"
    mib = result.deleted_bytes / (1024 * 1024)
    click.echo(
        f"scanned {result.scanned_files} files "
        f"({result.scanned_bytes / (1024 * 1024):.1f} MiB); "
        f"{verb} {result.deleted_count} ({mib:.1f} MiB)."
    )
    for d in result.deleted:
        click.echo(f"  {verb}: {d.path} ({d.reason}, {d.age_days:.1f}d)")
    for err in result.errors:
        click.echo(f"  error: {err}", err=True)


def _is_within(path: Path, parent: Path) -> bool:
    """True when ``path`` is ``parent`` or a descendant of it."""
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False
