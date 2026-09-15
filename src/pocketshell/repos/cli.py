"""The ``pocketshell repos`` Click command group."""
from __future__ import annotations
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Optional, Sequence
import click
# --- sibling modules ---
from pocketshell.repos.handlers import _try_daemon_list_local, _try_daemon_list_remote
from pocketshell.repos.local import DEFAULT_MAX_DEPTH, DEFAULT_ROOT_PATHS, clone_repo, find_local_repo, resolve_scan_roots, scan_roots
from pocketshell.repos.model import _to_jsonable, normalize_full_name
from pocketshell.repos.remote import GhCommandError, GhMissingError, fetch_remote_repos
from pocketshell.repos.render import _emit_repo_payload, _format_human_local, _format_human_remote


@click.group(
    name="repos",
    context_settings={"help_option_names": ["-h", "--help"]},
    help=(
        "Discover and operate on git repositories.\n\n"
        "``list --local`` enumerates cloned repos under the configured "
        "scan roots (default ``~/git``). ``list --remote`` delegates to "
        "``gh api user/repos --paginate --slurp`` to enumerate the authenticated "
        "user's GitHub repositories. The JSON shape is unified across "
        "both modes; see ``pocketshell.repos`` module docstring."
    ),
)
def repos_group() -> None:
    """Top-level group registered onto the root `pocketshell` CLI."""


def _validate_list_flags(
    ctx: click.Context,
    local_only: bool,
    remote_only: bool,
) -> bool:
    """Reject conflicting modes; default to ``--local`` with a hint.

    Returns the (possibly defaulted) ``local_only`` value.
    """
    if local_only and remote_only:
        click.echo(
            "pocketshell repos list: --local and --remote are mutually exclusive.",
            err=True,
        )
        ctx.exit(2)
    if not local_only and not remote_only:
        click.echo(
            "pocketshell repos list: defaulting to --local. "
            "Pass --remote to enumerate GitHub repositories instead.",
            err=True,
        )
        return True
    return local_only


def _inprocess_local_payload(
    scan_root_paths: Sequence[Path],
    max_depth: int,
) -> list[dict[str, Any]]:
    """Run the in-process scan, echoing collected warnings to stderr."""
    warnings: list[str] = []

    def _capture_warning(message: str) -> None:
        warnings.append(message)

    repos = scan_roots(
        scan_root_paths,
        max_depth=max_depth,
        warn_fn=_capture_warning,
    )
    for message in warnings:
        click.echo(message, err=True)
    return _to_jsonable(repos)


def _reject_negative_depth(ctx: click.Context, command: str, max_depth: int) -> None:
    """Exit 2 when ``--max-depth`` is negative (shared by the list command)."""
    if max_depth >= 0:
        return
    click.echo(
        f"pocketshell repos {command}: --max-depth must be >= 0 (got {max_depth})",
        err=True,
    )
    ctx.exit(2)


def _run_local(
    ctx: click.Context,
    *,
    json_output: bool,
    roots: tuple[str, ...],
    max_depth: int,
    no_daemon: bool,
    no_cache: bool,
) -> None:
    """Body of ``repos list --local``; pulled out for readability."""
    _reject_negative_depth(ctx, "list", max_depth)
    scan_root_paths = resolve_scan_roots(roots)

    # Daemon path is JSON-only; the human-readable rendering happens
    # client-side off the JSON payload so the daemon does not need to
    # learn two output formats.
    payload: Optional[list[dict[str, Any]]] = None
    if not no_daemon:
        payload = _try_daemon_list_local(
            roots=scan_root_paths,
            max_depth=max_depth,
            no_cache=no_cache,
        )
    if payload is None:
        payload = _inprocess_local_payload(scan_root_paths, max_depth)

    _emit_repo_payload(json_output, payload, formatter=_format_human_local)


def _remote_fallback_payload(ctx: click.Context, *, limit: Optional[int]) -> list[dict[str, Any]]:
    """Fetch remote repos in-process, mapping gh failures to CLI exits."""
    try:
        repos = fetch_remote_repos(limit=limit)
    except GhMissingError as exc:
        click.echo(str(exc), err=True)
        ctx.exit(127)
    except GhCommandError as exc:
        if exc.stderr:
            # Preserve trailing newline behaviour of subprocess capture.
            sys.stderr.write(exc.stderr)
            if not exc.stderr.endswith("\n"):
                sys.stderr.write("\n")
        ctx.exit(exc.returncode)
    return _to_jsonable(repos)


def _run_remote(
    ctx: click.Context,
    *,
    json_output: bool,
    limit: Optional[int],
    no_daemon: bool,
    no_cache: bool,
) -> None:
    """Body of ``repos list --remote``; pulled out for readability."""
    payload: Optional[list[dict[str, Any]]] = None
    if not no_daemon:
        payload = _try_daemon_list_remote(limit=limit, no_cache=no_cache)
    if payload is None:
        payload = _remote_fallback_payload(ctx, limit=limit)

    _emit_repo_payload(json_output, payload, formatter=_format_human_remote)


@repos_group.command(
    "list",
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.option(
    "--local",
    "local_only",
    is_flag=True,
    help=(
        "Scan the local filesystem for cloned git repos under the "
        "configured roots. Default behaviour when neither ``--local`` "
        "nor ``--remote`` is passed."
    ),
)
@click.option(
    "--remote",
    "remote_only",
    is_flag=True,
    help=(
        "Enumerate the authenticated user's GitHub repositories via "
        "``gh api user/repos --paginate --slurp``. Requires `gh` on PATH and a "
        "successful prior `gh auth login -s repo:read`."
    ),
)
@click.option(
    "--json",
    "json_output",
    is_flag=True,
    help="Emit a JSON array (one object per repo) instead of a human table.",
)
@click.option(
    "--root",
    "roots",
    multiple=True,
    type=str,
    help=(
        "Scan root directory (may be repeated). When passed, replaces "
        "(does NOT augment) the default ``~/git`` and the "
        "``POCKETSHELL_REPOS_ROOTS`` env var. Only meaningful with "
        "``--local``."
    ),
)
@click.option(
    "--max-depth",
    type=int,
    default=DEFAULT_MAX_DEPTH,
    show_default=True,
    help=(
        "Maximum directory depth (relative to each scan root) to descend "
        "while looking for a ``.git`` entry. Only meaningful with ``--local``."
    ),
)
@click.option(
    "--limit",
    type=int,
    default=None,
    help=(
        "Cap the number of remote repositories returned. Only "
        "meaningful with ``--remote``."
    ),
)
@click.option(
    "--no-daemon",
    "no_daemon",
    is_flag=True,
    help=(
        "Skip the IPC daemon and run the in-process scan even if a "
        "daemon is available. Useful for debugging."
    ),
)
@click.option(
    "--no-cache",
    "no_cache",
    is_flag=True,
    help=(
        "Bypass the daemon's per-method cache (10 s for ``repos.list_local``, "
        "5 min for ``repos.list_remote``). No effect on the in-process path, "
        "which always runs fresh."
    ),
)
@click.pass_context
def repos_list(
    ctx: click.Context,
    local_only: bool,
    remote_only: bool,
    json_output: bool,
    roots: tuple[str, ...],
    max_depth: int,
    limit: Optional[int],
    no_daemon: bool,
    no_cache: bool,
) -> None:
    """List repositories on this host (``--local``) or GitHub (``--remote``).

    Defaults to ``--local`` with a discoverability hint for ``--remote``.
    """
    local_only = _validate_list_flags(ctx, local_only, remote_only)
    if remote_only:
        _run_remote(
            ctx, json_output=json_output, limit=limit,
            no_daemon=no_daemon, no_cache=no_cache,
        )
        return
    _run_local(
        ctx, json_output=json_output, roots=roots, max_depth=max_depth,
        no_daemon=no_daemon, no_cache=no_cache,
    )


@repos_group.command(
    "open",
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.argument("repository")
@click.option(
    "--root",
    "roots",
    multiple=True,
    type=str,
    help=(
        "Scan root directory (may be repeated). When passed, replaces "
        "the default ``~/git`` and ``POCKETSHELL_REPOS_ROOTS``."
    ),
)
@click.option(
    "--max-depth",
    type=int,
    default=DEFAULT_MAX_DEPTH,
    show_default=True,
    help="Maximum directory depth to scan while locating the clone.",
)
def repos_open(repository: str, roots: tuple[str, ...], max_depth: int) -> None:
    """Print the local path for a cloned GitHub ``owner/repo``."""
    if max_depth < 0:
        click.echo(
            f"pocketshell repos open: --max-depth must be >= 0 (got {max_depth})",
            err=True,
        )
        raise click.exceptions.Exit(2)
    try:
        normalize_full_name(repository)
    except ValueError as exc:
        click.echo(f"pocketshell repos open: {exc}", err=True)
        raise click.exceptions.Exit(2)
    repo = find_local_repo(
        repository,
        roots=resolve_scan_roots(roots),
        max_depth=max_depth,
    )
    if repo is None or repo.local is None:
        click.echo(f"pocketshell repos open: repository is not cloned: {repository}", err=True)
        raise click.exceptions.Exit(1)
    click.echo(repo.local.path)


@repos_group.command(
    "clone",
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.argument("repository")
@click.option(
    "--root",
    type=str,
    default=DEFAULT_ROOT_PATHS[0],
    show_default=True,
    help="Clone root directory.",
)
@click.option(
    "--folder",
    "folder_name",
    type=str,
    default=None,
    help="Optional target folder name under the clone root.",
)
@click.option(
    "--protocol",
    type=click.Choice(["ssh", "https"]),
    default="ssh",
    show_default=True,
    help="GitHub clone URL protocol.",
)
def repos_clone(
    repository: str,
    root: str,
    folder_name: Optional[str],
    protocol: str,
) -> None:
    """Clone a GitHub ``owner/repo`` and print the target path."""
    try:
        target = clone_repo(
            repository,
            root=Path(os.path.expanduser(root)),
            folder_name=folder_name,
            protocol=protocol,
        )
    except ValueError as exc:
        click.echo(f"pocketshell repos clone: {exc}", err=True)
        raise click.exceptions.Exit(2)
    except FileExistsError as exc:
        click.echo(f"pocketshell repos clone: {exc}", err=True)
        raise click.exceptions.Exit(1)
    except FileNotFoundError:
        click.echo("pocketshell repos clone: `git` is not installed on this host.", err=True)
        raise click.exceptions.Exit(127)
    except subprocess.CalledProcessError as exc:
        raise click.exceptions.Exit(exc.returncode)
    click.echo(str(target))
