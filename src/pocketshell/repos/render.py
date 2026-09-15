"""Human-readable table rendering for the `repos list` output.

The Android side does NOT parse the human output — the JSON path is the
contract — so these renderers optimise purely for terminal readability.
Both render aligned three-column tables and render empty input to an empty
string (no header) so piping through ``wc -l`` reports 0 for the no-repos
case.
"""

from __future__ import annotations

import json
import sys
from typing import Any, Callable, Sequence

import click

from pocketshell.repos.model import Repo, _repo_from_jsonable


def _format_human_local(repos: Sequence[Repo]) -> str:
    """Render local-scan ``repos`` as an aligned three-column table.

    Columns: ``name``, ``local.path``, ``full_name`` (``-`` when the
    remote URL was not parseable).
    """
    if not repos:
        return ""
    name_w = max(len(r.name) for r in repos)
    path_w = max(len(r.local.path) if r.local else 0 for r in repos)
    lines: list[str] = []
    for repo in repos:
        path = repo.local.path if repo.local else "-"
        full = repo.full_name or "-"
        lines.append(f"{repo.name:<{name_w}}  {path:<{path_w}}  {full}")
    return "\n".join(lines) + "\n"


def _format_human_remote(repos: Sequence[Repo]) -> str:
    """Render remote-scan ``repos`` as an aligned three-column table.

    Columns: ``full_name``, ``default_branch`` (``-`` if absent),
    ``updated_at`` (``-`` if absent). Same empty-output policy as the
    local renderer.
    """
    if not repos:
        return ""
    full_w = max(len(r.full_name or r.name) for r in repos)
    branch_w = max(
        len((r.remote.default_branch if r.remote else None) or "-") for r in repos
    )
    lines: list[str] = []
    for repo in repos:
        full = repo.full_name or repo.name
        branch = (repo.remote.default_branch if repo.remote else None) or "-"
        updated = (repo.remote.updated_at if repo.remote else None) or "-"
        lines.append(f"{full:<{full_w}}  {branch:<{branch_w}}  {updated}")
    return "\n".join(lines) + "\n"


def _emit_repo_payload(
    json_output: bool,
    payload: list[dict[str, Any]],
    *,
    formatter: Callable[[Sequence[Repo]], str],
) -> None:
    """Emit a repos payload as JSON or as a human table via ``formatter``.

    The human path re-hydrates :class:`Repo` objects from the JSON
    dicts so the daemon and in-process paths share one formatter.
    """
    if json_output:
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
        return
    repos = [_repo_from_jsonable(entry) for entry in payload]
    rendered = formatter(repos)
    if rendered:
        sys.stdout.write(rendered)
