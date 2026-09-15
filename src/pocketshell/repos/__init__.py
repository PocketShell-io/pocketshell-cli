"""`pocketshell repos` subcommand group.

GitHub-aware project navigation. Two scan modes share a unified output
schema so the Android picker (PR-B follow-up) can render local clones,
remote repositories from the user's GitHub account, and the union of
the two from one JSON shape.

Subcommands
-----------

- ``pocketshell repos list --local`` — scan one or more roots on disk
  for cloned git repositories. Best-effort: missing roots warn to
  stderr, unreadable repos produce ``None`` metadata rather than
  aborting the scan.
- ``pocketshell repos list --remote`` — delegate to
  ``gh api user/repos --paginate --slurp`` (subprocess; same pattern as
  ``pocketshell usage`` delegating to ``quse``). Phone holds zero
  GitHub credentials — locked as D23.
- ``pocketshell repos list`` (no flag) — defaults to ``--local`` and
  prints a one-line hint to stderr mentioning ``--remote``. Rationale:
  the existing behaviour was ``--local``; mixing two scan modes (one
  filesystem + one network) implicitly under one command is surprising
  for scripts that pipe the output. Keeping the existing default
  preserves muscle memory; ``--remote`` is opt-in.
- ``pocketshell repos open <owner/repo>`` — print the local clone path
  for a known GitHub repository.
- ``pocketshell repos clone <owner/repo>`` — clone a GitHub repository
  into a configured root and print the resulting path.

Unified output schema (D22 hard cut)
------------------------------------

Every entry — whether produced by the local scan, the remote scan, or
the eventual merged-view command — uses one shape:

.. code-block:: json

    {
      "owner": "alexeygrigorev" | null,
      "name": "pocketshell",
      "full_name": "alexeygrigorev/pocketshell" | null,
      "local": {"path": "/home/...", "head": "main"} | null,
      "remote": {
        "default_branch": "main",
        "html_url": "https://github.com/...",
        "ssh_url": "git@github.com:...",
        "updated_at": "2026-05-27T12:00:00Z"
      } | null
    }

The previous ``{name, path, remote, head}`` shape is gone. No
compatibility shim, no version flag — per D22 in
``docs/decisions.md``. The Android consumer for ``repos list`` has
not yet shipped (no Kotlin parser exists in ``app/`` / ``shared/``),
so the schema swap is purely server-side.

Local-scan owner/name/full_name population
------------------------------------------

For a local clone we populate ``owner``/``full_name`` by parsing the
remote URL stored at ``remote.origin.url``. Supported forms:

- SSH: ``git@github.com:<owner>/<repo>[.git]``
- HTTPS: ``https://github.com/<owner>/<repo>[.git]``

Non-GitHub remotes (gitlab.com, gitea, internal hosts) currently leave
``owner``/``full_name`` as ``None``; ``name`` falls back to the
directory basename so identity stays stable.

Daemon integration
------------------

The daemon (``pocketshell.daemon``) gets two RPC methods:

- ``repos.list_local`` — 10 s TTL, same as the original PR.
- ``repos.list_remote`` — 5 min TTL. Remote repos change rarely; the
  GH API has tight rate limits (5000/hour for authenticated calls), so
  a longer cache window keeps the Android picker responsive without
  burning quota.

Both subcommands honour ``--no-daemon`` (skip the daemon entirely) and
``--no-cache`` (force the daemon to re-run upstream). On the
in-process path ``--no-cache`` is a no-op because there is no cache. The
shared daemon boundary falls back only for an absent/unavailable daemon or an
explicitly supported method skew; timeout and daemon-internal failures are
surfaced rather than retried locally.
"""
from __future__ import annotations

from pocketshell.repos.cli import (
    repos_group,
)
from pocketshell.repos.handlers import (
    daemon_handler_local,
    daemon_handler_remote,
    daemon_handler_clone,
    daemon_handler_open,
    DAEMON_CACHE_TTL_SECS,
    DAEMON_REMOTE_CACHE_TTL_SECS,
    CLONE_ERROR_INVALID_REPOSITORY,
    CLONE_ERROR_TARGET_EXISTS,
    CLONE_ERROR_GIT_MISSING,
    CLONE_ERROR_FAILED,
    OPEN_ERROR_INVALID_REPOSITORY,
    OPEN_ERROR_NOT_CLONED,
)
from pocketshell.repos.local import (
    find_local_repo,
    clone_repo,
    resolve_scan_roots,
    scan_roots,
    DEFAULT_ROOT_PATHS,
    DEFAULT_MAX_DEPTH,
)
from pocketshell.repos.model import (
    LocalInfo,
    RemoteInfo,
    Repo,
    parse_github_remote,
    normalize_full_name,
    github_clone_url,
    safe_clone_target,
)
from pocketshell.repos.remote import (
    fetch_remote_repos,
    GhMissingError,
    GhCommandError,
    GhUnauthenticatedError,
    GH_ERROR_MISSING,
    GH_ERROR_UNAUTHENTICATED,
    GH_ERROR_OTHER,
)

__all__ = [
    "LocalInfo",
    "RemoteInfo",
    "Repo",
    "parse_github_remote",
    "normalize_full_name",
    "github_clone_url",
    "safe_clone_target",
    "find_local_repo",
    "clone_repo",
    "resolve_scan_roots",
    "scan_roots",
    "fetch_remote_repos",
    "GhMissingError",
    "GhCommandError",
    "GhUnauthenticatedError",
    "GH_ERROR_MISSING",
    "GH_ERROR_UNAUTHENTICATED",
    "GH_ERROR_OTHER",
    "daemon_handler_local",
    "daemon_handler_remote",
    "daemon_handler_clone",
    "daemon_handler_open",
    "repos_group",
    "DEFAULT_ROOT_PATHS",
    "DEFAULT_MAX_DEPTH",
    "DAEMON_CACHE_TTL_SECS",
    "DAEMON_REMOTE_CACHE_TTL_SECS",
    "CLONE_ERROR_INVALID_REPOSITORY",
    "CLONE_ERROR_TARGET_EXISTS",
    "CLONE_ERROR_GIT_MISSING",
    "CLONE_ERROR_FAILED",
    "OPEN_ERROR_INVALID_REPOSITORY",
    "OPEN_ERROR_NOT_CLONED",
]
