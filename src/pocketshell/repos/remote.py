"""Remote repository listing via the ``gh`` CLI."""
from __future__ import annotations
import json
import shutil
import subprocess
from typing import Any, Optional
# --- sibling modules ---
from pocketshell.repos.model import RemoteInfo, Repo, _str_or_none


# Default page size for the GH API call. 100 is the GitHub-side
# maximum; smaller values just multiply the round-trips ``--paginate``
# takes to walk the full account.
GH_API_PER_PAGE = 100


def _resolve_gh_binary() -> Optional[str]:
    """Locate the ``gh`` CLI on PATH, or return ``None`` if absent.

    Pulled out as a function so the unit suite can monkeypatch it.
    """
    return shutil.which("gh")


def _gh_missing_message() -> str:
    """Friendly install hint shown when ``gh`` is not on PATH."""
    return (
        "pocketshell: `gh` is not installed on this host. "
        "Install it (`apt install gh` on Debian/Ubuntu, "
        "`brew install gh` on macOS) and authenticate with "
        "`gh auth login -s repo:read` before re-running."
    )


# Machine-readable error tokens carried on the gh-failure exceptions so
# the daemon (and, downstream, the Android bootstrap UI in #230) can
# branch on a stable string rather than re-parsing stderr. Kept here as
# constants so the daemon handler, the CLI, and the test suite agree on
# the exact spelling.
GH_ERROR_MISSING = "gh_missing"


GH_ERROR_UNAUTHENTICATED = "gh_unauthenticated"


GH_ERROR_OTHER = "gh_error"


# Substrings that mark a ``gh`` non-zero exit as an *authentication*
# failure rather than a generic error (rate limit, network, server 5xx).
# ``gh`` prints variations of these to stderr when no valid token is
# configured. Matched case-insensitively. Kept deliberately broad: the
# remediation for any of them is identical (``gh auth login``), so a
# false positive here only changes which bootstrap affordance the client
# shows, never whether the call can succeed.
_GH_AUTH_FAILURE_MARKERS: tuple[str, ...] = (
    "gh auth login",
    "not logged in",
    "no logged-in",
    "authentication required",
    "requires authentication",
    "must authenticate",
    "bad credentials",
    "401",
)


class GhMissingError(RuntimeError):
    """Raised when ``gh`` cannot be located on PATH.

    Carries :attr:`error_code` == :data:`GH_ERROR_MISSING` so callers can
    branch on a machine-readable token rather than the message text.
    """

    error_code = GH_ERROR_MISSING


class GhCommandError(RuntimeError):
    """Raised when ``gh`` exits non-zero. Carries returncode + stderr.

    The generic-failure case (rate limit, network, server error). The
    authentication-specific subclass :class:`GhUnauthenticatedError`
    carries a distinct :attr:`error_code` so the client can offer a
    ``gh auth login`` affordance instead of a generic retry.
    """

    error_code = GH_ERROR_OTHER

    def __init__(self, returncode: int, stderr: str) -> None:
        super().__init__(f"gh exited {returncode}: {stderr.strip()}")
        self.returncode = returncode
        self.stderr = stderr


class GhUnauthenticatedError(GhCommandError):
    """Raised when ``gh`` is installed but has no valid GitHub login.

    A subclass of :class:`GhCommandError` so existing ``except
    GhCommandError`` handlers keep catching it, but it carries a distinct
    :attr:`error_code` (:data:`GH_ERROR_UNAUTHENTICATED`) so the daemon
    and Android client can show "run ``gh auth login``" instead of a
    generic error banner.
    """

    error_code = GH_ERROR_UNAUTHENTICATED


def _is_gh_auth_failure(stderr: str) -> bool:
    """Return True when ``gh`` stderr indicates an authentication failure.

    Inspects ``stderr`` for any of :data:`_GH_AUTH_FAILURE_MARKERS`
    (case-insensitive). Used to split a generic non-zero ``gh`` exit into
    :class:`GhUnauthenticatedError` vs :class:`GhCommandError`.
    """
    lowered = stderr.lower()
    return any(marker in lowered for marker in _GH_AUTH_FAILURE_MARKERS)


def _classify_gh_command_error(returncode: int, stderr: str) -> GhCommandError:
    """Build the right ``gh`` failure exception from a non-zero exit.

    Returns :class:`GhUnauthenticatedError` when ``stderr`` matches an
    auth-failure marker, else :class:`GhCommandError`. The caller raises
    the returned instance.
    """
    if _is_gh_auth_failure(stderr):
        return GhUnauthenticatedError(returncode, stderr)
    return GhCommandError(returncode, stderr)


def _gh_api_args(binary: str, *, limit: Optional[int], per_page: int) -> list[str]:
    """Build the ``gh api user/repos`` argv for the request.

    ``per_page`` is capped at GitHub's 100-row API ceiling and, when a
    positive ``limit`` is set, additionally at the limit itself so we
    don't pull a 100-row page for a single-row request.
    """
    effective_per_page = min(per_page, GH_API_PER_PAGE)
    if limit is not None and limit > 0:
        effective_per_page = min(effective_per_page, limit)
    # Keep PR-A's remote list owner-only. GitHub's default for
    # /user/repos also includes collaborator/org-member repos, which
    # makes the picker noisy and was explicitly deferred to a future
    # --include-orgs style affordance in the #205 spike.
    return [
        binary,
        "api",
        f"user/repos?per_page={effective_per_page}&affiliation=owner&sort=updated",
        "--paginate",
        "--slurp",
    ]


def _run_gh_api(args: list[str]) -> str:
    """Run ``gh api``, returning stdout or raising the classified error."""
    completed = subprocess.run(
        args,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise _classify_gh_command_error(completed.returncode, completed.stderr)
    return completed.stdout


def _sorted_gh_repos(payload: list[Any], limit: Optional[int]) -> list[Repo]:
    """Parse GH API entries, sorted by ``updated_at`` descending.

    ``None`` sorts last so a record missing the field doesn't crowd the
    top of the picker. ``limit`` caps the returned rows.
    """
    repos = [_repo_from_gh_entry(entry) for entry in payload]
    repos.sort(
        key=lambda r: (r.remote.updated_at if r.remote else "") or "",
        reverse=True,
    )
    if limit is not None and limit > 0:
        repos = repos[:limit]
    return repos


def fetch_remote_repos(
    *,
    limit: Optional[int] = None,
    per_page: int = GH_API_PER_PAGE,
    gh_binary: Optional[str] = None,
) -> list[Repo]:
    """Call ``gh api user/repos --paginate --slurp`` and return parsed repos.

    Sorted by ``updated_at`` descending so the picker shows
    most-recently-touched repositories first. Each :class:`Repo` has
    ``remote`` populated; ``local`` is ``None``. ``limit`` caps the
    returned rows; ``gh_binary`` overrides the resolved ``gh`` path.

    Raises :class:`GhMissingError` when ``gh`` is not on PATH,
    :class:`GhUnauthenticatedError` when stderr matches an auth-failure
    marker, and :class:`GhCommandError` for any other non-zero exit
    (stderr preserved so the CLI can surface it).
    """
    binary = gh_binary or _resolve_gh_binary()
    if binary is None:
        raise GhMissingError(_gh_missing_message())

    stdout = _run_gh_api(_gh_api_args(binary, limit=limit, per_page=per_page))
    return _sorted_gh_repos(_parse_gh_api_output(stdout), limit)


def _parse_gh_api_output(raw: str) -> list[dict[str, Any]]:
    """Parse the stdout of ``gh api ... --paginate --slurp``.

    ``gh --paginate`` emits each page separately. ``--slurp`` wraps
    those page payloads in one outer array, so list endpoints become
    ``[[repo, ...], [repo, ...]]``. A flat ``[repo, ...]`` is accepted
    defensively for direct parser callers and older stubs.
    """
    text = raw.strip()
    if not text:
        return []
    data = json.loads(text)
    if not isinstance(data, list):
        # Defensive: GH could in theory return an object envelope
        # (e.g. on an error already surfaced via stderr); treat as
        # empty rather than crashing the scan.
        return []

    entries: list[dict[str, Any]] = []
    for item in data:
        if isinstance(item, dict):
            entries.append(item)
        elif isinstance(item, list):
            entries.extend(entry for entry in item if isinstance(entry, dict))
    return entries


def _repo_from_gh_entry(entry: dict[str, Any]) -> Repo:
    """Translate one ``gh api user/repos`` entry into a unified :class:`Repo`."""
    owner_obj = entry.get("owner")
    owner = (
        owner_obj.get("login")
        if isinstance(owner_obj, dict) and isinstance(owner_obj.get("login"), str)
        else None
    )
    name = entry.get("name") or ""
    full_name = entry.get("full_name") if isinstance(entry.get("full_name"), str) else None
    return Repo(
        name=str(name),
        owner=owner,
        full_name=full_name,
        local=None,
        remote=RemoteInfo(
            default_branch=_str_or_none(entry.get("default_branch")),
            html_url=_str_or_none(entry.get("html_url")),
            ssh_url=_str_or_none(entry.get("ssh_url")),
            updated_at=_str_or_none(entry.get("updated_at")),
        ),
    )
