"""Repository value objects and GitHub remote parsing."""
from __future__ import annotations
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional, Sequence


_FULL_NAME_RE = re.compile(r"^(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+)$")


@dataclass(frozen=True)
class LocalInfo:
    """Local clone metadata. Always paired with the unified ``Repo``."""

    path: str
    head: Optional[str]


@dataclass(frozen=True)
class RemoteInfo:
    """Remote (GitHub) metadata. Lifted straight from the GH API payload."""

    default_branch: Optional[str]
    html_url: Optional[str]
    ssh_url: Optional[str]
    updated_at: Optional[str]


@dataclass(frozen=True)
class Repo:
    """A unified repository entry.

    Either ``local`` or ``remote`` (or both, for a future merged view)
    is populated. ``owner``/``full_name`` may be ``None`` when the
    remote URL is missing or non-GitHub on a local-only scan.
    """

    name: str
    owner: Optional[str] = None
    full_name: Optional[str] = None
    local: Optional[LocalInfo] = None
    remote: Optional[RemoteInfo] = None


def _repo_to_dict(repo: Repo) -> dict[str, Any]:
    """Render a :class:`Repo` to its canonical JSON dict shape.

    Uses :func:`dataclasses.asdict` for the nested structures so the
    serialised shape and the dataclass definition cannot drift.
    """
    return {
        "owner": repo.owner,
        "name": repo.name,
        "full_name": repo.full_name,
        "local": asdict(repo.local) if repo.local is not None else None,
        "remote": asdict(repo.remote) if repo.remote is not None else None,
    }


# Match SSH form: ``git@github.com:<owner>/<repo>[.git]``. Owner and
# repo must be non-empty and contain only the URL-safe characters
# GitHub allows in slugs (``[\w.-]+`` is a superset; we keep it loose
# rather than tracking GitHub's exact slug rules).
_SSH_REMOTE_RE = re.compile(
    r"^git@github\.com:(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+?)(?:\.git)?/?$"
)


# Match HTTPS form: ``https://github.com/<owner>/<repo>[.git]``. We
# also accept the rare ``http://`` and ``git://`` variants since they
# show up in older clones.
_HTTPS_REMOTE_RE = re.compile(
    r"^(?:https?|git)://github\.com/(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+?)(?:\.git)?/?$"
)


def parse_github_remote(url: Optional[str]) -> Optional[tuple[str, str]]:
    """Return ``(owner, repo)`` parsed from a GitHub remote URL, or None.

    Supported forms (most common first):

    - ``git@github.com:owner/repo[.git]`` (SSH; the default for
      ``git clone`` when GitHub's "Copy" button is set to SSH).
    - ``https://github.com/owner/repo[.git]`` (HTTPS; the default
      when "Copy" is set to HTTPS).

    A non-GitHub URL (gitlab, gitea, internal host) returns ``None``
    so the caller can fall back to the directory basename for naming.
    """
    if not url:
        return None
    for pattern in (_SSH_REMOTE_RE, _HTTPS_REMOTE_RE):
        match = pattern.match(url.strip())
        if match:
            return match.group("owner"), match.group("repo")
    return None


def normalize_full_name(value: str) -> tuple[str, str]:
    """Return ``(owner, repo)`` for an ``owner/repo`` GitHub slug.

    The app will eventually pass this value from the GitHub project
    picker. Keep the accepted grammar intentionally small so the
    helper never interprets arbitrary shell input as a clone URL.
    """
    clean = value.strip().removesuffix(".git")
    match = _FULL_NAME_RE.match(clean)
    if match is None:
        raise ValueError("expected GitHub repository as owner/repo")
    return match.group("owner"), match.group("repo")


def github_clone_url(full_name: str, *, protocol: str = "ssh") -> str:
    """Build a clone URL for ``full_name`` using the requested protocol."""
    owner, repo = normalize_full_name(full_name)
    if protocol == "ssh":
        return f"git@github.com:{owner}/{repo}.git"
    if protocol == "https":
        return f"https://github.com/{owner}/{repo}.git"
    raise ValueError("protocol must be ssh or https")


def safe_clone_target(root: Path, full_name: str, folder_name: Optional[str] = None) -> Path:
    """Return the clone target path under ``root``.

    ``folder_name`` is optional and restricted to a single path segment.
    This prevents a malformed app payload from cloning outside the
    configured root via ``../`` or an absolute path.
    """
    _owner, repo = normalize_full_name(full_name)
    raw_name = folder_name.strip() if folder_name is not None else repo
    if not raw_name or raw_name in {".", ".."}:
        raise ValueError("folder name must not be empty")
    candidate = Path(raw_name)
    if candidate.is_absolute() or len(candidate.parts) != 1:
        raise ValueError("folder name must be a single path segment")
    return root.expanduser() / raw_name


def _to_jsonable(repos: Sequence[Repo]) -> list[dict[str, Any]]:
    """Convert ``repos`` to a list of plain dicts (JSON-serialisable)."""
    return [_repo_to_dict(r) for r in repos]


def _repo_from_jsonable(entry: dict[str, Any]) -> Repo:
    """Rehydrate one JSON dict (from daemon or in-process) into a :class:`Repo`."""
    local_obj = entry.get("local")
    local = None
    if isinstance(local_obj, dict):
        local = LocalInfo(
            path=str(local_obj.get("path", "")),
            head=_str_or_none(local_obj.get("head")),
        )
    remote_obj = entry.get("remote")
    remote = None
    if isinstance(remote_obj, dict):
        remote = RemoteInfo(
            default_branch=_str_or_none(remote_obj.get("default_branch")),
            html_url=_str_or_none(remote_obj.get("html_url")),
            ssh_url=_str_or_none(remote_obj.get("ssh_url")),
            updated_at=_str_or_none(remote_obj.get("updated_at")),
        )
    return Repo(
        name=str(entry.get("name", "")),
        owner=_str_or_none(entry.get("owner")),
        full_name=_str_or_none(entry.get("full_name")),
        local=local,
        remote=remote,
    )


def _str_or_none(value: Any) -> Optional[str]:
    """Return ``value`` as a string when it is one, else ``None``."""
    return value if isinstance(value, str) else None
