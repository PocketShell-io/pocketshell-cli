"""Local repository discovery, git metadata, and cloning."""
from __future__ import annotations
import os
import subprocess
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional, Sequence
# --- sibling modules ---
from pocketshell.repos.model import LocalInfo, Repo, github_clone_url, normalize_full_name, parse_github_remote, safe_clone_target


# Directories that ``scan_roots`` refuses to descend into. Speeds up
# scans on dev boxes that keep large dependency caches under their
# normal source-code root and matches the spike's recommendation.
DEFAULT_SKIP_DIRS: frozenset[str] = frozenset(
    {".git", "node_modules", ".venv", "venv", "dist", "build", "target"}
)


# Default scan depth — see module docstring for justification.
DEFAULT_MAX_DEPTH = 4


# Default scan root when neither ``--root`` nor ``POCKETSHELL_REPOS_ROOTS``
# is set. Single-entry list to keep ``resolve_scan_roots`` symmetrical
# with the explicit-list cases.
DEFAULT_ROOT_PATHS: tuple[str, ...] = ("~/git",)


def find_local_repo(
    full_name: str,
    *,
    roots: Sequence[Path],
    max_depth: int = DEFAULT_MAX_DEPTH,
) -> Optional[Repo]:
    """Find a local clone by canonical GitHub ``owner/repo`` identity."""
    owner, repo_name = normalize_full_name(full_name)
    canonical = f"{owner}/{repo_name}".lower()
    fallback_name = repo_name.lower()
    fallback: Optional[Repo] = None
    for repo in scan_roots(roots, max_depth=max_depth):
        if repo.full_name and repo.full_name.lower() == canonical:
            return repo
        if fallback is None and repo.name.lower() == fallback_name:
            fallback = repo
    return fallback


def clone_repo(
    full_name: str,
    *,
    root: Path,
    folder_name: Optional[str] = None,
    protocol: str = "ssh",
    git_binary: str = "git",
    capture_output: bool = False,
) -> Path:
    """Clone ``full_name`` into ``root`` and return the target path.

    ``capture_output`` controls whether ``git clone``'s stdout/stderr is
    captured (``True``, used by the daemon RPC handler so it can surface
    git's stderr in the failure envelope) or streamed to the terminal
    (``False``, the CLI default so the user sees clone progress live).
    Either way a non-zero exit raises :class:`subprocess.CalledProcessError`;
    when captured, its ``stderr`` attribute carries git's diagnostics.
    """
    target = safe_clone_target(root, full_name, folder_name)
    if target.exists():
        raise FileExistsError(f"clone target already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    url = github_clone_url(full_name, protocol=protocol)
    subprocess.run(
        [git_binary, "clone", url, str(target)],
        check=True,
        capture_output=capture_output,
        text=True if capture_output else None,
    )
    return target


def _scan_root_sources(
    explicit_roots: Sequence[str],
    env: Optional[dict[str, str]],
) -> Sequence[str]:
    """Pick the raw root strings: CLI args > env var > default."""
    if explicit_roots:
        return explicit_roots
    env_map = env if env is not None else os.environ
    env_value = env_map.get("POCKETSHELL_REPOS_ROOTS")
    if env_value:
        # Split on ``:`` like PATH. Empty entries (e.g. trailing
        # colon) are skipped silently — they would otherwise expand
        # to the current working dir, which is rarely useful and
        # is a common copy-paste footgun.
        return [part for part in env_value.split(":") if part]
    return DEFAULT_ROOT_PATHS


def resolve_scan_roots(
    explicit_roots: Sequence[str] = (),
    *,
    env: Optional[dict[str, str]] = None,
) -> list[Path]:
    """Return the ordered list of scan roots given CLI args + env.

    Precedence (highest to lowest, matching the docstring):
    ``--root`` CLI args, then the ``POCKETSHELL_REPOS_ROOTS`` env var
    (colon-separated like PATH), then ``DEFAULT_ROOT_PATHS``. Each
    entry is ``~``-expanded; duplicates are dropped preserving the
    first occurrence so a repeated root does not duplicate output.
    """
    seen: set[Path] = set()
    result: list[Path] = []
    for raw in _scan_root_sources(explicit_roots, env):
        path = Path(os.path.expanduser(raw))
        if path in seen:
            continue
        seen.add(path)
        result.append(path)
    return result


def _is_git_repo(candidate: Path) -> bool:
    """Return True if ``candidate`` contains a ``.git`` entry.

    Accepts both directory and file forms of ``.git``:

    - Directory: a normal clone (``<repo>/.git/``).
    - File: a git worktree or submodule (``<repo>/.git`` points at the
      real git dir via ``gitdir: ...`` text content).
    """
    return (candidate / ".git").exists()


def _head_branch(repo_path: Path) -> Optional[str]:
    """Resolve the checked-out branch for ``repo_path``, best-effort.

    ``rev-parse --abbrev-ref HEAD`` reports the literal ``HEAD`` for a
    detached HEAD (mapped to ``None`` so the JSON consumer can tell
    that apart from a real branch). On an empty repository (just
    ``git init``) ``rev-parse`` errors, but ``symbolic-ref --short
    HEAD`` still reads ``.git/HEAD`` — the fallback keeps brand-new
    clones visible to the picker.
    """
    head_raw = _git_run(repo_path, ["rev-parse", "--abbrev-ref", "HEAD"])
    if head_raw == "HEAD":
        return None
    if head_raw is not None:
        return head_raw
    symbolic = _git_run(repo_path, ["symbolic-ref", "--short", "HEAD"])
    return symbolic if symbolic else None


def _read_git_metadata(repo_path: Path) -> tuple[Optional[str], Optional[str]]:
    """Read ``(remote_url, head_branch)`` for a repo using ``git`` itself.

    Both fields are best-effort: any subprocess failure (missing git
    binary, corrupted repo, detached HEAD) yields ``None`` instead of
    propagating an exception. The scan loop must never abort on a
    single bad clone.
    """
    remote = _git_config_get(repo_path, "remote.origin.url")
    return remote, _head_branch(repo_path)


def _git_run(repo_path: Path, args: Sequence[str], *, timeout: float = 5.0) -> Optional[str]:
    """Run ``git -C <repo_path> <args>`` and return stripped stdout, or None.

    None on any failure (non-zero exit, missing binary, timeout). 5 s
    per-call timeout protects the scan from a slow filesystem hang on
    an NFS/sshfs mount.
    """
    try:
        completed = subprocess.run(
            ["git", "-C", str(repo_path), *args],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None
    if completed.returncode != 0:
        return None
    output = completed.stdout.strip()
    return output if output else None


def _git_config_get(repo_path: Path, key: str) -> Optional[str]:
    """Run ``git -C <repo> config --get <key>`` and return stripped value."""
    return _git_run(repo_path, ["config", "--get", key])


def _child_directories(current: Path, skip_set: frozenset[str]) -> Iterator[Path]:
    """Yield the subdirectories of ``current`` worth descending into.

    Skips names in ``skip_set``. Symlinks are NOT followed: a symlink
    to a directory would otherwise let a user create infinite recursion
    via ``ln -s .. infinity``.
    """
    try:
        entries = list(os.scandir(current))
    except (PermissionError, FileNotFoundError, NotADirectoryError, OSError):
        return
    for entry in entries:
        if entry.name in skip_set:
            continue
        try:
            is_dir = entry.is_dir(follow_symlinks=False)
        except OSError:
            continue
        if is_dir:
            yield Path(entry.path)


def _walk_for_repos(
    root: Path,
    *,
    max_depth: int,
    skip_dirs: Iterable[str] = DEFAULT_SKIP_DIRS,
) -> Iterator[Path]:
    """Yield repository directories under ``root`` up to ``max_depth`` deep.

    A ``.git`` entry at depth N marks the parent (depth N-1) a repo;
    detected repos are never descended into (monorepos do not nest-explode).
    """
    skip_set = frozenset(skip_dirs)
    # Stack of (path, depth_below_root) so we can prune by max_depth.
    # depth_below_root == 0 means we are at the root itself.
    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack:
        current, depth = stack.pop()
        # Check the current directory itself for a .git entry, but only
        # if depth > 0 — root is a scan target, not a repo we'd report.
        if depth > 0 and _is_git_repo(current):
            yield current
            # Don't descend into a detected repo.
            continue
        if depth >= max_depth:
            continue
        stack.extend(
            (child, depth + 1)
            for child in _child_directories(current, skip_set)
        )


def _repo_from_path(repo_path: Path) -> Repo:
    """Build a local-only :class:`Repo` from a discovered repo path.

    ``remote`` is always ``None`` on this path (the GH API is never
    called for a local scan); ``owner``/``full_name`` are best-effort
    from ``remote.origin.url``. ``name`` stays the directory basename
    so locally-renamed forks remain identifiable, while ``full_name``
    carries the canonical GitHub identity.
    """
    remote_url, head = _read_git_metadata(repo_path)
    parsed = parse_github_remote(remote_url)
    owner: Optional[str] = None
    full_name: Optional[str] = None
    if parsed is not None:
        owner, gh_name = parsed
        full_name = f"{owner}/{gh_name}"
    return Repo(
        name=repo_path.name,
        owner=owner,
        full_name=full_name,
        local=LocalInfo(path=str(repo_path), head=head),
        remote=None,
    )


def _verified_roots(roots: Sequence[Path], warn_fn) -> Iterator[Path]:
    """Yield roots that exist and are directories, warning about the rest."""
    for root in roots:
        if not root.exists():
            warn_fn(f"pocketshell: scan root does not exist: {root}")
        elif not root.is_dir():
            warn_fn(f"pocketshell: scan root is not a directory: {root}")
        else:
            yield root


def _collect_repos(
    roots: Iterable[Path],
    *,
    max_depth: int,
    skip_dirs: Iterable[str],
) -> list[Repo]:
    """Walk every verified root, de-duplicating resolved repo paths."""
    repos: list[Repo] = []
    seen_paths: set[Path] = set()
    for root in roots:
        for repo_path in _walk_for_repos(
            root, max_depth=max_depth, skip_dirs=skip_dirs
        ):
            resolved = repo_path.resolve()
            if resolved in seen_paths:
                continue
            seen_paths.add(resolved)
            repos.append(_repo_from_path(repo_path))
    return repos


def _sort_repos(repos: list[Repo]) -> None:
    """Stable sort by name then local path so the daemon's cache key
    collapses to a single entry regardless of root order."""
    repos.sort(
        key=lambda r: (r.name.lower(), r.local.path if r.local else "")
    )


def scan_roots(
    roots: Sequence[Path],
    *,
    max_depth: int = DEFAULT_MAX_DEPTH,
    skip_dirs: Iterable[str] = DEFAULT_SKIP_DIRS,
    warn_fn: Optional[Any] = None,
) -> list[Repo]:
    """Scan ``roots`` and return all detected repos, sorted by ``name``.

    ``warn_fn(message: str)`` is invoked once per missing/inaccessible
    root so the CLI can route the warnings to stderr. Defaults to a
    no-op so library callers (and tests) do not need to wire one up.
    Each :class:`Repo` returned has ``local`` populated and ``remote``
    ``None``.
    """
    if warn_fn is None:
        def warn_fn(_message: str) -> None:  # pragma: no cover - no-op
            return

    repos = _collect_repos(
        _verified_roots(roots, warn_fn),
        max_depth=max_depth,
        skip_dirs=skip_dirs,
    )
    _sort_repos(repos)
    return repos
