"""Daemon RPC handlers for the repos methods."""
from __future__ import annotations
import os
import subprocess
from pathlib import Path
from typing import Any, Optional, Sequence
# --- sibling modules ---
from pocketshell.repos.local import DEFAULT_MAX_DEPTH, DEFAULT_ROOT_PATHS, clone_repo, find_local_repo, resolve_scan_roots, scan_roots
from pocketshell.repos.model import _to_jsonable, normalize_full_name
from pocketshell.repos.remote import fetch_remote_repos


# Daemon-side TTL for ``repos.list_local``. Pulled into the module so
# the daemon and the docstring agree without duplicating the literal.
DAEMON_CACHE_TTL_SECS = 10.0


# Daemon-side TTL for ``repos.list_remote``. GH API rate-limited
# (5000/hour authenticated) so a longer cache keeps the picker fast
# without burning quota; remote repos rarely change minute-to-minute.
DAEMON_REMOTE_CACHE_TTL_SECS = 300.0


def _try_daemon_call(
    method: str,
    params: dict[str, Any],
    *,
    timeout: float = 10.0,
) -> Optional[list[dict[str, Any]]]:
    """Probe the daemon and dispatch ``method`` through typed fallback.

    Returns the JSON-RPC ``result`` (a list-of-dicts payload) on
    success, or ``None`` when the daemon is absent/unavailable or explicitly
    supports a method/version skew and the caller should fall through to the
    in-process path. Other daemon failures are surfaced and never masked.
    """
    from pocketshell import daemon as _daemon

    socket_path = _daemon.resolve_socket_path()
    return _daemon.try_call(
        method,
        params=params,
        socket_path=socket_path,
        timeout=timeout,
        result_validator=lambda result: (
            isinstance(result, list)
            and all(isinstance(entry, dict) for entry in result)
        ),
    )


def _try_daemon_list_local(
    *,
    roots: Sequence[Path],
    max_depth: int,
    no_cache: bool,
) -> Optional[list[dict[str, Any]]]:
    """Daemon probe for ``repos.list_local``. See :func:`_try_daemon_call`."""
    params: dict[str, Any] = {
        "roots": [str(p) for p in roots],
        "max_depth": max_depth,
    }
    if no_cache:
        params["no_cache"] = True
    return _try_daemon_call("repos.list_local", params)


def _try_daemon_list_remote(
    *,
    limit: Optional[int],
    no_cache: bool,
) -> Optional[list[dict[str, Any]]]:
    """Daemon probe for ``repos.list_remote``. See :func:`_try_daemon_call`."""
    params: dict[str, Any] = {}
    if limit is not None:
        params["limit"] = limit
    if no_cache:
        params["no_cache"] = True
    return _try_daemon_call("repos.list_remote", params)


def daemon_handler_local(params: dict[str, Any]) -> list[dict[str, Any]]:
    """JSON-RPC handler for ``repos.list_local``.

    Accepts ``roots`` (list of str) and ``max_depth`` (int); invalid
    values degrade to the defaults rather than raising. ``no_cache``
    is consumed by the daemon cache layer, not by this handler.
    """
    raw_roots = params.get("roots")
    if raw_roots is None:
        root_paths = resolve_scan_roots()
    elif isinstance(raw_roots, list) and all(isinstance(item, str) for item in raw_roots):
        root_paths = [Path(os.path.expanduser(item)) for item in raw_roots]
    else:
        root_paths = resolve_scan_roots()

    max_depth = _clamped_depth(params.get("max_depth"))
    repos = scan_roots(root_paths, max_depth=max_depth)
    return _to_jsonable(repos)


def _clamped_depth(max_depth_raw: Any) -> int:
    """Coerce a JSON depth value to a usable int, defaulting when invalid."""
    if isinstance(max_depth_raw, int) and max_depth_raw >= 0:
        return max_depth_raw
    return DEFAULT_MAX_DEPTH


def daemon_handler_remote(params: dict[str, Any]) -> list[dict[str, Any]]:
    """JSON-RPC handler for ``repos.list_remote``.

    Accepts ``limit`` (int, optional). Failures propagate as
    ``RuntimeError`` (translated by the daemon wrapper into a JSON-RPC
    internal-error envelope) so the client sees a clear error rather
    than an empty list.
    """
    limit_raw = params.get("limit")
    limit: Optional[int]
    if isinstance(limit_raw, int) and limit_raw > 0:
        limit = limit_raw
    else:
        limit = None
    repos = fetch_remote_repos(limit=limit)
    return _to_jsonable(repos)


# Machine-readable error tokens for the clone/open RPC result envelopes.
# Kept as constants so the daemon handler, the CLI, and the test suite
# agree on the exact spelling. The clone over SSH (``git clone
# git@github.com:...``) does not touch ``gh`` at all, so the gh_missing /
# gh_unauthenticated split applies to the remote-list path; clone failures
# get their own tokens here.
CLONE_ERROR_INVALID_REPOSITORY = "invalid_repository"


CLONE_ERROR_TARGET_EXISTS = "clone_target_exists"


CLONE_ERROR_GIT_MISSING = "git_missing"


CLONE_ERROR_FAILED = "clone_failed"


OPEN_ERROR_INVALID_REPOSITORY = "invalid_repository"


OPEN_ERROR_NOT_CLONED = "not_cloned"


def _error_envelope(error_code: str, message: str) -> dict[str, Any]:
    """Build the shared ``{"status": "error", ...}`` RPC envelope."""
    return {"status": "error", "error_code": error_code, "message": message}


def _clone_params(params: dict[str, Any]) -> tuple[Optional[dict[str, Any]], Optional[tuple[str, str, Optional[str], str]]]:
    """Validate ``repos.clone`` params.

    Returns ``(error_envelope, None)`` when the request is invalid, or
    ``(None, (repository, root, folder_name, protocol))`` when usable.
    """
    repository = params.get("repository")
    if not isinstance(repository, str) or not repository.strip():
        return _error_envelope(CLONE_ERROR_INVALID_REPOSITORY, "repos.clone: `repository` (owner/repo) is required"), None

    root_raw = params.get("root")
    root = root_raw if isinstance(root_raw, str) and root_raw else DEFAULT_ROOT_PATHS[0]

    folder_raw = params.get("folder")
    folder_name = folder_raw if isinstance(folder_raw, str) and folder_raw else None

    protocol_raw = params.get("protocol")
    protocol = protocol_raw if protocol_raw in ("ssh", "https") else "ssh"
    return None, (repository, root, folder_name, protocol)


def _clone_failure(exc: Exception) -> dict[str, Any]:
    """Map a clone exception to its machine-readable error envelope."""
    if isinstance(exc, ValueError):
        return _error_envelope(CLONE_ERROR_INVALID_REPOSITORY, f"repos.clone: {exc}")
    if isinstance(exc, FileExistsError):
        return _error_envelope(CLONE_ERROR_TARGET_EXISTS, f"repos.clone: {exc}")
    if isinstance(exc, FileNotFoundError):
        # ``git`` itself is not installed on the host.
        return _error_envelope(CLONE_ERROR_GIT_MISSING, "repos.clone: `git` is not installed on this host.")
    stderr = exc.stderr if isinstance(exc.stderr, str) else ""
    return {
        "status": "error",
        "error_code": CLONE_ERROR_FAILED,
        "message": f"repos.clone: git clone failed (exit {exc.returncode})",
        "returncode": exc.returncode,
        "stderr": stderr,
    }


def _clone_target(
    repository: str,
    root: str,
    folder_name: Optional[str],
    protocol: str,
) -> tuple[str, Path]:
    """Validate the slug and clone it; returns ``(full_name, target_path)``.

    The slug is validated up front so an invalid identifier reports a
    clean ``invalid_repository`` rather than a generic clone error.
    """
    full_owner, full_repo = normalize_full_name(repository)
    target = clone_repo(
        repository,
        root=Path(os.path.expanduser(root)),
        folder_name=folder_name,
        protocol=protocol,
        capture_output=True,
    )
    return f"{full_owner}/{full_repo}", target


def daemon_handler_clone(params: dict[str, Any]) -> dict[str, Any]:
    """JSON-RPC handler for ``repos.clone``.

    Mirrors the ``pocketshell repos clone`` CLI: clone ``repository``
    (``owner/repo``) into ``root`` (default ``~/git``) using ``protocol``
    (``ssh`` | ``https``). Returns a structured success envelope or an
    error envelope carrying a machine-readable ``CLONE_ERROR_*`` code.
    Failures are returned rather than raised so the daemon's
    cache-invalidation layer can key off successful returns.
    """
    error, parsed = _clone_params(params)
    if error is not None:
        return error
    repository, root, folder_name, protocol = parsed

    try:
        full_name, target = _clone_target(repository, root, folder_name, protocol)
    except (ValueError, FileExistsError, FileNotFoundError, subprocess.CalledProcessError) as exc:
        return _clone_failure(exc)

    return {
        "status": "cloned",
        "path": str(target),
        "full_name": full_name,
    }


def _open_roots(params: dict[str, Any]) -> list[Path]:
    """Resolve scan roots from ``repos.open`` params (default when absent)."""
    raw_roots = params.get("roots")
    if isinstance(raw_roots, list) and all(isinstance(item, str) for item in raw_roots):
        return resolve_scan_roots(tuple(raw_roots))
    return resolve_scan_roots()


def _open_located(repository: str, params: dict[str, Any]) -> dict[str, Any]:
    """Find the local clone for an already-validated slug."""
    repo = find_local_repo(
        repository,
        roots=_open_roots(params),
        max_depth=_clamped_depth(params.get("max_depth")),
    )
    if repo is None or repo.local is None:
        return _error_envelope(OPEN_ERROR_NOT_CLONED, f"repos.open: repository is not cloned: {repository}")
    return {
        "status": "open",
        "path": repo.local.path,
        "full_name": repo.full_name,
    }


def daemon_handler_open(params: dict[str, Any]) -> dict[str, Any]:
    """JSON-RPC handler for ``repos.open``.

    Mirrors the ``pocketshell repos open`` CLI: locate the local clone of
    ``repository`` (``owner/repo``) under the configured roots and return
    its path, or an envelope with an ``OPEN_ERROR_*`` ``error_code``.
    """
    repository = params.get("repository")
    if not isinstance(repository, str) or not repository.strip():
        return _error_envelope(OPEN_ERROR_INVALID_REPOSITORY, "repos.open: `repository` (owner/repo) is required")

    try:
        normalize_full_name(repository)
    except ValueError as exc:
        return _error_envelope(OPEN_ERROR_INVALID_REPOSITORY, f"repos.open: {exc}")

    return _open_located(repository, params)
