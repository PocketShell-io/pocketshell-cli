"""Attachment retention passes: TTL sweep, size-cap trim, result summary.

Pure filesystem work with injected ``now`` — no Click, no ``$HOME`` access
(the caller owns the containment check). Everything funnels into
:func:`prune_attachments`, which returns a structured
:class:`PruneResult`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# Retention tuning knobs. Kept as module constants so both the CLI and the
# unit suite reference one source of truth.
DEFAULT_TTL_DAYS: int = 14
DEFAULT_MAX_TOTAL_BYTES: int = 256 * 1024 * 1024  # 256 MiB
PROTECT_NEWEST_HOURS: int = 24

# The attachments root, relative to ``$HOME``. Mirrors the client's
# ``PromptAttachmentStager.REMOTE_DIRECTORY``.
ATTACHMENTS_RELATIVE_ROOT = Path(".pocketshell") / "attachments"

_SECONDS_PER_DAY = 24 * 60 * 60
_SECONDS_PER_HOUR = 60 * 60


@dataclass
class DeletedFile:
    """One file the prune removed (or would remove in dry-run)."""

    path: str
    size: int
    age_days: float
    reason: str  # "ttl" or "size-cap"


@dataclass
class PruneResult:
    """Structured summary of a prune pass (CLI emits this as JSON)."""

    root: str
    scanned_files: int = 0
    scanned_bytes: int = 0
    deleted: list[DeletedFile] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    dry_run: bool = False
    skipped_root_missing: bool = False

    @property
    def deleted_count(self) -> int:
        return len(self.deleted)

    @property
    def deleted_bytes(self) -> int:
        return sum(d.size for d in self.deleted)

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "dry_run": self.dry_run,
            "skipped_root_missing": self.skipped_root_missing,
            "scanned_files": self.scanned_files,
            "scanned_bytes": self.scanned_bytes,
            "deleted_count": self.deleted_count,
            "deleted_bytes": self.deleted_bytes,
            "deleted": [
                {
                    "path": d.path,
                    "size": d.size,
                    "age_days": round(d.age_days, 3),
                    "reason": d.reason,
                }
                for d in self.deleted
            ],
            "errors": self.errors,
        }


@dataclass
class _Candidate:
    path: Path
    size: int
    mtime: float


def resolve_attachments_root(home: Optional[Path] = None) -> Path:
    """Resolve ``~/.pocketshell/attachments`` from ``$HOME``.

    Pulled out so the unit suite can point it at a tmp dir. Uses the
    ``home`` argument when given, otherwise ``Path.home()``.
    """
    base = home if home is not None else Path.home()
    return (base / ATTACHMENTS_RELATIVE_ROOT).resolve()


def _safe_iterdir(directory: Path) -> list[Path]:
    try:
        return sorted(directory.iterdir())
    except OSError:
        return []


def _iter_attachment_files(root: Path) -> list[_Candidate]:
    """Collect regular files exactly two levels under ``root``.

    Layout is ``root/<scope>/<file>``. We deliberately do NOT recurse
    deeper and we never follow symlinks: a candidate must be a real
    regular file (``Path.is_file()`` follows symlinks, so we additionally
    reject symlinks with ``is_symlink()``).
    """
    candidates: list[_Candidate] = []
    for scope_dir in _safe_iterdir(root):
        # Only descend into real directories that are direct children of
        # the root — never symlinked dirs (which could point outside the
        # attachments tree).
        if scope_dir.is_symlink() or not scope_dir.is_dir():
            continue
        for entry in _safe_iterdir(scope_dir):
            if entry.is_symlink():
                continue
            if not entry.is_file():
                continue
            try:
                stat = entry.stat()
            except OSError:
                continue
            candidates.append(
                _Candidate(path=entry, size=stat.st_size, mtime=stat.st_mtime)
            )
    return candidates


def _delete(
    result: PruneResult,
    candidate: _Candidate,
    *,
    now: float,
    reason: str,
    dry_run: bool,
) -> None:
    """Record (and, unless dry-run, perform) one deletion. Best-effort."""
    age_days = (now - candidate.mtime) / _SECONDS_PER_DAY
    if not dry_run:
        try:
            candidate.path.unlink()
        except OSError as exc:
            result.errors.append(f"{candidate.path}: {exc}")
            return
    result.deleted.append(
        DeletedFile(
            path=str(candidate.path),
            size=candidate.size,
            age_days=age_days,
            reason=reason,
        )
    )


def _ttl_pass(
    result: PruneResult,
    candidates: list[_Candidate],
    *,
    now: float,
    ttl_seconds: float,
    dry_run: bool,
) -> list[_Candidate]:
    """Pass 1 — delete files strictly older than the TTL; return survivors."""
    survivors: list[_Candidate] = []
    for c in candidates:
        if now - c.mtime > ttl_seconds:
            _delete(result, c, now=now, reason="ttl", dry_run=dry_run)
        else:
            survivors.append(c)
    return survivors


def _size_cap_pass(
    result: PruneResult,
    survivors: list[_Candidate],
    *,
    now: float,
    max_total_bytes: int,
    protect_seconds: float,
    dry_run: bool,
) -> None:
    """Pass 2 — trim oldest survivors until under the cap.

    Files younger than the protect window are never deleted so an active
    session's just-uploaded files are spared even during a backlog clear.
    """
    surviving_bytes = sum(c.size for c in survivors)
    if surviving_bytes <= max_total_bytes:
        return
    for c in sorted(survivors, key=lambda x: x.mtime):
        if surviving_bytes <= max_total_bytes:
            break
        if now - c.mtime < protect_seconds:
            continue
        _delete(result, c, now=now, reason="size-cap", dry_run=dry_run)
        surviving_bytes -= c.size


def _root_missing(result: PruneResult, root: Path) -> bool:
    """Flag ``skipped_root_missing`` when ``root`` is absent / not a dir."""
    if root.exists() and root.is_dir():
        return False
    result.skipped_root_missing = True
    return True


def _scan_candidates(result: PruneResult, root: Path) -> list[_Candidate]:
    """Fill in the scanned counts and return the candidate list."""
    candidates = _iter_attachment_files(root)
    result.scanned_files = len(candidates)
    result.scanned_bytes = sum(c.size for c in candidates)
    return candidates


def prune_attachments(
    root: Path,
    *,
    now: float,
    ttl_days: int = DEFAULT_TTL_DAYS,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    protect_newest_hours: int = PROTECT_NEWEST_HOURS,
    dry_run: bool = False,
) -> PruneResult:
    """Prune attachments under ``root`` by TTL then by size cap.

    ``root`` MUST be the resolved attachments dir (the caller owns the
    ``$HOME`` containment check); ``now`` is injected epoch-seconds.
    """
    result = PruneResult(root=str(root), dry_run=dry_run)
    if _root_missing(result, root):
        return result

    candidates = _scan_candidates(result, root)
    survivors = _ttl_pass(
        result, candidates,
        now=now, ttl_seconds=ttl_days * _SECONDS_PER_DAY, dry_run=dry_run,
    )
    _size_cap_pass(
        result, survivors,
        now=now, max_total_bytes=max_total_bytes,
        protect_seconds=protect_newest_hours * _SECONDS_PER_HOUR,
        dry_run=dry_run,
    )
    return result
