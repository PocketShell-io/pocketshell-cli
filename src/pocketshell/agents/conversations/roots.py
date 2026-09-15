"""Per-engine session-storage root paths and cwd encodings."""
from __future__ import annotations
import os
from pathlib import Path
from typing import Optional


def _claude_projects_root() -> Path:
    """Root directory for Claude Code's per-cwd JSONL trees.

    Pulled out so the unit suite can monkeypatch HOME via the standard
    ``Path.home()`` mechanism without us hard-coding ``~`` expansion.
    """
    return Path.home() / ".claude" / "projects"


def _codex_sessions_root() -> Path:
    """Root directory for Codex's date-partitioned session JSONL tree."""
    return Path.home() / ".codex" / "sessions"


def _opencode_root() -> Path:
    """Root directory for OpenCode's JSONL conversation files.

    ``opencode.db`` (SQLite) also lives here but is not part of this
    reader — see module docstring.
    """
    return Path.home() / ".local" / "share" / "opencode"


def _grok_sessions_root() -> Path:
    """Root directory for Grok Build session trees.

    Honours ``GROK_HOME`` (default ``~/.grok``). Session files live at
    ``<root>/sessions/<urlencoded-cwd>/<session-id>/updates.jsonl``.
    """
    override = os.environ.get("GROK_HOME")
    if override:
        return Path(override).expanduser() / "sessions"
    return Path.home() / ".grok" / "sessions"


def _encode_grok_cwd(cwd: str) -> str:
    """Percent-encode a cwd the way Grok names session group directories."""
    from urllib.parse import quote

    trimmed = cwd.strip() or "/"
    return quote(trimmed, safe="")


def _encode_claude_cwd(cwd: str) -> str:
    """Mirror of ``AgentDetector.encodeClaudeCwd`` from core-agents.

    Replaces ``/`` with ``-`` and falls back to ``-`` for a blank input.
    Kept byte-identical so a ``--cwd /home/alexey/git/pocketshell``
    invocation here resolves to the same directory the Kotlin detector
    would pick on the same host.
    """
    trimmed = cwd.strip()
    if not trimmed:
        return "-"
    return trimmed.replace("/", "-")


def _is_within(path: Path, root: Path) -> bool:
    """True when ``path`` is ``root`` or a descendant, after resolving both.

    Mirrors ``attachments._is_within`` / the ``repos.safe_clone_target``
    containment pattern used elsewhere in this package. Both sides are
    ``resolve()``-d first so a legitimately symlinked HOME (e.g. ``/home`` ->
    ``/data/home``) does not falsely trip the guard — only genuine traversal
    *out* of the per-engine root is rejected.
    """
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def _contained_candidate(candidate: Path, root: Path) -> Optional[Path]:
    """Return ``candidate`` only if it is a regular file inside ``root``.

    The single choke point that closes the ``--session`` / ``--cwd`` path
    traversal (#774 §2): an app-supplied name carrying ``..`` segments or an
    absolute component is rejected because the resolved candidate escapes the
    per-engine log root. ``.jsonl`` suffix + "is a regular file" remain
    necessary but are no longer the *only* fence.
    """
    if not _is_within(candidate, root):
        return None
    return candidate if candidate.is_file() else None
