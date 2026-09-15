"""Resolve a session id (+ optional cwd) to a provider log file."""
from __future__ import annotations
from pathlib import Path
from typing import Optional
# --- sibling modules ---
from pocketshell.agent_log.roots import _claude_projects_root, _codex_sessions_root, _contained_candidate, _encode_claude_cwd, _encode_grok_cwd, _grok_sessions_root, _opencode_root


def _ensure_jsonl_suffix(session: str) -> str:
    """Append ``.jsonl`` if the caller passed a bare session id.

    The Kotlin side stores ``sessionId`` as the path's basename without
    the ``.jsonl`` extension (see ``AgentConversationRepository.parseCandidate``),
    so users running ``pocketshell agent-log --session <id>`` after
    copy-pasting an id from the app will not have the extension. We
    accept both.
    """
    if session.endswith(".jsonl"):
        return session
    return f"{session}.jsonl"


def _resolve_claude_path(session: str, cwd: Optional[str]) -> Optional[Path]:
    """Resolve a Claude Code session to its JSONL file.

    When ``cwd`` is provided the lookup is direct:
    ``~/.claude/projects/<encoded-cwd>/<session>.jsonl``. When omitted
    we scan every ``~/.claude/projects/*/`` directory for a file whose
    basename matches; the first hit wins.

    Returns ``None`` if nothing matches.
    """
    filename = _ensure_jsonl_suffix(session)
    root = _claude_projects_root()
    if cwd is not None:
        candidate = root / _encode_claude_cwd(cwd) / filename
        return _contained_candidate(candidate, root)
    if not root.is_dir():
        return None
    for project_dir in sorted(root.iterdir()):
        if not project_dir.is_dir():
            continue
        candidate = project_dir / filename
        contained = _contained_candidate(candidate, root)
        if contained is not None:
            return contained
    return None


def _resolve_codex_path(session: str) -> Optional[Path]:
    """Resolve a Codex session to its JSONL file under ``~/.codex/sessions``.

    Codex partitions sessions by date (``<YYYY>/<MM>/<DD>/``), so we walk
    the tree rather than asking the user to supply the partition. The
    first basename match wins.
    """
    filename = _ensure_jsonl_suffix(session)
    root = _codex_sessions_root()
    if not root.is_dir():
        return None
    # ``Path.rglob`` returns matches in directory-walk order; the codex
    # tree is shallow (year/month/day/file) so this is cheap even with
    # months of history. A ``..``-laden session name can make rglob surface
    # a traversal path, so each candidate is still containment-checked.
    for candidate in root.rglob(filename):
        contained = _contained_candidate(candidate, root)
        if contained is not None:
            return contained
    return None


def _resolve_grok_path(session: str, cwd: Optional[str]) -> Optional[Path]:
    """Resolve a Grok Build session to its ``updates.jsonl``.

    ``session`` is the session-id directory name. When ``cwd`` is given the
    lookup is ``$GROK_HOME/sessions/<urlencoded-cwd>/<session>/updates.jsonl``.
    When omitted we scan every encoded-cwd directory for that session id.
    """
    session_id = session
    if session.endswith("/updates.jsonl"):
        session_id = Path(session).parent.name
    elif session == "updates.jsonl":
        session_id = session
    root = _grok_sessions_root()
    if cwd is not None:
        candidate = root / _encode_grok_cwd(cwd) / session_id / "updates.jsonl"
        return _contained_candidate(candidate, root)
    if not root.is_dir():
        return None
    for project_dir in sorted(root.iterdir()):
        if not project_dir.is_dir():
            continue
        candidate = project_dir / session_id / "updates.jsonl"
        contained = _contained_candidate(candidate, root)
        if contained is not None:
            return contained
    return None


def _resolve_opencode_path(session: str) -> Optional[Path]:
    """Resolve an OpenCode session to its JSONL file.

    OpenCode's conversation JSONLs live one level deep under
    ``~/.local/share/opencode/``. The SQLite ``opencode.db`` is ignored
    (see module docstring); only ``*.jsonl`` files are tailable.
    """
    filename = _ensure_jsonl_suffix(session)
    root = _opencode_root()
    if not root.is_dir():
        return None
    candidate = root / filename
    return _contained_candidate(candidate, root)


def _resolve_log_path(
    engine: str,
    session: str,
    cwd: Optional[str],
) -> Optional[Path]:
    """Dispatch to the per-engine resolver. Returns ``None`` on miss."""
    if engine == "claude":
        return _resolve_claude_path(session, cwd)
    if engine == "codex":
        # ``--cwd`` is accepted at the CLI for symmetry with claude but
        # ignored here — Codex partitions by date, not by working dir.
        return _resolve_codex_path(session)
    if engine == "opencode":
        return _resolve_opencode_path(session)
    if engine == "grok":
        return _resolve_grok_path(session, cwd)
    # Click's ``type=Choice`` rejects unknown engines before we ever get
    # here; guard anyway so the function is total.
    return None
