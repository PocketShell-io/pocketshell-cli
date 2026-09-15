"""Latest per-engine session source discovery (for attach)."""
from __future__ import annotations
import json
import os
import sqlite3
from pathlib import Path
from typing import Optional
from urllib.parse import quote
# __SIBLING_IMPORTS__


def _encode_agent_cwd(cwd: str) -> str:
    trimmed = cwd.strip()
    return trimmed.replace("/", "-").replace(".", "-") if trimmed else "-"


def _encode_grok_cwd(cwd: str) -> str:
    """Percent-encode a cwd the way Grok names ``~/.grok/sessions/<cwd>/``."""
    trimmed = cwd.strip() or "/"
    return quote(trimmed, safe="")


def _grok_home() -> Path:
    override = os.environ.get("GROK_HOME")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".grok"


def _codex_file_cwd(path: Path) -> Optional[str]:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if '"session_meta"' not in line or '"cwd"' not in line:
                    continue
                row = json.loads(line)
                payload = row.get("payload")
                if row.get("type") == "session_meta" and isinstance(payload, dict):
                    cwd = payload.get("cwd")
                    return cwd if isinstance(cwd, str) else None
    except Exception:
        return None
    return None


def _path_mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def _latest_claude_source(cwd: str, started_at: float) -> Optional[str]:
    root = Path.home() / ".claude" / "projects" / _encode_agent_cwd(cwd)
    if not root.is_dir():
        return None
    candidates = [
        path
        for path in root.glob("*.jsonl")
        if path.is_file() and _path_mtime(path) >= started_at
    ]
    if not candidates:
        return None
    return str(max(candidates, key=_path_mtime))


def _latest_codex_source(cwd: str, started_at: float) -> Optional[str]:
    root = Path.home() / ".codex" / "sessions"
    if not root.is_dir():
        return None
    candidates = [
        path
        for path in root.rglob("*.jsonl")
        if path.is_file()
        and _path_mtime(path) >= started_at
        and _codex_file_cwd(path) == cwd
    ]
    if not candidates:
        return None
    return str(max(candidates, key=_path_mtime))


def _latest_grok_source(cwd: str, started_at: float) -> Optional[str]:
    root = _grok_home() / "sessions" / _encode_grok_cwd(cwd)
    if not root.is_dir():
        return None
    candidates = [
        path
        for path in root.glob("*/updates.jsonl")
        if path.is_file() and _path_mtime(path) >= started_at
    ]
    if not candidates:
        return None
    return str(max(candidates, key=_path_mtime))


def _latest_opencode_source(cwd: str, started_at: float) -> Optional[str]:
    db = Path.home() / ".local" / "share" / "opencode" / "opencode.db"
    if not db.is_file():
        return None
    normalized_cwd = cwd.rstrip("/") or "/"
    started_ms = int(started_at * 1000)
    query = """
        SELECT s.id, COALESCE(s.time_updated, s.time_created, 0),
               COALESCE(p.worktree, ''), COALESCE(s.directory, '')
        FROM session s
        LEFT JOIN project p ON p.id = s.project_id
        WHERE COALESCE(s.time_updated, s.time_created, 0) >= ?
        ORDER BY COALESCE(s.time_updated, s.time_created, 0) DESC
    """
    try:
        with sqlite3.connect(f"file:{db}?mode=ro", uri=True) as conn:
            rows = conn.execute(query, (started_ms,)).fetchall()
    except Exception:
        return None
    for session_id, _updated, worktree, directory in rows:
        for candidate_cwd in (worktree, directory):
            if not candidate_cwd:
                continue
            root = str(candidate_cwd).rstrip("/") or "/"
            if normalized_cwd == root or normalized_cwd.startswith(root + "/"):
                return f"{db}#{session_id}"
    return None


def _latest_agent_source(
    kind: str,
    cwd: str,
    started_at: float,
) -> Optional[str]:
    if kind == "claude":
        return _latest_claude_source(cwd, started_at)
    if kind == "codex":
        return _latest_codex_source(cwd, started_at)
    if kind == "opencode":
        return _latest_opencode_source(cwd, started_at)
    if kind == "grok":
        return _latest_grok_source(cwd, started_at)
    return None
