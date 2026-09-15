"""Device-token registry and already-sent log under the usage dir."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Optional
from pocketshell.usage_capture import (
    UsagePaths,
    _append_history,
    _write_private,
    resolve_paths,
)


# Where the registered device token + the per-reset_key "already pushed" log
# live, under the same usage state dir as the cache/history/reset-events.
TOKEN_FILENAME = "push-token.json"


SENT_LOG_FILENAME = "push-sent.jsonl"


# Bound the sent-log so it never grows without limit. Resets are rare, so a
# small cap is plenty for cross-run de-dup.
DEFAULT_SENT_LOG_MAX_LINES = 1000


def token_file(paths: UsagePaths) -> Path:
    """Return the registered-token path for ``paths``."""
    return paths.usage_dir / TOKEN_FILENAME


def sent_log_file(paths: UsagePaths) -> Path:
    """Return the per-``reset_key`` already-pushed log path for ``paths``."""
    return paths.usage_dir / SENT_LOG_FILENAME


def register_token(
    token: str,
    *,
    paths: Optional[UsagePaths] = None,
) -> Path:
    """Persist the device ``token`` atomically with mode ``0600``.

    The app calls this over a live foreground SSH session via
    ``pocketshell push register-token <token>``. Returns the path written.
    Raises :class:`ValueError` on an empty token (the CLI surfaces that as a
    non-zero exit) — a genuinely empty token is a caller bug, not a fail-soft
    condition.
    """
    trimmed = token.strip()
    if not trimmed:
        raise ValueError("token must not be empty")
    if paths is None:
        paths = resolve_paths()
    path = token_file(paths)
    _write_private(
        path,
        json.dumps({"token": trimmed}, sort_keys=True) + "\n",
    )
    return path


def read_token(paths: Optional[UsagePaths] = None) -> Optional[str]:
    """Return the registered device token, or ``None`` if none/unreadable."""
    if paths is None:
        paths = resolve_paths()
    path = token_file(paths)
    if not path.exists():
        return None
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(parsed, dict):
        return None
    token = parsed.get("token")
    if isinstance(token, str) and token.strip():
        return token.strip()
    return None


def sent_reset_keys(paths: Optional[UsagePaths] = None) -> set[str]:
    """Return the set of ``reset_key`` values already successfully pushed."""
    if paths is None:
        paths = resolve_paths()
    path = sent_log_file(paths)
    if not path.exists():
        return set()
    keys: set[str] = set()
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return set()
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            key = parsed.get("reset_key")
            if isinstance(key, str) and key:
                keys.add(key)
    return keys


def _mark_sent(
    reset_key: str,
    *,
    paths: UsagePaths,
    sent_log_max_lines: int = DEFAULT_SENT_LOG_MAX_LINES,
) -> None:
    """Record ``reset_key`` as successfully pushed so it never re-POSTs."""
    _append_history(
        sent_log_file(paths),
        {"reset_key": reset_key},
        history_max_lines=sent_log_max_lines,
    )
