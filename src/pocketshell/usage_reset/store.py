"""The reset-events log on disk and the app-facing JSON document.

Append-only JSONL under the usage state dir, capped like the history log,
plus :func:`reset_events_document` — the ``{"reset_events": [...]}``
document ``pocketshell usage --reset-events`` prints for the app.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from pocketshell.usage_capture import (
    UsagePaths,
    _append_history,
    resolve_paths,
)
from pocketshell.usage_reset.detect import detect_resets

# How many recent reset events to keep in the dedicated reset-events log.
# Resets are rare (a handful a day at most), so a small cap is plenty and
# keeps the cross-run de-dup scan trivial.
DEFAULT_RESET_EVENTS_MAX_LINES = 500

RESET_EVENTS_FILENAME = "usage-reset-events.jsonl"


def reset_events_file(paths: UsagePaths) -> Path:
    """Return the dedicated reset-events log path for ``paths``."""
    return paths.usage_dir / RESET_EVENTS_FILENAME


def read_reset_events(
    paths: Optional[UsagePaths] = None,
) -> list[dict[str, Any]]:
    """Return all recorded reset events (oldest first), or ``[]``."""
    if paths is None:
        paths = resolve_paths()
    path = reset_events_file(paths)
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            out.append(parsed)
    return out


def _known_reset_keys(paths: UsagePaths) -> set[str]:
    keys: set[str] = set()
    for event in read_reset_events(paths):
        key = event.get("reset_key")
        if isinstance(key, str):
            keys.add(key)
    return keys


def record_resets(
    previous_cache: Optional[dict[str, Any]],
    current_cache: dict[str, Any],
    *,
    paths: Optional[UsagePaths] = None,
    reset_events_max_lines: int = DEFAULT_RESET_EVENTS_MAX_LINES,
) -> list[dict[str, Any]]:
    """Detect resets, append new events to the reset-events log, and return them.

    Reads the existing reset-events log for cross-run de-dup so the same reset
    is never re-flagged on a later hourly run. Returns the list of NEW events
    written this run (empty when there was no reset, or every detected reset
    was already logged).
    """
    if paths is None:
        paths = resolve_paths()
    known = _known_reset_keys(paths)
    events = detect_resets(previous_cache, current_cache, known_reset_keys=known)
    if not events:
        return []
    path = reset_events_file(paths)
    for event in events:
        _append_history(path, event, history_max_lines=reset_events_max_lines)
    return events


def reset_events_document(paths: Optional[UsagePaths] = None) -> str:
    """Return the reset-events as the app-facing JSON document.

    Emits a single JSON object ``{"reset_events": [ {…}, … ]}`` (newest
    last). The app reads this to surface "limits reset at <time>" on next
    open (the non-push fallback) and a future push slice consumes the same
    detection output.
    """
    return json.dumps(
        {"reset_events": read_reset_events(paths)},
        sort_keys=True,
    ) + "\n"
