"""Server-side usage cache + history log (issue #689).

Stale-while-revalidate plumbing for the Android usage screen. The host
captures provider usage on a schedule (cron / systemd timer — server-side
scheduling is fine; D21 foreground-only applies to the Android app, not
the host CLI) and persists two artifacts:

1. **Cached latest reading** — ``usage-latest.json``, a single JSON object
   holding the most recent ``pocketshell usage --json`` NDJSON output plus
   a ``captured_at`` UTC timestamp. The app reads this and renders it
   *instantly* with a "last captured at <time>" label, then refreshes live
   in the foreground.
2. **Append-only history log** — ``usage-history.jsonl``, one JSON object
   per capture (``{"captured_at": ..., "records": [...]}``). Powers usage
   tracking over time and the future reset-detection follow-up. The log is
   size-bounded (line cap with rotation) so it never grows without limit.
   Rewrites use a unique same-directory temp, fsync the data before the
   atomic rename, fsync the parent directory after the rename where the
   filesystem supports it, and serialize writers with an advisory lock.

Storage location
----------------

``${XDG_STATE_HOME:-~/.local/state}/pocketshell/usage/``:

- ``usage-latest.json`` — the cached latest reading (mode ``0600``).
- ``usage-history.jsonl`` — the append-only history log (mode ``0600``).
- ``usage-history-malformed.jsonl`` — bounded diagnostics for malformed
  capture/history lines (mode ``0600``), written only when needed.

This mirrors :mod:`pocketshell.logs`' XDG-state convention so all
PocketShell server state lives under one root. Files are ``0600`` because
they carry per-provider quota detail.

History bound
-------------

Each append trims the history file to the most recent
:data:`DEFAULT_HISTORY_MAX_LINES` lines. At ~1 capture/hour that is ~83
days of hourly history in a file that stays well under ~1 MB. The trim is
in-place (read tail, rewrite) which is simple and correct for this volume;
no external logrotate dependency.
"""
from __future__ import annotations

from pocketshell.usage.capture.durability import (
    _write_private,
)
from pocketshell.usage.capture.history import (
    write_capture,
    _append_history,
    read_cache,
    cached_document,
)
from pocketshell.usage.capture.paths import (
    NEW_FILE_MODE,
    DEFAULT_HISTORY_MAX_LINES,
    CACHE_FILENAME,
    HISTORY_FILENAME,
    MALFORMED_HISTORY_FILENAME,
    DEFAULT_MALFORMED_MAX_LINES,
    MAX_MALFORMED_LINE_LENGTH,
    HISTORY_LOCK_FILENAME,
    UsagePaths,
    resolve_paths,
)
import os  # noqa: F401  (tests patch usage.capture.os.fsync/replace)

__all__ = [
    "NEW_FILE_MODE",
    "DEFAULT_HISTORY_MAX_LINES",
    "CACHE_FILENAME",
    "HISTORY_FILENAME",
    "MALFORMED_HISTORY_FILENAME",
    "DEFAULT_MALFORMED_MAX_LINES",
    "MAX_MALFORMED_LINE_LENGTH",
    "HISTORY_LOCK_FILENAME",
    "UsagePaths",
    "resolve_paths",
    "_write_private",
    "write_capture",
    "_append_history",
    "read_cache",
    "cached_document",
]
