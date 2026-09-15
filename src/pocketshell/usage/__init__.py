"""`pocketshell usage` subcommand.

Implementation delegates to the **pinned** `quse` CLI via `subprocess.run`
and normalizes its provider-keyed `--json` document into the per-provider
NDJSON the Android app consumes. Human output is proxied verbatim.

Modules
-------

- :mod:`pocketshell.usage.normalize` — the producer boundary: flattens
  quse's provider-keyed `--json` object into per-provider NDJSON.
- :mod:`pocketshell.usage.quse` — resolves and runs the pinned `quse`
  binary shipped next to the interpreter.
- :mod:`pocketshell.usage.cli` — the Click command: daemon proxy, the
  `--capture` / `--cached` / `--reset-events` special modes, fall-through.
"""
from __future__ import annotations

from pocketshell.usage.cli import (
    _exit_special,
    _try_daemon_usage_fetch,
    usage_command,
)
from pocketshell.usage.normalize import (
    _CLAUDE_USAGE_AUTH_SETUP_MESSAGE,
    _GROK_USAGE_AUTH_SETUP_MESSAGE,
    _actionable_error,
    normalize_usage_stdout,
)
from pocketshell.usage.quse import (
    _QUSE_MISSING_EXIT_CODE,
    _QUSE_MISSING_MESSAGE,
    _resolve_quse_binary,
)
from pocketshell.usage.capture import (
    CACHE_FILENAME,
    DEFAULT_HISTORY_MAX_LINES,
    DEFAULT_MALFORMED_MAX_LINES,
    HISTORY_FILENAME,
    HISTORY_LOCK_FILENAME,
    MALFORMED_HISTORY_FILENAME,
    MAX_MALFORMED_LINE_LENGTH,
    NEW_FILE_MODE,
    UsagePaths,
    _append_history,
    _write_private,
    cached_document,
    read_cache,
    resolve_paths,
    write_capture,
)
from pocketshell.usage.reset import (
    DEFAULT_RESET_EVENTS_MAX_LINES,
    RESET_EVENTS_FILENAME,
    RESET_RECOVERY_THRESHOLD,
    detect_resets,
    read_reset_events,
    record_resets,
    reset_events_document,
    reset_events_file,
)

__all__ = [
    "_CLAUDE_USAGE_AUTH_SETUP_MESSAGE",
    "_GROK_USAGE_AUTH_SETUP_MESSAGE",
    "_QUSE_MISSING_EXIT_CODE",
    "_QUSE_MISSING_MESSAGE",
    "_actionable_error",
    "_exit_special",
    "_resolve_quse_binary",
    "_try_daemon_usage_fetch",
    "CACHE_FILENAME",
    "DEFAULT_HISTORY_MAX_LINES",
    "DEFAULT_MALFORMED_MAX_LINES",
    "HISTORY_FILENAME",
    "HISTORY_LOCK_FILENAME",
    "MALFORMED_HISTORY_FILENAME",
    "MAX_MALFORMED_LINE_LENGTH",
    "NEW_FILE_MODE",
    "UsagePaths",
    "_append_history",
    "_write_private",
    "cached_document",
    "read_cache",
    "resolve_paths",
    "write_capture",
    "DEFAULT_RESET_EVENTS_MAX_LINES",
    "RESET_EVENTS_FILENAME",
    "RESET_RECOVERY_THRESHOLD",
    "detect_resets",
    "read_reset_events",
    "record_resets",
    "reset_events_document",
    "reset_events_file",
    "normalize_usage_stdout",
    "usage_command",
]
