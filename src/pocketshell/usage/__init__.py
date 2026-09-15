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

__all__ = [
    "_CLAUDE_USAGE_AUTH_SETUP_MESSAGE",
    "_GROK_USAGE_AUTH_SETUP_MESSAGE",
    "_QUSE_MISSING_EXIT_CODE",
    "_QUSE_MISSING_MESSAGE",
    "_actionable_error",
    "_exit_special",
    "_resolve_quse_binary",
    "_try_daemon_usage_fetch",
    "normalize_usage_stdout",
    "usage_command",
]
