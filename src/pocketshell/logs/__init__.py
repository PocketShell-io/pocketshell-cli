"""`pocketshell logs` subcommand group — canonical server-side event sink.

The dev box is the single canonical log host (Tier 1, locked decision
**D27**). This group is the **persistent, greppable record** of two
signals:

1. The in-app **action-assistant** action traces (`kind=agent_action`)
   and plain app / crash logs (`kind in {app_log, crash}`) — the phone
   pipes one JSON event over SSH into ``pocketshell logs ingest`` per
   meaningful action.
2. **Coding-agent engine events** (`kind=engine_event`) — Claude / Codex
   / OpenCode stop/idle/waiting signals, mirrored from the #267 hooks
   JSONL bus (``~/.cache/pocketshell/hooks/events.jsonl``) by
   ``pocketshell logs import-hooks``.

Why server-side (D27)
---------------------

Every meaningful assistant action is already a server-side ``pocketshell``
call over SSH (D19/D23 — zero provider credentials on the phone), so the
dev box is already the choke point. Volume is tiny (KB/day, append-only
JSONL). Putting the canonical sink here means the record:

- survives app deletion / reinstall (it lives on the server, not the
  phone),
- is readable even if the phone app crashes on startup — the orchestrator
  can ``rg`` the JSONL directly with no SDK, and
- adds **zero new credential surface** (the phone holds no cloud creds).

S3 / cloud was considered and rejected for Tier 1 (it adds AWS credential
brokering for ~no benefit at this volume). Off-box durability — a private
git mirror preferred over S3 — is deferred to a later Tier-2 issue and is
explicitly out of scope here.

Storage
-------

``${XDG_STATE_HOME:-~/.local/state}/pocketshell/logs/``:

- ``agent-YYYYMMDD.jsonl`` — ``kind in {agent_action, engine_event}``.
- ``app-YYYYMMDD.jsonl`` — ``kind in {app_log, crash}``.

Files are created mode ``0600`` (they may contain command lines and host
names). Dirs are created as needed.

Secret redaction (REQUIRED — aggressive, deny-by-default)
---------------------------------------------------------

``ingest`` redacts before anything is written. Secret values must NEVER
reach the file. Three independent passes:

- **secret-named keys** — any dict key matching ``*_KEY`` / ``*_TOKEN`` /
  ``*_SECRET`` / ``PASSWORD`` / ``SECRET`` / ``CREDENTIAL`` etc. has its
  value replaced with ``"<redacted>"``.
- **token-shaped strings** — any string value that looks like a provider
  token (``sk-…``, ``ghp_…``, long high-entropy base64/hex blobs, JWTs,
  AWS keys, …) is replaced.
- **inline ``KEY=value`` assignments** — inside any string (e.g. a
  ``run_command`` arg like ``export OPENAI_API_KEY=sk-…``) a
  secret-named assignment keeps the key but masks the value, so the
  record reads ``export OPENAI_API_KEY=<redacted>``.

Redaction walks the whole event recursively (nested dicts/lists), so a
secret cannot hide one level down.
"""
from __future__ import annotations

from pocketshell.logs.cli import (
    logs_group,
)
from pocketshell.logs.events import (
    normalize_event,
    ingest_event,
    read_records,
)
from pocketshell.logs.hooks import (
    import_hooks,
)
from pocketshell.logs.paths import (
    SCHEMA_VERSION,
    NEW_FILE_MODE,
    HOOKS_CURSOR_FILENAME,
    LogsPaths,
    resolve_paths,
)
from pocketshell.logs.redact import (
    redact,
)

__all__ = [
    "SCHEMA_VERSION",
    "NEW_FILE_MODE",
    "HOOKS_CURSOR_FILENAME",
    "LogsPaths",
    "resolve_paths",
    "redact",
    "normalize_event",
    "ingest_event",
    "read_records",
    "import_hooks",
    "logs_group",
]
