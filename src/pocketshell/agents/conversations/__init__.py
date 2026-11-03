"""Raw `pocketshell agent-log` conversation-log reads.

Mirrors the per-engine JSONL conversation-log reads the Android app
currently runs over SSH (see ``AgentConversationRepository`` in
``app/src/main/java/com/pocketshell/app/session/``). The command reads raw
JSONL so the Android client and IPC daemon can cache and serve the same
bytes the agent CLI wrote to disk.

Per-engine canonical paths (matching the Kotlin
``AgentConversationRepository.detectionCommand`` enumeration):

- **Claude Code**: ``~/.claude/projects/<encoded-cwd>/<session>.jsonl``.
  ``<encoded-cwd>`` is the working directory with ``/`` replaced by ``-``
  (see ``AgentDetector.encodeClaudeCwd``). When ``--cwd`` is omitted we
  walk every ``~/.claude/projects/*`` directory and pick the file whose
  basename matches ``<session>``.
- **Codex**: ``~/.codex/sessions/<YYYY>/<MM>/<DD>/<session>.jsonl``. The
  date partition is opaque to the caller, so we walk the subtree and
  match on basename.
- **OpenCode**: ``~/.local/share/opencode/<session>.jsonl``. OpenCode
  also persists state in ``opencode.db`` (SQLite), but the per-pane
  conversation feed the Android app consumes is the JSONL file (see
  ``OpenCodeReader`` for the row shape). The SQLite store is explicitly
  out of scope here — the brief calls for parity with the Kotlin reader,
  which only touches ``*.jsonl``.

Why direct file read instead of a subprocess delegation:

- There is no upstream CLI for these reads. The Android app reads them
  itself via ``ssh exec 'tail -n N <path>'``. There is no ``quse``- or
  host-side session binary on the host to wrap; reimplementing the
  ``tail -n N`` step in Python is the smallest reasonable parity layer.
- The JSONL files are append-only, plain text, one event per line. The
  read path emits raw lines verbatim.
- ``--json`` wraps the same raw lines in a small envelope (``engine``,
  ``session``, ``path``, ``lines``, ``count``) so machine consumers
  (the planned daemon, integration tests) can pin to a stable shape
  without re-parsing the JSONL themselves.
"""
from __future__ import annotations

from pocketshell.agents.conversations.cli import (
    agent_log_command,
)
from pocketshell.agents.conversations.resolve import (
    _resolve_claude_path,
    _resolve_codex_path,
    _resolve_grok_path,
    _resolve_opencode_path,
)

__all__ = [
    "_resolve_claude_path",
    "_resolve_codex_path",
    "_resolve_grok_path",
    "_resolve_opencode_path",
    "agent_log_command",
]
