"""`pocketshell agent-log` conversation domain.

Mirrors the per-engine JSONL conversation-log reads the Android app
currently runs over SSH (see ``AgentConversationRepository`` in
``app/src/main/java/com/pocketshell/app/session/``). The default command
still reads the raw JSONL so the Android client (and the planned IPC
daemon, #219) can cache + serve the same bytes the agent CLI wrote to
disk. The ``handoff`` subcommand adds a deliberately smaller export path:
it parses only user/assistant prose needed for cross-agent continuation
and skips tool calls/results by default.

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
  default read path emits raw lines verbatim. The ``handoff`` path only
  extracts the portable message subset (human/user + assistant text) so
  it can produce a compact Markdown artifact without raw tool JSON.
- ``--json`` wraps the same raw lines in a small envelope (``engine``,
  ``session``, ``path``, ``lines``, ``count``) so machine consumers
  (the planned daemon, integration tests) can pin to a stable shape
  without re-parsing the JSONL themselves.
"""
from __future__ import annotations

from pocketshell.agents.conversations.cli import (
    agent_log_command,
    handoff_command,
)
from pocketshell.agents.conversations.messages import (
    HandoffMessage,
)
from pocketshell.agents.conversations.resolve import (
    _resolve_claude_path,
    _resolve_codex_path,
    _resolve_grok_path,
    _resolve_opencode_path,
)

__all__ = [
    "HandoffMessage",
    "_resolve_claude_path",
    "_resolve_codex_path",
    "_resolve_grok_path",
    "_resolve_opencode_path",
    "agent_log_command",
    "handoff_command",
]
