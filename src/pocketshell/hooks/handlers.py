"""Generated handler/plugin sources written at install time."""
from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Sequence
# --- sibling modules ---
from pocketshell.hooks.paths import HooksPaths


_CLAUDE_HANDLER_SOURCE = '''\
#!/usr/bin/env python3
"""PocketShell Claude Code stop/idle hook handler (generated).

Registered for Stop / SubagentStop / Notification. Reads the hook
payload on stdin and appends a normalized record to the pocketshell
event bus configured at install time. Side-effect only: it never blocks the
stop and never injects a follow-up (integration only; see D26).
"""
import json
import os
import sys
from datetime import datetime, timezone

EVENTS_FILE = __POCKETSHELL_EVENTS_FILE__


def main():
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        payload = {}

    event_name = payload.get("hook_event_name", "")
    if event_name == "Notification":
        state = "WAITING_FOR_INPUT"
    elif event_name in ("Stop", "SubagentStop"):
        state = "FINISHED"
    else:
        state = "UNKNOWN"

    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "engine": "claude-code",
        "state": state,
        "source": "hook",
        "session_id": payload.get("session_id"),
        "cwd": payload.get("cwd"),
        "hook_event_name": event_name or None,
        "notification_type": payload.get("notification_type"),
        "transcript_path": payload.get("transcript_path"),
        "last_assistant_message": payload.get("last_assistant_message"),
    }
    os.makedirs(os.path.dirname(EVENTS_FILE), exist_ok=True)
    with open(EVENTS_FILE, "a") as handle:
        handle.write(json.dumps(record) + "\\n")
    # Exit clean with no stdout so Claude proceeds with the stop.
    sys.exit(0)


if __name__ == "__main__":
    main()
'''


_CODEX_HANDLER_SOURCE = '''\
#!/usr/bin/env python3
"""PocketShell Codex notify handler (generated).

Codex invokes ``notify`` with ONE argv: a JSON string describing the
event (notably ``agent-turn-complete`` after every ``codex exec`` turn).
Fire-and-forget; we just append a normalized record to the pocketshell
event bus configured at install time.
"""
import json
import os
import sys
from datetime import datetime, timezone

EVENTS_FILE = __POCKETSHELL_EVENTS_FILE__


def main():
    raw = sys.argv[1] if len(sys.argv) > 1 else "{}"
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        payload = {}

    ntype = payload.get("type", "")
    state = "FINISHED" if ntype in ("agent-turn-complete", "turn-complete") else "NOTIFY"
    # Codex uses dashed keys in notify payloads.
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "engine": "codex",
        "state": state,
        "source": "notify",
        "session_id": payload.get("thread-id") or payload.get("session-id"),
        "cwd": payload.get("cwd"),
        "notify_type": ntype or None,
        "turn_id": payload.get("turn-id"),
        "last_assistant_message": payload.get("last-assistant-message"),
    }
    os.makedirs(os.path.dirname(EVENTS_FILE), exist_ok=True)
    with open(EVENTS_FILE, "a") as handle:
        handle.write(json.dumps(record) + "\\n")
    sys.exit(0)


if __name__ == "__main__":
    main()
'''


_OPENCODE_PLUGIN_SOURCE = '''\
// PocketShell OpenCode idle-signal plugin (generated).
//
// Auto-loaded from the OpenCode plugin dir. The `event` hook fires for
// every bus event; we emit a normalized record to the pocketshell event
// bus when a session goes idle (FINISHED), asks for permission
// (WAITING_FOR_INPUT), or errors (ERROR). Integration only — no
// continue/stop decision (see D26).
import fs from "node:fs";
import path from "node:path";

const EVENTS_FILE = __POCKETSHELL_EVENTS_FILE__;

export const PocketShellIdleSignal = async () => {
  function emit(state, event) {
    const rec = {
      ts: new Date().toISOString(),
      engine: "opencode",
      state,
      source: "plugin",
      session_id: event.properties?.sessionID,
      payload: event,
    };
    try {
      fs.mkdirSync(path.dirname(EVENTS_FILE), { recursive: true });
      fs.appendFileSync(EVENTS_FILE, JSON.stringify(rec) + "\\n");
    } catch (e) {
      // best-effort; never throw out of a plugin hook
    }
  }
  return {
    event: async ({ event }) => {
      if (event.type === "session.idle") {
        emit("FINISHED", event);
      } else if (event.type === "permission.asked") {
        emit("WAITING_FOR_INPUT", event);
      } else if (event.type === "session.error") {
        emit("ERROR", event);
      }
    },
  };
};
'''


def _handler_source(template: str, events_file: Path) -> str:
    """Render a generated handler with its independent absolute bus path."""
    return template.replace("__POCKETSHELL_EVENTS_FILE__", repr(str(events_file)))


def _opencode_plugin_source(paths: HooksPaths) -> str:
    """Render the OpenCode plugin with the same separately resolved bus."""
    return _OPENCODE_PLUGIN_SOURCE.replace(
        "__POCKETSHELL_EVENTS_FILE__",
        json.dumps(str(paths.events_file)),
    )


def _claude_command(paths: HooksPaths) -> str:
    """The exact command string we register in Claude's settings."""
    return f"python3 {paths.claude_handler}"


def _codex_notify_value(paths: HooksPaths) -> list[str]:
    """The exact ``notify`` array we set in Codex config.toml."""
    return ["python3", str(paths.codex_handler)]


def _legacy_claude_command(paths: HooksPaths) -> str:
    """The pre-durability command whose executable lived in cache."""
    return f"python3 {paths.legacy_claude_handler}"


def _legacy_codex_notify_value(paths: HooksPaths) -> list[str]:
    """The pre-durability Codex notify value whose executable lived in cache."""
    return ["python3", str(paths.legacy_codex_handler)]


def _atomic_write_text(path: Path, text: str) -> None:
    """Atomically replace ``path`` without exposing a half-written config."""
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o600
    temp = path.parent / f".{path.name}.pocketshell-{os.getpid()}"
    try:
        with temp.open("w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        temp.chmod(mode)
        os.replace(temp, path)
    finally:
        if temp.exists():
            temp.unlink()


def _write_handlers(paths: HooksPaths, engines: Sequence[str]) -> None:
    """Write selected generated handlers and metadata into durable XDG data."""
    paths.handler_dir.mkdir(parents=True, exist_ok=True)
    if "claude" in engines:
        _atomic_write_text(
            paths.claude_handler,
            _handler_source(_CLAUDE_HANDLER_SOURCE, paths.events_file),
        )
        paths.claude_handler.chmod(0o755)
    if "codex" in engines:
        _atomic_write_text(
            paths.codex_handler,
            _handler_source(_CODEX_HANDLER_SOURCE, paths.events_file),
        )
        paths.codex_handler.chmod(0o755)
    _atomic_write_text(
        paths.install_marker,
        json.dumps(
            {
                "schema": 1,
                "handler_dir": str(paths.handler_dir),
                "events_file": str(paths.events_file),
            },
            sort_keys=True,
        ) + "\n",
    )
