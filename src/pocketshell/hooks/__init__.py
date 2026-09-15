"""`pocketshell hooks` subcommand group — agent stop/idle detection.

Installs **stop / idle-detection** hooks across the three agent engines
PocketShell cares about (Claude Code, Codex, OpenCode) and normalizes
their per-engine events into a single append-only JSONL bus the Android
app (and, later, an assistant supervisor) can read back.

This is **integration only** for now — the "check status and tell the
agent to continue" UX is a later issue. The empirical mechanism this
ports lives in the sibling ``stop-handle`` PoC repo; see issue #267 and
locked decision **D26** in ``docs/decisions.md``.

Design — merge, never clobber (D26)
-----------------------------------

``install`` is **non-destructive**. It reads each engine's existing
config and adds only our entries when they are absent, preserving every
other key and any pre-existing hooks:

- **Claude Code** — ``~/.claude/settings.json`` (JSON). We add a
  ``{type: "command", command: "python3 <handler>"}`` entry under the
  ``Stop``, ``SubagentStop`` and ``Notification`` hook events. Existing
  hook groups under those events are preserved; we only append our own
  group when it is not already present. All other top-level keys are
  left untouched.

- **Codex** — ``~/.codex/config.toml`` (TOML). We set the top-level
  ``notify`` program to our handler. Codex hooks do NOT fire under
  ``codex exec`` (proven in the PoC), so ``notify`` is the headless-safe
  signal. If ``notify`` is already set to *something else*, we **warn
  and skip** rather than clobber the user's program. The rest of the
  TOML is preserved byte-for-byte.

- **OpenCode** — a plugin file dropped into the OpenCode plugin dir
  (``~/.config/opencode/plugin/`` global, ``plugin/`` singular in
  1.15.12). Other plugins in that dir are untouched.

``install`` is **idempotent**: running it twice adds nothing new.

``uninstall`` removes **only** what we added and is idempotent. After an
``install`` → ``uninstall`` round-trip a pre-populated Claude settings
file is byte-equivalent for the unrelated parts, a Codex ``config.toml``
keeps all unrelated content, and other OpenCode plugins are untouched.

Per-engine uninstall procedure
------------------------------

- **Claude Code** — our command entry (and any hook group / event key we
  emptied) is removed from ``~/.claude/settings.json``. Event keys and
  the top-level ``hooks`` object are deleted only if *we* created them
  and they end up empty; a user's pre-existing hooks always survive.
- **Codex** — the top-level ``notify`` line is removed from
  ``~/.codex/config.toml`` **only** if it still points at our handler.
  A ``notify`` the user pointed elsewhere is left alone.
- **OpenCode** — our plugin file is deleted from the plugin dir. Other
  plugins, and the dir itself, are left in place.

Generated executable handlers and their ownership marker are durable data:
``$XDG_DATA_HOME/pocketshell/hooks`` (default
``~/.local/share/pocketshell/hooks``). The volatile event bus remains cache:
``$XDG_CACHE_HOME/pocketshell/hooks/events.jsonl`` (default
``~/.cache/pocketshell/hooks/events.jsonl``). The handlers embed that separate
bus path, so deleting the cache recreates an empty bus without deleting the
programs referenced by Claude and Codex.

``$POCKETSHELL_HOOKS_HANDLER_DIR`` overrides the durable handler directory and
``$POCKETSHELL_HOOKS_EVENTS_FILE`` overrides the bus file. The historical
``$POCKETSHELL_HOOKS_DIR`` name remains a handler-directory alias when the new
handler override is unset; it no longer silently relocates the bus. Set the two
new variables explicitly when both locations need overriding, then reinstall so
the generated handlers embed the selected bus file.
"""
from __future__ import annotations

from pocketshell.hooks.providers.claude import (
    claude_install,
    claude_uninstall,
)
from pocketshell.hooks.cli import (
    hooks_group,
)
from pocketshell.hooks.providers.codex import (
    codex_install,
    codex_uninstall,
)
from pocketshell.hooks.installers import (
    EngineResult,
    install_engines,
    uninstall_engines,
)
from pocketshell.hooks.paths import (
    ENGINES,
    CLAUDE_HOOK_EVENTS,
    OPENCODE_PLUGIN_FILENAME,
    CLAUDE_HANDLER_NAME,
    CODEX_HANDLER_NAME,
    EVENTS_FILENAME,
    INSTALL_MARKER_NAME,
    POCKETSHELL_MARKER,
    HooksPaths,
    resolve_paths,
)
from pocketshell.hooks.status import (
    engine_status,
    read_events,
)

__all__ = [
    "ENGINES",
    "CLAUDE_HOOK_EVENTS",
    "OPENCODE_PLUGIN_FILENAME",
    "CLAUDE_HANDLER_NAME",
    "CODEX_HANDLER_NAME",
    "EVENTS_FILENAME",
    "INSTALL_MARKER_NAME",
    "POCKETSHELL_MARKER",
    "HooksPaths",
    "resolve_paths",
    "claude_install",
    "claude_uninstall",
    "codex_install",
    "codex_uninstall",
    "EngineResult",
    "install_engines",
    "uninstall_engines",
    "engine_status",
    "read_events",
    "hooks_group",
]
