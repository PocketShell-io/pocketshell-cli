"""Resolved filesystem locations for the hooks feature."""
from __future__ import annotations
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


# Engine identifiers. ``all`` is the CLI sentinel meaning "every engine".
ENGINES: tuple[str, ...] = ("claude", "codex", "opencode")


# Claude hook event names we register our command under. ``Stop`` /
# ``SubagentStop`` map to FINISHED; ``Notification`` maps to
# WAITING_FOR_INPUT (it cannot block and does not fire under ``-p``, but
# it is the only waiting-for-input signal Claude exposes).
CLAUDE_HOOK_EVENTS: tuple[str, ...] = ("Stop", "SubagentStop", "Notification")


# The OpenCode plugin filename we own. Stable so uninstall can find it.
OPENCODE_PLUGIN_FILENAME = "pocketshell-idle-signal.js"


# Handler script filenames written into the pocketshell hooks dir.
CLAUDE_HANDLER_NAME = "claude_hook.py"


CODEX_HANDLER_NAME = "codex_notify.py"


# The bus filename inside the volatile hooks cache dir.
EVENTS_FILENAME = "events.jsonl"


# Durable ownership/install marker. Engine config remains the authority for
# status; this marker identifies the generated data directory for operators and
# bootstrap fixtures without placing durable metadata in cache.
INSTALL_MARKER_NAME = ".installed"


# A stable marker string embedded in every generated handler + the
# OpenCode plugin so we can recognise our own entries even if the user's
# home moves. The handler paths always contain this marker because they
# live under the pocketshell hooks dir.
POCKETSHELL_MARKER = "pocketshell"


@dataclass(frozen=True)
class HooksPaths:
    """Resolved filesystem locations for the hooks feature.

    All engine config roots, the durable generated-data directory, and the
    volatile event file are fields so tests can point them at a tmp dir.
    Nothing in this module reads ``~`` directly — everything flows through
    here.
    """

    handler_dir: Path
    events_file: Path
    legacy_handler_dir: Path
    claude_settings: Path
    codex_config: Path
    opencode_plugin_dir: Path

    @property
    def install_marker(self) -> Path:
        return self.handler_dir / INSTALL_MARKER_NAME

    @property
    def claude_handler(self) -> Path:
        return self.handler_dir / CLAUDE_HANDLER_NAME

    @property
    def codex_handler(self) -> Path:
        return self.handler_dir / CODEX_HANDLER_NAME

    @property
    def legacy_claude_handler(self) -> Path:
        return self.legacy_handler_dir / CLAUDE_HANDLER_NAME

    @property
    def legacy_codex_handler(self) -> Path:
        return self.legacy_handler_dir / CODEX_HANDLER_NAME

    @property
    def legacy_install_marker(self) -> Path:
        return self.legacy_handler_dir / INSTALL_MARKER_NAME

    @property
    def opencode_plugin(self) -> Path:
        return self.opencode_plugin_dir / OPENCODE_PLUGIN_FILENAME


def _resolve_handler_dir(env_map, base_home: Path) -> Path:
    """Handler dir: explicit override > legacy alias > XDG data root."""
    handler_env = env_map.get("POCKETSHELL_HOOKS_HANDLER_DIR")
    legacy_hooks_env = env_map.get("POCKETSHELL_HOOKS_DIR")
    if handler_env:
        return Path(os.path.expanduser(handler_env))
    if legacy_hooks_env:
        return Path(os.path.expanduser(legacy_hooks_env))
    data_root_env = env_map.get("XDG_DATA_HOME")
    data_root = (
        Path(os.path.expanduser(data_root_env))
        if data_root_env
        else base_home / ".local" / "share"
    )
    return data_root / "pocketshell" / "hooks"


def _resolve_events_file(env_map, base_home: Path) -> Path:
    """Bus file: explicit override > XDG cache root (independent precedence)."""
    events_env = env_map.get("POCKETSHELL_HOOKS_EVENTS_FILE")
    if events_env:
        return Path(os.path.expanduser(events_env))
    cache_root_env = env_map.get("XDG_CACHE_HOME")
    cache_root = (
        Path(os.path.expanduser(cache_root_env))
        if cache_root_env
        else base_home / ".cache"
    )
    return cache_root / "pocketshell" / "hooks" / EVENTS_FILENAME


def _resolve_legacy_handler_dir(env_map, base_home: Path) -> Path:
    """Pre-durability default that co-located handlers and bus in cache."""
    legacy_hooks_env = env_map.get("POCKETSHELL_HOOKS_DIR")
    if legacy_hooks_env:
        return Path(os.path.expanduser(legacy_hooks_env))
    return base_home / ".cache" / "pocketshell" / "hooks"


def resolve_paths(
    *,
    home: Optional[Path] = None,
    env: Optional[dict[str, str]] = None,
) -> HooksPaths:
    """Return the :class:`HooksPaths` for ``home`` (default ``~``).

    Durable handler-dir precedence: ``$POCKETSHELL_HOOKS_HANDLER_DIR``,
    then ``$POCKETSHELL_HOOKS_DIR`` (historical alias), then
    ``$XDG_DATA_HOME/pocketshell/hooks``, then ``<home>/.local/share/...``.
    Volatile bus-file precedence is independent: ``$POCKETSHELL_HOOKS_EVENTS_FILE``,
    then ``$XDG_CACHE_HOME/pocketshell/hooks/events.jsonl``, then ``<home>/.cache/...``.
    Engine config roots always hang off ``home`` so a test can pass a
    throwaway home and be sure the real ``~/.claude`` etc. are never touched.
    """
    env_map = env if env is not None else os.environ
    base_home = home if home is not None else Path(os.path.expanduser("~"))

    return HooksPaths(
        handler_dir=_resolve_handler_dir(env_map, base_home),
        events_file=_resolve_events_file(env_map, base_home),
        legacy_handler_dir=_resolve_legacy_handler_dir(env_map, base_home),
        claude_settings=base_home / ".claude" / "settings.json",
        codex_config=base_home / ".codex" / "config.toml",
        opencode_plugin_dir=base_home / ".config" / "opencode" / "plugin",
    )
