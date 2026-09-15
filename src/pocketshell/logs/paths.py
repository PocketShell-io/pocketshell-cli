"""Log-store file locations and durability constants."""
from __future__ import annotations
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


# Schema version stamped on every normalized record.
SCHEMA_VERSION = 1

# Recognised event kinds; ``agent`` and ``app`` are the two file families
# on disk.
AGENT_KINDS: tuple[str, ...] = ("agent_action", "engine_event")
APP_KINDS: tuple[str, ...] = ("app_log", "crash")
KNOWN_KINDS: tuple[str, ...] = AGENT_KINDS + APP_KINDS

# Recognised event sources.
KNOWN_SOURCES: tuple[str, ...] = ("phone", "cli")

# File permissions for any freshly-created log file. ``0600`` keeps the
# record readable only by the owning user — it can hold command lines.
NEW_FILE_MODE = 0o600

# Cursor file recording how far ``import-hooks`` has drained the hooks
# bus, so re-running it never duplicates engine events.
HOOKS_CURSOR_FILENAME = "hooks-import.cursor"


@dataclass(frozen=True)
class LogsPaths:
    """Resolved filesystem locations for the logs feature.

    Both the canonical logs dir and the hooks bus path are fields so the
    unit suite can point them at a tmp dir. Nothing in this module reads
    ``~`` directly — everything flows through here.
    """

    logs_dir: Path
    hooks_events_file: Path

    @property
    def cursor_file(self) -> Path:
        return self.logs_dir / HOOKS_CURSOR_FILENAME

    def agent_file(self, day: str) -> Path:
        return self.logs_dir / f"agent-{day}.jsonl"

    def app_file(self, day: str) -> Path:
        return self.logs_dir / f"app-{day}.jsonl"

    def file_for_kind(self, kind: str, day: str) -> Path:
        """Return the dated log file a given ``kind`` lands in."""
        if kind in APP_KINDS:
            return self.app_file(day)
        return self.agent_file(day)

    def files_for_family(self, family: str) -> list[Path]:
        """Return existing dated files for a log family (``agent``/``app``).

        Sorted by name, which is chronological because the date is
        zero-padded ``YYYYMMDD``.
        """
        if not self.logs_dir.exists():
            return []
        return sorted(self.logs_dir.glob(f"{family}-*.jsonl"))


def _logs_dir(env_map: dict[str, str], base_home: Path) -> Path:
    """The canonical logs dir: ``$XDG_STATE_HOME`` wins, else
    ``<home>/.local/state``."""
    xdg_state = env_map.get("XDG_STATE_HOME")
    if xdg_state:
        state_root = Path(os.path.expanduser(xdg_state))
    else:
        state_root = base_home / ".local" / "state"
    return state_root / "pocketshell" / "logs"


def _hooks_bus_path(env_map: dict[str, str], base_home: Path) -> Path:
    """The volatile hooks bus path, mirroring
    :func:`pocketshell.hooks.resolve_paths`: ``$POCKETSHELL_HOOKS_EVENTS_FILE``
    wins, else ``$XDG_CACHE_HOME`` / ``<home>/.cache``. ``$POCKETSHELL_HOOKS_DIR``
    is only the historical handler-directory alias; it deliberately does not
    relocate this cache bus."""
    hooks_events_env = env_map.get("POCKETSHELL_HOOKS_EVENTS_FILE")
    if hooks_events_env:
        return Path(os.path.expanduser(hooks_events_env))
    cache_root_env = env_map.get("XDG_CACHE_HOME")
    cache_root = (
        Path(os.path.expanduser(cache_root_env))
        if cache_root_env
        else base_home / ".cache"
    )
    return cache_root / "pocketshell" / "hooks" / "events.jsonl"


def resolve_paths(
    *,
    home: Optional[Path] = None,
    env: Optional[dict[str, str]] = None,
) -> LogsPaths:
    """Return the :class:`LogsPaths` for the current (or given) environment."""
    env_map = env if env is not None else os.environ
    base_home = home if home is not None else Path(os.path.expanduser("~"))
    return LogsPaths(
        logs_dir=_logs_dir(env_map, base_home),
        hooks_events_file=_hooks_bus_path(env_map, base_home),
    )
