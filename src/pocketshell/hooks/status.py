"""Per-engine install status and event-bus reads."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Optional
# --- sibling modules ---
from pocketshell.hooks.providers.claude import _claude_is_fully_installed, _load_claude_settings
from pocketshell.hooks.handlers import _claude_command, _codex_notify_value, _legacy_claude_command, _legacy_codex_notify_value
from pocketshell.hooks.installers import _codex_configured_value
from pocketshell.hooks.paths import ENGINES, HooksPaths


def _engine_status_dict(
    engine: str,
    config_path: Path,
    handler: Path,
    *,
    configured: bool,
    legacy: bool,
) -> dict[str, Any]:
    """Build the shared status envelope for a config+handler engine."""
    return {
        "engine": engine,
        "installed": configured and handler.exists(),
        "configured": configured,
        "legacy": legacy,
        "config_path": str(config_path),
        "config_exists": config_path.exists(),
        "handler_path": str(handler),
        "handler_exists": handler.exists(),
    }


def _claude_status(paths: HooksPaths) -> dict[str, Any]:
    """Status for Claude: fully-installed check over all hook events."""
    command = _claude_command(paths)
    legacy_command = _legacy_claude_command(paths)
    try:
        settings = _load_claude_settings(paths.claude_settings)
    except ValueError:
        settings = {}
    current_configured = _claude_is_fully_installed(settings, command)
    legacy_configured = _claude_is_fully_installed(settings, legacy_command)
    legacy = legacy_configured and not current_configured
    handler = paths.legacy_claude_handler if legacy else paths.claude_handler
    return _engine_status_dict(
        "claude",
        paths.claude_settings,
        handler,
        configured=current_configured or legacy_configured,
        legacy=legacy,
    )


def _codex_status(paths: HooksPaths) -> dict[str, Any]:
    """Status for Codex: configured-value comparison in config.toml."""
    configured_value = _codex_configured_value(paths)
    current_configured = configured_value == _codex_notify_value(paths)
    legacy_configured = configured_value == _legacy_codex_notify_value(paths)
    legacy = legacy_configured and not current_configured
    handler = paths.legacy_codex_handler if legacy else paths.codex_handler
    return _engine_status_dict(
        "codex",
        paths.codex_config,
        handler,
        configured=current_configured or legacy_configured,
        legacy=legacy,
    )


def _opencode_status(paths: HooksPaths) -> dict[str, Any]:
    """Status for OpenCode: the plugin file is both config and handler."""
    return _engine_status_dict(
        "opencode",
        paths.opencode_plugin,
        paths.opencode_plugin,
        configured=paths.opencode_plugin.exists(),
        legacy=False,
    )


def engine_status(engine: str, paths: HooksPaths) -> dict[str, Any]:
    """Return a status dict for one ``engine``."""
    if engine == "claude":
        return _claude_status(paths)
    if engine == "codex":
        return _codex_status(paths)
    return _opencode_status(paths)


def _parse_event_line(line: str, since: Optional[str]) -> Optional[dict[str, Any]]:
    """Parse one bus line; ``None`` when malformed/not-a-dict/too old."""
    try:
        obj = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(obj, dict):
        return None
    if since is not None:
        ts = obj.get("ts")
        if not isinstance(ts, str) or ts <= since:
            return None
    return obj


def read_events(
    paths: HooksPaths,
    *,
    limit: Optional[int] = None,
    since: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Read normalized records from the bus (most-recent-last order).

    ``limit`` keeps only the last N records. ``since`` keeps records
    whose ``ts`` is lexicographically greater than the value (ISO-8601
    timestamps sort correctly as strings). Malformed lines are skipped.
    """
    if not paths.events_file.exists():
        return []
    records: list[dict[str, Any]] = []
    for line in paths.events_file.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        obj = _parse_event_line(line, since)
        if obj is not None:
            records.append(obj)
    if limit is not None and limit >= 0:
        records = records[-limit:]
    return records


def _resolve_engines(engine: str) -> list[str]:
    if engine == "all":
        return list(ENGINES)
    return [engine]
