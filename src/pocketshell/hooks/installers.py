"""Per-engine install/uninstall dispatch and shared cleanup."""
from __future__ import annotations
import json
from dataclasses import dataclass
from typing import Optional, Sequence
# --- sibling modules ---
from pocketshell.hooks.claude import _claude_is_fully_installed, _claude_is_installed, _claude_uninstall_commands, _load_claude_settings, claude_install
from pocketshell.hooks.codex import _extract_notify_command, _find_top_level_notify, codex_install, codex_uninstall
from pocketshell.hooks.handlers import _atomic_write_text, _claude_command, _codex_notify_value, _legacy_claude_command, _legacy_codex_notify_value, _opencode_plugin_source, _write_handlers
from pocketshell.hooks.paths import HooksPaths


@dataclass
class EngineResult:
    """Outcome of an install/uninstall action for one engine."""

    engine: str
    status: str
    message: str


def _install_claude(paths: HooksPaths) -> EngineResult:
    command = _claude_command(paths)
    legacy_command = _legacy_claude_command(paths)
    settings = _load_claude_settings(paths.claude_settings)
    legacy_present = _claude_is_installed(settings, legacy_command) and legacy_command != command
    if _claude_is_fully_installed(settings, command) and not legacy_present:
        return EngineResult("claude", "present", "hook already installed")
    cleaned = _claude_uninstall_commands(settings, [legacy_command])
    merged = claude_install(cleaned, command)
    _atomic_write_text(paths.claude_settings, json.dumps(merged, indent=2) + "\n")
    status = "migrated" if legacy_present else "installed"
    return EngineResult("claude", status, f"merged hook into {paths.claude_settings}")


def _uninstall_claude(paths: HooksPaths) -> EngineResult:
    commands = [_claude_command(paths), _legacy_claude_command(paths)]
    if not paths.claude_settings.exists():
        return EngineResult("claude", "absent", "no settings file")
    settings = _load_claude_settings(paths.claude_settings)
    if not any(_claude_is_installed(settings, command) for command in commands):
        return EngineResult("claude", "absent", "hook not present")
    cleaned = _claude_uninstall_commands(settings, commands)
    _atomic_write_text(paths.claude_settings, json.dumps(cleaned, indent=2) + "\n")
    return EngineResult("claude", "removed", f"removed hook from {paths.claude_settings}")


def _install_codex(paths: HooksPaths) -> EngineResult:
    text = paths.codex_config.read_text() if paths.codex_config.exists() else ""
    new_text, status = codex_install(
        text,
        _codex_notify_value(paths),
        replace_values=[_legacy_codex_notify_value(paths)],
    )
    if status == "skipped":
        return EngineResult(
            "codex",
            "skipped",
            "notify already set to another program; left untouched",
        )
    if status == "present":
        return EngineResult("codex", "present", "notify already installed")
    _atomic_write_text(paths.codex_config, new_text)
    result_status = "migrated" if status == "migrated" else "installed"
    return EngineResult("codex", result_status, f"set notify in {paths.codex_config}")


def _uninstall_codex(paths: HooksPaths) -> EngineResult:
    if not paths.codex_config.exists():
        return EngineResult("codex", "absent", "no config file")
    text = paths.codex_config.read_text()
    values = [_codex_notify_value(paths), _legacy_codex_notify_value(paths)]
    span = _find_top_level_notify(text)
    if span is None:
        return EngineResult("codex", "absent", "no notify entry")
    existing = _extract_notify_command(text[span[0]:span[1]])
    owned = next((value for value in values if existing == value), None)
    if owned is None:
        return EngineResult("codex", "skipped", "notify points elsewhere; left untouched")
    new_text, _ = codex_uninstall(text, owned)
    _atomic_write_text(paths.codex_config, new_text)
    return EngineResult("codex", "removed", f"removed notify from {paths.codex_config}")


def _install_opencode(paths: HooksPaths) -> EngineResult:
    paths.opencode_plugin_dir.mkdir(parents=True, exist_ok=True)
    source = _opencode_plugin_source(paths)
    if paths.opencode_plugin.exists():
        # Rewrite to keep the source current; idempotent for status.
        existing = paths.opencode_plugin.read_text()
        if existing == source:
            return EngineResult("opencode", "present", "plugin already installed")
    _atomic_write_text(paths.opencode_plugin, source)
    return EngineResult("opencode", "installed", f"wrote plugin {paths.opencode_plugin}")


def _uninstall_opencode(paths: HooksPaths) -> EngineResult:
    if not paths.opencode_plugin.exists():
        return EngineResult("opencode", "absent", "plugin not present")
    paths.opencode_plugin.unlink()
    return EngineResult("opencode", "removed", f"removed plugin {paths.opencode_plugin}")


_INSTALLERS = {
    "claude": _install_claude,
    "codex": _install_codex,
    "opencode": _install_opencode,
}


_UNINSTALLERS = {
    "claude": _uninstall_claude,
    "codex": _uninstall_codex,
    "opencode": _uninstall_opencode,
}


def install_engines(engines: Sequence[str], paths: HooksPaths) -> list[EngineResult]:
    """Install hooks for ``engines`` and return one result per engine."""
    _write_handlers(paths, engines)
    results = [_INSTALLERS[engine](paths) for engine in engines]
    _cleanup_migrated_legacy_artifacts(paths, results)
    return results


def uninstall_engines(engines: Sequence[str], paths: HooksPaths) -> list[EngineResult]:
    """Uninstall hooks for ``engines`` and return one result per engine.

    Generated executable/metadata files are removed from durable data once no
    PocketShell engine config references them. The volatile bus is preserved so
    already-emitted events stay readable.
    """
    results = [_UNINSTALLERS[engine](paths) for engine in engines]
    _maybe_cleanup_handlers(set(engines), paths)
    return results


def _maybe_cleanup_handlers(engines: set[str], paths: HooksPaths) -> None:
    """Remove current + legacy generated artifacts, never the event bus."""
    if "claude" in engines and paths.claude_handler.exists():
        paths.claude_handler.unlink()
    if (
        "claude" in engines
        and paths.legacy_claude_handler != paths.claude_handler
        and paths.legacy_claude_handler.exists()
    ):
        paths.legacy_claude_handler.unlink()
    if "codex" in engines and paths.codex_handler.exists():
        paths.codex_handler.unlink()
    if (
        "codex" in engines
        and paths.legacy_codex_handler != paths.codex_handler
        and paths.legacy_codex_handler.exists()
    ):
        paths.legacy_codex_handler.unlink()
    if not _any_current_install_reference(paths) and paths.install_marker.exists():
        paths.install_marker.unlink()
    if not _any_legacy_install_reference(paths) and paths.legacy_install_marker.exists():
        paths.legacy_install_marker.unlink()


def _cleanup_migrated_legacy_artifacts(
    paths: HooksPaths,
    results: Sequence[EngineResult],
) -> None:
    """Delete obsolete executables only after their config migration landed."""
    migrated = {result.engine for result in results if result.status == "migrated"}
    if "claude" in migrated and paths.legacy_claude_handler.exists():
        if paths.legacy_claude_handler != paths.claude_handler:
            paths.legacy_claude_handler.unlink()
    if "codex" in migrated and paths.legacy_codex_handler.exists():
        if paths.legacy_codex_handler != paths.codex_handler:
            paths.legacy_codex_handler.unlink()
    if not _any_legacy_install_reference(paths) and paths.legacy_install_marker.exists():
        if paths.legacy_install_marker != paths.install_marker:
            paths.legacy_install_marker.unlink()


def _codex_configured_value(paths: HooksPaths) -> Optional[list[str]]:
    if not paths.codex_config.exists():
        return None
    text = paths.codex_config.read_text()
    span = _find_top_level_notify(text)
    if span is None:
        return None
    return _extract_notify_command(text[span[0]:span[1]])


def _any_current_install_reference(paths: HooksPaths) -> bool:
    try:
        settings = _load_claude_settings(paths.claude_settings)
    except (ValueError, json.JSONDecodeError):
        settings = {}
    return (
        _claude_is_installed(settings, _claude_command(paths))
        or _codex_configured_value(paths) == _codex_notify_value(paths)
        or paths.opencode_plugin.exists()
    )


def _any_legacy_install_reference(paths: HooksPaths) -> bool:
    try:
        settings = _load_claude_settings(paths.claude_settings)
    except (ValueError, json.JSONDecodeError):
        settings = {}
    return (
        _claude_is_installed(settings, _legacy_claude_command(paths))
        or _codex_configured_value(paths) == _legacy_codex_notify_value(paths)
    )
