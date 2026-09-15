"""Merge-style install/uninstall of hooks in Claude Code settings.json."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Optional, Sequence
# --- sibling modules ---
from pocketshell.hooks.paths import CLAUDE_HOOK_EVENTS


def _load_claude_settings(path: Path) -> dict[str, Any]:
    """Load Claude settings JSON, returning ``{}`` when absent/blank.

    A malformed settings file raises ``ValueError`` so install/uninstall
    refuse to silently clobber a file we cannot parse.
    """
    if not path.exists():
        return {}
    text = path.read_text()
    if not text.strip():
        return {}
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a JSON object at the top level")
    return data


def _our_claude_group(command: str) -> dict[str, Any]:
    """The hook *group* we add under each Claude event."""
    return {"hooks": [{"type": "command", "command": command}]}


def _group_is_ours(group: Any, command: str) -> bool:
    """True when ``group`` is a hook group containing only our command.

    We match on the command string so a user group with the same shape
    but a different command is never treated as ours.
    """
    if not isinstance(group, dict):
        return False
    inner = group.get("hooks")
    if not isinstance(inner, list):
        return False
    return any(
        isinstance(h, dict) and h.get("type") == "command" and h.get("command") == command
        for h in inner
    )


def claude_install(settings: dict[str, Any], command: str) -> dict[str, Any]:
    """Return ``settings`` with our hook command merged in (pure function).

    Adds ``command`` under each of :data:`CLAUDE_HOOK_EVENTS` only when
    no existing group already carries it. Existing keys, existing hook
    events, and existing groups are preserved. Idempotent.
    """
    result = json.loads(json.dumps(settings))  # deep copy
    hooks_obj = result.get("hooks")
    if not isinstance(hooks_obj, dict):
        hooks_obj = {}
        result["hooks"] = hooks_obj

    for event in CLAUDE_HOOK_EVENTS:
        groups = hooks_obj.get(event)
        if not isinstance(groups, list):
            groups = []
            hooks_obj[event] = groups
        already = any(_group_is_ours(group, command) for group in groups)
        if not already:
            groups.append(_our_claude_group(command))
    return result


def _kept_groups(groups: list[Any], command: str) -> Optional[list[Any]]:
    """Filter our command out of one event's groups; ``None`` if all dropped.

    Groups we do not recognise (or that hold other hooks) pass through
    untouched; a group that loses some hooks keeps its remaining metadata.
    """
    kept_groups: list[Any] = []
    for group in groups:
        if not isinstance(group, dict) or not isinstance(group.get("hooks"), list):
            kept_groups.append(group)
            continue
        kept_hooks = [
            hook
            for hook in group["hooks"]
            if not (
                isinstance(hook, dict)
                and hook.get("type") == "command"
                and hook.get("command") == command
            )
        ]
        if len(kept_hooks) == len(group["hooks"]):
            kept_groups.append(group)
        elif kept_hooks:
            kept_group = dict(group)
            kept_group["hooks"] = kept_hooks
            kept_groups.append(kept_group)
    return kept_groups


def claude_uninstall(settings: dict[str, Any], command: str) -> dict[str, Any]:
    """Return ``settings`` with our hook command removed (pure function).

    Removes only matching command entries from each Claude event. If a user has
    placed another hook in the same group, that hook and all group metadata are
    preserved. Empty groups/events are dropped; the top-level ``hooks`` object
    is dropped only when it no longer holds user data. Idempotent.
    """
    result = json.loads(json.dumps(settings))  # deep copy
    hooks_obj = result.get("hooks")
    if not isinstance(hooks_obj, dict):
        return result

    for event in CLAUDE_HOOK_EVENTS:
        groups = hooks_obj.get(event)
        if not isinstance(groups, list):
            continue
        kept_groups = _kept_groups(groups, command)
        if kept_groups:
            hooks_obj[event] = kept_groups
        else:
            del hooks_obj[event]

    if not hooks_obj:
        del result["hooks"]
    return result


def _claude_uninstall_commands(
    settings: dict[str, Any],
    commands: Sequence[str],
) -> dict[str, Any]:
    """Remove every exact PocketShell-owned command in ``commands``."""
    result = settings
    for command in dict.fromkeys(commands):
        result = claude_uninstall(result, command)
    return result


def _claude_is_installed(settings: dict[str, Any], command: str) -> bool:
    hooks_obj = settings.get("hooks")
    if not isinstance(hooks_obj, dict):
        return False
    for event in CLAUDE_HOOK_EVENTS:
        groups = hooks_obj.get(event)
        if isinstance(groups, list) and any(_group_is_ours(g, command) for g in groups):
            return True
    return False


def _claude_is_fully_installed(settings: dict[str, Any], command: str) -> bool:
    """True only when every configured Claude event carries ``command``."""
    hooks_obj = settings.get("hooks")
    if not isinstance(hooks_obj, dict):
        return False
    return all(
        isinstance(hooks_obj.get(event), list)
        and any(_group_is_ours(group, command) for group in hooks_obj[event])
        for event in CLAUDE_HOOK_EVENTS
    )
