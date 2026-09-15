"""Claude config-dir trust seeding."""
from __future__ import annotations
import json
import os
from pathlib import Path
from typing import Optional


def claude_config_path(env: dict[str, str]) -> Path:
    """Return the ``~/.claude.json`` path claude reads its trust state from.

    Honours ``CLAUDE_CONFIG_DIR`` (set when a non-default profile is
    selected) — claude stores ``.claude.json`` inside that dir; otherwise
    it lives at ``$HOME/.claude.json``.
    """
    config_dir = env.get("CLAUDE_CONFIG_DIR")
    if config_dir:
        return Path(config_dir).expanduser() / ".claude.json"
    home = env.get("HOME") or os.path.expanduser("~")
    return Path(home) / ".claude.json"


def _load_json_object(path: Path) -> Optional[dict]:
    """Read a JSON object from ``path``; ``{}`` when absent, ``None`` invalid."""
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else None


def _trust_entry(data: dict, directory: str) -> Optional[dict]:
    """The ``projects`` entry to mutate, or ``None`` when the shape is off."""
    projects = data.setdefault("projects", {})
    if not isinstance(projects, dict):
        return None
    entry = projects.setdefault(directory, {})
    return entry if isinstance(entry, dict) else None


def seed_claude_trust(config_path: Path, directory: str) -> None:
    """Pre-accept claude's workspace-trust dialog for ``directory``.

    claude gates the *"Is this a project you trust?"* modal on
    ``projects.<dir>.hasTrustDialogAccepted`` in ``~/.claude.json``; even
    ``--dangerously-skip-permissions`` does NOT skip it (#703), so the
    wrapper seeds the flag before exec. Best-effort and non-destructive:
    only the one nested flag changes; any error is swallowed so claude
    falls back to showing its own trust prompt (the old behaviour).
    """
    try:
        data = _load_json_object(config_path)
        entry = _trust_entry(data, directory) if data is not None else None
        if entry is None or entry.get("hasTrustDialogAccepted") is True:
            return  # corrupt shape, or already trusted; nothing to write
        entry["hasTrustDialogAccepted"] = True
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(
            json.dumps(data, ensure_ascii=False), encoding="utf-8"
        )
    except (OSError, ValueError):
        # Trust seeding is best-effort; a failure here only means claude
        # shows its own prompt (the old behaviour), never a broken launch.
        return
