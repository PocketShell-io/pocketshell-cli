"""Aplexer launch-spec helpers."""
from __future__ import annotations
from pathlib import Path
from typing import Optional
from pocketshell.runtime import aplexer
# __SIBLING_IMPORTS__


def _aplexer_profile_id(config_dir: Optional[str]) -> Optional[str]:
    """Dir-stem aplexer uses as the profile id (``zlaude`` from ``~/.zlaude``)."""
    if not config_dir:
        return None
    stem = Path(config_dir).name.lstrip(".")
    return stem or None


def _aplexer_launch_spec(
    kind: str,
    cwd: str,
    *,
    skip_permissions: bool,
    config_dir: Optional[str],
) -> Optional[dict]:
    """``a launch-spec --json`` or None on skip/failure.

    PocketShell still owns folder ``.env`` merge and Claude trust seeding;
    this is only argv + provider-strip + engine env.
    """
    args = ["launch-spec", "--engine", kind, "--cwd", cwd]
    if not skip_permissions:
        args.append("--no-skip-permissions")
    profile_id = _aplexer_profile_id(config_dir)
    if profile_id:
        args.extend(["--profile", profile_id])
    payload = aplexer.run_json(
        args, feature="launch", timeout=aplexer.LAUNCH_TIMEOUT_S
    )
    if not isinstance(payload, dict):
        return None
    argv = payload.get("argv")
    if not isinstance(argv, list) or not argv:
        return None
    return payload
