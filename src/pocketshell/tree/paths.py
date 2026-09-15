"""Tree registry file locations."""
from __future__ import annotations
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Optional


# File permissions for the registry file. ``0600`` keeps the per-host tree
# state readable only by the owning user, matching usage.capture.
NEW_FILE_MODE = 0o600


REGISTRY_FILENAME = "registry.json"


# Optimistic-grace guard, mirrored from ``HostTreeModel.OPTIMISTIC_GRACE_MS``
# (30 s, expressed in seconds here). A node the registry holds but live
# The live listing does not yet report is NOT pruned while it is still within
# this window of its ``optimistic_since`` stamp, so a session the client just
# created (and upserted optimistically) survives the immediately-following
# reconcile that has not yet observed it.
OPTIMISTIC_GRACE_SECS = 30.0


@dataclass(frozen=True)
class TreePaths:
    """Resolved filesystem location for the tree registry.

    The path is a field so the unit suite can point it at a tmp dir; nothing in
    this module reads ``~`` directly — everything flows through
    :func:`resolve_paths`.
    """

    tree_dir: Path

    @property
    def registry_file(self) -> Path:
        return self.tree_dir / REGISTRY_FILENAME

    @property
    def lock_file(self) -> Path:
        return self.tree_dir / (REGISTRY_FILENAME + ".lock")


def resolve_paths(
    *,
    home: Optional[Path] = None,
    env: Optional[Mapping[str, str]] = None,
) -> TreePaths:
    """Return the :class:`TreePaths` for the current (or given) environment.

    Precedence for the tree state dir:

    1. ``$XDG_STATE_HOME/pocketshell/tree`` when ``$XDG_STATE_HOME`` is set.
    2. ``<home>/.local/state/pocketshell/tree``.

    Mirrors :func:`pocketshell.usage.capture.resolve_paths` so all PocketShell
    durable state lives under one XDG-state root.
    """
    env_map = env if env is not None else os.environ
    base_home = home if home is not None else Path(os.path.expanduser("~"))

    xdg_state = env_map.get("XDG_STATE_HOME")
    if xdg_state:
        state_root = Path(os.path.expanduser(xdg_state))
    else:
        state_root = base_home / ".local" / "state"
    tree_dir = state_root / "pocketshell" / "tree"
    return TreePaths(tree_dir=tree_dir)
