"""Durable workspace membership and its command surface."""

from pocketshell.tree.workspaces.membership import (
    MAX_OPEN_TABS,
    WORKSPACE_KEY,
    get_workspace,
    upsert_workspace,
)

__all__ = [
    "WORKSPACE_KEY",
    "MAX_OPEN_TABS",
    "get_workspace",
    "upsert_workspace",
]
