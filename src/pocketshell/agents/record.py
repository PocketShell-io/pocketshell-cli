"""Telemetry hooks for agent kind/source recording."""
from __future__ import annotations
# __SIBLING_IMPORTS__


def record_agent_kind(*_args, **_kwargs) -> bool:
    """Compatibility hook retained for callers of the pre-aplexer launcher.

    Session metadata is owned by aplexer now. The old host-side option writer
    was a second source of truth and has been removed; launch remains
    successful when a caller still injects this optional hook in a test.
    """
    return False


def record_agent_source(*_args, **_kwargs) -> bool:
    """Compatibility hook for callers of the removed session source watcher."""
    return False
