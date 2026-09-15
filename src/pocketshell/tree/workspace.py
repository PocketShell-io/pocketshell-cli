"""Per-host workspace tab groups (default workspace + cap)."""
from __future__ import annotations
from typing import Any, Mapping, Optional
# --- sibling modules ---
from pocketshell.tree.model import _cli_version
from pocketshell.tree.paths import TreePaths, resolve_paths
from pocketshell.tree.storage import _read_registry, _registry_lock, _write_registry


WORKSPACE_KEY = "default"


MAX_OPEN_TABS = 12


def _normalise_absolute_path(raw: Any) -> Optional[str]:
    """Return a canonical absolute Unix path, or ``None`` if invalid."""
    if not isinstance(raw, str):
        return None
    path = raw.strip()
    if not path.startswith("/"):
        return None
    parts: list[str] = []
    for part in path.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return "/" + "/".join(parts) if parts else "/"


def _normalise_tab(raw: Any) -> Optional[dict[str, Any]]:
    if not isinstance(raw, Mapping):
        return None
    path = _normalise_absolute_path(raw.get("path"))
    if path is None:
        return None
    stamp = raw.get("last_activated_ms", 0)
    try:
        last_activated_ms = int(stamp)
    except (TypeError, ValueError):
        return None
    return {"path": path, "last_activated_ms": last_activated_ms}


def _dedupe_by_path(
    incoming: list[dict[str, Any]],
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Dedupe by path, preserving first insertion order; later recency wins."""
    by_path: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for tab in incoming:
        path = tab["path"]
        if path in by_path:
            if tab["last_activated_ms"] >= by_path[path]["last_activated_ms"]:
                by_path[path] = tab
        else:
            by_path[path] = tab
            order.append(path)
    return by_path, order


def _recover_active(
    by_path: dict[str, dict[str, Any]],
    order: list[str],
    active_raw: Any,
) -> Optional[str]:
    """Validate the inbound active path, else fall back to most recent."""
    active = _normalise_absolute_path(active_raw)
    if active is not None and active in by_path:
        return active
    if order:
        return max(order, key=lambda p: by_path[p]["last_activated_ms"])
    return None


def _cap_to_max(
    by_path: dict[str, dict[str, Any]],
    order: list[str],
    active: Optional[str],
) -> list[str]:
    """Evict least-recently-activated paths (never the active one) past cap."""
    if len(order) <= MAX_OPEN_TABS:
        return order
    evictable = [p for p in order if p != active]
    evictable.sort(key=lambda p: by_path[p]["last_activated_ms"])
    drop_count = len(order) - MAX_OPEN_TABS
    dropped = set(evictable[:drop_count])
    return [p for p in order if p not in dropped]


def _reduce_workspace(
    tabs_raw: Any,
    active_raw: Any,
    *,
    now_ms: Optional[int] = None,
) -> dict[str, Any]:
    """Normalise, dedupe, recover active, and cap at [MAX_OPEN_TABS]."""
    incoming: list[dict[str, Any]] = []
    if isinstance(tabs_raw, list):
        for raw in tabs_raw:
            tab = _normalise_tab(raw)
            if tab is not None:
                incoming.append(tab)

    by_path, order = _dedupe_by_path(incoming)
    active = _recover_active(by_path, order, active_raw)
    order = _cap_to_max(by_path, order, active)
    tabs = [by_path[p] for p in order]
    return {"tabs": tabs, "active_path": active}


def get_workspace(
    params: Mapping[str, Any],
    *,
    paths: Optional[TreePaths] = None,
) -> dict[str, Any]:
    """Handle ``tree.workspace.get`` — the host file-workspace hydrate read."""
    if paths is None:
        paths = resolve_paths()
    with _registry_lock(paths, exclusive=False):
        doc = _read_registry(paths)
    workspaces = doc.get("file_workspaces")
    raw: Any = None
    if isinstance(workspaces, Mapping):
        raw = workspaces.get(WORKSPACE_KEY)
    tabs_raw = raw.get("tabs") if isinstance(raw, Mapping) else []
    active_raw = raw.get("active_path") if isinstance(raw, Mapping) else None
    reduced = _reduce_workspace(tabs_raw, active_raw)
    reduced["cli_version"] = _cli_version()
    return reduced


def upsert_workspace(
    params: Mapping[str, Any],
    *,
    paths: Optional[TreePaths] = None,
    now_ms: Optional[int] = None,
) -> dict[str, Any]:
    """Handle ``tree.workspace.upsert`` — persist the host file workspace.

    Preserves the ``hosts`` tree document so the two presentation writers
    cannot erase each other.
    """
    if paths is None:
        paths = resolve_paths()
    reduced = _reduce_workspace(
        params.get("tabs"),
        params.get("active_path"),
        now_ms=now_ms,
    )
    with _registry_lock(paths, exclusive=True):
        doc = _read_registry(paths)
        workspaces = doc.setdefault("file_workspaces", {})
        if not isinstance(workspaces, dict):
            workspaces = {}
            doc["file_workspaces"] = workspaces
        workspaces[WORKSPACE_KEY] = {
            "tabs": reduced["tabs"],
            "active_path": reduced["active_path"],
        }
        _write_registry(paths, doc)
    return {"status": "ok", **reduced}
