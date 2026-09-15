"""Tab-tree get/upsert/reconcile semantics (versioned per host)."""
from __future__ import annotations
import time
from typing import Any, Mapping, Optional
# --- sibling modules ---
from pocketshell.tree.paths import OPTIMISTIC_GRACE_SECS, TreePaths, resolve_paths
from pocketshell.tree.storage import _read_registry, _registry_lock, _write_registry


def _coerced_order(raw: Mapping[str, Any], fallback_order: int) -> int:
    """Read ``order`` as an int, falling back to the batch position."""
    try:
        return int(raw.get("order", fallback_order))
    except (TypeError, ValueError):
        return fallback_order


def _apply_generation(node: dict[str, Any], raw: Mapping[str, Any]) -> None:
    """Persist ``session_id``/``session_created`` as the exact generation.

    An incomplete or non-positive pair is treated as provisional and omitted.
    """
    session_id = raw.get("session_id")
    session_created = raw.get("session_created")
    if not isinstance(session_id, str) or not session_id.strip():
        return
    try:
        created = int(session_created)
    except (TypeError, ValueError):
        created = 0
    if created > 0:
        node["session_id"] = session_id.strip()
        node["session_created"] = created


def _apply_optimistic_since(node: dict[str, Any], raw: Mapping[str, Any]) -> None:
    """Preserve the optimistic-grace marker so reconcile spares fresh nodes."""
    optimistic_since = raw.get("optimistic_since")
    if isinstance(optimistic_since, (int, float)):
        node["optimistic_since"] = float(optimistic_since)


def _node_base(raw: Mapping[str, Any], fallback_order: int) -> dict[str, Any]:
    """Build the required-and-defaulted base fields of a node."""
    folder_path = raw.get("folder_path")
    return {
        "session": raw["session"],
        "order": _coerced_order(raw, fallback_order),
        "folder_path": folder_path if isinstance(folder_path, str) else "",
        "collapsed": bool(raw.get("collapsed", False)),
    }


def _normalise_node(raw: Any, fallback_order: int) -> Optional[dict[str, Any]]:
    """Coerce one inbound node into the persisted shape, or ``None`` if invalid.

    A node MUST have a non-empty ``session`` string; everything else is
    optional and defaulted. ``foreign_kind`` is the cheap foreign-guess cache
    (NOT the confirmed kind). One malformed node never sinks the batch — the
    caller filters ``None`` out.
    """
    if not isinstance(raw, Mapping):
        return None
    session = raw.get("session")
    if not isinstance(session, str) or not session:
        return None
    node = _node_base(raw, fallback_order)
    foreign_kind = raw.get("foreign_kind")
    if isinstance(foreign_kind, str) and foreign_kind:
        node["foreign_kind"] = foreign_kind
    _apply_generation(node, raw)
    _apply_optimistic_since(node, raw)
    return node


def _host_nodes(doc: Mapping[str, Any], host: str) -> list[dict[str, Any]]:
    hosts = doc.get("hosts")
    if not isinstance(hosts, Mapping):
        return []
    entry = hosts.get(host)
    if not isinstance(entry, Mapping):
        return []
    nodes = entry.get("nodes")
    if not isinstance(nodes, list):
        return []
    out: list[dict[str, Any]] = []
    for index, raw in enumerate(nodes):
        node = _normalise_node(raw, fallback_order=index)
        if node is not None:
            out.append(node)
    return out


def _host_version(doc: Mapping[str, Any], host: str) -> int:
    hosts = doc.get("hosts")
    if not isinstance(hosts, Mapping):
        return 0
    entry = hosts.get(host)
    if not isinstance(entry, Mapping):
        return 0
    version = entry.get("version")
    try:
        return int(version)
    except (TypeError, ValueError):
        return 0


def _require_host(params: Mapping[str, Any]) -> str:
    host = params.get("host")
    if not isinstance(host, str) or not host:
        raise ValueError("tree: `host` must be a non-empty string")
    return host


def _cli_version() -> str:
    """The installed ``pocketshell`` version, for the passive client check.

    Issue #885: the PocketShell client execs ``tree get`` / ``tree reconcile``
    on EVERY host open (warm/direct included), so stamping the server CLI
    version into those envelopes lets the client detect a version mismatch
    PASSIVELY during normal use — no separate slow blocking ``--version`` exec,
    and consistently regardless of how the host was opened. A read failure
    degrades to an empty string (the client treats "unknown" as "no signal").
    """
    try:
        from pocketshell import __version__

        return str(__version__)
    except Exception:  # pragma: no cover - defensive; never wedge the payload
        return ""


def _live_session_names(env: Optional[Mapping[str, str]] = None) -> Optional[set[str]]:
    """Return live aplexer session names, or ``None`` when it is unavailable."""
    from pocketshell.session_enum import enumerate_live_sessions

    rows, errors = enumerate_live_sessions(env=env)
    if errors:
        return None
    return {row.name for row in rows}


def get_tree(
    params: Mapping[str, Any],
    *,
    paths: Optional[TreePaths] = None,
) -> dict[str, Any]:
    """Handle ``tree.get`` — return the persisted node list for one host.

    An empty result (no registry yet) is valid: the client seeds a fresh tree.
    """
    host = _require_host(params)
    if paths is None:
        paths = resolve_paths()
    with _registry_lock(paths, exclusive=False):
        doc = _read_registry(paths)
    return {
        "nodes": _host_nodes(doc, host),
        "version": _host_version(doc, host),
        # Issue #885: passive payload-version detection — the client compares
        # this against its expected version on every normal open.
        "cli_version": _cli_version(),
    }


def _inbound_nodes(params: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Collect and normalise the ``nodes``/``node`` payload for an upsert."""
    raw_nodes = params.get("nodes")
    if raw_nodes is None:
        single = params.get("node")
        raw_nodes = [single] if single is not None else []
    if not isinstance(raw_nodes, list):
        raise ValueError("tree.upsert: `nodes` must be a list of node objects")
    nodes: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_nodes):
        node = _normalise_node(raw, fallback_order=index)
        if node is not None:
            nodes.append(node)
    return nodes


def _expected_version(params: Mapping[str, Any]) -> int:
    """Validate and return ``expected_version`` (a non-negative int)."""
    expected = params.get("expected_version")
    if not isinstance(expected, int) or isinstance(expected, bool) or expected < 0:
        raise ValueError(
            "tree.upsert: `expected_version` must be a non-negative integer"
        )
    return expected


def _write_host_entry(
    doc: dict[str, Any],
    host: str,
    nodes: list[dict[str, Any]],
    version: int,
) -> None:
    """Store ``nodes`` under ``host`` with ``version``, in place."""
    hosts = doc.setdefault("hosts", {})
    if not isinstance(hosts, dict):
        hosts = {}
        doc["hosts"] = hosts
    hosts[host] = {"nodes": nodes, "version": version}


def upsert_tree(
    params: Mapping[str, Any],
    *,
    paths: Optional[TreePaths] = None,
) -> dict[str, Any]:
    """Handle ``tree.upsert`` — atomically persist the node list for one host.

    A mutation: it bumps the host's ``version`` and rewrites the registry with
    the atomic private-write. Accepts either a ``nodes`` list or a single
    ``node`` object. One malformed node is skipped; the rest persist. The
    daemon invalidates the ``tree.get`` cache for this host afterwards.
    """
    host = _require_host(params)
    if paths is None:
        paths = resolve_paths()
    nodes = _inbound_nodes(params)
    expected = _expected_version(params)

    with _registry_lock(paths, exclusive=True):
        doc = _read_registry(paths)
        current_version = _host_version(doc, host)
        if expected != current_version:
            return {"status": "conflict", "version": current_version}
        version = current_version + 1
        _write_host_entry(doc, host, nodes, version)
        _write_registry(paths, doc)
    return {"status": "ok", "version": version}


def _reconcile_payload(
    alive: list[str], gone: list[str], added: list[str]
) -> dict[str, Any]:
    """Assemble the reconcile envelope with the passive CLI-version stamp."""
    return {
        "alive": alive,
        "gone": gone,
        "added": added,
        "cli_version": _cli_version(),
    }


def _unavailable_payload(paths: TreePaths, host: str) -> dict[str, Any]:
    """Report every registry session alive; the enumeration is unavailable."""
    with _registry_lock(paths, exclusive=False):
        doc = _read_registry(paths)
        nodes = _host_nodes(doc, host)
    registry_names = [node["session"] for node in nodes]
    # Enumeration unavailable — do NOT prune. Report everything alive.
    return _reconcile_payload(list(registry_names), [], [])


def _partition_nodes(
    nodes: list[dict[str, Any]],
    live_names: set[str],
    now: float,
) -> tuple[list[str], list[str], list[dict[str, Any]]]:
    """Split registry nodes into (alive, gone-past-grace, kept) triples."""
    alive: list[str] = []
    gone: list[str] = []
    kept_nodes: list[dict[str, Any]] = []
    for node in nodes:
        name = node["session"]
        if name in live_names:
            alive.append(name)
            kept_nodes.append(node)
            continue
        since = node.get("optimistic_since")
        if isinstance(since, (int, float)) and (now - since) < OPTIMISTIC_GRACE_SECS:
            alive.append(name)
            kept_nodes.append(node)
            continue
        gone.append(name)
    return alive, gone, kept_nodes


def _prune_gone(
    paths: TreePaths,
    doc: dict[str, Any],
    host: str,
    kept_nodes: list[dict[str, Any]],
) -> None:
    """Persist the registry with gone sessions removed, bumping the version."""
    hosts = doc.setdefault("hosts", {})
    if not isinstance(hosts, dict):
        hosts = {}
        doc["hosts"] = hosts
    version = _host_version(doc, host) + 1
    hosts[host] = {"nodes": kept_nodes, "version": version}
    _write_registry(paths, doc)


def _reconcile_locked(
    paths: TreePaths,
    host: str,
    resolved_live: set[str],
    now: float,
) -> tuple[list[str], list[str], list[str]]:
    """Diff + prune under the exclusive registry lock.

    Returns ``(alive, gone, added)``; prunes gone sessions from the
    persisted registry when there are any.
    """
    with _registry_lock(paths, exclusive=True):
        doc = _read_registry(paths)
        nodes = _host_nodes(doc, host)
        registry_names = [node["session"] for node in nodes]
        alive, gone, kept_nodes = _partition_nodes(nodes, resolved_live, now)
        added = [name for name in resolved_live if name not in registry_names]
        if gone:
            _prune_gone(paths, doc, host, kept_nodes)
    return alive, gone, added


def reconcile_tree(
    params: Mapping[str, Any],
    *,
    paths: Optional[TreePaths] = None,
    live_names: Optional[set[str]] = None,
    now: Optional[float] = None,
) -> dict[str, Any]:
    """Handle ``tree.reconcile`` — return ``{alive, gone, added}`` DELTAS.

    Diffs the persisted registry against the live aplexer listing by name.
    ``gone`` sessions (absent from the live listing AND past their optimistic
    grace) are pruned from the registry; ``added`` live sessions are reported
    for the client to upsert, never auto-registered. When the live enumeration
    cannot be performed, NOTHING is pruned and every registry session reports
    alive, so a transient hiccup never wipes the held tree. ``live_names`` /
    ``now`` are injectable for deterministic tests.
    """
    host = _require_host(params)
    paths = resolve_paths() if paths is None else paths
    now = time.time() if now is None else now

    resolved_live = live_names if live_names is not None else _live_session_names()
    if resolved_live is None:
        return _unavailable_payload(paths, host)

    alive, gone, added = _reconcile_locked(paths, host, resolved_live, now)
    return _reconcile_payload(alive, gone, added)
