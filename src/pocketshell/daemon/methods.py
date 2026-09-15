"""The daemon's default RPC method registry and its thin handler shims."""
from __future__ import annotations
import subprocess
from typing import Any, Callable, Mapping
# --- sibling modules ---
from pocketshell.daemon.failures import JSONRPC_INVALID_PARAMS, _RpcError


# Handler signature: ``(params: Mapping[str, Any]) -> Any``.
RpcHandler = Callable[[Mapping[str, Any]], Any]


def _validated_provider(params: Mapping[str, Any]) -> Any:
    """Read ``provider`` (string or null) from the request params."""
    provider = params.get("provider")
    if provider is not None and not isinstance(provider, str):
        raise _RpcError(
            JSONRPC_INVALID_PARAMS,
            "usage.fetch: `provider` must be a string or null",
        )
    return provider


def _missing_quse_envelope(provider: Any) -> dict[str, Any]:
    """Envelope for a missing pinned quse (a packaging-integrity error).

    quse is bundled WITH pocketshell (issue #1318): a missing pinned copy
    is not an "install quse" nag. The daemon does NOT cache this failure.
    """
    from pocketshell import usage as _usage

    return {
        "stdout": "",
        "stderr": _usage._QUSE_MISSING_MESSAGE + "\n",
        "returncode": _usage._QUSE_MISSING_EXIT_CODE,
        "provider": provider,
    }


def _fetch_usage_stdout(quse_path: str, provider: Any) -> dict[str, Any]:
    """Run ``quse [provider] --json`` and build the result envelope."""
    from pocketshell import usage as _usage

    args: list[str] = [quse_path]
    if provider:
        args.append(provider)
    args.append("--json")
    completed = subprocess.run(
        args,
        check=False,
        capture_output=True,
        text=True,
    )
    # Only a successful (exit 0) quse run is flattened into per-provider
    # NDJSON. A failed fetch is proxied raw (it is not a valid provider-keyed
    # document, and the daemon does not cache failures anyway).
    stdout = (
        _usage.normalize_usage_stdout(completed.stdout)
        if completed.returncode == 0
        else completed.stdout
    )
    return {
        "stdout": stdout,
        "stderr": completed.stderr,
        "returncode": completed.returncode,
        "provider": provider,
    }


def _usage_fetch_handler(params: Mapping[str, Any]) -> dict[str, Any]:
    """Run ``quse [provider] --json`` and return its result envelope.

    Returning stdout in the envelope (``{stdout, stderr, returncode,
    provider}``) preserves the CLI/daemon contract. ``quse --json`` emits
    a **provider-keyed JSON object**; the daemon FLATTENS it into
    per-provider NDJSON via :func:`pocketshell.usage.normalize_usage_stdout`
    before caching, so the cached envelope stdout is already the app-facing
    NDJSON wire format (the CLI proxies it verbatim, without re-flattening).
    """
    # Lazy import to avoid a circular module load at startup: the
    # daemon module is imported from ``cli.py`` which also imports
    # ``usage`` directly.
    from pocketshell import usage as _usage

    provider = _validated_provider(params)
    quse_path = _usage._resolve_quse_binary()
    if quse_path is None:
        return _missing_quse_envelope(provider)
    return _fetch_usage_stdout(quse_path, provider)


def _repos_list_local_handler(params: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Scan configured roots for cloned git repos and return them as JSON.

    Thin shim around :func:`pocketshell.repos.daemon_handler_local`. The
    shim exists so the daemon module does not need to import
    :mod:`pocketshell.repos` at module load time (which would create a
    circular dependency: ``repos`` imports ``daemon`` lazily for the
    client-side probe). Lazy import keeps the daemon's cold-start cost
    paid only when this method is actually invoked.
    """
    from pocketshell import repos as _repos

    return _repos.daemon_handler_local(dict(params))


def _repos_list_remote_handler(params: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Enumerate the authenticated user's GitHub repositories via ``gh api``.

    Same lazy-import pattern as :func:`_repos_list_local_handler` so
    the daemon's cold-start cost is paid only when actually invoked.
    Exceptions raised by the underlying ``gh`` call (missing binary,
    non-zero exit) propagate up so the daemon wrapper translates them
    into a JSON-RPC error envelope — the CLI's fall-through path then
    handles the user-visible exit code.
    """
    from pocketshell import repos as _repos

    return _repos.daemon_handler_remote(dict(params))


def _repos_clone_handler(params: Mapping[str, Any]) -> dict[str, Any]:
    """Clone a GitHub repository and return a structured status envelope.

    Same lazy-import pattern as the other ``repos.*`` handlers. Returns a
    success envelope ``{"status": "cloned", "path": ..., "full_name": ...}``
    or a failure envelope carrying a machine-readable ``error_code``. A
    *successful* clone invalidates the ``repos.list_local`` cache (see
    :data:`METHOD_CACHE_INVALIDATIONS`) so the very next ``repos.list_local``
    reflects the new clone instead of serving the pre-clone cached scan.
    """
    from pocketshell import repos as _repos

    return _repos.daemon_handler_clone(dict(params))


def _repos_open_handler(params: Mapping[str, Any]) -> dict[str, Any]:
    """Locate a cloned repository and return its path.

    Same lazy-import pattern as the other ``repos.*`` handlers. Returns
    ``{"status": "open", "path": ..., "full_name": ...}`` on success or a
    failure envelope with a machine-readable ``error_code``.
    """
    from pocketshell import repos as _repos

    return _repos.daemon_handler_open(dict(params))


def _sessions_list_handler(params: Mapping[str, Any]) -> dict[str, Any]:
    """Delegate ``sessions.list`` to the host session wrapper."""
    from pocketshell import sessions as _sessions

    return _sessions.daemon_handler_list(dict(params))


def _validated_panes(params: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Read ``panes`` (list of objects) from the request params."""
    raw_panes = params.get("panes")
    if raw_panes is None:
        return []
    if isinstance(raw_panes, list):
        return [p for p in raw_panes if isinstance(p, Mapping)]
    raise _RpcError(
        JSONRPC_INVALID_PARAMS,
        "agents.kind_for_panes: `panes` must be a list of objects",
    )


def _agents_kind_for_panes_handler(params: Mapping[str, Any]) -> dict[str, Any]:
    """Classify the agent kind running in each pane's cgroup scope.

    Server-side cgroup-v2 + ``/proc`` read replacing the client's fragile
    ``ps -eo … | grep`` scan (#809/#811): each pane's ``pane_pid`` resolves
    to its ``aplexer-workload-<session>.scope`` via ``/proc/<pid>/cgroup``,
    the scope's ``cgroup.procs`` are read, and each proc's ``comm``/
    ``cmdline`` is matched against the claude/codex/opencode token rules
    (mirrored from ``AgentDetector.namesAgent``). No ``systemctl`` shell-out.

    Request ``{"panes": [{"pane_id": "%1", "pane_pid": 2647034}, ...]}``;
    result ``{"results": [{"pane_id", "agent_kind", "scope",
    "evidence_pid"}, ...]}`` where ``agent_kind`` is one of ``claude`` /
    ``codex`` / ``opencode`` / ``none`` (readable scope, no agent) /
    ``unknown`` (pane pid/cgroup unreadable). One bad pane never sinks
    the batch.
    """
    from pocketshell.runtime import cgroups as _cgroup_agents

    return {"results": _cgroup_agents.kind_for_panes(_validated_panes(params))}


def _tree_get_handler(params: Mapping[str, Any]) -> dict[str, Any]:
    """Delegate ``tree.get`` to the durable per-host tree registry."""
    from pocketshell import tree as _tree

    return _tree.daemon_handler_get(dict(params))


def _tree_upsert_handler(params: Mapping[str, Any]) -> dict[str, Any]:
    """Delegate ``tree.upsert`` to the durable per-host tree registry."""
    from pocketshell import tree as _tree

    return _tree.daemon_handler_upsert(dict(params))


def _tree_reconcile_handler(params: Mapping[str, Any]) -> dict[str, Any]:
    """Delegate ``tree.reconcile`` to the durable per-host tree registry."""
    from pocketshell import tree as _tree

    return _tree.daemon_handler_reconcile(dict(params))


def _tree_workspace_get_handler(params: Mapping[str, Any]) -> dict[str, Any]:
    """Delegate ``tree.workspace.get`` to the durable file-workspace registry."""
    from pocketshell import tree as _tree

    return _tree.daemon_handler_workspace_get(dict(params))


def _tree_workspace_upsert_handler(params: Mapping[str, Any]) -> dict[str, Any]:
    """Delegate ``tree.workspace.upsert`` to the durable file-workspace registry."""
    from pocketshell import tree as _tree

    return _tree.daemon_handler_workspace_upsert(dict(params))


# Single shared registry; tests can register additional methods via
# :meth:`Daemon.register_method` on a fresh instance without touching
# this dict.
DEFAULT_METHODS: Mapping[str, RpcHandler] = {
    "usage.fetch": _usage_fetch_handler,
    "repos.list_local": _repos_list_local_handler,
    "repos.list_remote": _repos_list_remote_handler,
    "repos.clone": _repos_clone_handler,
    "repos.open": _repos_open_handler,
    "sessions.list": _sessions_list_handler,
    "agents.kind_for_panes": _agents_kind_for_panes_handler,
    "tree.get": _tree_get_handler,
    "tree.upsert": _tree_upsert_handler,
    "tree.reconcile": _tree_reconcile_handler,
    "tree.workspace.get": _tree_workspace_get_handler,
    "tree.workspace.upsert": _tree_workspace_upsert_handler,
}


# Cache-invalidation policy. Maps a method name to the cache entries that
# a *successful* call to it must evict. ``repos.clone`` writes a new
# repository to disk, so after it succeeds the cached ``repos.list_local``
# scan is stale and must be dropped — otherwise the Android picker would
# keep showing the pre-clone repo set for up to the 10 s TTL. Kept next to
# :data:`METHOD_TTLS` so the cache policy stays auditable in one place.
#
# ``repos.clone`` and ``repos.open`` themselves carry no TTL (not in
# METHOD_TTLS) so their own results are never cached: a clone is a
# side-effecting mutation and ``open`` is a cheap lookup whose answer can
# change as soon as a clone lands.
METHOD_CACHE_INVALIDATIONS: Mapping[str, tuple[str, ...]] = {
    "repos.clone": ("repos.list_local",),
    # `tree.upsert` rewrites the host's persisted node list, so the cached
    # `tree.get` cold-start read is stale the moment it lands — drop it so the
    # very next `tree.get` reflects the just-persisted ordering/expansion.
    # `tree.reconcile` prunes gone nodes from the registry, so it must also
    # invalidate the `tree.get` cache.
    "tree.upsert": ("tree.get",),
    "tree.reconcile": ("tree.get",),
    # Issue #1715: a workspace mutation must drop the cached hydrate read so
    # the next Open-files restore sees the just-written tabs. Tree writers
    # do NOT evict the workspace cache (and vice versa) — they own sibling
    # top-level fields in the same document.
    "tree.workspace.upsert": ("tree.workspace.get",),
}
