"""Durable per-host project-tree registry (epic #821 workstream C, issue #837).

The PocketShell Android client maintains an in-memory project tree per host
(`HostTreeModel`, #679): the session ordering, folder expand/collapse memory,
and a one-shot foreign-agent guess cache. That tree is volatile — a process
kill loses it, so a cold start shows a brief Loading flash and can shuffle the
session order until the first authoritative probe re-seeds it.

This module is the host-side durability store for that small *presentation*
state. It is a host-keyed JSON registry the `pocketshell` daemon owns, exposed
via three JSON-RPC methods:

- ``tree.get {host}`` -> ``{nodes: [...], version}`` — the persisted node list
  (order, folder_path, collapsed, optional cached foreign-guess kind, and the
  exact session generation when known). An empty result is valid (no registry yet
  → the client seeds fresh). Cached with a short TTL (~5 s) like
  ``sessions.list``.
- ``tree.upsert {host, nodes}`` -> ``{status, version}`` — atomically persists
  the node list. A mutation: it carries NO TTL and invalidates the ``tree.get``
  cache for that host (see :data:`pocketshell.daemon.METHOD_CACHE_INVALIDATIONS`).
- ``tree.reconcile {host}`` -> ``{alive, gone, added}`` — diffs the persisted
  registry against live aplexer sessions and returns DELTAS ONLY (never a full
  reload), pruning the gone sessions from the registry with an optimistic-grace
  guard (mirrors ``HostTreeModel.reconcile`` + ``OPTIMISTIC_GRACE_MS``).

What this store deliberately does NOT hold
-------------------------------------------

The per-session agent **kind** (recorded AND confirmed-foreign) is owned by the
session backend. This registry stores no kind copy — a second kind writer would
be the exact "third cache / two writers" smell the design forbids. The optional
``foreign_kind`` field on a node is the cheap one-shot foreign-GUESS cache (a
hint the client re-derives if absent), not the confirmed kind.

Storage
-------

``${XDG_STATE_HOME:-~/.local/state}/pocketshell/tree/registry.json`` — a single
JSON document keyed by host alias. Persisted with the atomic temp-file +
``os.replace`` private-write pattern (mode 0600, dir 0700) copied from
:func:`pocketshell.usage_capture._write_private`, so a concurrent reader (the
app's SSH fetch racing a mutation) never sees a half-written file. JSON, not
SQLite: the dataset is tiny (a few hosts × tens of sessions) and read-whole /
write-whole semantics match the per-open ``tree.get`` + per-mutation
``tree.upsert`` access pattern (#837 non-goal: SQLite / versioned history).
"""
from __future__ import annotations

from pocketshell.tree.cli import (
    tree_group,
)
from pocketshell.tree.daemon import (
    daemon_handler_get,
    daemon_handler_upsert,
    daemon_handler_reconcile,
    daemon_handler_workspace_get,
    daemon_handler_workspace_upsert,
    _try_daemon_call,
)
from pocketshell.tree.model import (
    _cli_version,
    _live_session_names,
    get_tree,
    upsert_tree,
    reconcile_tree,
)
from pocketshell.tree.paths import (
    NEW_FILE_MODE,
    REGISTRY_FILENAME,
    OPTIMISTIC_GRACE_SECS,
    TreePaths,
    resolve_paths,
)
from pocketshell.tree.storage import (
    _ensure_dir,
    _write_private,
    _registry_lock,
    _read_registry,
    _write_registry,
)
from pocketshell.tree.workspace import (
    WORKSPACE_KEY,
    MAX_OPEN_TABS,
    get_workspace,
    upsert_workspace,
)
import os  # noqa: F401  (tests patch tree_mod.os.fsync/replace)

__all__ = [
    "NEW_FILE_MODE",
    "REGISTRY_FILENAME",
    "OPTIMISTIC_GRACE_SECS",
    "TreePaths",
    "resolve_paths",
    "_ensure_dir",
    "_write_private",
    "_registry_lock",
    "_read_registry",
    "_write_registry",
    "_cli_version",
    "_live_session_names",
    "get_tree",
    "upsert_tree",
    "reconcile_tree",
    "WORKSPACE_KEY",
    "MAX_OPEN_TABS",
    "get_workspace",
    "upsert_workspace",
    "daemon_handler_get",
    "daemon_handler_upsert",
    "daemon_handler_reconcile",
    "daemon_handler_workspace_get",
    "daemon_handler_workspace_upsert",
    "_try_daemon_call",
    "tree_group",
]
