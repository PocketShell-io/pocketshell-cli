"""The `pocketshell tree` click command group."""
from __future__ import annotations
import json
import click
# --- sibling modules ---
from pocketshell.tree.daemon import _read_stdin_params, _try_daemon_call
from pocketshell.tree.model import get_tree, reconcile_tree, upsert_tree
from pocketshell.tree.workspace import get_workspace, upsert_workspace


@click.group(
    name="tree",
    context_settings={"help_option_names": ["-h", "--help"]},
    help=(
        "Durable per-host project-tree registry (epic #821 slice C).\n\n"
        "`get` / `upsert` / `reconcile` persist + restore the maintained "
        "project tree's ordering, expand/collapse memory, and foreign-guess "
        "cache so the PocketShell client renders the held tree instantly "
        "across an app restart. Params are read as a JSON object on stdin "
        "(the RPC request shape); the result envelope is emitted as JSON on "
        "stdout. NB: the per-session agent KIND is NOT stored here — it lives "
        "in the session backend (one source of truth)."
    ),
)
def tree_group() -> None:
    """Top-level `tree` group registered onto the root `pocketshell` CLI."""


@tree_group.command(
    name="get",
    context_settings={"help_option_names": ["-h", "--help"]},
    help=(
        "Return the persisted node list for a host. Reads `{\"host\": ...}` on "
        "stdin; emits `{\"nodes\": [...], \"version\": N}`. Empty registry -> "
        "`{\"nodes\": [], \"version\": 0}` (the client seeds fresh)."
    ),
)
def tree_get_command() -> None:
    params = _read_stdin_params()
    envelope = _try_daemon_call("tree.get", params)
    if envelope is None:
        envelope = get_tree(params)
    click.echo(json.dumps(envelope))


@tree_group.command(
    name="upsert",
    context_settings={"help_option_names": ["-h", "--help"]},
    help=(
        "Persist a host's node list atomically. Reads "
        "`{\"host\": ..., \"nodes\": [...]}` on stdin; emits "
        "`{\"status\": \"ok\", \"version\": N}`."
    ),
)
def tree_upsert_command() -> None:
    params = _read_stdin_params()
    envelope = _try_daemon_call("tree.upsert", params)
    if envelope is None:
        envelope = upsert_tree(params)
    click.echo(json.dumps(envelope))


@tree_group.command(
    name="reconcile",
    context_settings={"help_option_names": ["-h", "--help"]},
    help=(
        "Diff the registry against live aplexer sessions and return deltas. "
        "Reads `{\"host\": ...}` on stdin; emits "
        "`{\"alive\": [...], \"gone\": [...], \"added\": [...]}`. Gone "
        "sessions (past optimistic grace) are pruned from the registry."
    ),
)
def tree_reconcile_command() -> None:
    params = _read_stdin_params()
    envelope = _try_daemon_call("tree.reconcile", params)
    if envelope is None:
        envelope = reconcile_tree(params)
    click.echo(json.dumps(envelope))


@tree_group.command(
    name="workspace-get",
    context_settings={"help_option_names": ["-h", "--help"]},
    help=(
        "Return this Unix account's open-file workspace. Emits "
        '`{"tabs": [...], "active_path": ...}`. Empty registry -> '
        '`{"tabs": [], "active_path": null}`.'
    ),
)
def tree_workspace_get_command() -> None:
    params = _read_stdin_params()
    envelope = _try_daemon_call("tree.workspace.get", params)
    if envelope is None:
        envelope = get_workspace(params)
    click.echo(json.dumps(envelope))


@tree_group.command(
    name="workspace-upsert",
    context_settings={"help_option_names": ["-h", "--help"]},
    help=(
        "Persist this Unix account's open-file workspace atomically. Reads "
        '`{"tabs": [...], "active_path": ...}` on stdin; emits '
        '`{"status": "ok", ...}`.'
    ),
)
def tree_workspace_upsert_command() -> None:
    params = _read_stdin_params()
    envelope = _try_daemon_call("tree.workspace.upsert", params)
    if envelope is None:
        envelope = upsert_workspace(params)
    click.echo(json.dumps(envelope))
