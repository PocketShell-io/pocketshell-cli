"""Survivor accounting for the Windows gateway Ctrl+C checks.

``scripts/windows-gateway-qualify.py`` and the e2e harness count leftover
session processes by (pid, image). Pids are reused and parent-pids go
stale, so that match alone over-captures: CI run 40247494230 reported
"survivors 131" for a 3-4 process session while the session itself tore
down correctly (exit 130 after 0.0s). The pure helpers under test add
creation-time identity; they run on any platform.
"""

from __future__ import annotations

import ast
import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "windows-gateway-qualify.py"
E2E = Path(__file__).resolve().parent / "test_windows_gateway_e2e.py"


@pytest.fixture(scope="module")
def qualify():
    spec = importlib.util.spec_from_file_location("windows_gateway_qualify", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_prune_drops_children_older_than_root(qualify):
    tree = [(11, 10, "ssh.exe"), (12, 11, "python.exe"), (13, 12, "python.exe")]
    births = {11: 100, 12: 101, 13: 50}  # 13 predates the root: stale ppid
    assert qualify.prune_stale_descendants(100, tree, births) == tree[:2]


def test_prune_keeps_equal_birth_and_unknown_birth(qualify):
    tree = [(11, 10, "ssh.exe"), (12, 11, "python.exe"), (13, 11, "conhost.exe")]
    births = {11: 100, 12: 100}  # 13 could not be opened: keep, do not hide
    assert qualify.prune_stale_descendants(100, tree, births) == tree


def test_prune_without_root_birth_keeps_everything(qualify):
    tree = [(11, 10, "ssh.exe")]
    assert qualify.prune_stale_descendants(None, tree, {}) == tree


def test_live_survivors_counts_only_the_same_process(qualify):
    names = {11: ("ssh.exe", 100), 12: ("python.exe", 101), 13: ("python.exe", 102)}
    current = [(11, 10, "ssh.exe"), (12, 11, "python.exe")]  # 13 reaped
    assert qualify.live_survivors(names, current, lambda pid: {11: 100, 12: 101}[pid]) == current


def test_live_survivors_ignores_pid_reuse(qualify):
    names = {11: ("python.exe", 100)}
    # same pid, same image, but a different process (creation time differs)
    assert qualify.live_survivors(names, [(11, 1, "python.exe")], lambda pid: 999) == []
    # same pid reused by another image entirely
    assert qualify.live_survivors(names, [(11, 1, "svchost.exe")], lambda pid: 100) == []


def test_live_survivors_falls_back_when_birth_unknown(qualify):
    names = {11: ("python.exe", None)}  # snapshot birth unavailable
    assert qualify.live_survivors(names, [(11, 1, "python.exe")], lambda pid: 999) == [(11, 1, "python.exe")]
    names = {11: ("python.exe", 100)}  # current birth unavailable
    assert qualify.live_survivors(names, [(11, 1, "python.exe")], lambda pid: None) == [(11, 1, "python.exe")]


def test_ci_failure_shape_over_capture_is_pruned(qualify):
    """Model of run 40247494230: the snapshot over-captures 131 stale
    orphans (older than the session root) plus the 3 real members; after
    Ctrl+C tears the session down, no survivor may be reported."""
    root, root_birth = 5000, 1_000_000
    real = [(5001, root, "ssh.exe"), (5002, 5001, "python.exe"), (5003, 5002, "python.exe")]
    stale = [(9000 + i, root, "svchost.exe") for i in range(131)]
    tree = real + stale
    births = {pid: root_birth + 10 for pid, _, _ in real}
    births.update({pid: root_birth - 10_000 - (pid - 9000) for pid, _, _ in stale})
    pruned = qualify.prune_stale_descendants(root_birth, tree, births)
    assert pruned == real
    names = {t[0]: (t[2], births.get(t[0])) for t in pruned}
    assert qualify.live_survivors(names, [], lambda pid: None) == []


def _harness_source():
    tree = ast.parse(E2E.read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", "") == "HARNESS":
            return ast.literal_eval(node.value)
    raise AssertionError("HARNESS not found")


def test_e2e_harness_compiles_and_matches_on_birth_identity():
    compile(_harness_source(), str(E2E), "exec")
