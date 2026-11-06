"""Malformed/uncertain operations never guess a target or invoke cleanup."""
from __future__ import annotations

import copy
import subprocess
from uuid import uuid4

import pytest

from pocketshell import windows_session_lifecycle as subject


@pytest.fixture
def backend(monkeypatch, tmp_path):
    monkeypatch.setattr(subject, "workspace_path", lambda value, **_kw: str(value))
    monkeypatch.setattr(subject, "backend", lambda: "verified-bundled-a")
    row = {"id": str(uuid4()), "workspace": str(tmp_path), "tag": "home", "state": "running",
           "limits": {"memory_bytes": 12 * 1024**3}, "workload_pid": 1234}
    calls = []
    snapshots = [[], [copy.deepcopy(row)]]
    def json_call(binary, args, **kwargs):
        assert binary == "verified-bundled-a"
        calls.append((args, kwargs))
        if args == ["snapshot"]:
            return snapshots.pop(0)
        if args[0] == "start":
            return copy.deepcopy(row)
        raise AssertionError("Unexpected side effect: " + repr(args))
    monkeypatch.setattr(subject, "_json", json_call)
    def verify(ident, pid, requested=None):
        assert ident == row["id"] and pid == 1234
        if requested is not None and row["limits"]["memory_bytes"] > requested:
            raise subject.windows_job.JobError("weaker limit")
        return {"mode": "windows_job", "memory_limit_bytes": row["limits"]["memory_bytes"]}
    monkeypatch.setattr(subject.windows_job, "verify", verify)
    return row, calls, snapshots


def test_default_create_uses_native_memory_option_not_systemd(backend, tmp_path):
    row, calls, _ = backend
    result = subject.create("home", str(tmp_path))
    assert result["id"] == row["id"] and result["created"] is True
    args = next(args for args, _ in calls if args[0] == "start")
    assert args[args.index("--memory") + 1] == str(12 * 1024**3)
    assert "systemd-run" not in args and "none" not in args


@pytest.mark.parametrize("mem", ["none", "bogus", "1"])
def test_invalid_or_uncapped_policy_refuses_before_backend_call(backend, tmp_path, mem):
    _, calls, _ = backend
    with pytest.raises(subject.SessionError):
        subject.create("home", str(tmp_path), mem=mem)
    assert calls == []


def test_project_cannot_request_uncapped_memory(backend, tmp_path):
    (tmp_path / "cgroups.toml").write_text('mem = "none"\n')
    with pytest.raises(subject.SessionError):
        subject.create("home", str(tmp_path))
    assert backend[1] == []


@pytest.mark.parametrize("field,value", [("id", None), ("id", "invalid"), ("tag", "another"),
                                        ("workspace", "other-workspace")])
def test_malformed_create_never_guesses_or_kills_an_id(backend, tmp_path, field, value):
    row, calls, _ = backend
    row[field] = value
    with pytest.raises(subject.SessionError) as caught:
        subject.create("home", str(tmp_path))
    assert caught.value.uncertain
    assert not any(args[0] == "kill" for args, _ in calls)


def test_existing_same_session_is_reused_with_verified_bound(backend, tmp_path):
    row, calls, snapshots = backend
    snapshots[:] = [[copy.deepcopy(row)]]
    result = subject.create("home", str(tmp_path))
    assert result["id"] == row["id"] and not result["created"]
    assert [args for args, _ in calls] == [["snapshot"]]


def test_weaker_existing_job_is_never_silently_reused_or_killed(backend, tmp_path):
    row, calls, snapshots = backend
    row["limits"]["memory_bytes"] = 24 * 1024**3
    snapshots[:] = [[copy.deepcopy(row)]]
    with pytest.raises(subject.SessionError, match="weaker"):
        subject.create("home", str(tmp_path))
    assert [args for args, _ in calls] == [["snapshot"]]


@pytest.mark.parametrize("limits", [[], "broken", {}, {"memory_bytes": True}])
def test_bad_memory_record_is_refused_without_kernel_or_cleanup(backend, limits):
    row, _, _ = backend
    row["limits"] = limits
    with pytest.raises(subject.SessionError):
        subject._verify_record(row)


def test_duplicate_display_names_require_uuid(backend, monkeypatch):
    row, _, _ = backend
    second = {**row, "id": str(uuid4())}
    monkeypatch.setattr(subject, "snapshot", lambda binary: [row, second])
    with pytest.raises(subject.SessionError, match="full immutable"):
        subject.resolve("verified-bundled-a", subject.sessions.aplexer_display_name(row))


def test_json_timeout_marks_create_uncertain_without_retry(monkeypatch):
    calls = []
    def timeout(argv, **kwargs):
        calls.append(argv)
        raise subprocess.TimeoutExpired(argv, 20)
    monkeypatch.setattr(subprocess, "run", timeout)
    with pytest.raises(subject.SessionError) as caught:
        subject._json("verified-a", ["start"], creating=True)
    assert caught.value.code == 124 and caught.value.uncertain and len(calls) == 1


def test_json_malformed_success_is_not_accepted(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda argv, **kw: subprocess.CompletedProcess(argv, 0, "not json", ""))
    with pytest.raises(subject.SessionError) as caught:
        subject._json("verified-a", ["start"], creating=True)
    assert caught.value.uncertain


def test_kill_requires_exact_backend_removal_receipt(backend, monkeypatch):
    row, calls, _ = backend
    monkeypatch.setattr(subject, "resolve", lambda binary, selector: row)
    monkeypatch.setattr(subject, "_json", lambda binary, args: {"id": str(uuid4()), "record_removed": True})
    with pytest.raises(subject.SessionError, match="not confirmed"):
        subject.kill(row["id"])
    assert calls == []


@pytest.mark.parametrize("value", [None, "", "abc", str(uuid4()).upper()])
def test_only_canonical_full_uuids_are_accepted(value):
    with pytest.raises(subject.SessionError):
        subject._uuid(value)


def test_packaged_backend_pair_is_required_not_path_fallback(monkeypatch, tmp_path):
    from types import SimpleNamespace
    monkeypatch.setattr(subject.sys, "executable", str(tmp_path / "python.exe"))
    bundled, worker = tmp_path / "a.exe", tmp_path / "aplexer.exe"
    bundled.write_bytes(b"same-reviewed-pair")
    worker.write_bytes(bundled.read_bytes())
    selected = SimpleNamespace(path=str(bundled), worker=str(worker))
    monkeypatch.setattr(subject.aplexer, "resolve_a", lambda: selected)
    assert subject.backend() == str(bundled)
    selected.path = str(tmp_path / "PATH/a.exe")
    with pytest.raises(subject.SessionError, match="packaged"):
        subject.backend()
    selected.path = str(bundled)
    worker.write_bytes(b"changed-worker")
    with pytest.raises(subject.SessionError, match="does not verify"):
        subject.backend()


def test_duplicate_backend_ids_are_never_treated_as_one_target(monkeypatch):
    row = {"id": str(uuid4())}
    monkeypatch.setattr(subject, "_json", lambda *args: [row, row.copy()])
    with pytest.raises(subject.SessionError, match="duplicate identities"):
        subject.snapshot("verified-bundled-a")
