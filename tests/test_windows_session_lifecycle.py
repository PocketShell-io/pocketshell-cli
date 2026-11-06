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
    row = {"id": str(uuid4()), "workspace": str(tmp_path), "tag": "home", "phase": "running", "state": "running",
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
    monkeypatch.setattr(subject, "_record", lambda binary, selector: row)
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


def test_explicit_finished_kill_requires_native_removal_and_fresh_absence(backend, monkeypatch):
    row, calls, snapshots = backend
    row.update(phase="exited", state="exited", worker_alive=False, containment_empty=True, worker_pid=5678)
    snapshots[:] = [[copy.deepcopy(row)], [copy.deepcopy(row)], []]
    checked = []
    monkeypatch.setattr(subject.windows_job, "verify_finished", lambda *args: checked.append(args))
    original = subject._json
    def response(binary, args, **kwargs):
        if args[0] == "kill":
            calls.append((args, kwargs))
            return {"id": row["id"], "record_removed": True}
        return original(binary, args, **kwargs)
    monkeypatch.setattr(subject, "_json", response)
    result = subject.kill(row["id"])
    assert result["killed"] is True and result["reaped"] is True
    assert checked == [(row["id"], 5678, 1234)]
    assert [args for args, _ in calls] == [["snapshot"], ["snapshot"], ["kill", row["id"], "--grace-ms", "1000"], ["snapshot"]]


@pytest.mark.parametrize("field,value", [("worker_alive", True), ("worker_alive", None),
    ("worker_alive", 0), ("containment_empty", False), ("containment_empty", None),
    ("phase", "running"), ("state", "running"), ("state", None), ("phase", "unknown")])
def test_finished_cleanup_refuses_missing_or_contradictory_facts(backend, monkeypatch, field, value):
    row, calls, snapshots = backend
    row.update(phase="exited", state="exited", worker_alive=False, containment_empty=True, worker_pid=5678)
    row[field] = value
    snapshots[:] = [[copy.deepcopy(row)]]
    checked = []
    monkeypatch.setattr(subject.windows_job, "verify_finished", lambda *args: checked.append(args))
    with pytest.raises(subject.SessionError):
        subject.kill(row["id"])
    assert not checked and all(args == ["snapshot"] for args, _ in calls)


def test_finished_cleanup_refuses_native_absence_uncertainty(backend, monkeypatch):
    row, calls, snapshots = backend
    row.update(phase="exited", state="exited", worker_alive=False, containment_empty=True, worker_pid=5678)
    snapshots[:] = [[copy.deepcopy(row)]]
    def uncertain(*args):
        raise subject.windows_job.JobError("access denied or reused PID")
    monkeypatch.setattr(subject.windows_job, "verify_finished", uncertain)
    with pytest.raises(subject.SessionError, match="access denied"):
        subject.kill(row["id"])
    assert [args for args, _ in calls] == [["snapshot"]]


def test_finished_cleanup_refuses_identity_changed_during_absence_check(backend, monkeypatch):
    row, calls, snapshots = backend
    row.update(phase="exited", state="exited", worker_alive=False, containment_empty=True, worker_pid=5678)
    changed = {**row, "worker_pid": 9999}
    snapshots[:] = [[copy.deepcopy(row)], [changed]]
    monkeypatch.setattr(subject.windows_job, "verify_finished", lambda *args: None)
    with pytest.raises(subject.SessionError, match="identity changed"):
        subject.kill(row["id"])
    assert [args for args, _ in calls] == [["snapshot"], ["snapshot"]]


@pytest.mark.parametrize("process_result,process_error,job_result,job_error,allowed", [
    (0, 87, 0, 2, True), (0, 1168, 0, 2, True),
    (123, 0, 0, 2, False), (0, 5, 0, 2, False), (0, 6, 0, 2, False),
    (0, 87, 456, 0, False), (0, 87, 0, 5, False), (0, 87, 0, 0, False),
])
def test_finished_native_guard_uses_only_read_queries_and_refuses_ambiguity(
        monkeypatch, process_result, process_error, job_result, job_error, allowed):
    import ctypes
    from types import SimpleNamespace
    error, calls = [0], []
    class Function:
        def __init__(self, name, result, last_error):
            self.name, self.result, self.last_error = name, result, last_error
        def __call__(self, *args):
            calls.append((self.name, args))
            error[0] = self.last_error
            return self.result
    kernel = SimpleNamespace(OpenProcess=Function("process", process_result, process_error),
                             OpenJobObjectW=Function("job", job_result, job_error),
                             CloseHandle=Function("close", 1, 0))
    monkeypatch.setattr(ctypes, "WinDLL", lambda *args, **kwargs: kernel, raising=False)
    monkeypatch.setattr(ctypes, "get_last_error", lambda: error[0], raising=False)
    if allowed:
        subject.windows_job.verify_finished(str(uuid4()), 1234, 5678)
        assert [name for name, _ in calls] == ["process", "process", "job"]
    else:
        with pytest.raises(subject.windows_job.JobError):
            subject.windows_job.verify_finished(str(uuid4()), 1234, 5678)
    assert all(args[0] == 0x1000 for name, args in calls if name == "process")
    assert all(args[0] == 4 for name, args in calls if name == "job")
    if process_result:
        assert ("close", (process_result,)) in calls
    if job_result and not process_result and process_error in (87, 1168):
        assert ("close", (job_result,)) in calls


@pytest.mark.parametrize("pids", [(None, 1), (True, 1), (0, 1), (-1, 1), (2**32, 1), (1, 1)])
def test_finished_guard_refuses_unknown_pid_identity_before_any_os_query(monkeypatch, pids):
    import ctypes
    def forbidden(*args, **kwargs):
        raise AssertionError("No OS query is allowed for malformed identities")
    monkeypatch.setattr(ctypes, "WinDLL", forbidden, raising=False)
    with pytest.raises(subject.windows_job.JobError):
        subject.windows_job.verify_finished(str(uuid4()), *pids)


def test_live_kill_retained_record_is_never_automatically_reaped(backend, monkeypatch):
    row, _, _ = backend
    calls = []
    monkeypatch.setattr(subject, "_record", lambda binary, selector: row)
    def answer(binary, args):
        calls.append(args)
        return {"id": row["id"], "record_removed": False}
    monkeypatch.setattr(subject, "_json", answer)
    monkeypatch.setattr(subject.windows_job, "verify_finished", lambda *args: pytest.fail("No automatic cleanup"))
    with pytest.raises(subject.SessionError, match="not confirmed"):
        subject.kill(row["id"])
    assert calls == [["kill", row["id"], "--grace-ms", "1000"]]


def test_finished_removal_receipt_does_not_replace_fresh_registry_absence(backend, monkeypatch):
    row, _, _ = backend
    row.update(phase="exited", state="exited", worker_alive=False, containment_empty=True, worker_pid=5678)
    monkeypatch.setattr(subject, "_record", lambda binary, selector: row)
    monkeypatch.setattr(subject.windows_job, "verify_finished", lambda *args: None)
    monkeypatch.setattr(subject, "_json", lambda binary, args: {"id": row["id"], "record_removed": True})
    monkeypatch.setattr(subject, "snapshot", lambda binary: [row])
    with pytest.raises(subject.SessionError, match="still appears"):
        subject.kill(row["id"])
