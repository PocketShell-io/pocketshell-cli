"""Run aplexer session commands; reap dead records safely."""
from __future__ import annotations
import json
import os
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Sequence
from pocketshell import session_enum as _session_enum


_SESSION_COMMAND_TIMEOUT_S = 5.0


def _run_session_command(argv: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(argv),
        check=False,
        capture_output=True,
        text=True,
        timeout=_SESSION_COMMAND_TIMEOUT_S,
    )


def _aplexer_records_holding(
    payload: Any, *, workspace: str, tag: str
) -> list[Mapping[str, Any]]:
    if not isinstance(payload, list):
        return []
    target = os.path.realpath(workspace)
    records: list[Mapping[str, Any]] = []
    for raw in payload:
        if not isinstance(raw, Mapping):
            continue
        if str(raw.get("tag") or "") != tag:
            continue
        raw_workspace = raw.get("workspace") or raw.get("cwd") or ""
        if os.path.realpath(str(raw_workspace)) == target:
            records.append(raw)
    return records


def _aplexer_existing_record(
    payload: Any, *, workspace: str, tag: str
) -> Optional[Mapping[str, Any]]:
    for raw in _aplexer_records_holding(payload, workspace=workspace, tag=tag):
        if _session_enum.aplexer_record_is_alive(raw):
            return raw
    return None


def _process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return True
    return True


def _aplexer_live_workload_pid(raw: Mapping[str, Any]) -> Optional[int]:
    try:
        pid = int(raw["workload_pid"])
    except (KeyError, TypeError, ValueError):
        return None
    if pid <= 0 or not _process_alive(pid):
        return None
    return pid


@dataclass(frozen=True)
class _BlockerReap:
    workload_alive: tuple[tuple[str, int], ...] = ()
    may_survive: tuple[str, ...] = ()
    unreaped: tuple[str, ...] = ()


def _reap_aplexer_blockers(
    payload: Any, *, aplexer_path: str, workspace: str, tag: str
) -> _BlockerReap:
    workload_alive: list[tuple[str, int]] = []
    may_survive: list[str] = []
    unreaped: list[str] = []
    for raw in _aplexer_records_holding(payload, workspace=workspace, tag=tag):
        ident = str(raw.get("id") or "").strip()
        if not ident or _session_enum.aplexer_record_is_alive(raw):
            continue
        pid = _aplexer_live_workload_pid(raw)
        if pid is not None:
            workload_alive.append((ident, pid))
            continue
        outcome = _reap_aplexer_record(aplexer_path, ident)
        if not outcome.reaped:
            unreaped.append(ident)
        elif outcome.workload_may_survive:
            may_survive.append(ident)
    return _BlockerReap(tuple(workload_alive), tuple(may_survive), tuple(unreaped))


# ``a kill`` can leave a terminal record behind while the worker winds down.
_REAP_WORKER_STILL_LIVE = "still has a live worker"


_REAP_ALREADY_GONE = "no matching session"


_REAP_MAX_ATTEMPTS = 30


_REAP_POLL_S = 0.1


_REAP_BUDGET_S = 3.0


def _reap_wait() -> None:
    time.sleep(_REAP_POLL_S)


@dataclass(frozen=True)
class _ReapOutcome:
    reaped: bool
    workload_may_survive: bool = False


def _reap_aplexer_record(aplexer_path: str, aplexer_id: str) -> _ReapOutcome:
    deadline = time.monotonic() + _REAP_BUDGET_S
    argv = [aplexer_path, "--json", "forget", "--force", str(aplexer_id)]
    for attempt in range(_REAP_MAX_ATTEMPTS):
        try:
            completed = _run_session_command(argv)
        except (subprocess.TimeoutExpired, OSError):
            return _ReapOutcome(False)
        if completed.returncode == 0:
            return _ReapOutcome(
                True, _reap_workload_may_survive(completed.stdout)
            )
        detail = f"{completed.stderr or ''}{completed.stdout or ''}"
        if _REAP_ALREADY_GONE in detail:
            return _ReapOutcome(True)
        if _REAP_WORKER_STILL_LIVE not in detail:
            return _ReapOutcome(False)
        if attempt + 1 >= _REAP_MAX_ATTEMPTS or time.monotonic() >= deadline:
            return _ReapOutcome(False)
        _reap_wait()
    return _ReapOutcome(False)


def _reap_workload_may_survive(stdout: Optional[str]) -> bool:
    try:
        payload = json.loads(stdout or "")
    except ValueError:
        return False
    return isinstance(payload, Mapping) and bool(payload.get("workload_may_survive"))


def _workload_survivor_warning(name: str, aplexer_id: str) -> str:
    return (
        f"pocketshell: reclaimed {name!r} from aplexer record {aplexer_id}, "
        "but aplexer could not prove its workload containment was empty; "
        "its processes may still be running and are no longer tracked."
    )
