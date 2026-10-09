"""`pocketshell gateway agent` — the ordinary-user (active-console) Windows runtime.

Contract: /home/alexey/tmp/pocketshell-fleet-20261008/user-background-api-agreement.md (v1).
No elevation, no scheduled task, no S4U: the Desktop app (tray, started at
sign-in) invokes the CLI with a fixed argv; the CLI spawns the guardian and
the outbound link hidden in the caller's own session and reports a JSON
status. The guardian's READY context must be the ACTIVE-CONSOLE branch
(own SID, the caller's session, WinSta0/Default at launch); after launch a
locked workstation (input desktop = Winlogon) keeps it ready.

Everything native is faked here (Linux-run); test_windows_gateway_user_agent_native.py
runs the fake guardian for real in the runner's interactive session.
"""

# ruff: noqa: F811
from __future__ import annotations

import hashlib
import json
import os

import pytest
from click.testing import CliRunner

from pocketshell.cli import cli
from pocketshell.gateway import service_endpoint as ep
from pocketshell.gateway import service_hostkey as hostkey
from pocketshell.gateway import service_windows as win
from pocketshell.gateway import service_windows_endpoint as wep
from pocketshell.gateway.service_common import ServiceError

from test_gateway_service import QUALIFIED, USER_SID, WIN_CONFIG, WIN_HELPER, _task_verbs, fake_windows  # noqa: F401
from test_gateway_service_endpoint import (  # noqa: F401
    API, GUARDIAN, MANIFEST, POLICY, PYTHON, ROOT, SHA_A, SHA_G, SHA_P, SHOW_22024, STATE,
    EndpointApi, Guardian, encode, manifest, config_text,
)

SESSION = 1
CONSOLE = {"ownerSID": USER_SID, "session": SESSION, "station": "WinSta0", "stationVisible": True,
           "desktop": "Default", "activeConsoleSession": SESSION, "authenticationLUID": "77"}


class AgentApi(EndpointApi):
    """Native facts of an ordinary user session + hidden spawns."""

    def __init__(self, vfs, guardian_holder):
        super().__init__(vfs)
        self.session = SESSION
        self.spawns = []
        self.terminated = []
        self.guardian_holder = guardian_holder
        self.next_link_pid = 9000
        self.input_desktop = "Default"

    def current_session(self):
        return self.session

    # job situation of spawned children: None = broke away (no job);
    # otherwise {"killOnJobClose": bool} for the caller's job they stayed in
    caller_job = None
    terminate_fails = False

    def spawn_hidden(self, argv, cwd, env, *, image_sha256=None):
        self.spawns.append({"argv": list(argv), "cwd": cwd, "env": dict(env) if env is not None else None,
                            "imageSHA256": image_sha256})
        if self.caller_job is not None:
            raise win.CallerJobError("the child is inside a job object (it could not break away from the "
                                     "caller's job; KILL_ON_JOB_CLOSE "
                                     f"{'set' if self.caller_job['killOnJobClose'] else 'not set on the nearest job'}); "
                                     "independence cannot be proven; the suspended child was terminated before resume")
        job = {"inJob": self.caller_job is not None,
               "callerJobKillOnClose": bool(self.caller_job and self.caller_job["killOnJobClose"]),
               "brokeAway": self.caller_job is None, "elevated": False, "session": self.session}
        if argv[0] == PYTHON:
            self.guardian_holder["g"].run("agent")
            ready = json.loads(self.vfs[self.guardian_holder["g"].generation + "\\READY.json"]) \
                if self.guardian_holder["g"].ready_on_run else None
            pid = ready["guardianPID"] if ready else self.guardian_holder["g"].next_pid - 1
            return {"pid": pid, "creationFILETIME": self.births.get(pid, "1"), **job}
        pid = self.next_link_pid
        self.next_link_pid += 1
        self.births[pid] = f"1350{pid}"
        self.images[pid] = argv[0]
        return {"pid": pid, "creationFILETIME": self.births[pid], **job}

    denied_birth = frozenset()   # pids whose birth query is denied (unverifiable)
    denied_image = frozenset()   # pids whose image query is denied (unverifiable)

    def process_birth(self, pid):
        return None if pid in self.denied_birth else self.births.get(pid)

    def process_image(self, pid):
        return None if pid in self.denied_image else self.images.get(pid)

    def process_identity(self, pid):
        """Tri-state, as WindowsApi.process_identity: absent is PROVEN only."""
        if pid in self.denied_birth:
            return {"state": "unknown", "birth": None, "image": None}
        if pid not in self.births:
            return {"state": "absent", "birth": None, "image": None}
        image = None if pid in self.denied_image else self.images.get(pid)
        return {"state": "present", "birth": self.births[pid], "image": image}

    def terminate_exact(self, pid, birth, image):
        if self.terminate_fails or pid in self.denied_birth or pid in self.denied_image:
            return False  # e.g. access denied / wait timeout: the process stays alive
        if self.births.get(pid) != birth or not win._same_path(self.images.get(pid), image):
            return False
        self.terminated.append((pid, birth, image))
        self.births.pop(pid)
        return True


@pytest.fixture
def agent(fake_windows, monkeypatch, tmp_path):
    vfs: dict = {}
    doc = manifest()
    data = encode(doc)
    vfs[MANIFEST] = data
    vfs[ep.ntpath.normpath(doc["config"])] = config_text(doc).encode()
    holder: dict = {}
    api = AgentApi(vfs, holder)
    g = Guardian(fake_windows, api, vfs, data)
    g.context = CONSOLE
    holder["g"] = g
    api.guardian = g
    fake_windows.show_out = SHOW_22024
    monkeypatch.setattr(wep, "read_bounded", lambda path, limit: vfs.get(path))
    monkeypatch.setattr(ep, "ALLOWED_ENDPOINT_MANIFEST_SHA256", frozenset({hashlib.sha256(data).hexdigest()}))
    monkeypatch.setattr(ep, "ALLOWED_GUARDIAN_SOURCES", frozenset({(SHA_G, SHA_A, SHA_P)}))
    digests = {GUARDIAN: SHA_G, API: SHA_A, POLICY: SHA_P}
    monkeypatch.setattr(win, "file_sha256", lambda p: digests.get(p, QUALIFIED))
    monkeypatch.setattr(hostkey, "verify_host_key", lambda port, key, **kw: (True, "proved the enrolled host key"))
    monkeypatch.setattr(win, "WindowsApi", lambda: api)
    monkeypatch.setattr(wep, "POLL_SECONDS", 0.01)
    monkeypatch.setattr(wep, "STOP_CONFIRM_SECONDS", 0.3)
    from pocketshell.gateway import service_user_agent as agent_mod

    def write(path, data):  # the private store, without the native DACL layer (unit level)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(data)

    def read(path, limit=65536):
        try:
            with open(path, "rb") as handle:
                return handle.read(limit)
        except FileNotFoundError:
            return None

    monkeypatch.setattr(agent_mod, "_write_private", write)
    monkeypatch.setattr(agent_mod, "_read_private", read)
    monkeypatch.setattr("sys.platform", "win32")
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "profile"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    return {"api": api, "g": g, "vfs": vfs, "fake": fake_windows, "doc": doc}


def run(*args):
    result = CliRunner().invoke(cli, ["gateway", "agent", *args])
    data = None
    if result.stdout.strip().startswith("{"):
        data = json.loads(result.stdout)
    return result, data


def bind():
    return run("bind", "--manifest", MANIFEST, "--config-dir", WIN_CONFIG, "--helper", WIN_HELPER, "--json")


# --- READY: the active-console mode (never weakening the S4U task checks) ---------------


def _ready(context, station_prefix=None):
    m = ep.parse_manifest(encode(manifest()), MANIFEST)
    station = station_prefix or context["station"]
    ready = {"pid": 10, "creationFILETIME": "1234", "guardianPID": 11, "manifestSHA256": m.sha256,
             "port": 22024, "sourceSHA256": SHA_G, "heldProcessHandle": True, "ownedJob": True,
             "context": context, "privateDesktop": station + "\\PocketShellPrivate_" + "a" * 32,
             "desktopACL": {"ownerSID": USER_SID, "protectedDACL": True,
                            "allowTrustees": sorted([USER_SID, "S-1-5-18", "S-1-5-32-544"]), "ACECount": 3}}
    return m, json.dumps(ready).encode()


def test_active_console_ready_is_a_distinct_mode():
    m, data = _ready(CONSOLE)
    ready = ep.parse_ready(data, m, mode=ep.MODE_ACTIVE_CONSOLE, session=SESSION)
    assert ready.mode == ep.MODE_ACTIVE_CONSOLE and ready.session == SESSION
    with pytest.raises(ServiceError, match="session"):
        ep.parse_ready(data, m)  # the S4U task path still refuses the interactive branch


@pytest.mark.parametrize(
    "change, message",
    [
        ({"session": 2}, "session"),
        ({"session": 0}, "session"),
        ({"station": "Service-0x0-1$"}, "WinSta0"),
        ({"stationVisible": False}, "visible"),
        ({"desktop": "Winlogon"}, "Default"),
        ({"activeConsoleSession": 3}, "active console"),
        ({"ownerSID": "S-1-5-21-1-2-3-4"}, "owner"),
    ],
)
def test_active_console_ready_refusals(change, message):
    m, data = _ready({**CONSOLE, **change})
    with pytest.raises(ServiceError, match=message):
        ep.parse_ready(data, m, mode=ep.MODE_ACTIVE_CONSOLE, session=SESSION)


def test_active_console_private_desktop_on_winsta0():
    m, data = _ready(CONSOLE, station_prefix="Service-0x0-1$")
    with pytest.raises(ServiceError, match="privateDesktop"):
        ep.parse_ready(data, m, mode=ep.MODE_ACTIVE_CONSOLE, session=SESSION)


# --- CLI: bind / status / start / stop -------------------------------------------------------


def test_agent_group_exists():
    result = CliRunner().invoke(cli, ["gateway", "agent", "--help"])
    assert result.exit_code == 0
    for verb in ("bind", "start", "stop", "status"):
        assert verb in result.output


def test_bind_validates_and_stores_the_protected_binding(agent):
    result, data = bind()
    assert result.exit_code == 0, result.output
    assert data["version"] == 1 and data["binding"]["manifestSHA256"] == hashlib.sha256(
        agent["vfs"][MANIFEST]).hexdigest()
    assert data["binding"]["deviceId"] == "host-laptop-pha6tcnc-75fu" and data["binding"]["port"] == 22024
    assert not _task_verbs(agent["fake"])  # no scheduled task in this mode


def test_bind_refuses_unreviewed_manifest(agent, monkeypatch):
    monkeypatch.setattr(ep, "ALLOWED_ENDPOINT_MANIFEST_SHA256", frozenset())
    result, data = bind()
    assert result.exit_code == 1 and data["error"]["code"] == "binding-refused"


def test_status_unbound_and_stopped(agent):
    result, data = run("status", "--json")
    assert result.exit_code == 1 and data["error"]["code"] == "not-bound" and data["state"] == "unavailable"
    bind()
    result, data = run("status", "--json", "--operation-id", "op-1")
    assert result.exit_code == 4, result.output
    assert data["state"] == "stopped" and data["operationId"] == "op-1"
    assert data["mode"] == "active-console" and data["owner"]["sid"] == USER_SID and data["owner"]["session"] == SESSION


def test_start_spawns_guardian_and_link_hidden_and_reports_ready(agent):
    bind()
    result, data = run("start", "--json", "--operation-id", "op-2")
    assert result.exit_code == 0, result.output
    guardian, link = agent["api"].spawns
    assert guardian["argv"] == [PYTHON, "-I", "-S", "-B", GUARDIAN, "--manifest", MANIFEST]
    assert guardian["cwd"] == ROOT
    assert guardian["env"] == agent["doc"]["environment"]
    assert link["argv"] == [WIN_HELPER, "run", "--config-dir", WIN_CONFIG]
    assert data["state"] == "ready" and data["operationId"] == "op-2"
    e = data["endpoint"]
    assert e["state"] == "ready" and e["hostKey"]["proven"] is True
    assert e["daemon"]["pid"] and e["daemon"]["creationFILETIME"]
    assert e["context"]["station"] == "WinSta0" and e["context"]["session"] == SESSION
    assert data["outbound"]["state"] == "running" and data["outbound"]["pid"] == 9000
    assert not _task_verbs(agent["fake"])
    # idempotent: a second start spawns nothing
    result, data = run("start", "--json")
    assert result.exit_code == 0 and len(agent["api"].spawns) == 2


def test_lock_keeps_it_ready(agent):
    """Locking switches the INPUT desktop to Winlogon; readiness never asks."""
    bind()
    run("start", "--json")
    agent["api"].input_desktop = "Winlogon"
    result, data = run("status", "--json")
    assert result.exit_code == 0 and data["state"] == "ready"


def test_other_session_is_not_ready(agent):
    bind()
    run("start", "--json")
    agent["api"].session = 2
    result, data = run("status", "--json")
    assert result.exit_code == 3 and data["endpoint"]["state"] != "ready"


def test_start_not_ready_by_deadline(agent):
    bind()
    agent["g"].ready_on_run = False
    result, data = run("start", "--json", "--timeout", "0.2")
    assert result.exit_code == 5, result.output
    assert data["state"] in ("starting", "failed") and data["error"]["code"] == "start-deadline"


def test_stop_uses_the_stop_protocol_and_exact_link_identity(agent):
    bind()
    run("start", "--json")
    gen = agent["g"].generation
    ready = json.loads(agent["vfs"][gen + "\\READY.json"])
    result, data = run("stop", "--json", "--operation-id", "op-3")
    assert result.exit_code == 0, result.output
    assert agent["g"].stop_requests == [{"pid": ready["pid"], "creationFILETIME": ready["creationFILETIME"],
                                         "manifestSHA256": hashlib.sha256(agent["vfs"][MANIFEST]).hexdigest(),
                                         "stopOwnedJob": True}]
    assert agent["api"].terminated == [(9000, "13509000", WIN_HELPER)]
    assert data["state"] == "stopped" and data["operationId"] == "op-3"
    result, data = run("status", "--json")
    assert result.exit_code == 4 and data["state"] == "stopped"


def test_stop_never_kills_a_reused_link_pid(agent):
    bind()
    run("start", "--json")
    agent["api"].births[9000] = "999"  # the pid now belongs to another process
    result, data = run("stop", "--json")
    assert agent["api"].terminated == []
    assert data["outbound"]["state"] == "stopped"


def test_stop_failure_is_reported_not_success(agent):
    bind()
    run("start", "--json")
    agent["g"].close_accepted = False
    result, data = run("stop", "--json")
    assert result.exit_code == 1 and data["state"] == "failed" and data["error"]["code"] == "stop-failed"


def test_operation_id_validation_and_platform(agent, monkeypatch):
    result, data = run("status", "--json", "--operation-id", "bad id;x")
    assert result.exit_code == 2
    monkeypatch.setattr("sys.platform", "linux")
    result, data = run("status", "--json")
    assert result.exit_code == 1 and data["error"]["code"] == "unsupported-platform"


def test_no_elevation_or_task_scheduler_anywhere(agent):
    bind()
    run("start", "--json")
    run("status", "--json")
    run("stop", "--json")
    for argv in agent["fake"].calls:
        joined = " ".join(map(str, argv)).lower()
        assert "schtasks" not in joined and "registertask" not in joined and "runas" not in joined


# --- root review of 28fae5c ------------------------------------------------------------


def test_r1_failed_link_termination_keeps_custody_and_fails(agent):
    bind()
    run("start", "--json")
    agent["api"].terminate_fails = True
    result, data = run("stop", "--json")
    assert result.exit_code == 1 and data["state"] == "failed"
    assert data["outbound"]["state"] == "running" and data["outbound"]["pid"] == 9000
    from pocketshell.gateway import service_user_agent as agent_mod

    assert os.path.exists(agent_mod._path("link.json")), "link custody must be retained"
    agent["api"].terminate_fails = False
    result, data = run("stop", "--json")
    assert result.exit_code == 0 and data["state"] == "stopped"
    assert agent["api"].terminated == [(9000, "13509000", WIN_HELPER)]


def test_r1_link_gone_or_pid_reused_counts_as_stopped(agent):
    bind()
    run("start", "--json")
    agent["api"].terminate_fails = True
    agent["api"].births[9000] = "424242"  # pid reused by another process
    result, data = run("stop", "--json")
    assert result.exit_code == 0 and data["outbound"]["state"] == "stopped"
    assert agent["api"].terminated == []


def test_r2_children_in_a_kill_on_close_caller_job_are_refused(agent):
    bind()
    agent["api"].caller_job = {"killOnJobClose": True}
    result, data = run("start", "--json")
    assert result.exit_code == 1 and data["error"]["code"] == "caller-job"
    assert "KILL_ON_JOB_CLOSE" in data["error"]["message"]


def test_r2_any_job_membership_is_refused_never_claimed(agent):
    """root 626 review: the nearest job cannot prove ancestor KILL semantics."""
    bind()
    agent["api"].caller_job = {"killOnJobClose": False}
    result, data = run("start", "--json")
    assert result.exit_code == 1 and data["error"]["code"] == "caller-job"
    assert "independence cannot be proven" in data["error"]["message"]


def test_r2_broke_away_children(agent):
    bind()
    result, data = run("start", "--json")
    assert data["endpoint"]["launch"]["brokeAway"] is True and data["endpoint"]["launch"]["inJob"] is False
    assert data["outbound"]["launch"]["brokeAway"] is True


# --- root START2: guardian launch custody without CURRENT/READY ---------------------------


def _guardian_launch(agent):
    from pocketshell.gateway import service_user_agent as agent_mod

    data = agent_mod._read_private(agent_mod._path("guardian.json"))
    return json.loads(data) if data else None


def test_start2_timeout_keeps_guardian_custody_and_stop_consumes_it(agent):
    bind()
    agent["g"].ready_on_run = False
    result, data = run("start", "--json", "--timeout", "0.2")
    assert result.exit_code == 5
    launch = _guardian_launch(agent)
    assert launch and agent["api"].process_birth(launch["pid"]) == launch["creationFILETIME"]
    assert data["endpoint"]["guardianLaunch"] == {"pid": launch["pid"], "creationFILETIME": launch["creationFILETIME"],
                                                  "running": True}
    result, data = run("stop", "--json")
    assert result.exit_code == 0, data
    assert (launch["pid"], launch["creationFILETIME"], PYTHON) in agent["api"].terminated
    assert _guardian_launch(agent) is None and data["state"] == "stopped"


def test_start2_live_noready_guardian_failed_stop_retains_custody(agent):
    bind()
    agent["g"].ready_on_run = False
    run("start", "--json", "--timeout", "0.2")
    launch = _guardian_launch(agent)
    agent["api"].terminate_fails = True
    result, data = run("stop", "--json")
    assert result.exit_code == 1 and data["state"] == "failed"
    assert str(launch["pid"]) in data["error"]["message"]
    assert _guardian_launch(agent) == launch
    agent["api"].terminate_fails = False
    result, data = run("stop", "--json")
    assert result.exit_code == 0 and _guardian_launch(agent) is None


def test_start2_restart_reuses_live_launched_guardian(agent):
    bind()
    agent["g"].ready_on_run = False
    run("start", "--json", "--timeout", "0.2")
    launch = _guardian_launch(agent)
    guardians = [s for s in agent["api"].spawns if s["argv"][0] == PYTHON]
    result, data = run("start", "--json", "--timeout", "0.2")
    assert result.exit_code == 5
    assert [s for s in agent["api"].spawns if s["argv"][0] == PYTHON] == guardians, "no second guardian"
    assert _guardian_launch(agent) == launch


# --- root review of 5a50: unverifiable is not absent; record-write failure -------------


@pytest.mark.parametrize("denied", ["denied_birth", "denied_image"])
def test_u1_unverifiable_guardian_is_retained_and_stop_fails(agent, denied):
    bind()
    agent["g"].ready_on_run = False
    run("start", "--json", "--timeout", "0.2")
    launch = _guardian_launch(agent)
    setattr(agent["api"], denied, frozenset({launch["pid"]}))
    result, data = run("stop", "--json")
    assert result.exit_code == 1 and data["state"] == "failed", data
    assert str(launch["pid"]) in data["error"]["message"]
    assert _guardian_launch(agent) == launch, "unverifiable custody must be retained"
    setattr(agent["api"], denied, frozenset())
    result, data = run("stop", "--json")
    assert result.exit_code == 0 and _guardian_launch(agent) is None


@pytest.mark.parametrize("denied", ["denied_birth", "denied_image"])
def test_u1_unverifiable_link_is_retained_and_stop_fails(agent, denied):
    from pocketshell.gateway import service_user_agent as agent_mod

    bind()
    run("start", "--json")
    setattr(agent["api"], denied, frozenset({9000}))
    result, data = run("stop", "--json")
    assert result.exit_code == 1 and data["state"] == "failed"
    assert os.path.exists(agent_mod._path("link.json"))
    setattr(agent["api"], denied, frozenset())
    result, data = run("stop", "--json")
    assert result.exit_code == 0 and not os.path.exists(agent_mod._path("link.json"))


def test_u1_unverifiable_launched_guardian_blocks_a_second_spawn(agent):
    bind()
    agent["g"].ready_on_run = False
    run("start", "--json", "--timeout", "0.2")
    launch = _guardian_launch(agent)
    agent["api"].denied_birth = frozenset({launch["pid"]})
    n = len(agent["api"].spawns)
    result, data = run("start", "--json", "--timeout", "0.2")
    assert result.exit_code == 1 and data["error"]["code"] == "custody-unverifiable"
    assert len(agent["api"].spawns) == n


def test_u2_record_write_and_termination_both_fail_keep_a_recovery_identity(agent, monkeypatch):
    from pocketshell.gateway import service_user_agent as agent_mod

    bind()
    real = agent_mod._write_private

    def failing(path, data):
        if path.endswith("guardian.json"):
            raise OSError("disk full")
        return real(path, data)

    monkeypatch.setattr(agent_mod, "_write_private", failing)
    agent["api"].terminate_fails = True
    result, data = run("start", "--json", "--timeout", "0.2")
    assert result.exit_code == 1 and data["error"]["code"] == "launch-unrecorded"
    rec = data["error"]["recovery"]
    pid = rec["pid"]
    assert rec == {"pid": pid, "creationFILETIME": agent["api"].births[pid], "image": PYTHON,
                   "record": "guardian.json"}
    assert "was ended" not in data["error"]["message"]
    saved = json.loads(agent_mod._read_private(agent_mod._path(f"recovery-guardian-{pid}.json")))
    assert saved == rec


def test_u2_record_write_fails_but_termination_proven(agent, monkeypatch):
    from pocketshell.gateway import service_user_agent as agent_mod

    bind()
    real = agent_mod._write_private
    monkeypatch.setattr(agent_mod, "_write_private",
                        lambda p, d: (_ for _ in ()).throw(OSError("disk full")) if p.endswith("guardian.json")
                        else real(p, d))
    result, data = run("start", "--json", "--timeout", "0.2")
    assert result.exit_code == 1 and data["error"]["code"] == "launch-unrecorded"
    assert "was ended" in data["error"]["message"] and data["error"].get("recovery") is None


# --- root review of 83379b7: residual custody ----------------------------------------


def test_a1_unverifiable_link_is_not_stopped_and_blocks_a_second_link(agent):
    from pocketshell.gateway import service_user_agent as agent_mod

    bind()
    run("start", "--json")
    link = json.loads(agent_mod._read_private(agent_mod._path("link.json")))
    agent["api"].denied_birth = frozenset({9000})
    result, data = run("status", "--json")
    assert data["outbound"]["state"] == "unknown" and data["state"] != "stopped"
    assert result.exit_code == 3 and data["state"] == "failed"
    n = len(agent["api"].spawns)
    result, data = run("start", "--json")
    assert result.exit_code == 1 and data["error"]["code"] == "custody-unverifiable"
    assert len(agent["api"].spawns) == n, "no duplicate link"
    assert json.loads(agent_mod._read_private(agent_mod._path("link.json"))) == link


def _fail_guardian_record(agent, monkeypatch):
    from pocketshell.gateway import service_user_agent as agent_mod

    real = agent_mod._write_private

    def failing(path, data):
        if path.endswith("guardian.json"):
            raise OSError("disk full")
        return real(path, data)

    monkeypatch.setattr(agent_mod, "_write_private", failing)
    agent["api"].terminate_fails = True
    result, data = run("start", "--json", "--timeout", "0.2")
    assert data["error"]["code"] == "launch-unrecorded"
    monkeypatch.setattr(agent_mod, "_write_private", real)
    agent["api"].terminate_fails = False
    return data["error"]["recovery"]


def test_a2_recovery_record_is_custody_for_status_start_and_stop(agent, monkeypatch):
    from pocketshell.gateway import service_user_agent as agent_mod

    bind()
    agent["g"].ready_on_run = False
    rec = _fail_guardian_record(agent, monkeypatch)
    result, data = run("status", "--json")
    assert data["state"] == "failed" and result.exit_code == 3
    assert any(str(rec["pid"]) in p for p in data["endpoint"]["problems"])
    n = len(agent["api"].spawns)
    result, data = run("start", "--json", "--timeout", "0.2")
    assert result.exit_code == 1 and data["error"]["code"] == "custody-recovery"
    assert len(agent["api"].spawns) == n
    result, data = run("stop", "--json")  # no manual PID action
    assert result.exit_code == 0, data
    assert (rec["pid"], rec["creationFILETIME"], PYTHON) in agent["api"].terminated
    assert not os.path.exists(agent_mod._path(f"recovery-guardian-{rec['pid']}.json"))
    result, data = run("status", "--json")
    assert result.exit_code == 4 and data["state"] == "stopped"


def test_a2_live_recovery_record_survives_a_failed_stop(agent, monkeypatch):
    from pocketshell.gateway import service_user_agent as agent_mod

    bind()
    agent["g"].ready_on_run = False
    rec = _fail_guardian_record(agent, monkeypatch)
    agent["api"].terminate_fails = True
    result, data = run("stop", "--json")
    assert result.exit_code == 1 and str(rec["pid"]) in data["error"]["message"]
    assert os.path.exists(agent_mod._path(f"recovery-guardian-{rec['pid']}.json"))


@pytest.mark.parametrize("record", ["guardian.json", "link.json"])
@pytest.mark.parametrize("payload", [b"{", b"[]", b'{"pid": "x"}'])
def test_a3_malformed_custody_record_is_failed_and_retained(agent, record, payload):
    from pocketshell.gateway import service_user_agent as agent_mod

    bind()
    agent_mod._write_private(agent_mod._path(record), payload)
    result, data = run("status", "--json")
    assert data["state"] == "failed" and result.exit_code == 3
    result, data = run("stop", "--json")
    assert result.exit_code == 1 and data["state"] == "failed"
    assert "malformed" in data["error"]["message"]
    assert agent_mod._read_private(agent_mod._path(record)) == payload
    n = len(agent["api"].spawns)
    result, data = run("start", "--json", "--timeout", "0.2")
    assert result.exit_code == 1 and data["error"]["code"] == "custody-unverifiable"
    assert len(agent["api"].spawns) == n


# --- v3.1 (consumer review): stopped requires the listener proven absent --------------


def test_v31_no_generation_but_port_served_is_not_stopped(agent):
    bind()
    agent["api"].listeners[22024] = [("127.0.0.1", 4242)]  # served, no CURRENT/READY, no custody
    result, data = run("status", "--json")
    assert data["endpoint"]["state"] != "stopped" and data["state"] != "stopped"
    assert result.exit_code == 3
    assert any("22024" in p for p in data["endpoint"]["problems"])


def test_v31_listener_query_failure_is_not_stopped(agent, monkeypatch):
    bind()

    def boom(port):
        raise ServiceError("GetExtendedTcpTable failed")

    monkeypatch.setattr(agent["api"], "listener_pids", boom)
    result, data = run("status", "--json")
    assert data["state"] != "stopped" and result.exit_code in (1, 3)


def test_v31_spawns_hold_and_pin_their_images(agent):
    bind()
    run("start", "--json")
    link = [x for x in agent["api"].spawns if x["argv"][0] == WIN_HELPER][0]
    assert link["imageSHA256"] == QUALIFIED  # the bound helper digest, re-hashed from the held handle


def test_v31_partial_start_with_unverifiable_custody_is_failed_not_starting(agent, monkeypatch):
    """exit 5 'starting' only when nothing is unknown; unknown custody => failed."""
    bind()
    agent["g"].ready_on_run = False
    real = agent["api"].spawn_hidden

    def spawn(argv, cwd, env, *, image_sha256=None):
        meta = real(argv, cwd, env, image_sha256=image_sha256)
        if argv[0] == WIN_HELPER:
            agent["api"].denied_birth = frozenset({meta["pid"]})
        return meta

    monkeypatch.setattr(agent["api"], "spawn_hidden", spawn)
    result, data = run("start", "--json", "--timeout", "0.2")
    assert result.exit_code == 5 and data["error"]["code"] == "start-deadline"
    assert data["state"] == "failed" and data["outbound"]["state"] == "unknown"


# --- root review of 1e00f00: UNKNOWN primary guardian identity is never ready ---------


@pytest.mark.parametrize("denied", ["denied_birth", "denied_image"])
def test_r1e00_unknown_primary_guardian_is_not_ready(agent, denied):
    bind()
    result, data = run("start", "--json")
    assert result.exit_code == 0 and data["state"] == "ready"
    launch = _guardian_launch(agent)
    setattr(agent["api"], denied, frozenset({launch["pid"]}))
    result, data = run("status", "--json")
    assert data["outbound"]["state"] == "running"
    assert data["endpoint"]["guardianLaunch"]["running"] is None
    assert data["state"] == "failed" and result.exit_code == 3, data
    assert any(str(launch["pid"]) in p for p in data["endpoint"]["custodyProblems"])
    result, data = run("start", "--json")
    assert result.exit_code == 1 and data["error"]["code"] == "custody-unverifiable"


def test_r1e00_ready_requires_the_current_measured_guardian(agent):
    """READY's guardianPID must be the exact launched guardian, measured alive."""
    from pocketshell.gateway import service_user_agent as agent_mod

    bind()
    run("start", "--json")
    os.unlink(agent_mod._path("guardian.json"))  # no current launch measurement at all
    result, data = run("status", "--json")
    assert data["state"] != "ready" and result.exit_code == 3, data
