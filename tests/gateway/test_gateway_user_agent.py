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

    def spawn_hidden(self, argv, cwd, env):
        self.spawns.append({"argv": list(argv), "cwd": cwd, "env": dict(env) if env is not None else None})
        if argv[0] == PYTHON:
            self.guardian_holder["g"].run("agent")
            ready = json.loads(self.vfs[self.guardian_holder["g"].generation + "\\READY.json"]) \
                if self.guardian_holder["g"].ready_on_run else None
            pid = ready["guardianPID"] if ready else self.guardian_holder["g"].next_pid - 1
            return pid, self.births.get(pid, "1")
        pid = self.next_link_pid
        self.next_link_pid += 1
        self.births[pid] = f"1350{pid}"
        self.images[pid] = argv[0]
        return pid, self.births[pid]

    def terminate_exact(self, pid, birth, image):
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
