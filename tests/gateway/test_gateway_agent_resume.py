# ruff: noqa: F811
"""Sleep/resume recovery controls (agreement §16.20): children that die WITHOUT
a stop (Modern Standby/S3/hibernate, a crash) leave a measured 'stopped' state,
and an idempotent `start` re-establishes them with fresh custody: a new guardian
generation, new identities, no adoption of dead or PID-reused identities, no
duplicates. Test-only: existing producer behaviour, the fake native layer."""

from __future__ import annotations

import json

from test_gateway_service import fake_windows  # noqa: F401
from test_gateway_user_agent import agent, bind, run  # noqa: F401

from pocketshell.gateway import service_user_agent as agent_mod


def _ready(agent):
    gen = agent["g"].generation
    return gen, json.loads(agent["vfs"][gen + "\\READY.json"])


def _custody(name):
    return json.loads(agent_mod._read_private(agent_mod._path(name)))


def _kill(agent, *, daemon=False, guardian=False, link=False):
    """Death without STOP: the process objects are gone (no receipts)."""
    api = agent["api"]
    _gen, ready = _ready(agent)
    if daemon or guardian:  # the guardian's owned job takes the daemon; a dead daemon ends the guardian
        api.births.pop(ready["pid"], None)
        api.births.pop(ready["guardianPID"], None)
        api.listeners.pop(ready["port"], None)
    if link:
        api.births.pop(_custody("link.json")["pid"], None)


def _start_ready(agent):
    result, data = run("start", "--json")
    assert result.exit_code == 0 and data["state"] == "ready", result.output
    return data


def test_all_children_dead_without_stop_recover_with_fresh_custody(agent):
    bind()
    first = _start_ready(agent)
    gen1, ready1 = _ready(agent)
    guardian1, link1 = _custody("guardian.json"), _custody("link.json")
    _kill(agent, daemon=True, guardian=True, link=True)
    result, data = run("status", "--json")
    assert result.exit_code == 4 and data["state"] == "stopped"
    assert data["endpoint"]["absenceVerified"] and data["outbound"]["absenceVerified"]
    spawns = len(agent["api"].spawns)
    second = _start_ready(agent)
    gen2, ready2 = _ready(agent)
    assert gen2 != gen1 and ready2["pid"] != ready1["pid"] and ready2["guardianPID"] != ready1["guardianPID"]
    assert _custody("guardian.json")["pid"] != guardian1["pid"] and _custody("link.json")["pid"] != link1["pid"]
    assert len(agent["api"].spawns) == spawns + 2  # exactly one guardian + one link: no duplicates
    assert second["endpoint"]["hostKey"]["proven"] is True
    assert first["outbound"]["pid"] != second["outbound"]["pid"]
    assert agent["api"].terminated == []  # nothing dead was "stopped" or adopted
    result, data = run("start", "--json")  # idempotent once recovered
    assert result.exit_code == 0 and len(agent["api"].spawns) == spawns + 2


def test_a_reused_link_pid_is_never_adopted_after_resume(agent):
    bind()
    _start_ready(agent)
    link1 = _custody("link.json")
    _kill(agent, link=True)
    agent["api"].births[link1["pid"]] = "999999"  # another process now owns the pid
    agent["api"].images[link1["pid"]] = "C:\\other\\thing.exe"
    result, data = run("status", "--json")
    assert data["outbound"]["state"] == "stopped"
    spawns = len(agent["api"].spawns)
    _start_ready(agent)
    assert _custody("link.json")["pid"] != link1["pid"] and len(agent["api"].spawns) == spawns + 1
    assert agent["api"].terminated == []  # the unrelated process is never touched


def test_daemon_only_death_recovers_the_endpoint_and_keeps_the_link(agent):
    bind()
    _start_ready(agent)
    gen1, _r = _ready(agent)
    link1 = _custody("link.json")
    _kill(agent, daemon=True)  # the guardian exits with it (CLOSED failure)
    result, data = run("status", "--json")
    assert result.exit_code != 0 and data["endpoint"]["state"] == "stopped" and data["outbound"]["state"] == "running"
    spawns = len(agent["api"].spawns)
    _start_ready(agent)
    assert _ready(agent)[0] != gen1
    assert _custody("link.json") == link1 and len(agent["api"].spawns) == spawns + 1  # guardian only


def test_link_only_death_recovers_the_link_and_keeps_the_endpoint(agent):
    bind()
    _start_ready(agent)
    gen1, ready1 = _ready(agent)
    link1 = _custody("link.json")
    _kill(agent, link=True)
    result, data = run("status", "--json")
    assert data["endpoint"]["state"] == "ready" and data["outbound"]["state"] == "stopped"
    spawns = len(agent["api"].spawns)
    _start_ready(agent)
    assert _ready(agent) == (gen1, ready1)  # the endpoint was untouched
    assert _custody("link.json")["pid"] != link1["pid"] and len(agent["api"].spawns) == spawns + 1
