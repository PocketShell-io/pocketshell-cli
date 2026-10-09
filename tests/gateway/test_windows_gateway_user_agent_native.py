# ruff: noqa: F811
"""Native Windows: the ordinary-user agent with the fake guardian, for real.

Runs in the runner's own (interactive, if it has one) session: `gateway agent
bind/start/status/stop` spawn the fake guardian and the fake link hidden,
read the guardian's truthful READY context (session, WinSta0, desktop at
launch), prove the enrolled host key against the fake's real SSH daemon, and
stop through STOP.json + the exact link identity. No scheduled task, no
elevation step (the runner account happens to be an administrator; nothing
here requires it). Protocol-only: not a qualification of the real guardian.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from click.testing import CliRunner

pytestmark = pytest.mark.skipif(
    os.name != "nt"
    or os.environ.get("POCKETSHELL_WINDOWS_SERVICE_E2E") != "1"
    or not os.environ.get("POCKETSHELL_TEST_FAKE_LINK")
    or not os.environ.get("POCKETSHELL_TEST_FAKE_GUARDIAN"),
    reason="native agent round trip: CI windows-latest job only",
)

from pocketshell.cli import cli  # noqa: E402
from pocketshell.gateway import service_windows as win  # noqa: E402

from test_windows_gateway_service_native import (  # noqa: E402,F401
    ENDPOINT_TASK, _build_endpoint, _free_port, _query_xml, layout, listening,
)


def _agent(*args):
    result = CliRunner().invoke(cli, ["gateway", "agent", *args, "--json"])
    print(f"$ pocketshell gateway agent {' '.join(args)} --json -> exit {result.exit_code}")
    print(result.output)
    return result, (json.loads(result.stdout) if result.stdout.strip().startswith("{") else None)


def test_ordinary_user_agent_round_trip(layout, monkeypatch, tmp_path):
    api = win.WindowsApi()
    session = api.current_session()
    print("runner session:", session, "active console:", __import__("ctypes").windll.kernel32.WTSGetActiveConsoleSessionId())
    if session == 0:
        pytest.skip("the runner process is in session 0 (no interactive session to host the active-console mode)")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "agent-config"))
    port = _free_port()
    endpoint = _build_endpoint(layout, monkeypatch, port=port, enrolled_port=port, name="agent")
    result, data = _agent("bind", "--manifest", endpoint["manifest"], "--config-dir", layout["config"],
                          "--helper", layout["helper"])
    assert result.exit_code == 0, result.output

    result, data = _agent("status")
    assert result.exit_code == 4 and data["state"] == "stopped"

    result, data = _agent("start", "--timeout", "60")
    if result.exit_code != 0:
        for p in sorted(Path(endpoint["state"]).rglob("*.json")):
            print(p, p.read_text(encoding="utf-8", errors="replace")[:1500])
    assert result.exit_code == 0, result.output
    e = data["endpoint"]
    assert data["state"] == "ready" and data["mode"] == "active-console"
    assert e["context"]["station"] == "WinSta0" and e["context"]["session"] == session
    assert e["hostKey"]["proven"] is True
    assert data["outbound"]["state"] == "running"
    assert _query_xml() is None and _query_xml(ENDPOINT_TASK) is None  # no scheduled task in this mode

    result, again = _agent("start")
    assert result.exit_code == 0 and again["endpoint"]["daemon"] == e["daemon"]  # idempotent

    result, data = _agent("stop", "--timeout", "45")
    assert result.exit_code == 0, result.output
    assert data["state"] == "stopped"
    assert not listening(port)
    assert api.process_birth(again["outbound"]["pid"]) != again["outbound"]["creationFILETIME"]
    result, data = _agent("status")
    assert result.exit_code == 4
