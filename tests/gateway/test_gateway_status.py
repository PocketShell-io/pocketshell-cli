"""Unit tests for pocketshell gateway status [--json] and lifecycle commands.

Tests all parsers (ss, netstat, proc/net/tcp, sshd auth log, authorized_keys),
collectors with fakes, state derivation, caching, and CLI commands.
"""

from __future__ import annotations

import base64
import json
import os
from click.testing import CliRunner

from pocketshell.cli import cli
from pocketshell.gateway import devices as gateway_devices
from pocketshell.gateway import pins as gateway_pins
from pocketshell.gateway import service_common as common
from pocketshell.gateway import status as gst
from pocketshell.runtime import sessions as runtime_sessions

FAKE_ED25519_BLOB = base64.b64decode("AAAAC3NzaC1lZDI1NTE5AAAAIKtcCuruWy5XRjBBYu1q1J62Gb9L3I5JTRMReZ9YQN0/")
FAKE_FP = gateway_pins.fingerprint_of_blob(FAKE_ED25519_BLOB)
FAKE_KEY_LINE = f"ssh-ed25519 {base64.b64encode(FAKE_ED25519_BLOB).decode()} grok-bot"


# --- 1. Parser Tests ------------------------------------------------------------------

def test_parse_ss_established_ports():
    ss_output = """State      Recv-Q Send-Q Local Address:Port               Peer Address:Port              
ESTAB      0      0          127.0.0.1:22                    127.0.0.1:54321              
ESTAB      0      0          127.0.0.1:54321                 127.0.0.1:22                 
ESTAB      0      0          127.0.0.1:22                    127.0.0.1:54322              
ESTAB      0      0              [::1]:22                        [::1]:54323              
ESTAB      0      0    135.181.114.209:22                  2.215.239.4:4463               
TIME-WAIT  0      0          127.0.0.1:22                    127.0.0.1:54300              
LISTEN     0      128        127.0.0.1:22                      0.0.0.0:*                  
"""
    ports = gst.parse_ss_established_ports(ss_output, 22)
    assert ports == {54321, 54322, 54323}


def test_parse_netstat_established_ports():
    netstat_output = """Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    127.0.0.1:22           127.0.0.1:54321        ESTABLISHED     1234
  TCP    127.0.0.1:54321        127.0.0.1:22           ESTABLISHED     5678
  TCP    127.0.0.1:22           127.0.0.1:54322        ESTABLISHED     1234
  TCP    0.0.0.0:22             0.0.0.0:0              LISTENING       1234
  TCP    192.168.1.5:22         192.168.1.10:4463      ESTABLISHED     1234
  TCP    127.0.0.1:22           127.0.0.1:54300        TIME_WAIT       0
"""
    ports = gst.parse_netstat_established_ports(netstat_output, 22)
    assert ports == {54321, 54322}


def test_parse_proc_net_tcp():
    proc_tcp = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0016 0100007F:D431 01 00000000:00000000 00:00000000 00000000  1000        0 2983049
   1: 0100007F:D431 0100007F:0016 01 00000000:00000000 00:00000000 00000000  1000        0 2983050
   2: 0100007F:0016 0100007F:D432 01 00000000:00000000 00:00000000 00000000  1000        0 2983051
   3: 0501A8C0:0016 0A01A8C0:116F 01 00000000:00000000 00:00000000 00000000  1000        0 2983052
   4: 0100007F:0016 0100007F:D430 06 00000000:00000000 00:00000000 00000000  1000        0 2983053
"""
    # 0x0016 = 22, 0xD431 = 54321, 0xD432 = 54322, state 01 = ESTAB, 06 = TIME_WAIT
    ports = gst.parse_proc_net_tcp(proc_tcp, 22)
    assert ports == {54321, 54322}


def test_parse_sshd_auth_log():
    log_text = f"""
Oct 13 19:15:30 RMTHZ sshd[1234]: Accepted publickey for alexey from 127.0.0.1 port 54321 ssh2: ED25519 {FAKE_FP}
2026-10-13T19:20:00.123456+02:00 host sshd[1235]: Accepted publickey for bob from 127.0.0.1 port 54322 ssh2: RSA SHA256:someRSARSA
2026-10-13 19:25:00 sshd[1236]: Accepted password for charlie from 127.0.0.1 port 54323 ssh2
Oct 13 19:30:00 RMTHZ sshd[1237]: Failed password for root from 1.2.3.4 port 9999 ssh2
# Port reuse:
Oct 13 19:35:00 RMTHZ sshd[1238]: Accepted publickey for alexey_reused from 127.0.0.1 port 54321 ssh2: ED25519 {FAKE_FP}
"""
    entries = gst.parse_sshd_auth_log(log_text)
    assert 54321 in entries
    assert entries[54321]["user"] == "alexey_reused"
    assert entries[54321]["key_fingerprint"] == FAKE_FP
    assert entries[54321]["since"] is not None

    assert 54322 in entries
    assert entries[54322]["user"] == "bob"
    assert entries[54322]["key_fingerprint"] == "SHA256:someRSARSA"
    assert entries[54322]["since"] == "2026-10-13T19:20:00.123456+02:00"

    assert 54323 in entries
    assert entries[54323]["user"] == "charlie"
    assert entries[54323]["key_fingerprint"] is None

    assert 9999 not in entries


def test_parse_authorized_keys():
    content = f"""
# A comment line
{FAKE_KEY_LINE}

# With options:
restrict,pty ssh-ed25519 {base64.b64encode(FAKE_ED25519_BLOB).decode()} laptop-key
ssh-ed25519 {base64.b64encode(FAKE_ED25519_BLOB).decode()}
"""
    comments = gst.parse_authorized_keys(content)
    # Earlier entries without comment don't overwrite if parsed properly
    assert FAKE_FP in comments
    assert comments[FAKE_FP] in ("grok-bot", "laptop-key")


# --- 2. Collector Tests ----------------------------------------------------------------

def test_collect_clients_status():
    auth_log = f"""
Oct 13 19:15:30 RMTHZ sshd[1234]: Accepted publickey for alexey from 127.0.0.1 port 54321 ssh2: ED25519 {FAKE_FP}
"""
    auth_keys = {FAKE_FP: "grok-bot"}
    established = {54321, 54399}

    clients, errors = gst.collect_clients_status(
        22,
        established_ports=established,
        auth_log_text=auth_log,
        auth_keys_comments=auth_keys,
    )
    assert errors == []
    assert len(clients) == 2

    c1 = next(c for c in clients if c["user"] == "alexey")
    assert c1["key_fingerprint"] == FAKE_FP
    assert c1["key_comment"] == "grok-bot"
    assert c1["via"] == "gateway"
    assert c1["since"] is not None

    # Port 54399 was in established sockets but not in auth log:
    c2 = next(c for c in clients if c["user"] is None)
    assert c2["key_fingerprint"] is None
    assert c2["key_comment"] is None
    assert c2["since"] is None
    assert c2["via"] == "gateway"


def test_collect_sshd_status():
    assert gst.check_sshd_reachable(22, connect_fn=lambda port, timeout: True) is True
    assert gst.check_sshd_reachable(22, connect_fn=lambda port, timeout: False) is False


def test_collect_sessions_status():
    def fake_live_sessions():
        s1 = runtime_sessions.LiveSession(
            name="pocketshell:test",
            aplexer_id="id-1",
            engine="claude",
            phase="running",
            agent_state="working",
        )
        return [s1], []

    sessions, errors = gst.collect_sessions_status(enumerate_fn=fake_live_sessions)
    assert errors == []
    assert len(sessions) == 1
    assert sessions[0] == {
        "name": "pocketshell:test",
        "id": "id-1",
        "engine": "claude",
        "state": "running",
        "agent_state": "working",
    }


def test_collect_sessions_status_error_degradation():
    def failing_enum():
        return [], [{"message": "aplexer missing"}]

    sessions, errors = gst.collect_sessions_status(enumerate_fn=failing_enum)
    assert sessions == []
    assert "aplexer missing" in errors


# --- 3. Agent & Presence Tests --------------------------------------------------------

def test_agent_status_with_presence(monkeypatch):
    device_id = "test-box"

    def fake_fetch(ep, tp):
        return [
            gateway_devices.DeviceInfo(
                id="test-box",
                id_valid=True,
                revoked=False,
                advertised_key=None,
                presence=gateway_devices.Presence(
                    online=True,
                    observed_at="2026-10-13T19:20:00Z",
                    connected_since="2026-10-13T19:00:00Z",
                    session_generation=1,
                ),
            )
        ]

    # Clean cache
    cache_path = gst._presence_cache_path(device_id)
    if os.path.isfile(cache_path):
        os.unlink(cache_path)

    agent, errors = gst.collect_agent_status(
        device_id,
        presence_fetcher=fake_fetch,
    )
    assert errors == []
    assert agent["connected"] is True
    assert agent["connected_since"] == "2026-10-13T19:00:00Z"
    assert agent["source"] == "presence"

    # Second call should read from cache even if fetcher raises
    def boom_fetch(ep, tp):
        raise AssertionError("network call should be cached!")

    agent2, errors2 = gst.collect_agent_status(
        device_id,
        presence_fetcher=boom_fetch,
    )
    assert errors2 == []
    assert agent2["connected"] is True
    assert agent2["source"] == "presence"


def test_agent_status_network_failure_falls_back_to_local(monkeypatch):
    device_id = "test-box-fail"
    cache_path = gst._presence_cache_path(device_id)
    if os.path.isfile(cache_path):
        os.unlink(cache_path)

    def failing_fetch(ep, tp):
        raise gateway_devices.DevicesError("gateway connection timed out")

    agent, errors = gst.collect_agent_status(
        device_id,
        presence_fetcher=failing_fetch,
    )
    assert "broker presence unavailable: gateway connection timed out" in errors
    assert agent["source"] == "local"
    assert "gateway connection timed out" in str(agent["last_error"])


# --- 4. State Derivation Tests --------------------------------------------------------

def test_derive_state_not_installed():
    state, summary = gst.derive_state(
        agent={"installed": False, "running": False, "connected": False},
        sshd={"reachable": False},
        device_id=None,
    )
    assert state == "not_installed"
    assert "not enrolled" in summary


def test_derive_state_offline_agent_not_running():
    state, summary = gst.derive_state(
        agent={"installed": True, "running": False, "connected": False},
        sshd={"reachable": True},
        device_id="dev-1",
    )
    assert state == "offline"
    assert summary == "Gateway agent is not running"


def test_derive_state_offline_presence_offline():
    state, summary = gst.derive_state(
        agent={"installed": True, "running": True, "connected": False},
        sshd={"reachable": True},
        device_id="dev-1",
    )
    assert state == "offline"
    assert summary == "Gateway agent is offline"


def test_derive_state_degraded_sshd_unreachable():
    state, summary = gst.derive_state(
        agent={"installed": True, "running": True, "connected": True},
        sshd={"reachable": False},
        device_id="dev-1",
    )
    assert state == "degraded"
    assert summary == "Connected to gateway, but local SSH server is not running — nobody can connect"


def test_derive_state_online():
    state, summary = gst.derive_state(
        agent={"installed": True, "running": True, "connected": True},
        sshd={"reachable": True},
        device_id="dev-1",
    )
    assert state == "online"
    assert summary == "Connected to gateway, local SSH server reachable"


# --- 5. Full Contract Assembly Test ---------------------------------------------------

def test_collect_gateway_status_contract():
    doc = gst.collect_gateway_status(
        connect_fn=lambda port, timeout: True,
        established_ports=set(),
        enumerate_sessions_fn=lambda: ([], []),
    )
    assert doc["v"] == 1
    assert "checked_at" in doc
    assert "state" in doc
    assert "summary" in doc
    assert "agent" in doc
    assert "sshd" in doc
    assert isinstance(doc["clients"], list)
    assert isinstance(doc["sessions"], list)
    assert isinstance(doc["errors"], list)

    human = gst.format_human_status(doc)
    assert "Gateway status:" in human
    assert "Summary:" in human
    assert "Agent:" in human
    assert "SSHD:" in human


# --- 6. CLI Command Tests -------------------------------------------------------------

def test_cli_gateway_status_json():
    runner = CliRunner()
    result = runner.invoke(cli, ["gateway", "status", "--json"])
    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["v"] == 1
    assert data["state"] in ("online", "degraded", "offline", "not_installed", "error")
    assert "summary" in data
    assert "agent" in data
    assert "sshd" in data
    assert "clients" in data
    assert "sessions" in data
    assert "errors" in data


def test_cli_gateway_status_plain():
    runner = CliRunner()
    result = runner.invoke(cli, ["gateway", "status"])
    assert result.exit_code == 0, result.output
    assert "Gateway status:" in result.output
    assert "Summary:" in result.output


def test_cli_gateway_lifecycle_mocked(monkeypatch):
    def fake_run(argv, **kwargs):
        return common.ChildResult(0, b"", b"")

    monkeypatch.setattr(gst, "start_gateway", lambda runner=None: "started pocketshell-gateway.service")
    monkeypatch.setattr(gst, "stop_gateway", lambda runner=None: "stopped pocketshell-gateway.service")
    monkeypatch.setattr(gst, "restart_gateway", lambda runner=None: "restarted pocketshell-gateway.service")

    runner = CliRunner()
    r_start = runner.invoke(cli, ["gateway", "start"])
    assert r_start.exit_code == 0
    assert "started pocketshell-gateway.service" in r_start.output

    r_stop = runner.invoke(cli, ["gateway", "stop"])
    assert r_stop.exit_code == 0
    assert "stopped pocketshell-gateway.service" in r_stop.output

    r_restart = runner.invoke(cli, ["gateway", "restart"])
    assert r_restart.exit_code == 0
    assert "restarted pocketshell-gateway.service" in r_restart.output
