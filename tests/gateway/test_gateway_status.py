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
ESTAB      0      0          127.0.0.1:22                    127.0.0.1:54321    users:(("sshd",pid=1512054,fd=4))
ESTAB      0      0          127.0.0.1:54321                 127.0.0.1:22       users:(("pocketshell-link",pid=2345,fd=5))
ESTAB      0      0          127.0.0.1:22                    127.0.0.1:54322    users:(("sshd-session",pid=1512055,fd=4))
ESTAB      0      0              [::1]:22                        [::1]:54323              
ESTAB      0      0    135.181.114.209:22                  2.215.239.4:4463               
TIME-WAIT  0      0          127.0.0.1:22                    127.0.0.1:54300              
LISTEN     0      128        127.0.0.1:22                      0.0.0.0:*                  
"""
    ports = gst.parse_ss_established_ports(ss_output, 22)
    assert ports == {54321, 54322, 54323}

    ports, port_to_pid = gst.parse_ss_established_connections(ss_output, 22)
    assert ports == {54321, 54322, 54323}
    assert port_to_pid == {54321: 1512054, 54322: 1512055}


def test_parse_netstat_established_ports():
    netstat_output = """Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    127.0.0.1:22           127.0.0.1:54321        ESTABLISHED     1234
  TCP    127.0.0.1:54321        127.0.0.1:22           ESTABLISHED     5678
  TCP    127.0.0.1:22           127.0.0.1:54322        ESTABLISHED     1235
  TCP    0.0.0.0:22             0.0.0.0:0              LISTENING       1234
  TCP    192.168.1.5:22         192.168.1.10:4463      ESTABLISHED     1234
  TCP    127.0.0.1:22           127.0.0.1:54300        TIME_WAIT       0
"""
    ports = gst.parse_netstat_established_ports(netstat_output, 22)
    assert ports == {54321, 54322}

    ports, port_to_pid = gst.parse_netstat_established_connections(netstat_output, 22)
    assert ports == {54321, 54322}
    assert port_to_pid == {54321: 1234, 54322: 1235}


def test_parse_wmic_cim_timestamp():
    ts = gst.parse_wmic_cim_timestamp("20261013192000.123456+120")
    assert ts == "2026-10-13T17:20:00Z"

    ts_utc = gst.parse_wmic_cim_timestamp("20261013192000.000000+000")
    assert ts_utc == "2026-10-13T19:20:00Z"

    assert gst.parse_wmic_cim_timestamp("invalid") is None


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
        discovered_sessions=[],
    )
    assert errors == []
    assert len(clients) == 2

    c1 = next(c for c in clients if c["user"] == "alexey")
    assert c1["key_fingerprint"] == FAKE_FP
    assert c1["key_comment"] == "grok-bot"
    assert c1["via"] == "gateway"
    assert c1["since"] is not None

    # Port 54399 was in established sockets but not in auth log and no discovered sessions:
    c2 = next(c for c in clients if c["user"] is None)
    assert c2["key_fingerprint"] is None
    assert c2["key_comment"] is None
    assert c2["since"] is None
    assert c2["via"] == "gateway"


def test_discover_sshd_session_processes_linux():
    ps_output = """  PID USER     ELAPSED ARGS
  46350 root       12345 sshd: /usr/sbin/sshd -D -e [listener]
 591410 root         543 sshd: alexey [priv]
 592798 alexey       539 sshd: alexey@pts/38
1512054 alexey      7071 sshd: alexey@notty
"""
    def fake_runner(cmd):
        assert cmd[:2] == ["ps", "-eo"]
        return common.ChildResult(returncode=0, stdout=ps_output.encode("utf-8"), stderr=b"")

    sessions = gst.discover_sshd_session_processes(runner=fake_runner, platform="linux")
    assert len(sessions) == 2
    assert sessions[0].user == "alexey"
    assert sessions[0].pid in (592798, 1512054)
    assert sessions[0].since is not None


def test_parse_proc_pid_stat_starttime():
    btime = 1728840000
    # Field 22 is 1000 ticks at 100 Hz = 10.0 seconds after boot
    stat_content = "12345 (sshd: alexey@notty) S 1 1 1 0 -1 4194304 100 0 0 0 0 0 0 0 20 0 1 0 1000 10000 100"
    since = gst.parse_proc_pid_stat_starttime(stat_content, btime, clk_tck=100)
    assert since == "2024-10-13T17:20:10Z"

    # comm with spaces and parentheses: (sshd: user (test)@pts/1)
    stat_tricky = "12345 (sshd: user (test)@pts/1) S 1 1 1 0 -1 4194304 100 0 0 0 0 0 0 0 20 0 1 0 2000 10000 100"
    since_tricky = gst.parse_proc_pid_stat_starttime(stat_tricky, btime, clk_tck=100)
    assert since_tricky == "2024-10-13T17:20:20Z"


def test_discover_sshd_session_processes_fake_proc(tmp_path):
    proc_dir = tmp_path / "proc"
    proc_dir.mkdir()

    # /proc/stat
    (proc_dir / "stat").write_text("cpu 1 2 3\nbtime 1728840000\n", encoding="ascii")

    # PID 101: sshd: alexey@notty, starttime = 1000 ticks (10s)
    pid101 = proc_dir / "101"
    pid101.mkdir()
    (pid101 / "cmdline").write_bytes(b"sshd: alexey@notty\x00")
    (pid101 / "stat").write_text("101 (sshd: alexey@notty) S 1 1 1 0 -1 4194304 100 0 0 0 0 0 0 0 20 0 1 0 1000 10000 100\n", encoding="ascii")

    # PID 102: sshd: bob@pts/1, starttime = 2000 ticks (20s)
    pid102 = proc_dir / "102"
    pid102.mkdir()
    (pid102 / "cmdline").write_bytes(b"sshd: bob@pts/1\x00")
    (pid102 / "stat").write_text("102 (sshd: bob@pts/1) S 1 1 1 0 -1 4194304 100 0 0 0 0 0 0 0 20 0 1 0 2000 10000 100\n", encoding="ascii")

    # PID 103: sshd: /usr/sbin/sshd -D -e [listener] (ignored)
    pid103 = proc_dir / "103"
    pid103.mkdir()
    (pid103 / "cmdline").write_bytes(b"sshd: /usr/sbin/sshd -D -e [listener]\x00")
    (pid103 / "stat").write_text("103 (sshd) S 1 1 1 0 -1 4194304 100 0 0 0 0 0 0 0 20 0 1 0 500 10000 100\n", encoding="ascii")

    # PID 104: sshd: alexey [priv] (ignored privsep monitor)
    pid104 = proc_dir / "104"
    pid104.mkdir()
    (pid104 / "cmdline").write_bytes(b"sshd: alexey [priv]\x00")
    (pid104 / "stat").write_text("104 (sshd) S 1 1 1 0 -1 4194304 100 0 0 0 0 0 0 0 20 0 1 0 999 10000 100\n", encoding="ascii")

    sessions = gst.discover_sshd_session_processes(proc_dir=str(proc_dir), platform="linux")
    assert len(sessions) == 2
    # Sorted newest first: 102 (20s) comes before 101 (10s)
    assert sessions[0].pid == 102
    assert sessions[0].user == "bob"
    assert sessions[0].since == "2024-10-13T17:20:20Z"

    assert sessions[1].pid == 101
    assert sessions[1].user == "alexey"
    assert sessions[1].since == "2024-10-13T17:20:10Z"


def test_discover_sshd_session_processes_windows():
    tasklist_csv = """"Image Name","PID","Session Name","Session#","Mem Usage","Status","User Name","CPU Time","Window Title"
"sshd.exe","1234","Services","0","4,500 K","Unknown","NT AUTHORITY\\SYSTEM","0:00:00","N/A"
"sshd.exe","5678","Console","1","5,200 K","Running","WIN35\\alexey","0:00:01","N/A"
"""
    wmic_csv = """Node,CreationDate,ProcessId
WIN35,20261013192000.000000+000,5678
"""
    def fake_runner(cmd):
        if cmd[0] == "wmic":
            return common.ChildResult(returncode=0, stdout=wmic_csv.encode("ascii"), stderr=b"")
        if cmd[0] == "tasklist":
            return common.ChildResult(returncode=0, stdout=tasklist_csv.encode("ascii"), stderr=b"")
        raise AssertionError(f"unexpected cmd: {cmd}")

    sessions = gst.discover_sshd_session_processes(runner=fake_runner, platform="win32")
    assert len(sessions) == 1
    assert sessions[0].pid == 5678
    assert sessions[0].user == "alexey"
    assert sessions[0].since == "2026-10-13T19:20:00Z"


def test_collect_clients_status_fallback_to_process_session():
    # Auth log is empty / unreadable (non-root)
    established = {54321}
    fake_sessions = [
        gst.SshdProcessSession(pid=1512054, user="alexey", since="2026-10-13T19:25:52Z")
    ]

    clients, errors = gst.collect_clients_status(
        22,
        established_ports=established,
        auth_log_text="",
        discovered_sessions=fake_sessions,
    )
    assert errors == []
    assert len(clients) == 1
    c = clients[0]
    assert c["user"] == "alexey"
    assert c["since"] == "2026-10-13T19:25:52Z"
    assert c["key_fingerprint"] is None
    assert c["key_comment"] is None
    assert c["via"] == "gateway"


def test_collect_clients_status_fallback_with_port_to_pid():
    established = {54321, 54322}
    port_to_pid = {54321: 101, 54322: 102}
    fake_sessions = [
        gst.SshdProcessSession(pid=102, user="bob", since="2026-10-13T19:30:00Z"),
        gst.SshdProcessSession(pid=101, user="alexey", since="2026-10-13T19:20:00Z"),
    ]

    clients, errors = gst.collect_clients_status(
        22,
        established_ports=established,
        port_to_pid=port_to_pid,
        auth_log_text="",
        discovered_sessions=fake_sessions,
    )
    assert errors == []
    assert len(clients) == 2

    c1 = next(c for c in clients if c["user"] == "alexey")
    assert c1["since"] == "2026-10-13T19:20:00Z"
    assert c1["key_fingerprint"] is None

    c2 = next(c for c in clients if c["user"] == "bob")
    assert c2["since"] == "2026-10-13T19:30:00Z"
    assert c2["key_fingerprint"] is None


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
        return gst.Presence(
            online=True,
            observed_at="2026-10-13T19:20:00Z",
            connected_since="2026-10-13T19:00:00Z",
            session_generation=1,
        )

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
        raise RuntimeError("gateway connection timed out")

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


def test_start_gateway_service_installed(monkeypatch):
    commands = []

    def fake_run(argv, **kwargs):
        commands.append(list(argv))
        return common.ChildResult(0, b"", b"")

    monkeypatch.setattr("pocketshell.gateway.service_linux.unit_path", lambda: "/tmp/fake.service")
    monkeypatch.setattr(os.path, "lexists", lambda p: True if p == "/tmp/fake.service" else False)

    msg = gst.start_gateway(runner=fake_run)
    assert "started pocketshell-gateway.service" in msg
    assert any("start" in cmd for cmd in commands)


def test_start_gateway_fallback_when_not_installed(monkeypatch):
    monkeypatch.setattr("pocketshell.gateway.service_linux.unit_path", lambda: "/tmp/fake.service")
    monkeypatch.setattr(os.path, "lexists", lambda p: False)

    spawned = []

    class FakeProc:
        pid = 4242

    def fake_spawn(argv):
        spawned.append(argv)
        return FakeProc()

    msg = gst.start_gateway(spawn_fn=fake_spawn)
    assert "pocketshell-gateway.service is not installed" in msg
    assert "spawned detached 'pocketshell gateway run' (PID 4242)" in msg
    assert len(spawned) == 1
    assert "gateway" in spawned[0] and "run" in spawned[0]


def test_start_gateway_windows_fallback(monkeypatch):
    monkeypatch.setattr(gst.sys, "platform", "win32")

    def fake_run(argv, **kwargs):
        return common.ChildResult(1, b"ERROR: not found", b"")

    class FakeProc:
        pid = 9999

    msg = gst.start_gateway(runner=fake_run, spawn_fn=lambda argv: FakeProc())
    assert "Task Scheduler task is not installed" in msg
    assert "spawned detached 'pocketshell gateway run' (PID 9999)" in msg


def test_stop_gateway_service_installed(monkeypatch):
    commands = []

    def fake_run(argv, **kwargs):
        commands.append(list(argv))
        return common.ChildResult(0, b"", b"")

    monkeypatch.setattr("pocketshell.gateway.service_linux.unit_path", lambda: "/tmp/fake.service")
    monkeypatch.setattr(os.path, "lexists", lambda p: True if p == "/tmp/fake.service" else False)
    monkeypatch.setattr(gst, "find_running_gateway_pids", lambda runner=None: [])

    msg = gst.stop_gateway(runner=fake_run)
    assert "stopped pocketshell-gateway.service" in msg
    assert any("stop" in cmd for cmd in commands)


def test_stop_gateway_detached_process(monkeypatch):
    monkeypatch.setattr("pocketshell.gateway.service_linux.unit_path", lambda: "/tmp/fake.service")
    monkeypatch.setattr(os.path, "lexists", lambda p: False)
    monkeypatch.setattr(gst, "find_running_gateway_pids", lambda runner=None: [5678])

    killed = []
    msg = gst.stop_gateway(kill_fn=lambda pid: killed.append(pid))
    assert killed == [5678]
    assert "stopped detached gateway agent (PID 5678)" in msg


def test_stop_gateway_nothing_running(monkeypatch):
    monkeypatch.setattr("pocketshell.gateway.service_linux.unit_path", lambda: "/tmp/fake.service")
    monkeypatch.setattr(os.path, "lexists", lambda p: False)
    monkeypatch.setattr(gst, "find_running_gateway_pids", lambda runner=None: [])

    msg = gst.stop_gateway()
    assert msg == "gateway agent is not running"


def test_restart_gateway_service_installed(monkeypatch):
    commands = []

    def fake_run(argv, **kwargs):
        commands.append(list(argv))
        return common.ChildResult(0, b"", b"")

    monkeypatch.setattr("pocketshell.gateway.service_linux.unit_path", lambda: "/tmp/fake.service")
    monkeypatch.setattr(os.path, "lexists", lambda p: True if p == "/tmp/fake.service" else False)

    msg = gst.restart_gateway(runner=fake_run)
    assert "restarted pocketshell-gateway.service" in msg
    assert any("restart" in cmd for cmd in commands)


def test_restart_gateway_fallback_when_not_installed(monkeypatch):
    monkeypatch.setattr("pocketshell.gateway.service_linux.unit_path", lambda: "/tmp/fake.service")
    monkeypatch.setattr(os.path, "lexists", lambda p: False)
    monkeypatch.setattr(gst, "find_running_gateway_pids", lambda runner=None: [1111])

    killed = []

    class FakeProc:
        pid = 2222

    msg = gst.restart_gateway(
        kill_fn=lambda pid: killed.append(pid),
        spawn_fn=lambda argv: FakeProc(),
    )
    assert killed == [1111]
    assert "pocketshell-gateway.service is not installed" in msg
    assert "restarted detached 'pocketshell gateway run' (PID 2222)" in msg


def test_lifecycle_cli_failures_exit_nonzero_with_single_line_stderr(monkeypatch):
    def boom(*args, **kwargs):
        raise common.ServiceError("systemctl failed with error 5\nMore multi-line details here")

    monkeypatch.setattr(gst, "start_gateway", boom)
    monkeypatch.setattr(gst, "stop_gateway", boom)
    monkeypatch.setattr(gst, "restart_gateway", boom)

    runner = CliRunner()
    for verb in ("start", "stop", "restart"):
        result = runner.invoke(cli, ["gateway", verb])
        assert result.exit_code != 0
        err_lines = [line for line in result.output.splitlines() if line.strip()]
        assert len(err_lines) == 1
        assert err_lines[0].startswith("error: systemctl failed with error 5")

