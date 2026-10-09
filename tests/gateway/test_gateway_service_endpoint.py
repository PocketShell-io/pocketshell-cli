"""`gateway service --with-endpoint`: the guardian protocol (unit tests, any OS).

The endpoint task launches ``<python> <guardian.py> --manifest <manifest>``;
status and stop follow CURRENT.json -> generation -> READY.json and the exact
held daemon PID + birth; stop is the guardian's STOP.json protocol, never a
kill; readiness requires the EXACT enrolled host key. Task Scheduler, the
filesystem under the (Windows-path) manifest root, the native API and the
SSH probe are faked here; tests/gateway/test_windows_gateway_service_native.py
runs the real thing on windows-latest with a fake guardian, and
test_hostkey_probe_* below run the real OpenSSH client against a real sshd.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time

import pytest
from gateway_keyblobs import ED25519_LINE

from pocketshell.gateway import pins
from pocketshell.gateway import service_common as common
from pocketshell.gateway import service_endpoint as ep
from pocketshell.gateway import service_hostkey as hostkey
from pocketshell.gateway import service_windows as win
from pocketshell.gateway import service_windows_endpoint as wep
from pocketshell.gateway.service_common import ServiceError

from test_gateway_service import (  # noqa: F401  (fixtures + fakes)
    QUALIFIED,
    USER_SID,
    OTHER_SID,
    WIN_CONFIG,
    WIN_HELPER,
    FakeApi,
    _task_verbs,
    _windows_cli,
    fake_windows,
)

ROOT = r"C:\Users\alexey\PocketShellFleet\durable-endpoint"
STATE = ROOT + r"\state"
MANIFEST = ROOT + r"\manifest.json"
PYTHON = r"C:\Users\alexey\AppData\Roaming\uv\python\cpython-3.14.3-windows-x86_64-none\python.exe"
GUARDIAN = ROOT + r"\guardian\guardian.py"
DAEMON = ROOT + r"\bin\sshd.exe"
CONFIG = ROOT + r"\sshd-22024.conf"
GUARDIAN_SHA = "a" * 64
HOST_KEY = pins.parse_host_key(ED25519_LINE)
SHOW_22024 = (
    "server:          wss://gateway.pocketshell.io\n"
    "device id:       host-laptop-pha6tcnc-75fu\n"
    "local ssh:       127.0.0.1:22024 (loopback only)\n"
    "device key:      SHA256:abc\n"
    f"pinned ssh host key: {ED25519_LINE}\n"
)


def manifest(**overrides) -> dict:
    doc = {
        "version": 1,
        "ownerSID": USER_SID,
        "root": ROOT,
        "state": STATE,
        "config": CONFIG,
        "port": 22024,
        "daemon": DAEMON,
        "python": PYTHON,
        "pins": {PYTHON: QUALIFIED, GUARDIAN: GUARDIAN_SHA, DAEMON: QUALIFIED, CONFIG: QUALIFIED},
        "environment": {
            "SystemRoot": "C:/Windows", "WINDIR": "C:/Windows", "SystemDrive": "C:",
            "ProgramData": "C:/ProgramData", "USERPROFILE": r"C:\Users\alexey",
            "HOME": r"C:\Users\alexey", "TEMP": STATE + r"\tmp", "TMP": STATE + r"\tmp",
        },
    }
    for key, value in overrides.items():
        if value is None:
            doc.pop(key)
        else:
            doc[key] = value
    return doc


def encode(doc) -> bytes:
    return json.dumps(doc, indent=1).encode("utf-8")


class Guardian:
    """Simulates the agreed guardian protocol inside a virtual filesystem."""

    def __init__(self, fake, api, vfs, data: bytes):
        self.fake, self.api, self.vfs = fake, api, vfs
        self.manifest_sha = hashlib.sha256(data).hexdigest()
        self.generation = None
        self.next_pid = 5000
        self.ready_on_run = True
        self.close_accepted = True
        self.stop_requests = []

    def run(self, leaf):
        self.generation = os.urandom(16).hex()
        gen = f"{STATE}\\generations\\{self.generation}"
        daemon, guardian = self.next_pid, self.next_pid + 1
        self.next_pid += 2
        self.api.births[daemon] = f"13436{daemon}0000000"
        self.api.births[guardian] = f"13436{guardian}0000001"
        if not self.ready_on_run:
            return
        self.api.listeners[22024] = [("127.0.0.1", daemon)]
        current = {
            "schema": 1, "generation": self.generation, "manifestSHA256": self.manifest_sha,
            "pid": daemon, "creationFILETIME": self.api.births[daemon],
            "guardianPID": guardian, "guardianCreationFILETIME": self.api.births[guardian],
            "port": 22024, "readyAt": "2026-10-09T18:00:00Z",
        }
        ready = {k: current[k] for k in ("generation", "pid", "creationFILETIME", "guardianPID", "port")}
        ready["manifestSHA256"] = self.manifest_sha
        self.vfs[gen + r"\READY.json"] = json.dumps(ready).encode()
        self.vfs[STATE + r"\CURRENT.json"] = json.dumps(current).encode()  # only after READY

    def on_stop(self, path, data):
        self.stop_requests.append(json.loads(data))
        cur = json.loads(self.vfs[STATE + r"\CURRENT.json"])
        expected = {"pid": cur["pid"], "creationFILETIME": cur["creationFILETIME"],
                    "manifestSHA256": self.manifest_sha, "stopOwnedJob": True}
        accepted = json.loads(data) == expected and self.close_accepted
        if accepted:
            self.api.births.pop(cur["pid"], None)
            self.api.births.pop(cur["guardianPID"], None)
            self.api.listeners.pop(cur["port"], None)
            for task in self.fake.tasks.values():
                if task["state"] == "Running":
                    task["state"] = "Disabled"
        closed = path.replace("STOP.json", "CLOSED.json")
        self.vfs[closed] = json.dumps({"generation": cur["generation"], "accepted": accepted,
                                       "cleanupErrors": []}).encode()


class EndpointApi(FakeApi):
    def __init__(self, vfs, **kw):
        super().__init__(**kw)
        self.vfs = vfs
        self.births = {}
        self.listeners = {}
        self.guardian = None
        self.writes = []

    def process_birth(self, pid):
        return self.births.get(pid)

    def listener_pids(self, port):
        return list(self.listeners.get(port, []))

    def write_owned_file(self, path, data, owner_sid):
        assert path not in self.vfs, "STOP.json must never be overwritten"
        self.writes.append((path, owner_sid))
        self.vfs[path] = data
        if path.endswith("STOP.json") and self.guardian is not None:
            self.guardian.on_stop(path, data)


@pytest.fixture
def env(fake_windows, monkeypatch):  # noqa: F811
    vfs: dict = {}
    data = encode(manifest())
    vfs[MANIFEST] = data
    api = EndpointApi(vfs)
    guardian = Guardian(fake_windows, api, vfs, data)
    api.guardian = guardian
    fake_windows.show_out = SHOW_22024
    fake_windows.on_run = {}
    monkeypatch.setattr(wep, "read_bounded", lambda path, limit: vfs.get(path))
    monkeypatch.setattr(ep, "ALLOWED_ENDPOINT_MANIFEST_SHA256", frozenset({hashlib.sha256(data).hexdigest()}))
    monkeypatch.setattr(ep, "ALLOWED_GUARDIAN_SOURCE_SHA256", frozenset({GUARDIAN_SHA}))
    monkeypatch.setattr(win, "file_sha256", lambda p: GUARDIAN_SHA if p == GUARDIAN else QUALIFIED)
    probe = {"result": (True, "proved the enrolled host key"), "calls": 0}

    def verify(port, key, **kw):
        probe["calls"] += 1
        assert key.line == HOST_KEY.line and port == 22024
        return probe["result"]

    monkeypatch.setattr(hostkey, "verify_host_key", verify)
    monkeypatch.setattr(wep, "ENDPOINT_CONFIRM_SECONDS", 0.3)
    monkeypatch.setattr(wep, "STOP_CONFIRM_SECONDS", 0.3)
    monkeypatch.setattr(wep, "POLL_SECONDS", 0.01)
    monkeypatch.setattr(win, "WindowsApi", lambda: api)

    def on_run(leaf):
        return lambda: guardian.run(leaf)

    fake_windows.on_run = {ep.ENDPOINT_LEAF: on_run(ep.ENDPOINT_LEAF),
                           ep.leaf_for("N1"): on_run(ep.leaf_for("N1"))}
    return {"vfs": vfs, "api": api, "guardian": guardian, "fake": fake_windows, "probe": probe,
            "data": data, "monkeypatch": monkeypatch}


def _set_manifest(env, doc):
    data = encode(doc)
    env["vfs"][MANIFEST] = data
    env["monkeypatch"].setattr(ep, "ALLOWED_ENDPOINT_MANIFEST_SHA256", frozenset({hashlib.sha256(data).hexdigest()}))
    env["guardian"].manifest_sha = hashlib.sha256(data).hexdigest()


def _plan(env, **kw):
    kw.setdefault("force", False)
    kw.setdefault("start", True)
    kw.setdefault("api", env["api"])
    return win.plan_install(WIN_HELPER, WIN_CONFIG, endpoint_manifest=MANIFEST, **kw)


# --- manifest: the guardian's closed schema ----------------------------------------------


def test_reviewed_lists_start_empty():
    assert ep.ALLOWED_ENDPOINT_MANIFEST_SHA256 == frozenset()
    assert ep.ALLOWED_GUARDIAN_SOURCE_SHA256 == frozenset()


@pytest.mark.parametrize(
    "overrides, message",
    [
        ({"version": 2}, "closed guardian schema"),
        ({"extra": 1}, "closed guardian schema"),
        ({"environment": None}, "closed guardian schema"),
        ({"ownerSID": "S-1-5-18"}, "own-account SID"),
        ({"root": "relative"}, "absolute"),
        ({"state": r"C:\elsewhere\state"}, "escapes the protected root"),
        ({"daemon": ROOT + r"\..\x\sshd.exe"}, "traversal"),
        ({"config": ROOT + r"\a.conf:ads"}, "alternate data stream"),
        ({"port": 22}, "unprivileged"),
        ({"port": "22024"}, "unprivileged"),
        ({"pins": {PYTHON: QUALIFIED, DAEMON: QUALIFIED, CONFIG: QUALIFIED}}, "guardian.py"),
        ({"pins": {GUARDIAN: GUARDIAN_SHA, DAEMON: QUALIFIED, CONFIG: QUALIFIED}}, "lacks a pin"),
        ({"pins": {PYTHON: "X" * 64, GUARDIAN: GUARDIAN_SHA, DAEMON: QUALIFIED, CONFIG: QUALIFIED}}, "lowercase sha256"),
    ],
)
def test_manifest_schema_refusals(env, overrides, message):
    _set_manifest(env, manifest(**overrides))
    with pytest.raises(ServiceError, match=message):
        _plan(env)


def test_manifest_environment_is_closed_and_qualified(env):
    doc = manifest()
    doc["environment"]["PATH"] = "C:/x"
    _set_manifest(env, doc)
    with pytest.raises(ServiceError, match="closed fixed environment"):
        _plan(env)
    doc = manifest()
    doc["environment"]["SystemRoot"] = "D:/Windows"
    _set_manifest(env, doc)
    with pytest.raises(ServiceError, match="qualified system paths"):
        _plan(env)
    doc = manifest()
    doc["environment"]["TEMP"] = r"C:\Temp"
    _set_manifest(env, doc)
    with pytest.raises(ServiceError, match="TEMP escapes"):
        _plan(env)


def test_manifest_must_live_below_its_root(env, monkeypatch):
    data = env["vfs"].pop(MANIFEST)
    env["vfs"][r"C:\elsewhere\manifest.json"] = data
    with pytest.raises(ServiceError, match="manifest itself escapes"):
        win.plan_install(WIN_HELPER, WIN_CONFIG, endpoint_manifest=r"C:\elsewhere\manifest.json",
                         force=False, start=True, api=env["api"])


def test_trust_requires_reviewed_manifest_reviewed_guardian_and_disk_pins(env, monkeypatch):
    monkeypatch.setattr(ep, "ALLOWED_ENDPOINT_MANIFEST_SHA256", frozenset())
    with pytest.raises(ServiceError, match="not a reviewed manifest"):
        _plan(env)
    monkeypatch.setattr(ep, "ALLOWED_ENDPOINT_MANIFEST_SHA256", frozenset({hashlib.sha256(env["data"]).hexdigest()}))
    monkeypatch.setattr(ep, "ALLOWED_GUARDIAN_SOURCE_SHA256", frozenset())
    with pytest.raises(ServiceError, match="not a reviewed guardian source"):
        _plan(env)
    monkeypatch.setattr(ep, "ALLOWED_GUARDIAN_SOURCE_SHA256", frozenset({GUARDIAN_SHA}))
    monkeypatch.setattr(win, "file_sha256", lambda p: "0" * 64 if p == DAEMON else (GUARDIAN_SHA if p == GUARDIAN else QUALIFIED))
    with pytest.raises(ServiceError, match="does not match the manifest"):
        _plan(env)


def test_binding_owner_sid_port_and_pinned_key(env):
    _set_manifest(env, manifest(ownerSID=OTHER_SID))
    with pytest.raises(ServiceError, match="ownerSID"):
        _plan(env)
    _set_manifest(env, manifest(port=22025))
    with pytest.raises(ServiceError, match="not the enrolled local ssh"):
        _plan(env)
    _set_manifest(env, manifest())
    env["fake"].show_out = SHOW_22024.replace(f"pinned ssh host key: {ED25519_LINE}\n", "")
    with pytest.raises(ServiceError, match="no usable pinned host key"):
        _plan(env)


def test_state_tree_must_be_owned_by_the_manifest_owner(env):
    env["api"].owners[STATE] = "S-1-5-32-544"
    with pytest.raises(ServiceError, match="guardian would refuse"):
        _plan(env)


def test_held_endpoint_on_the_port_is_never_touched(env):
    env["api"].listeners[22024] = [("127.0.0.1", 38832)]
    with pytest.raises(ServiceError, match="already served by another process"):
        _plan(env)
    assert all(v[0] != "/Create" for v in _task_verbs(env["fake"]))


# --- task definition ------------------------------------------------------------------------


def test_endpoint_task_launches_python_guardian_directly(env):
    plan = _plan(env)
    fields = win.parse_task_xml(plan.endpoint.xml)
    assert fields["command"] == PYTHON
    assert win.parse_arguments(fields["arguments"]) == [GUARDIAN, "--manifest", MANIFEST]
    assert fields["working_directory"] == ROOT
    assert fields["user_id"] == USER_SID and fields["logon_type"] == "S4U"
    assert fields["run_level"] == "LeastPrivilege" and fields["exec_count"] == 1
    assert f"Enrolled host key: {ED25519_LINE}." in fields["description"]
    low = plan.endpoint.xml.lower()
    for forbidden in ("cmd.exe", "powershell", "conhost", "&gt;"):
        assert forbidden not in low


# --- install: READY = new generation + held daemon + listener + exact host key --------------


def test_install_confirms_ready_before_the_link(env):
    win.apply_install(_plan(env), api=env["api"])
    verbs = [v for v in _task_verbs(env["fake"]) if v[0] in ("/Create", "/Run")]
    assert verbs == [("/Create", "GatewayEndpoint"), ("/Run", "GatewayEndpoint"),
                     ("/Create", "GatewayLink"), ("/Run", "GatewayLink")]
    assert env["probe"]["calls"] >= 1


@pytest.mark.parametrize("breakage", ["no-current", "wrong-key", "foreign-listener", "dead-daemon"])
def test_not_ready_endpoint_exits_5_and_link_is_not_registered(env, breakage):
    if breakage == "no-current":
        env["guardian"].ready_on_run = False
    elif breakage == "wrong-key":
        env["probe"]["result"] = (False, "does NOT prove the enrolled host key")
    elif breakage == "foreign-listener":
        original = env["guardian"].run
        env["fake"].on_run[ep.ENDPOINT_LEAF] = lambda: (original("x"), env["api"].listeners.__setitem__(
            22024, [("127.0.0.1", 4242)]))
    elif breakage == "dead-daemon":
        original = env["guardian"].run

        def run_then_die():
            original("x")
            env["api"].births.clear()

        env["fake"].on_run[ep.ENDPOINT_LEAF] = run_then_die
    with pytest.raises(common.NotStartedError, match="GatewayEndpoint is registered but NOT ready"):
        win.apply_install(_plan(env), api=env["api"])
    assert "GatewayEndpoint" in env["fake"].tasks
    assert "GatewayLink" not in env["fake"].tasks


def test_banner_alone_is_not_readiness(env):
    """Root requirement 1: any SSH-2.0 answer is not enough, only the exact key."""
    env["probe"]["result"] = (False, "127.0.0.1:22024 does NOT prove the enrolled host key")
    with pytest.raises(common.NotStartedError, match="does NOT prove the enrolled host key"):
        win.apply_install(_plan(env), api=env["api"])


def test_existing_endpoint_task_is_never_replaced_in_place(env):
    win.apply_install(_plan(env), api=env["api"])
    with pytest.raises(ServiceError, match="STOP protocol"):
        _plan(env, force=True)


# --- status --------------------------------------------------------------------------------


def test_status_follows_current_generation(env):
    win.apply_install(_plan(env), api=env["api"])
    st = win.status(api=env["api"])
    assert st.exit_code == 0, st.warnings
    ready = st.details["endpoint"]["readiness"]
    assert ready["ok"] and ready["generation"] == env["guardian"].generation
    # a same-image process does not help: the held identity is pid+birth
    cur = json.loads(env["vfs"][STATE + r"\CURRENT.json"])
    env["api"].births[cur["pid"]] = "1"
    st = win.status(api=env["api"])
    assert st.exit_code == 3
    assert any("not alive" in w for w in st.warnings)


def test_status_refuses_foreign_or_mismatched_current(env):
    win.apply_install(_plan(env), api=env["api"])
    env["api"].owners[STATE + r"\CURRENT.json"] = OTHER_SID
    assert win.status(api=env["api"]).exit_code == 3
    env["api"].owners.pop(STATE + r"\CURRENT.json")
    cur = json.loads(env["vfs"][STATE + r"\CURRENT.json"])
    cur["manifestSHA256"] = "b" * 64
    env["vfs"][STATE + r"\CURRENT.json"] = json.dumps(cur).encode()
    st = win.status(api=env["api"])
    assert st.exit_code == 3 and any("different manifest" in w for w in st.warnings)


def test_status_wrong_host_key_is_not_running(env):
    win.apply_install(_plan(env), api=env["api"])
    env["probe"]["result"] = (False, "does NOT prove the enrolled host key")
    assert win.status(api=env["api"]).exit_code == 3


# --- uninstall: disable -> STOP protocol -> delete; never /End, never kill -----------------


def test_uninstall_uses_the_stop_protocol(env):
    win.apply_install(_plan(env), api=env["api"])
    env["fake"].calls.clear()
    cur = json.loads(env["vfs"][STATE + r"\CURRENT.json"])
    message = win.uninstall(api=env["api"])
    assert "CLOSED accepted" in message
    stop = env["guardian"].stop_requests
    assert stop == [{"pid": cur["pid"], "creationFILETIME": cur["creationFILETIME"],
                     "manifestSHA256": hashlib.sha256(env["data"]).hexdigest(), "stopOwnedJob": True}]
    path, owner = env["api"].writes[-1]
    assert path == f"{STATE}\\generations\\{cur['generation']}\\STOP.json" and owner == USER_SID
    verbs = _task_verbs(env["fake"])
    assert ("/End", "GatewayEndpoint") not in verbs  # never a hard End for the endpoint
    disable = [c for c in env["fake"].calls if "Enabled=$false" in c[-1]]
    assert disable and env["fake"].calls.index(disable[0]) < len(env["fake"].calls)
    assert verbs.index(("/Delete", "GatewayLink")) < verbs.index(("/Delete", "GatewayEndpoint"))
    assert env["fake"].tasks == {}
    assert "nothing to do" in win.uninstall(api=env["api"])


def test_uninstall_rejected_stop_leaves_task_disabled_not_deleted(env):
    win.apply_install(_plan(env), api=env["api"])
    env["guardian"].close_accepted = False  # guardian writes CLOSED accepted=false, daemon stays
    with pytest.raises(ServiceError, match="still alive|left DISABLED|still Running"):
        win.uninstall(api=env["api"])
    assert "GatewayEndpoint" in env["fake"].tasks
    assert ("/Delete", "GatewayEndpoint") not in _task_verbs(env["fake"])


def test_uninstall_without_closed_never_kills(env, monkeypatch):
    win.apply_install(_plan(env), api=env["api"])
    env["api"].guardian = None  # guardian ignores STOP
    with pytest.raises(ServiceError, match="did not write CLOSED.json"):
        win.uninstall(api=env["api"])
    assert ("/Delete", "GatewayEndpoint") not in _task_verbs(env["fake"])
    assert ("/End", "GatewayEndpoint") not in _task_verbs(env["fake"])


# --- qualification instance ------------------------------------------------------------------


def test_qualification_instance_is_isolated(env, monkeypatch):
    _set_manifest(env, manifest(port=22025))
    env["guardian"].ready_on_run = True

    def run_q():
        env["guardian"].run("q")
        cur = json.loads(env["vfs"][STATE + r"\CURRENT.json"])
        cur["port"] = 22025
        env["vfs"][STATE + r"\CURRENT.json"] = json.dumps(cur).encode()
        gen = f"{STATE}\\generations\\{cur['generation']}\\READY.json"
        ready = json.loads(env["vfs"][gen])
        ready["port"] = 22025
        env["vfs"][gen] = json.dumps(ready).encode()
        env["api"].listeners[22025] = env["api"].listeners.pop(22024)

    env["fake"].on_run[ep.leaf_for("N1")] = run_q
    monkeypatch.setattr(hostkey, "verify_host_key", lambda port, key, **kw: (port == 22025, "probe"))
    with pytest.raises(ServiceError, match="--endpoint-only"):
        _plan(env, instance="N1")
    plan = _plan(env, endpoint_only=True, instance="N1")
    assert plan.endpoint.leaf == "GatewayEndpointQN1" and plan.include_link is False
    win.apply_install(plan, api=env["api"])
    assert set(env["fake"].tasks) == {"GatewayEndpointQN1"}
    assert win.status(api=env["api"], instance="N1").exit_code == 0
    assert "GatewayLink" not in [v[1] for v in _task_verbs(env["fake"]) if v[0] == "/Create"]
    message = win.uninstall(api=env["api"], instance="N1")
    assert "CLOSED accepted" in message and env["fake"].tasks == {}


def test_qualification_may_not_use_the_production_port(env):
    with pytest.raises(ServiceError, match="must not use the enrolled production port"):
        _plan(env, endpoint_only=True, instance="N1")


def test_cli_endpoint_flags(env, monkeypatch):
    result = _windows_cli(monkeypatch, "install", "--helper", WIN_HELPER, "--config-dir", WIN_CONFIG,
                          "--with-endpoint", MANIFEST, "--dry-run")
    assert result.exit_code == 0, result.output
    assert json.dumps([PYTHON, GUARDIAN, "--manifest", MANIFEST]) in result.stdout
    assert result.stdout.count("<LogonType>S4U</LogonType>") == 2
    assert env["fake"].tasks == {}
    result = _windows_cli(monkeypatch, "status", "--instance", "bad-name")
    assert result.exit_code == 1 and "1-32 letters" in result.stderr


# --- the real host-key probe (OpenSSH client against a real sshd) ---------------------------

SSHD = shutil.which("sshd") or ("/usr/sbin/sshd" if os.path.exists("/usr/sbin/sshd") else None)
REAL_SSH = os.name == "posix" and SSHD and shutil.which("ssh") and shutil.which("ssh-keygen")


@pytest.fixture
def real_sshd(tmp_path):
    if not REAL_SSH:
        pytest.skip("needs OpenSSH sshd, ssh and ssh-keygen")
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    hk = tmp_path / "hk"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(hk)], check=True)
    cfg = tmp_path / "cfg"
    cfg.write_text(
        f"Port {port}\nListenAddress 127.0.0.1\nHostKey {hk}\nPidFile {tmp_path / 'pid'}\n"
        "AuthenticationMethods publickey\nPasswordAuthentication no\n"
        "KbdInteractiveAuthentication no\nUsePAM no\nStrictModes no\n"
    )
    proc = subprocess.Popen([SSHD, "-D", "-e", "-f", str(cfg)], stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.05)
    yield port, (tmp_path / "hk.pub").read_text().split()[:2], tmp_path
    proc.terminate()
    proc.wait(5)


def test_hostkey_probe_accepts_only_the_exact_key(real_sshd):
    port, (ktype, blob), tmp = real_sshd
    good = pins.parse_host_key(f"{ktype} {blob}")
    ok, detail = hostkey.verify_host_key(port, good)
    assert ok, detail
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(tmp / "other")], check=True)
    other = pins.parse_host_key(" ".join((tmp / "other.pub").read_text().split()[:2]))
    ok, detail = hostkey.verify_host_key(port, other)
    assert not ok and "does NOT prove" in detail


def test_hostkey_probe_without_a_server_is_not_ready(tmp_path):
    if not shutil.which("ssh"):
        pytest.skip("needs ssh")
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    ok, detail = hostkey.verify_host_key(port, HOST_KEY)
    assert not ok and "could not verify" in detail


def test_probe_argv_disables_every_auth_method_and_pins_strictly():
    import sys

    known, spelled = ("C:\\t\\kh", "C:/t/kh") if sys.platform == "win32" else ("/tmp/kh", "/tmp/kh")
    argv = hostkey.probe_argv("ssh", 22024, known, "ssh-ed25519")
    joined = " ".join(argv)
    for opt in ("StrictHostKeyChecking=yes", "BatchMode=yes", "PubkeyAuthentication=no",
                "PasswordAuthentication=no", "KbdInteractiveAuthentication=no",
                "GSSAPIAuthentication=no", "HostbasedAuthentication=no",
                f"UserKnownHostsFile={spelled}", f"GlobalKnownHostsFile={spelled}",
                "HostKeyAlgorithms=ssh-ed25519"):
        assert opt in joined
    assert argv[argv.index("-l") + 1] == hostkey.PROBE_USER
    assert argv[-2:] == ["127.0.0.1", "exit"]
