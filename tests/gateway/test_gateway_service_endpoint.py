"""`gateway service --with-endpoint`: the FINAL guardian ABI (unit tests, any OS).

Authoritative: windows-durable-native-guardian-74a0-api/INTERFACE.md + the
6cf7ae85 successor (guardian 6cf7ae85 / policy e92bbe02 / native_api cab601e2):

- task action: <qualified python.exe> -I -S -B <protected guardian.py>
  --manifest <protected manifest> (Phase A qualification adds --check-only);
- manifest version 1 with exactly ownerSID, root, state, config, port,
  daemon, python, pins, environment, configBindings;
- state is a stable GENERATION BASE: INSTANCE.lock, generation-<uuidhex>/
  {READY,STOP,CLOSED}.json, CURRENT.json = {version, generation, ready,
  manifestSHA256} (absolute paths), metadata from the referenced READY;
- STOP = exactly {pid, creationFILETIME, manifestSHA256, stopOwnedJob:true}.

Task Scheduler, the files under the (Windows-path) root, the native API
(path authority, process births, listeners) and the SSH probe are faked;
tests/gateway/test_windows_gateway_service_native.py runs the real Task
Scheduler on windows-latest with a fake guardian, and test_hostkey_probe_*
run the real OpenSSH client against a real sshd.
"""

from __future__ import annotations

import copy
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

R = "C:/Users/alexey/PocketShellFleet/durable-endpoint-s4u-candidate"
PY = "C:/Users/alexey/AppData/Roaming/uv/python/cpython-3.14.3-windows-x86_64-none/python.exe"


def W(path: str) -> str:  # the normalized (backslash) spelling the service uses
    return path.replace("/", "\\")


ROOT, STATE, MANIFEST = W(R), W(R + "/state"), W(R + "/endpoint-manifest.json")
GUARDIAN, API, POLICY = W(R + "/native/guardian.py"), W(R + "/native/native_api.py"), W(R + "/native/policy.py")
CONFIG, DAEMON, PYTHON = W(R + "/endpoint-22024.conf"), W(R + "/bin/sshd.exe"), W(PY)
SHA_G, SHA_A, SHA_P = "6cf7ae85ad21b23496e7187da7e3bb4f171adef5f63edd2fd01f6ce6435bd047", \
    "cab601e27e9814ee8c4e3cd72e0dfd55fd2808682d302655725885b4a4812231", \
    "e92bbe02c497c959702b35cfd2d4444a073eafe6e17d5e3872449c3bd4f6b1ce"
HOST_KEY = pins.parse_host_key(ED25519_LINE)
SHOW_22024 = (
    "server:          wss://gateway.pocketshell.io\n"
    "device id:       host-laptop-pha6tcnc-75fu\n"
    "local ssh:       127.0.0.1:22024 (loopback only)\n"
    "device key:      SHA256:abc\n"
    f"pinned ssh host key: {ED25519_LINE}\n"
)
SET_ENV = {
    "APLEXER_CONFIG": R + "/backend/aplexer.toml",
    "APLEXER_RUNTIME_DIR": R + "/backend/run",
    "APLEXER_STATE_DIR": R + "/backend/state",
    "APLEXER_RUN_IN_PLACE": "1",
    "APLEXER_SHELL": "",
    "XDG_CONFIG_HOME": R + "/backend/xdg-config",
    "XDG_STATE_HOME": R + "/backend/xdg-state",
    "XDG_DATA_HOME": R + "/backend/xdg-data",
    "XDG_CACHE_HOME": R + "/backend/xdg-cache",
    "BASH_ENV": "",
    "ENV": "",
    "ZDOTDIR": "",
}


def manifest(port: int = 22024) -> dict:
    """INTERFACE.md manifest, concrete (no placeholders)."""
    config = f"{R}/endpoint-{port}.conf"
    return {
        "version": 1,
        "ownerSID": USER_SID,
        "root": R,
        "state": R + "/state",
        "config": config,
        "port": port,
        "daemon": R + "/bin/sshd.exe",
        "python": PY,
        "pins": {
            R + "/bin/sshd.exe": QUALIFIED,
            PY: QUALIFIED,
            config: QUALIFIED,
            R + "/sftp-9.5.6.2/sftp-server.exe": QUALIFIED,
            R + "/runtime/portablegit/usr/bin/bash.exe": QUALIFIED,
            R + "/runtime/portablegit/usr/bin/msys-2.0.dll": QUALIFIED,
            R + "/backend/aplexer.toml": QUALIFIED,
            R + "/native/guardian.py": SHA_G,
            R + "/native/native_api.py": SHA_A,
            R + "/native/policy.py": SHA_P,
            "C:/Windows/System32/conhost.exe": QUALIFIED,
        },
        "environment": {
            "SystemRoot": "C:/Windows", "WINDIR": "C:/Windows", "SystemDrive": "C:",
            "ProgramData": "C:/ProgramData", "USERPROFILE": "C:/Users/alexey", "HOME": "C:/Users/alexey",
            "TEMP": R + "/state/tmp", "TMP": R + "/state/tmp",
        },
        "configBindings": {
            "hostKey": "C:/Users/alexey/PocketShellFleet/quiet-sshd-v26a/host_ed25519",
            "authorizedKeys": "C:/Users/alexey/PocketShellFleet/quiet-sshd-v26a/authorized_keys.fleet",
            "pidFile": R + "/state/sshd.pid",
            "allowUser": "alexey",
            "sftp": R + "/sftp-9.5.6.2/sftp-server.exe",
            "backendConfig": R + "/backend/aplexer.toml",
            "backendExecutable": R + "/runtime/portablegit/usr/bin/bash.exe",
            "backendDLL": R + "/runtime/portablegit/usr/bin/msys-2.0.dll",
            "setEnv": dict(SET_ENV),
        },
    }


def config_text(m: dict) -> str:
    b = m["configBindings"]
    setenv = " ".join(f'"{k}={v}"' for k, v in b["setEnv"].items())
    return (
        f"Port {m['port']}\nListenAddress 127.0.0.1\nHostKey \"{b['hostKey']}\"\n"
        f"PidFile \"{b['pidFile']}\"\nAuthorizedKeysFile \"{b['authorizedKeys']}\"\n"
        "AuthenticationMethods publickey\nPubkeyAuthentication yes\nPasswordAuthentication no\n"
        "KbdInteractiveAuthentication no\nPermitEmptyPasswords no\n"
        f"AllowUsers {b['allowUser']}\nDisableForwarding yes\nPermitTTY yes\nLogLevel VERBOSE\n"
        f"Subsystem sftp \"{b['sftp']}\"\nSetEnv {setenv}\n"
    )


def encode(doc) -> bytes:
    return json.dumps(doc, indent=1).encode("utf-8")


class Guardian:
    """Simulates the final guardian protocol inside a virtual filesystem."""

    def __init__(self, fake, api, vfs, data: bytes, port: int = 22024):
        self.fake, self.api, self.vfs = fake, api, vfs
        self.manifest_sha = hashlib.sha256(data).hexdigest()
        self.port = port
        self.generation = None
        self.next_pid = 5000
        self.ready_on_run = True
        self.close_accepted = True
        self.stop_requests = []
        self.runs = []

    def run(self, leaf):
        self.runs.append(leaf)
        self.generation = STATE + "\\generation-" + os.urandom(16).hex()
        daemon, guardian = self.next_pid, self.next_pid + 1
        self.next_pid += 2
        self.api.births[daemon] = f"13436{daemon}0000000"
        self.api.births[guardian] = f"13436{guardian}0000000"
        self.api.images[guardian] = PYTHON
        if not self.ready_on_run:
            return
        self.api.listeners[self.port] = [("127.0.0.1", daemon)]
        ready = {
            "accepted": False, "manifestSHA256": self.manifest_sha, "context": {"session": 0},
            "cleanupErrors": [], "pid": daemon, "creationFILETIME": self.api.births[daemon],
            "guardianPID": guardian, "sourceSHA256": SHA_G, "port": self.port,
            "heldProcessHandle": True, "ownedJob": True,
        }
        self.vfs[self.generation + "\\READY.json"] = json.dumps(ready).encode()
        self.vfs[STATE + "\\CURRENT.json"] = json.dumps({
            "version": 1, "generation": self.generation,
            "ready": self.generation + "\\READY.json", "manifestSHA256": self.manifest_sha,
        }).encode()

    def on_stop(self, path, data):
        self.stop_requests.append(json.loads(data))
        ready = json.loads(self.vfs[path.replace("STOP.json", "READY.json")])
        expected = {"pid": ready["pid"], "creationFILETIME": ready["creationFILETIME"],
                    "manifestSHA256": self.manifest_sha, "stopOwnedJob": True}
        accepted = json.loads(data) == expected and self.close_accepted
        if accepted:
            self.api.births.pop(ready["pid"], None)
            self.api.births.pop(ready["guardianPID"], None)
            self.api.listeners.pop(ready["port"], None)
            for task in self.fake.tasks.values():
                if task["state"] == "Running":
                    task["state"] = "Disabled"
        self.vfs[path.replace("STOP.json", "CLOSED.json")] = json.dumps({
            "accepted": accepted, "requestedOwnedJobStop": accepted, "activeAtClose": 0,
            "cleanupErrors": [],
        }).encode()


class EndpointApi(FakeApi):
    def __init__(self, vfs, **kw):
        super().__init__(**kw)
        self.vfs = vfs
        self.births, self.images, self.listeners = {}, {}, {}
        self.guardian = None
        self.writes, self.authority = [], []
        self.authority_failures = {}

    def process_birth(self, pid):
        return self.births.get(pid)

    def process_image(self, pid):
        return self.images.get(pid)

    def listener_pids(self, port):
        return list(self.listeners.get(port, []))

    def path_authority(self, path, owner_sid, *, role, directory=False, protected=False, servicing=False):
        self.authority.append((path, role, directory, protected, servicing))
        if path in self.authority_failures:
            raise ServiceError(self.authority_failures[path])

    def write_owned_file(self, path, data, owner_sid):
        assert path not in self.vfs, "STOP.json must never be overwritten"
        self.writes.append((path, owner_sid))
        self.vfs[path] = data
        if path.endswith("STOP.json") and self.guardian is not None:
            self.guardian.on_stop(path, data)


@pytest.fixture
def env(fake_windows, monkeypatch):  # noqa: F811
    vfs: dict = {}
    doc = manifest()
    data = encode(doc)
    vfs[MANIFEST] = data
    vfs[CONFIG] = config_text(doc).encode()
    api = EndpointApi(vfs)
    guardian = Guardian(fake_windows, api, vfs, data)
    api.guardian = guardian
    fake_windows.show_out = SHOW_22024
    monkeypatch.setattr(wep, "read_bounded", lambda path, limit: vfs.get(path))
    monkeypatch.setattr(ep, "ALLOWED_ENDPOINT_MANIFEST_SHA256", frozenset({hashlib.sha256(data).hexdigest()}))
    monkeypatch.setattr(ep, "ALLOWED_GUARDIAN_SOURCES", frozenset({(SHA_G, SHA_A, SHA_P)}))
    digests = {GUARDIAN: SHA_G, API: SHA_A, POLICY: SHA_P}
    monkeypatch.setattr(win, "file_sha256", lambda p: digests.get(p, QUALIFIED))
    probe = {"result": (True, "proved the enrolled host key"), "calls": 0}

    def verify(port, key, **kw):
        probe["calls"] += 1
        assert key.line == HOST_KEY.line
        return probe["result"]

    monkeypatch.setattr(hostkey, "verify_host_key", verify)
    monkeypatch.setattr(wep, "ENDPOINT_CONFIRM_SECONDS", 0.3)
    monkeypatch.setattr(wep, "STOP_CONFIRM_SECONDS", 0.3)
    monkeypatch.setattr(wep, "POLL_SECONDS", 0.01)
    monkeypatch.setattr(win, "WindowsApi", lambda: api)
    fake_windows.on_run = {ep.ENDPOINT_LEAF: lambda: guardian.run("prod")}
    return {"vfs": vfs, "api": api, "guardian": guardian, "fake": fake_windows, "probe": probe,
            "data": data, "doc": doc, "monkeypatch": monkeypatch}


def _set_manifest(env, doc):
    data = encode(doc)
    env["vfs"][MANIFEST] = data
    if "setEnv" in doc.get("configBindings", {}):
        env["vfs"][W(doc["config"])] = config_text(doc).encode()
    env["monkeypatch"].setattr(ep, "ALLOWED_ENDPOINT_MANIFEST_SHA256", frozenset({hashlib.sha256(data).hexdigest()}))
    env["guardian"].manifest_sha = hashlib.sha256(data).hexdigest()
    env["guardian"].port = doc["port"]


def _plan(env, **kw):
    kw.setdefault("force", False)
    kw.setdefault("start", True)
    kw.setdefault("api", env["api"])
    return win.plan_install(WIN_HELPER, WIN_CONFIG, endpoint_manifest=MANIFEST, **kw)


# --- RED controls: the final ABI vs the previous (v2-protocol) service -----------------------


def test_final_manifest_with_config_bindings_is_accepted(env):
    """RED on 30fb39c: its closed ten-key schema refuses `configBindings`."""
    plan = _plan(env)
    assert plan.endpoint.manifest.config_bindings["allowUser"] == "alexey"


def test_manifest_without_config_bindings_is_refused(env):
    """RED on 30fb39c: it ACCEPTED the initial a028 schema the final ABI rejects."""
    doc = manifest()
    del doc["configBindings"]
    _set_manifest(env, doc)
    with pytest.raises(ServiceError, match="closed guardian schema"):
        _plan(env)


def test_task_action_is_the_exact_isolated_bootstrap_argv(env):
    """RED on 30fb39c: its action was (guardian, --manifest, manifest), no -I -S -B."""
    plan = _plan(env)
    fields = win.parse_task_xml(plan.endpoint.xml)
    assert fields["command"] == PYTHON
    assert win.parse_arguments(fields["arguments"]) == ["-I", "-S", "-B", GUARDIAN, "--manifest", MANIFEST]
    assert fields["working_directory"] == ROOT


def test_current_json_is_the_final_pointer(env):
    """RED on 30fb39c: it required schema/pid/birth/port duplicates the final
    CURRENT.json does not have, and `generations/<hex>` instead of
    `generation-<uuidhex>`."""
    win.apply_install(_plan(env), api=env["api"])
    st = win.status(api=env["api"])
    assert st.exit_code == 0, st.warnings


# --- manifest: the final closed schema (policy e92bbe02 validate_manifest) ----------------


def _without(doc, *path):
    target = doc
    for key in path[:-1]:
        target = target[key]
    del target[path[-1]]
    return doc


def _with(doc, value, *path):
    target = doc
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    return doc


@pytest.mark.parametrize(
    "mutate, message",
    [
        (lambda d: _with(d, 2, "version"), "closed guardian schema"),
        (lambda d: _with(d, 1, "extra"), "closed guardian schema"),
        (lambda d: _with(d, "S-1-5-18", "ownerSID"), "own-account SID"),
        (lambda d: _with(d, "C:/elsewhere/state", "state"), "escapes the protected root"),
        (lambda d: _with(d, 22, "port"), "unprivileged"),
        (lambda d: _without(d, "pins", R + "/native/policy.py"), "source closure"),
        (lambda d: _without(d, "pins", PY), "lacks a pin"),
        (lambda d: _with(d, "X" * 64, "pins", PY), "lowercase sha256"),
        (lambda d: _without(d, "configBindings", "setEnv"), "config binding roles"),
        (lambda d: _with(d, R + "/elsewhere.pid", "configBindings", "pidFile"), "pidFile escapes"),
        (lambda d: _without(d, "pins", R + "/sftp-9.5.6.2/sftp-server.exe"), "runtime role lacks a pin"),
        (lambda d: _with(d, "two users", "configBindings", "allowUser"), "one explicit username"),
        (lambda d: _with(d, "/bin/sh", "configBindings", "setEnv", "BASH_ENV"), "closed incoming backend environment"),
        (lambda d: _with(d, "0", "configBindings", "setEnv", "APLEXER_RUN_IN_PLACE"), "closed incoming backend environment"),
        (lambda d: _with(d, R + "/x.toml", "configBindings", "setEnv", "APLEXER_CONFIG"), "closed incoming backend environment"),
        (lambda d: _with(d, "C:/x", "environment", "PATH"), "closed fixed environment"),
        (lambda d: _with(d, "D:/Windows", "environment", "SystemRoot"), "qualified system paths"),
        (lambda d: _with(d, "C:/Temp", "environment", "TEMP"), "TEMP escapes"),
    ],
)
def test_manifest_final_schema_refusals(env, mutate, message):
    _set_manifest(env, mutate(copy.deepcopy(manifest())))
    with pytest.raises(ServiceError, match=message):
        _plan(env)


def test_source_closure_must_sit_together_below_root(env):
    doc = manifest()
    doc["pins"].pop(R + "/native/native_api.py")
    doc["pins"][R + "/other/native_api.py"] = SHA_A
    _set_manifest(env, doc)
    with pytest.raises(ServiceError, match="next to guardian.py"):
        _plan(env)


@pytest.mark.parametrize(
    "edit, message",
    [
        (lambda t: t.replace("Port 22024", "Port 22026"), "loopback key-only"),
        (lambda t: t.replace("PasswordAuthentication no", "PasswordAuthentication yes"), "loopback key-only"),
        (lambda t: t + "Include other.conf\n", "Undeclared config directive"),
        (lambda t: t.replace("authorized_keys.fleet", "authorized_keys.other"), "path role mismatch"),
        (lambda t: t.replace("Subsystem sftp", "Subsystem sftp-x"), "SFTP binding"),
        (lambda t: t.replace('"APLEXER_RUN_IN_PLACE=1"', '"APLEXER_RUN_IN_PLACE=0"'), "environment binding"),
    ],
)
def test_config_guard_mirrors_the_guardian(env, edit, message):
    env["vfs"][CONFIG] = edit(config_text(env["doc"])).encode()
    with pytest.raises(ServiceError, match=message):
        _plan(env)


def test_trust_reviewed_manifest_and_full_source_triple_and_disk(env, monkeypatch):
    monkeypatch.setattr(ep, "ALLOWED_ENDPOINT_MANIFEST_SHA256", frozenset())
    with pytest.raises(ServiceError, match="not a reviewed manifest"):
        _plan(env)
    monkeypatch.setattr(ep, "ALLOWED_ENDPOINT_MANIFEST_SHA256", frozenset({hashlib.sha256(env["data"]).hexdigest()}))
    monkeypatch.setattr(ep, "ALLOWED_GUARDIAN_SOURCES", frozenset({(SHA_G, SHA_A, "0" * 64)}))
    with pytest.raises(ServiceError, match="not a reviewed guardian/native_api/policy"):
        _plan(env)
    monkeypatch.setattr(ep, "ALLOWED_GUARDIAN_SOURCES", frozenset({(SHA_G, SHA_A, SHA_P)}))
    monkeypatch.setattr(win, "file_sha256", lambda p: "0" * 64 if p == PYTHON else {GUARDIAN: SHA_G, API: SHA_A, POLICY: SHA_P}.get(p, QUALIFIED))
    with pytest.raises(ServiceError, match="does not match the manifest"):
        _plan(env)


def test_reviewed_lists_start_empty():
    assert ep.ALLOWED_ENDPOINT_MANIFEST_SHA256 == frozenset()
    assert ep.ALLOWED_GUARDIAN_SOURCES == frozenset()


def test_protected_ancestor_authority_is_checked_before_registration(env):
    plan = _plan(env)
    checked = {(p, role) for p, role, *_ in env["api"].authority}
    for path, role in [(ROOT, "private"), (STATE, "private"), (MANIFEST, "private"), (GUARDIAN, "private"),
                       (API, "private"), (POLICY, "private"), (CONFIG, "private"), (PYTHON, "file"),
                       (DAEMON, "file"), (W(R + "/state/tmp"), "private"),
                       (W("C:/Users/alexey/PocketShellFleet/quiet-sshd-v26a/host_ed25519"), "private"),
                       (W(R + "/runtime/portablegit/usr/bin/bash.exe"), "file")]:
        assert (path, role) in checked, (path, role)
    root = [a for a in env["api"].authority if a[0] == ROOT][0]
    assert root[3] is True  # protected DACL required on the root
    servicing = [a for a in env["api"].authority if a[0] == W("C:/Windows/System32/conhost.exe")][0]
    assert servicing[4] is True and servicing[1] == "file"
    assert plan.endpoint is not None
    env["api"].authority_failures[PYTHON] = "foreign mutation authority on an ancestor"
    with pytest.raises(ServiceError, match="foreign mutation"):
        _plan(env)
    assert all(v[0] != "/Create" for v in _task_verbs(env["fake"]))


def test_binding_owner_port_and_pin(env):
    doc = manifest()
    doc["ownerSID"] = OTHER_SID
    _set_manifest(env, doc)
    with pytest.raises(ServiceError, match="ownerSID"):
        _plan(env)
    _set_manifest(env, manifest(port=22025))
    with pytest.raises(ServiceError, match="not the enrolled local ssh"):
        _plan(env)


def test_held_endpoint_on_the_port_is_never_touched(env):
    env["api"].listeners[22024] = [("127.0.0.1", 38832)]
    with pytest.raises(ServiceError, match="already served by another process"):
        _plan(env)


# --- install / readiness -------------------------------------------------------------------


def test_install_confirms_ready_before_the_link(env):
    win.apply_install(_plan(env), api=env["api"])
    verbs = [v for v in _task_verbs(env["fake"]) if v[0] in ("/Create", "/Run")]
    assert verbs == [("/Create", "GatewayEndpoint"), ("/Run", "GatewayEndpoint"),
                     ("/Create", "GatewayLink"), ("/Run", "GatewayLink")]


@pytest.mark.parametrize("breakage", ["no-current", "wrong-key", "foreign-listener", "dead-daemon",
                                      "guardian-not-python", "stale-current"])
def test_not_ready_endpoint_exits_5_and_link_is_not_registered(env, breakage):
    g = env["guardian"]
    if breakage == "no-current":
        g.ready_on_run = False
    elif breakage == "wrong-key":
        env["probe"]["result"] = (False, "does NOT prove the enrolled host key")
    elif breakage in ("foreign-listener", "dead-daemon", "guardian-not-python", "stale-current"):
        if breakage == "stale-current":
            g.run("earlier")  # a generation left over from an earlier, since stopped guardian
            env["api"].listeners.clear()
            g.ready_on_run = False  # this start never becomes READY: CURRENT still names the old one

        def run():
            if breakage == "stale-current":
                g.run("x")
                return
            g.run("x")
            ready = json.loads(env["vfs"][g.generation + "\\READY.json"])
            if breakage == "foreign-listener":
                env["api"].listeners[22024] = [("127.0.0.1", 4242)]
            elif breakage == "dead-daemon":
                env["api"].births.pop(ready["pid"])
            else:
                env["api"].images[ready["guardianPID"]] = "C:\\Windows\\System32\\cmd.exe"
        env["fake"].on_run[ep.ENDPOINT_LEAF] = run
    with pytest.raises(common.NotStartedError, match="registered but NOT ready"):
        win.apply_install(_plan(env), api=env["api"])
    assert "GatewayLink" not in env["fake"].tasks


def test_current_must_point_inside_the_generation_base(env):
    win.apply_install(_plan(env), api=env["api"])
    cur = json.loads(env["vfs"][STATE + "\\CURRENT.json"])
    for bad in ({**cur, "generation": "C:\\elsewhere\\generation-" + "a" * 32},
                {**cur, "ready": cur["generation"] + "\\..\\READY.json"},
                {**cur, "generation": STATE + "\\generations\\" + "a" * 32},
                {**cur, "manifestSHA256": "b" * 64},
                {**cur, "schema": 1}):
        env["vfs"][STATE + "\\CURRENT.json"] = json.dumps(bad).encode()
        assert win.status(api=env["api"]).exit_code == 3, bad


def test_ready_binds_daemon_birth_and_manifest(env):
    win.apply_install(_plan(env), api=env["api"])
    ready_path = env["guardian"].generation + "\\READY.json"
    ready = json.loads(env["vfs"][ready_path])
    env["api"].births[ready["pid"]] = "1"
    assert win.status(api=env["api"]).exit_code == 3
    env["api"].births[ready["pid"]] = ready["creationFILETIME"]
    for field, value in (("creationFILETIME", 134), ("port", 22025), ("manifestSHA256", "c" * 64)):
        env["vfs"][ready_path] = json.dumps({**ready, field: value}).encode()
        assert win.status(api=env["api"]).exit_code == 3, field


def test_readiness_never_counts_a_banner(env):
    env["probe"]["result"] = (False, "127.0.0.1:22024 does NOT prove the enrolled host key")
    with pytest.raises(common.NotStartedError, match="does NOT prove the enrolled host key"):
        win.apply_install(_plan(env), api=env["api"])


# --- uninstall: disable -> STOP into the CURRENT generation -> delete ---------------------


def test_uninstall_uses_the_exact_stop_in_the_current_generation(env):
    win.apply_install(_plan(env), api=env["api"])
    ready = json.loads(env["vfs"][env["guardian"].generation + "\\READY.json"])
    message = win.uninstall(api=env["api"])
    assert "CLOSED accepted" in message
    assert env["guardian"].stop_requests == [{
        "pid": ready["pid"], "creationFILETIME": ready["creationFILETIME"],
        "manifestSHA256": hashlib.sha256(env["data"]).hexdigest(), "stopOwnedJob": True}]
    assert env["api"].writes[-1] == (env["guardian"].generation + "\\STOP.json", USER_SID)
    verbs = _task_verbs(env["fake"])
    assert ("/End", "GatewayEndpoint") not in verbs
    assert verbs.index(("/Delete", "GatewayLink")) < verbs.index(("/Delete", "GatewayEndpoint"))
    assert env["fake"].tasks == {}


def test_uninstall_rejected_or_ignored_stop_leaves_task_disabled(env):
    win.apply_install(_plan(env), api=env["api"])
    env["guardian"].close_accepted = False
    with pytest.raises(ServiceError, match="still alive|left DISABLED|still Running"):
        win.uninstall(api=env["api"])
    assert "GatewayEndpoint" in env["fake"].tasks


def test_closed_requires_the_final_acceptance_fields(env):
    win.apply_install(_plan(env), api=env["api"])
    g = env["guardian"]

    def partial_close(path, data):
        g.stop_requests.append(json.loads(data))
        ready = json.loads(env["vfs"][path.replace("STOP.json", "READY.json")])
        env["api"].births.pop(ready["pid"], None)
        env["api"].listeners.pop(22024, None)
        for task in env["fake"].tasks.values():
            task["state"] = "Disabled"
        env["vfs"][path.replace("STOP.json", "CLOSED.json")] = json.dumps(
            {"accepted": True, "requestedOwnedJobStop": True, "activeAtClose": 1, "cleanupErrors": []}).encode()

    g.on_stop = partial_close
    message = win.uninstall(api=env["api"])
    assert "without acceptance" in message


# --- Phase A check-only and the isolated qualification instance ---------------------------


def _qualification(env, monkeypatch, check_only=False):
    _set_manifest(env, manifest(port=22025))
    env["fake"].on_run[ep.leaf_for("N1")] = lambda: env["guardian"].run("q")
    return _plan(env, endpoint_only=True, instance="N1", check_only=check_only)


def test_check_only_qualification_task(env, monkeypatch):
    plan = _qualification(env, monkeypatch, check_only=True)
    fields = win.parse_task_xml(plan.endpoint.xml)
    assert win.parse_arguments(fields["arguments"]) == [
        "-I", "-S", "-B", GUARDIAN, "--manifest", MANIFEST, "--check-only"]
    assert "<Triggers" not in plan.endpoint.xml or "<BootTrigger>" not in plan.endpoint.xml
    assert "<ExecutionTimeLimit>PT5M</ExecutionTimeLimit>" in plan.endpoint.xml

    def finish():
        env["fake"].tasks["GatewayEndpointQN1"]["state"] = "Ready"
        env["fake"].last_result["GatewayEndpointQN1"] = 0

    env["fake"].on_run[ep.leaf_for("N1")] = finish
    result = win.apply_install(plan, api=env["api"])
    assert any("check-only preflight exited 0" in r for r in result)
    assert env["guardian"].runs == []  # no generation, no daemon
    message = win.uninstall(api=env["api"], instance="N1")
    assert "removed" in message and env["fake"].tasks == {}


def test_check_only_nonzero_exit_is_not_started(env, monkeypatch):
    plan = _qualification(env, monkeypatch, check_only=True)

    def fail():
        env["fake"].tasks["GatewayEndpointQN1"]["state"] = "Ready"
        env["fake"].last_result["GatewayEndpointQN1"] = 1

    env["fake"].on_run[ep.leaf_for("N1")] = fail
    with pytest.raises(common.NotStartedError, match="check-only preflight exited 1"):
        win.apply_install(plan, api=env["api"])


def test_check_only_is_qualification_only(env):
    with pytest.raises(ServiceError, match="--check-only"):
        _plan(env, check_only=True)


def test_qualification_instance_lifecycle(env, monkeypatch):
    plan = _qualification(env, monkeypatch)
    assert plan.endpoint.leaf == "GatewayEndpointQN1" and plan.include_link is False
    win.apply_install(plan, api=env["api"])
    assert set(env["fake"].tasks) == {"GatewayEndpointQN1"}
    assert win.status(api=env["api"], instance="N1").exit_code == 0
    assert "CLOSED accepted" in win.uninstall(api=env["api"], instance="N1")
    assert env["fake"].tasks == {}


def test_cli_dry_run_shows_the_exact_argv(env, monkeypatch):
    result = _windows_cli(monkeypatch, "install", "--helper", WIN_HELPER, "--config-dir", WIN_CONFIG,
                          "--with-endpoint", MANIFEST, "--dry-run")
    assert result.exit_code == 0, result.output
    assert json.dumps([PYTHON, "-I", "-S", "-B", GUARDIAN, "--manifest", MANIFEST]) in result.stdout
    assert env["fake"].tasks == {}


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
    ok, detail = hostkey.verify_host_key(port, pins.parse_host_key(f"{ktype} {blob}"))
    assert ok, detail
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(tmp / "other")], check=True)
    other = pins.parse_host_key(" ".join((tmp / "other.pub").read_text().split()[:2]))
    ok, detail = hostkey.verify_host_key(port, other)
    assert not ok and "does NOT prove" in detail


def test_hostkey_probe_without_a_server_is_not_ready():
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
    joined = " ".join(hostkey.probe_argv("ssh", 22024, known, "ssh-ed25519"))
    for opt in ("StrictHostKeyChecking=yes", "BatchMode=yes", "PubkeyAuthentication=no",
                "PasswordAuthentication=no", "KbdInteractiveAuthentication=no",
                f"UserKnownHostsFile={spelled}", "HostKeyAlgorithms=ssh-ed25519"):
        assert opt in joined
