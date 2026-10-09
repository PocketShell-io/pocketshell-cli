"""Native Windows: a REAL `gateway service install|status|uninstall` round trip.

Registers the real ``\\PocketShell\\GatewayLink`` task on the (disposable)
windows-latest CI runner, so it is gated twice:

- ``POCKETSHELL_WINDOWS_SERVICE_E2E=1`` (only the CI job sets it), and
- ``POCKETSHELL_TEST_FAKE_LINK`` = a fake ``pocketshell-link.exe`` built from
  tests/gateway/fakelink/main.go (``version``/``show``/``run`` only; ``run``
  writes a marker next to the exe and idles).

The fake's sha256 enters the reviewed allow-list ONLY through monkeypatch
here (the test seam); the product has no runtime override. The fake config
dir holds dummy files — never a real key — and must be byte-for-byte
untouched after uninstall.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest
from click.testing import CliRunner

pytestmark = pytest.mark.skipif(
    os.name != "nt"
    or os.environ.get("POCKETSHELL_WINDOWS_SERVICE_E2E") != "1"
    or not os.environ.get("POCKETSHELL_TEST_FAKE_LINK"),
    reason="real Task Scheduler round trip: CI windows-latest job only",
)

from pocketshell.cli import cli  # noqa: E402
from pocketshell.gateway import service_common as common  # noqa: E402
from pocketshell.gateway import service_endpoint as ep  # noqa: E402
from pocketshell.gateway import service_windows as win  # noqa: E402

ENDPOINT_TASK = win.TASK_FOLDER + ep.ENDPOINT_LEAF
INSTANCE = "CI1"
QUALIFICATION_TASK = win.TASK_FOLDER + ep.leaf_for(INSTANCE)

CREATE_NO_WINDOW = 0x08000000


def _run(argv):
    return subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                          creationflags=CREATE_NO_WINDOW, timeout=60)


def _query_xml(name=None):
    proc = _run(win.schtasks("/Query", "/TN", name or win.TASK_NAME, "/XML"))
    return common.decode(proc.stdout) if proc.returncode == 0 else None


def _set_owner(path: Path, sid: str) -> None:
    proc = _run(["icacls", str(path), "/setowner", "*" + sid])
    assert proc.returncode == 0, common.decode(proc.stdout + proc.stderr)


def _snapshot(directory: Path) -> dict:
    return {
        p.name: (p.stat().st_mtime_ns, p.stat().st_size, hashlib.sha256(p.read_bytes()).hexdigest())
        for p in sorted(directory.iterdir())
    }


def _service(*args):
    result = CliRunner().invoke(cli, ["gateway", "service", *args])
    print(f"$ pocketshell gateway service {' '.join(args)}  -> exit {result.exit_code}")
    print(result.output)
    return result


@pytest.fixture
def layout(tmp_path, monkeypatch):
    # A space and non-ASCII in both paths exercise the action quoting.
    base = Path(win.final_path(str(tmp_path))) / "svc e2e ü"
    bin_dir = base / "helper dir"
    config = base / "keys dir"
    bin_dir.mkdir(parents=True)
    config.mkdir()
    helper = bin_dir / "pocketshell-link.exe"
    shutil.copyfile(os.environ["POCKETSHELL_TEST_FAKE_LINK"], helper)
    (config / "config.json").write_text('{"device_id":"win-service-e2e"}')
    (config / "device_ed25519.pem").write_text("DUMMY - NOT A KEY")
    sid = win.WindowsApi().current_sid()
    for path in (config, config / "device_ed25519.pem"):
        _set_owner(path, sid)  # like the real helper: O:<user>
    digest = hashlib.sha256(helper.read_bytes()).hexdigest()
    # THE test-only seam: the fake build joins the reviewed allow-list
    # for this process only.
    monkeypatch.setattr(win, "ALLOWED_HELPER_SHA256", win.ALLOWED_HELPER_SHA256 | {digest})
    _cleanup_tasks()  # leftovers from an aborted earlier run
    yield {"helper": str(helper), "config": str(config), "bin": bin_dir, "sid": sid, "base": base}
    _cleanup_tasks()


def _cleanup_tasks():
    for name in (win.TASK_NAME, ENDPOINT_TASK, QUALIFICATION_TASK):
        if _query_xml(name) is not None:
            _run(win.schtasks("/End", "/TN", name))
            _run(win.schtasks("/Delete", "/TN", name, "/F"))


def _markers(bin_dir: Path):
    return sorted(bin_dir.glob("run-*.json"))


def test_refusals_before_anything_is_registered(layout, tmp_path):
    empty = tmp_path / "not enrolled"
    empty.mkdir()
    result = _service("install", "--helper", layout["helper"], "--config-dir", str(empty))
    assert result.exit_code == 1 and "gateway enroll" in result.output
    # key owned by Administrators instead of the user -> refused
    key = Path(layout["config"]) / "device_ed25519.pem"
    _set_owner(key, "S-1-5-32-544")
    try:
        result = _service("install", "--helper", layout["helper"], "--config-dir", layout["config"])
        assert result.exit_code == 1 and "owned by S-1-5-32-544" in result.output
    finally:
        _set_owner(key, layout["sid"])
    # a helper outside the allow-list -> refused
    other = layout["bin"] / "other.exe"
    other.write_bytes(Path(layout["helper"]).read_bytes() + b"\0")
    result = _service("install", "--helper", str(other), "--config-dir", layout["config"])
    assert result.exit_code == 1 and "not a reviewed" in result.output
    assert _query_xml() is None
    assert "Traceback" not in result.output


def test_real_task_round_trip(layout):
    helper, config, sid = layout["helper"], layout["config"], layout["sid"]
    before = _snapshot(Path(config))

    dry = _service("install", "--helper", helper, "--config-dir", config, "--dry-run")
    assert dry.exit_code == 0
    assert _query_xml() is None, "--dry-run registered something"
    assert json.dumps([helper, "run", "--config-dir", config]) in dry.output

    assert _service("status").exit_code == common.EXIT_NOT_INSTALLED

    result = _service("install", "--helper", helper, "--config-dir", config)
    logon_type = "S4U"
    if result.exit_code != 0:
        # The runner refused S4U registration: the refusal must be clear,
        # then (TEST ONLY) the rest is exercised with a permitted type.
        assert "registering \\PocketShell\\GatewayLink failed" in result.output
        assert "S4U" in result.output and "Traceback" not in result.output
        logon_type = "InteractiveToken"
        print("S4U registration refused on this runner; continuing with", logon_type)
        plan = win.plan_install(helper, config, force=False, start=True, logon_type=logon_type)
        win.apply_install(plan)

    xml = _query_xml()
    assert xml is not None
    print(xml)
    fields = win.parse_task_xml(xml)
    assert fields["user_id"] == sid or fields["user_id"].lower().endswith(
        "\\" + os.environ["USERNAME"].lower()
    )
    assert fields["logon_type"] == logon_type
    assert fields["run_level"] == "LeastPrivilege"
    assert fields["exec_count"] == 1 and fields["action_count"] == 1
    assert fields["command"] == helper
    assert win.parse_arguments(fields["arguments"]) == ["run", "--config-dir", config]
    assert fields["working_directory"] == str(layout["bin"])
    assert fields["boot_trigger"] and fields["watchdog_interval"] == "PT5M"
    assert fields["multiple_instances"] == "IgnoreNew"
    assert fields["execution_time_limit"] == "PT0S"
    assert "cmd.exe" not in xml.lower() and "cmd /" not in xml.lower()

    # the task's process: direct argv, cwd = helper dir, session 0 (S4U)
    deadline = time.monotonic() + 60
    while not _markers(layout["bin"]) and time.monotonic() < deadline:
        time.sleep(1)
    markers = _markers(layout["bin"])
    if logon_type == "S4U":
        assert markers, "the task never started the helper"
    if markers:
        marker = json.loads(markers[0].read_text(encoding="utf-8"))
        print("marker:", marker)
        assert marker["args"][1:] == ["run", "--config-dir", config]
        assert Path(marker["exe"]).resolve() == Path(helper).resolve()
        assert Path(marker["cwd"]).resolve() == layout["bin"].resolve()
        assert marker["enrolled"] is True

        status = _service("status", "--json")
        data = json.loads(status.stdout)
        assert status.exit_code == common.EXIT_RUNNING, data
        assert data["running"] and data["installed"] and data["managed"]
        assert data["helper"] == helper and data["config_dir"] == config
        assert data["helper_allowed"] is True
        assert data["details"]["direct_launch"] is True
        assert "win-service-e2e" in (data["show"] or "")
        pids = {p["pid"] for p in data["processes"]}
        assert marker["pid"] in pids
        if logon_type == "S4U":
            assert {p["session_id"] for p in data["processes"]} == {0}
        assert _service("status").exit_code == common.EXIT_RUNNING

    # replace needs --force
    again = _service("install", "--helper", helper, "--config-dir", config, "--no-start")
    assert again.exit_code == 1 and "--force" in again.output

    gone = _service("uninstall")
    assert gone.exit_code == 0 and "removed" in gone.output
    assert _query_xml() is None
    if markers:
        pid = json.loads(markers[0].read_text(encoding="utf-8"))["pid"]
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if pid not in {p["pid"] for p in win.WindowsApi().processes("pocketshell-link.exe")}:
                break
            time.sleep(0.5)
        else:
            pytest.fail("the task's helper process survived uninstall")
    assert _snapshot(Path(config)) == before, "uninstall touched the config dir"

    idem = _service("uninstall")
    assert idem.exit_code == 0 and "nothing to do" in idem.output
    assert _service("status").exit_code == common.EXIT_NOT_INSTALLED
    assert _snapshot(Path(config)) == before


# --- --with-endpoint: a fake guardian speaking the agreed protocol -------------------
#
# tests/gateway/fakeguardian is ONE binary playing both the protected
# interpreter (python.exe <guardian.py> --manifest M: lock, generation, Job,
# READY then CURRENT, STOP/CLOSED) and the daemon (sshd.exe -D -f CONFIG: a
# real SSH server holding the test's host key). The manifest and guardian
# digests join the reviewed lists ONLY through monkeypatch.


def _free_port() -> int:
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _host_key():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                           serialization.PublicFormat.OpenSSH).decode()
    return private, public


def _fs(path) -> str:
    """Forward-slash spelling: the guardian's config_guard uses POSIX shlex,
    where backslashes are escapes (INTERFACE example paths use C:/...)."""
    return str(path).replace("\\", "/")


def _icacls(*args):
    proc = _run(["icacls", *map(str, args)])
    assert proc.returncode == 0, common.decode(proc.stdout + proc.stderr)


def _build_endpoint(layout, monkeypatch, *, port: int, enrolled_port: int, name: str):
    """A protected private root laid out exactly as INTERFACE.md, with the
    fake as both the qualified interpreter and the daemon."""
    fake = os.environ.get("POCKETSHELL_TEST_FAKE_GUARDIAN")
    if not fake:
        pytest.skip("POCKETSHELL_TEST_FAKE_GUARDIAN not built")
    sid = layout["sid"]
    user = os.environ["USERNAME"]
    root = layout["base"] / f"endpoint {name} ü"
    root.mkdir()
    # protected root: owner = user, DACL user/SYSTEM/Administrators only, inherited by children
    _icacls(root, "/inheritance:r", "/grant:r", f"*{sid}:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F")
    for sub in ("py", "native", "bin", "state", "state/tmp", "keys", "sftp", "runtime",
                "backend/run", "backend/state", "backend/xdg-config", "backend/xdg-state",
                "backend/xdg-data", "backend/xdg-cache"):
        (root / sub).mkdir(parents=True, exist_ok=True)
    python, daemon = root / "py" / "python.exe", root / "bin" / "sshd.exe"
    shutil.copyfile(fake, python)
    shutil.copyfile(fake, daemon)
    for source in ("guardian.py", "native_api.py", "policy.py"):
        (root / "native" / source).write_text(f"# CI stand-in for the reviewed {source}\n")
    sftp = root / "sftp" / "sftp-server.exe"
    bash = root / "runtime" / "bash.exe"
    dll = root / "runtime" / "msys-2.0.dll"
    for dummy in (sftp, bash, dll):
        dummy.write_bytes(b"CI stand-in " + dummy.name.encode())
    backend = root / "backend" / "aplexer.toml"
    backend.write_text("[engines.shell]\n", encoding="utf-8")
    private, public = _host_key()
    hostkey_file, authorized = root / "keys" / "host_ed25519", root / "keys" / "authorized_keys"
    hostkey_file.write_bytes(private)
    authorized.write_text("")
    state = root / "state"
    set_env = {
        "APLEXER_CONFIG": _fs(backend), "APLEXER_RUNTIME_DIR": _fs(root / "backend/run"),
        "APLEXER_STATE_DIR": _fs(root / "backend/state"), "APLEXER_RUN_IN_PLACE": "1", "APLEXER_SHELL": "",
        "XDG_CONFIG_HOME": _fs(root / "backend/xdg-config"), "XDG_STATE_HOME": _fs(root / "backend/xdg-state"),
        "XDG_DATA_HOME": _fs(root / "backend/xdg-data"), "XDG_CACHE_HOME": _fs(root / "backend/xdg-cache"),
        "BASH_ENV": "", "ENV": "", "ZDOTDIR": "",
    }
    bindings = {
        "hostKey": _fs(hostkey_file), "authorizedKeys": _fs(authorized), "pidFile": _fs(state / "sshd.pid"),
        "allowUser": user, "sftp": _fs(sftp), "backendConfig": _fs(backend),
        "backendExecutable": _fs(bash), "backendDLL": _fs(dll), "setEnv": set_env,
    }
    config = root / f"endpoint-{port}.conf"
    setenv_line = " ".join(f'"{k}={v}"' for k, v in set_env.items())
    config.write_text(
        f"Port {port}\nListenAddress 127.0.0.1\nHostKey \"{bindings['hostKey']}\"\n"
        f"PidFile \"{bindings['pidFile']}\"\nAuthorizedKeysFile \"{bindings['authorizedKeys']}\"\n"
        "AuthenticationMethods publickey\nPubkeyAuthentication yes\nPasswordAuthentication no\n"
        "KbdInteractiveAuthentication no\nPermitEmptyPasswords no\n"
        f"AllowUsers {user}\nDisableForwarding yes\nPermitTTY yes\nLogLevel VERBOSE\n"
        f"Subsystem sftp \"{bindings['sftp']}\"\nSetEnv {setenv_line}\n",
        encoding="utf-8",  # the guardian reads its config as UTF-8 (paths contain ü)
    )
    pinned = [python, daemon, config, sftp, bash, dll, backend,
              root / "native" / "guardian.py", root / "native" / "native_api.py", root / "native" / "policy.py"]
    pins = {_fs(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in pinned}
    doc = {
        "version": 1, "ownerSID": sid, "root": _fs(root), "state": _fs(state), "config": _fs(config),
        "port": port, "daemon": _fs(daemon), "python": _fs(python), "pins": pins,
        "environment": {
            "SystemRoot": "C:/Windows", "WINDIR": "C:/Windows", "SystemDrive": "C:",
            "ProgramData": "C:/ProgramData", "USERPROFILE": _fs(os.environ["USERPROFILE"]),
            "HOME": _fs(os.environ["USERPROFILE"]), "TEMP": _fs(state / "tmp"), "TMP": _fs(state / "tmp"),
        },
        "configBindings": bindings,
    }
    manifest = root / "endpoint-manifest.json"
    manifest.write_bytes(json.dumps(doc, indent=1).encode("utf-8"))
    # private objects must be owned by the user (an elevated create stamps Administrators)
    _icacls(root, "/setowner", f"*{sid}", "/T", "/C", "/Q")
    config_json = Path(layout["config"]) / "config.json"
    config_json.write_text(json.dumps({
        "device_id": "win-service-e2e", "ssh_host": f"127.0.0.1:{enrolled_port}",
        "ssh_host_key": " ".join(public.split()[:2]),
    }))
    # THE test-only seams: this manifest and this source triple are "reviewed".
    monkeypatch.setattr(ep, "ALLOWED_ENDPOINT_MANIFEST_SHA256",
                        ep.ALLOWED_ENDPOINT_MANIFEST_SHA256 | {hashlib.sha256(manifest.read_bytes()).hexdigest()})
    triple = tuple(pins[_fs(root / "native" / n)] for n in ("guardian.py", "native_api.py", "policy.py"))
    monkeypatch.setattr(ep, "ALLOWED_GUARDIAN_SOURCES", ep.ALLOWED_GUARDIAN_SOURCES | {triple})
    return {"root": root, "state": state, "manifest": os.path.normpath(str(manifest)), "port": port,
            "python": os.path.normpath(str(python)),
            "guardian": os.path.normpath(str(root / "native" / "guardian.py")), "public": public}


def _diagnose(endpoint, leaf):
    """Print what the guardian left behind (CI diagnostics only)."""
    try:
        info = win.query_task(None, leaf)
        print("task:", info.state if info else None, "last result:", info.last_result if info else None)
    except Exception as exc:  # noqa: BLE001
        print("task query failed:", exc)
    for path in sorted(endpoint["state"].rglob("*")):
        print("state:", ascii(str(path.relative_to(endpoint["state"]))))
        if path.suffix in (".json", ".log"):
            print("   ", ascii(path.read_text(encoding="utf-8", errors="replace")[:2000]))


def _ready_info(endpoint) -> dict:
    current = json.loads((endpoint["state"] / "CURRENT.json").read_text(encoding="utf-8"))
    ready = json.loads(Path(current["ready"]).read_text(encoding="utf-8"))
    return {**ready, "generation": current["generation"], "current": current}


def _wait(predicate, seconds, step=2.0):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(step)
    return predicate()


def _parent_pid(pid: int):
    import ctypes as c
    from ctypes import wintypes as w

    class Entry(c.Structure):
        _fields_ = [("dwSize", w.DWORD), ("cntUsage", w.DWORD), ("th32ProcessID", w.DWORD),
                    ("th32DefaultHeapID", c.c_size_t), ("th32ModuleID", w.DWORD), ("cntThreads", w.DWORD),
                    ("th32ParentProcessID", w.DWORD), ("pcPriClassBase", w.LONG), ("dwFlags", w.DWORD),
                    ("szExeFile", w.WCHAR * 260)]

    k = c.WinDLL("kernel32")
    k.CreateToolhelp32Snapshot.restype = w.HANDLE
    snap = k.CreateToolhelp32Snapshot(2, 0)
    entry = Entry()
    entry.dwSize = c.sizeof(Entry)
    ok = k.Process32FirstW(snap, c.byref(entry))
    try:
        while ok:
            if entry.th32ProcessID == pid:
                return entry.th32ParentProcessID
            ok = k.Process32NextW(snap, c.byref(entry))
    finally:
        k.CloseHandle(snap)
    return None


def listening(port):
    import socket

    try:
        socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
        return True
    except OSError:
        return False


def test_endpoint_port_already_served_is_refused(layout, monkeypatch):
    import socket

    port = _free_port()
    endpoint = _build_endpoint(layout, monkeypatch, port=port, enrolled_port=port, name="held")
    with socket.socket() as held:  # stands in for the currently held endpoint
        held.bind(("127.0.0.1", port))
        held.listen(1)
        result = _service("install", "--helper", layout["helper"], "--config-dir", layout["config"],
                          "--with-endpoint", endpoint["manifest"])
    assert result.exit_code == 1 and "already served by another process" in result.output
    assert _query_xml() is None and _query_xml(ENDPOINT_TASK) is None


def test_phase_a_check_only_qualification(layout, monkeypatch):
    enrolled, port = _free_port(), _free_port()
    endpoint = _build_endpoint(layout, monkeypatch, port=port, enrolled_port=enrolled, name="chk")
    result = _service("install", "--helper", layout["helper"], "--config-dir", layout["config"],
                      "--with-endpoint", endpoint["manifest"], "--endpoint-only", "--instance", INSTANCE,
                      "--check-only")
    if result.exit_code != 0:
        _diagnose(endpoint, ep.leaf_for(INSTANCE))
    assert result.exit_code == 0, result.output
    assert "check-only preflight exited 0" in result.output
    xml = _query_xml(QUALIFICATION_TASK)
    fields = win.parse_task_xml(xml)
    assert win.parse_arguments(fields["arguments"]) == [
        "-I", "-S", "-B", endpoint["guardian"], "--manifest", endpoint["manifest"], "--check-only"]
    assert "<BootTrigger>" not in xml and "<TimeTrigger>" not in xml
    assert not list(endpoint["state"].glob("generation-*")), "check-only allocated a generation"
    assert _query_xml() is None
    gone = _service("uninstall", "--instance", INSTANCE)
    assert gone.exit_code == 0 and _query_xml(QUALIFICATION_TASK) is None


def test_real_endpoint_and_link_lifecycle(layout, monkeypatch):
    port = _free_port()
    endpoint = _build_endpoint(layout, monkeypatch, port=port, enrolled_port=port, name="prod")
    config_before = _snapshot(Path(layout["config"]))
    manifest_before = Path(endpoint["manifest"]).read_bytes()
    args = ["install", "--helper", layout["helper"], "--config-dir", layout["config"],
            "--with-endpoint", endpoint["manifest"]]

    assert _service(*args, "--dry-run").exit_code == 0
    assert _query_xml() is None and _query_xml(ENDPOINT_TASK) is None

    result = _service(*args)
    if result.exit_code != 0:
        _diagnose(endpoint, ep.ENDPOINT_LEAF)
    assert result.exit_code == 0, result.output
    assert "enrolled host key proven" in result.output

    xml = _query_xml(ENDPOINT_TASK)
    print(xml)
    fields = win.parse_task_xml(xml)
    assert fields["command"] == endpoint["python"]
    assert win.parse_arguments(fields["arguments"]) == [
        "-I", "-S", "-B", endpoint["guardian"], "--manifest", endpoint["manifest"]]
    assert fields["working_directory"] == os.path.normpath(str(endpoint["root"]))
    assert fields["logon_type"] == "S4U" and fields["run_level"] == "LeastPrivilege"
    assert fields["exec_count"] == 1 and "cmd.exe" not in xml.lower()

    first = _ready_info(endpoint)
    print("CURRENT:", first["current"])
    assert set(first["current"]) == {"version", "generation", "ready", "manifestSHA256"}
    assert Path(first["generation"]).name.startswith("generation-")
    status = _service("status", "--json")
    data = json.loads(status.stdout)
    assert status.exit_code == common.EXIT_RUNNING, data
    epst = data["details"]["endpoint"]
    assert epst["running"] and epst["readiness"]["ok"] and not epst["contract"]
    assert epst["readiness"]["generation"].lower() == first["generation"].lower()
    assert "proved the enrolled host key" in epst["readiness"]["hostKey"]
    api = win.WindowsApi()
    sessions = {p["session_id"] for p in api.processes("python.exe") if p["pid"] == first["guardianPID"]}
    assert sessions == {0}, sessions
    parent = _parent_pid(first["guardianPID"])
    print("guardian parent pid:", parent, "test pid:", os.getpid())
    assert parent not in (None, os.getpid())

    # scheduler-owned restart: fault-inject a daemon crash (CI fake only)
    started = time.monotonic()
    subprocess.run(["taskkill", "/F", "/PID", str(first["pid"])], capture_output=True,
                   creationflags=CREATE_NO_WINDOW, timeout=30)
    closed = Path(first["generation"]) / "CLOSED.json"
    assert _wait(closed.exists, 30), "guardian did not close the crashed generation"
    assert json.loads(closed.read_text(encoding="utf-8"))["accepted"] is False
    restarted = _wait(lambda: _ready_info(endpoint)["generation"] != first["generation"], 420, step=5)
    print(f"scheduler-owned restart after {time.monotonic() - started:.0f}s")
    assert restarted, "Task Scheduler did not restart the guardian"
    second = _ready_info(endpoint)
    assert second["pid"] != first["pid"]
    assert _wait(lambda: _service("status").exit_code == common.EXIT_RUNNING, 60, step=3)

    gone = _service("uninstall")
    assert gone.exit_code == 0, gone.output
    assert "CLOSED accepted" in gone.output
    stop = json.loads((Path(second["generation"]) / "STOP.json").read_text())
    assert stop == {"pid": second["pid"], "creationFILETIME": second["creationFILETIME"],
                    "manifestSHA256": hashlib.sha256(manifest_before).hexdigest(), "stopOwnedJob": True}
    closed2 = json.loads((Path(second["generation"]) / "CLOSED.json").read_text())
    assert closed2["accepted"] and closed2["requestedOwnedJobStop"] and closed2["activeAtClose"] == 0
    assert _query_xml() is None and _query_xml(ENDPOINT_TASK) is None
    assert not listening(port)
    assert len(list(endpoint["state"].glob("generation-*"))) >= 2  # generations are retained
    assert _snapshot(Path(layout["config"])) == config_before
    assert Path(endpoint["manifest"]).read_bytes() == manifest_before
    assert _service("status").exit_code == common.EXIT_NOT_INSTALLED


def test_isolated_qualification_instance(layout, monkeypatch):
    enrolled = _free_port()
    port = _free_port()
    endpoint = _build_endpoint(layout, monkeypatch, port=port, enrolled_port=enrolled, name="qual")
    result = _service("install", "--helper", layout["helper"], "--config-dir", layout["config"],
                      "--with-endpoint", endpoint["manifest"], "--endpoint-only", "--instance", INSTANCE)
    if result.exit_code != 0:
        _diagnose(endpoint, ep.leaf_for(INSTANCE))
    assert result.exit_code == 0, result.output
    assert _query_xml() is None, "a qualification install must never register GatewayLink"
    status = _service("status", "--instance", INSTANCE, "--json")
    assert status.exit_code == common.EXIT_RUNNING, status.output
    gone = _service("uninstall", "--instance", INSTANCE)
    assert gone.exit_code == 0 and "CLOSED accepted" in gone.output
    assert _query_xml(QUALIFICATION_TASK) is None and not listening(port)


# --- Task Scheduler OBJECT security (contract ec8534aa) --------------------------------
#
# tests/gateway/fixtures/task-object-authority.ps1 is the native owner's FROZEN
# validator (sha256 02dbc13b…), byte-identical, used only as a test oracle: the
# service's Python validator must give the same verdict on the real runner's
# task/folder descriptors and on every control descriptor.

ORACLE = Path(__file__).parent / "fixtures" / "task-object-authority.ps1"
ORACLE_SHA256 = "02dbc13be3446504fe8dbdc900a984d6280646bf6fda75f92e6d460e1d82c389"


def _oracle(cases):
    """[(taskSDDL, folderSDDL, owner)] -> [accepted] by their frozen function."""
    import base64

    assert hashlib.sha256(ORACLE.read_bytes()).hexdigest() == ORACLE_SHA256
    payload = base64.b64encode(json.dumps([{"t": t, "f": f, "o": o} for t, f, o in cases]).encode()).decode()
    script = (
        "$ErrorActionPreference='Stop';"
        f". ([scriptblock]::Create([IO.File]::ReadAllText('{ORACLE}')));"
        f"$cases=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{payload}'))|ConvertFrom-Json;"
        "$out=@();foreach($c in $cases){try{"
        "$t=New-Object Security.AccessControl.RawSecurityDescriptor($c.t);"
        "$f=New-Object Security.AccessControl.RawSecurityDescriptor($c.f);"
        "$null=AssertTaskObjectAuthority $t $c.o $f;$out+=$true}catch{$out+=$false}};"
        "ConvertTo-Json -Compress -InputObject @($out)"
    )
    proc = _run(win._powershell(script))
    assert proc.returncode == 0, common.decode(proc.stderr)
    return json.loads(common.decode(proc.stdout))


def _read_task_security(leaf):
    script = (
        "$ErrorActionPreference='Stop';$s=New-Object -ComObject Schedule.Service;$s.Connect();"
        f"$f=$s.GetFolder('\\PocketShell');$t=$f.GetTask('{leaf}');"
        "[ordered]@{task=[string]$t.GetSecurityDescriptor(7);folder=[string]$f.GetSecurityDescriptor(7)}"
        "|ConvertTo-Json -Compress"
    )
    proc = _run(win._powershell(script))
    assert proc.returncode == 0, common.decode(proc.stderr)
    return json.loads(common.decode(proc.stdout))


def test_task_object_security_contract_on_the_real_scheduler(layout):
    from pocketshell.gateway import service_task_acl as acl

    sid = layout["sid"]
    result = _service("install", "--helper", layout["helper"], "--config-dir", layout["config"], "--no-start")
    assert result.exit_code == 0, result.output
    sd = _read_task_security("GatewayLink")
    print("REAL task SD:", sd["task"])
    print("REAL folder SD:", sd["folder"])
    info = win.query_task(None, "GatewayLink")  # the service's own structured readback
    print("service structured task SD:", info.task_sddl)
    assert acl.task_object_problems(info.task_sddl, info.folder_sddl, sid) == []
    assert _oracle([(sd["task"], sd["folder"], sid)]) == [True], "the native frozen validator disagrees"
    status = _service("status", "--json")
    data = json.loads(status.stdout)
    assert data["details"]["taskObjectAuthority"]["ok"] is True, data
    # the same verdicts as their 19 SDDL controls, on the runner's own SID
    from test_gateway_service_task_acl import CASES, OWN

    cases = [(t.replace(OWN, sid), f.replace(OWN, sid), sid) for _, t, f, _ in CASES]
    python = [acl.task_object_problems(t, f, o) == [] for t, f, o in cases]
    oracle = _oracle(cases)
    print("verdicts python/oracle:", python, oracle)
    assert python == oracle == [c[3] for c in CASES]
    assert _service("uninstall").exit_code == 0
