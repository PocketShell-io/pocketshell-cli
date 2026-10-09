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


def _build_endpoint(layout, monkeypatch, *, port: int, enrolled_port: int, name: str):
    fake = os.environ.get("POCKETSHELL_TEST_FAKE_GUARDIAN")
    if not fake:
        pytest.skip("POCKETSHELL_TEST_FAKE_GUARDIAN not built")
    sid = layout["sid"]
    root = layout["base"] / f"endpoint {name} ü"
    for sub in ("py", "guardian", "bin", "state", "state/tmp", "keys"):
        (root / sub).mkdir(parents=True, exist_ok=True)
    python = root / "py" / "python.exe"
    daemon = root / "bin" / "sshd.exe"
    shutil.copyfile(fake, python)
    shutil.copyfile(fake, daemon)
    guardian = root / "guardian" / "guardian.py"
    guardian.write_text("# stand-in for the reviewed guardian source (CI fake)\n")
    private, public = _host_key()
    hostkey_file = root / "keys" / "host_ed25519"
    hostkey_file.write_bytes(private)
    config = root / f"sshd-{port}.conf"
    config.write_text(
        f"Port {port}\nListenAddress 127.0.0.1\nHostKey {hostkey_file}\n"
        "AuthenticationMethods publickey\nPubkeyAuthentication yes\nPasswordAuthentication no\n"
        "KbdInteractiveAuthentication no\nPermitEmptyPasswords no\nDisableForwarding yes\nPermitTTY yes\n"
        f"AuthorizedKeysFile {root / 'keys' / 'authorized_keys'}\n",
        encoding="utf-8",  # the guardian reads its config as UTF-8 (paths contain ü)
    )
    pins = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (python, guardian, daemon, config)}
    state = root / "state"
    doc = {
        "version": 1, "ownerSID": sid, "root": str(root), "state": str(state), "config": str(config),
        "port": port, "daemon": str(daemon), "python": str(python), "pins": pins,
        "environment": {
            "SystemRoot": "C:/Windows", "WINDIR": "C:/Windows", "SystemDrive": "C:",
            "ProgramData": "C:/ProgramData", "USERPROFILE": os.environ["USERPROFILE"],
            "HOME": os.environ["USERPROFILE"], "TEMP": str(state / "tmp"), "TMP": str(state / "tmp"),
        },
    }
    manifest = root / "manifest.json"
    manifest.write_bytes(json.dumps(doc, indent=1).encode("utf-8"))
    for path in (root, state, manifest, config):
        _set_owner(path, sid)  # an elevated mkdir stamps Administrators; the guardian requires its owner
    config_json = Path(layout["config"]) / "config.json"
    config_json.write_text(json.dumps({
        "device_id": "win-service-e2e", "ssh_host": f"127.0.0.1:{enrolled_port}",
        "ssh_host_key": " ".join(public.split()[:2]),
    }))
    # THE test-only seams: this manifest and this guardian source are "reviewed".
    monkeypatch.setattr(ep, "ALLOWED_ENDPOINT_MANIFEST_SHA256",
                        ep.ALLOWED_ENDPOINT_MANIFEST_SHA256 | {hashlib.sha256(manifest.read_bytes()).hexdigest()})
    monkeypatch.setattr(ep, "ALLOWED_GUARDIAN_SOURCE_SHA256",
                        ep.ALLOWED_GUARDIAN_SOURCE_SHA256 | {pins[str(guardian)]})
    return {"root": root, "state": state, "manifest": str(manifest), "port": port, "python": str(python),
            "guardian": str(guardian), "public": public}


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


def _current(endpoint) -> dict:
    return json.loads((endpoint["state"] / "CURRENT.json").read_text(encoding="utf-8"))


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
    assert win.parse_arguments(fields["arguments"]) == [endpoint["guardian"], "--manifest", endpoint["manifest"]]
    assert fields["working_directory"] == str(endpoint["root"])
    assert fields["logon_type"] == "S4U" and fields["run_level"] == "LeastPrivilege"
    assert fields["exec_count"] == 1 and "cmd.exe" not in xml.lower()

    first = _current(endpoint)
    print("CURRENT:", first)
    status = _service("status", "--json")
    data = json.loads(status.stdout)
    assert status.exit_code == common.EXIT_RUNNING, data
    epst = data["details"]["endpoint"]
    assert epst["running"] and epst["readiness"]["ok"] and not epst["contract"]
    assert epst["readiness"]["generation"] == first["generation"]
    assert "proved the enrolled host key" in epst["readiness"]["hostKey"]
    api = win.WindowsApi()
    sessions = {p["session_id"] for p in api.processes("python.exe") if p["pid"] == first["guardianPID"]}
    assert sessions == {0}, sessions
    # coordinator independence: the guardian's parent is the scheduler, not this test
    parent = _parent_pid(first["guardianPID"])
    print("guardian parent pid:", parent, "test pid:", os.getpid())
    assert parent not in (None, os.getpid())

    # scheduler-owned restart: fault-inject a daemon crash (CI fake only); the
    # guardian closes its generation and exits 1; Task Scheduler (RestartOnFailure
    # or the 5-minute watchdog) starts a NEW generation without any coordinator.
    started = time.monotonic()
    subprocess.run(["taskkill", "/F", "/PID", str(first["pid"])], capture_output=True,
                   creationflags=CREATE_NO_WINDOW, timeout=30)
    closed = endpoint["state"] / "generations" / first["generation"] / "CLOSED.json"
    assert _wait(closed.exists, 30), "guardian did not close the crashed generation"
    assert json.loads(closed.read_text(encoding="utf-8"))["accepted"] is False
    restarted = _wait(lambda: (endpoint["state"] / "CURRENT.json").exists()
                      and _current(endpoint)["generation"] != first["generation"], 420, step=5)
    elapsed = time.monotonic() - started
    print(f"scheduler-owned restart after {elapsed:.0f}s")
    assert restarted, "Task Scheduler did not restart the guardian"
    second = _current(endpoint)
    assert second["pid"] != first["pid"]
    assert _wait(lambda: _service("status").exit_code == common.EXIT_RUNNING, 60, step=3)

    # uninstall: link first, then the endpoint through the STOP protocol
    gone = _service("uninstall")
    assert gone.exit_code == 0, gone.output
    assert "CLOSED accepted" in gone.output
    stop = json.loads((endpoint["state"] / "generations" / second["generation"] / "STOP.json").read_text())
    assert stop == {"pid": second["pid"], "creationFILETIME": second["creationFILETIME"],
                    "manifestSHA256": hashlib.sha256(manifest_before).hexdigest(), "stopOwnedJob": True}
    assert _query_xml() is None and _query_xml(ENDPOINT_TASK) is None
    assert not _wait(lambda: listening(port), 1)
    assert _snapshot(Path(layout["config"])) == config_before
    assert Path(endpoint["manifest"]).read_bytes() == manifest_before
    assert _service("status").exit_code == common.EXIT_NOT_INSTALLED


def listening(port):
    import socket

    try:
        socket.create_connection(("127.0.0.1", port), timeout=0.5).close()
        return True
    except OSError:
        return False


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
    assert _query_xml(QUALIFICATION_TASK) is not None
    status = _service("status", "--instance", INSTANCE, "--json")
    assert status.exit_code == common.EXIT_RUNNING, status.output
    gone = _service("uninstall", "--instance", INSTANCE)
    assert gone.exit_code == 0 and "CLOSED accepted" in gone.output
    assert _query_xml(QUALIFICATION_TASK) is None and not listening(port)
