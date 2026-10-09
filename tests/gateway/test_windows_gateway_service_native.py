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
    for name in (win.TASK_NAME, ENDPOINT_TASK):
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


# --- --with-endpoint: a fake guardian as the private loopback endpoint ----------------


def _free_port() -> int:
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def endpoint(layout, monkeypatch):
    guardian_src = os.environ.get("POCKETSHELL_TEST_FAKE_GUARDIAN")
    if not guardian_src:
        pytest.skip("POCKETSHELL_TEST_FAKE_GUARDIAN not built")
    from gateway_keyblobs import ED25519_LINE
    from pocketshell.gateway import pins

    port = _free_port()
    ep_dir = layout["base"] / "endpoint dir ü"
    ep_dir.mkdir()
    guardian = ep_dir / "guardian.exe"
    shutil.copyfile(guardian_src, guardian)
    config = Path(layout["config"])
    # the enrolled local ssh + pinned host key (dummy values, like enroll writes)
    (config / "config.json").write_text(json.dumps({
        "device_id": "win-service-e2e", "ssh_host": f"127.0.0.1:{port}", "ssh_host_key": ED25519_LINE,
    }))
    doc = {
        "schema": 1,
        "name": "fake-guardian-e2e",
        "guardian": {
            "command": str(guardian),
            "sha256": hashlib.sha256(guardian.read_bytes()).hexdigest(),
            "arguments": ["--listen", f"127.0.0.1:{port}", "--note", "a b ü"],
            "working_directory": str(ep_dir),
        },
        "pinned_files": [],
        "listen": f"127.0.0.1:{port}",
        "host_key_fingerprint": pins.parse_host_key(ED25519_LINE).fingerprint,
    }
    manifest = layout["base"] / "endpoint-manifest.json"
    manifest.write_bytes(json.dumps(doc).encode("utf-8"))
    # THE test-only seam for the endpoint: this manifest joins the reviewed list.
    monkeypatch.setattr(
        ep, "ALLOWED_ENDPOINT_MANIFEST_SHA256",
        frozenset({hashlib.sha256(manifest.read_bytes()).hexdigest()}),
    )
    return {"port": port, "dir": ep_dir, "guardian": str(guardian), "manifest": str(manifest),
            "args": doc["guardian"]["arguments"]}


def _snapshot_tree(directory: Path) -> dict:
    return {
        p.name: hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(directory.iterdir())
        if p.is_file() and not p.name.startswith("guardian-")
    }


def test_endpoint_port_already_served_is_refused(layout, endpoint):
    import socket

    with socket.socket() as held:  # stands in for the currently held endpoint
        held.bind(("127.0.0.1", endpoint["port"]))
        held.listen(1)
        result = _service("install", "--helper", layout["helper"], "--config-dir", layout["config"],
                          "--with-endpoint", endpoint["manifest"])
    assert result.exit_code == 1 and "already served by another process" in result.output
    assert _query_xml() is None and _query_xml(ENDPOINT_TASK) is None


def test_real_endpoint_and_link_round_trip(layout, endpoint):
    helper, config = layout["helper"], layout["config"]
    before_config = _snapshot(Path(config))
    before_ep = _snapshot_tree(endpoint["dir"])
    args = ["install", "--helper", helper, "--config-dir", config, "--with-endpoint", endpoint["manifest"]]

    dry = _service(*args, "--dry-run")
    assert dry.exit_code == 0
    assert _query_xml() is None and _query_xml(ENDPOINT_TASK) is None

    result = _service(*args)
    assert result.exit_code == 0, result.output
    assert "SSH banner answered" in result.output

    xml = _query_xml(ENDPOINT_TASK)
    print(xml)
    fields = win.parse_task_xml(xml)
    assert fields["command"] == endpoint["guardian"]
    assert win.parse_arguments(fields["arguments"]) == endpoint["args"]
    assert fields["working_directory"] == str(endpoint["dir"])
    assert fields["logon_type"] == "S4U" and fields["run_level"] == "LeastPrivilege"
    assert fields["exec_count"] == 1 and "cmd.exe" not in xml.lower()

    ok, banner = ep.probe_banner("127.0.0.1", endpoint["port"])
    assert ok and banner.startswith("SSH-2.0-FakeGuardian")
    markers = sorted(endpoint["dir"].glob("guardian-*.json"))
    assert markers
    marker = json.loads(markers[0].read_text(encoding="utf-8"))
    print("guardian marker:", marker)
    assert marker["args"][1:] == endpoint["args"]
    assert Path(marker["cwd"]).resolve() == endpoint["dir"].resolve()

    status = _service("status", "--json")
    data = json.loads(status.stdout)
    assert status.exit_code == common.EXIT_RUNNING, data
    epst = data["details"]["endpoint"]
    assert epst["running"] and epst["banner_ok"] and epst["managed"]
    assert {p["session_id"] for p in epst["processes"]} == {0}
    assert marker["pid"] in {p["pid"] for p in epst["processes"]}

    gone = _service("uninstall")
    assert gone.exit_code == 0 and ENDPOINT_TASK in gone.output
    assert _query_xml() is None and _query_xml(ENDPOINT_TASK) is None
    deadline = time.monotonic() + 15
    while ep.port_in_use("127.0.0.1", endpoint["port"]) and time.monotonic() < deadline:
        time.sleep(0.5)
    assert not ep.port_in_use("127.0.0.1", endpoint["port"]), "guardian survived uninstall"
    assert _snapshot(Path(config)) == before_config
    assert _snapshot_tree(endpoint["dir"]) == before_ep
    assert _service("status").exit_code == common.EXIT_NOT_INSTALLED
