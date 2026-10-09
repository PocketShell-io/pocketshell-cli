"""`gateway service install --with-endpoint MANIFEST` — unit tests (any OS).

The private loopback endpoint gets a second managed task,
\\PocketShell\\GatewayEndpoint, from a reviewed manifest. Task Scheduler,
the helper, the TCP probes and the native API are all faked here;
tests/gateway/test_windows_gateway_service_native.py registers real tasks on
the windows-latest runner with a fake guardian.
"""

from __future__ import annotations

import hashlib
import json

import pytest
from gateway_keyblobs import ED25519_LINE

from pocketshell.gateway import pins
from pocketshell.gateway import service_common as common
from pocketshell.gateway import service_endpoint as ep
from pocketshell.gateway import service_windows as win
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

FP = pins.parse_host_key(ED25519_LINE).fingerprint
GUARDIAN = r"C:\Users\alexey\PocketShellFleet\quiet-sshd-v26a\guardian.exe"
EP_DIR = r"C:\Users\alexey\PocketShellFleet\quiet-sshd-v26a"
MANIFEST_PATH = r"C:\Users\alexey\PocketShellFleet\quiet-sshd-v26a\endpoint-manifest.json"
SHOW_22024 = (
    "server:          wss://gateway.pocketshell.io\n"
    "device id:       host-laptop-pha6tcnc-75fu\n"
    "local ssh:       127.0.0.1:22024 (loopback only)\n"
    "device key:      SHA256:abc\n"
    f"pinned ssh host key: {ED25519_LINE}\n"
)


def manifest(**overrides) -> dict:
    doc = {
        "schema": 1,
        "name": "quiet-sshd-v26a",
        "guardian": {
            "command": GUARDIAN,
            "sha256": QUALIFIED,
            "arguments": ["--config", EP_DIR + r"\sshd config", "--listen", "127.0.0.1:22024"],
            "working_directory": EP_DIR,
        },
        "pinned_files": [{"path": EP_DIR + r"\usr\bin\sshd.exe", "sha256": QUALIFIED}],
        "listen": "127.0.0.1:22024",
        "host_key_fingerprint": FP,
    }
    for key, value in overrides.items():
        if key.startswith("guardian_"):
            doc["guardian"][key[len("guardian_"):]] = value
        elif value is None:
            doc.pop(key, None)
        else:
            doc[key] = value
    return doc


def encode(doc) -> bytes:
    return json.dumps(doc, indent=1).encode("utf-8")


@pytest.fixture
def endpoint_env(fake_windows, monkeypatch):  # noqa: F811
    """A reviewed manifest at MANIFEST_PATH, the enrolled local ssh = 22024."""
    state = {"data": encode(manifest()), "port_busy": False, "banner": (True, "SSH-2.0-OpenSSH_9.9")}
    fake_windows.show_out = SHOW_22024
    monkeypatch.setattr(win, "read_manifest", lambda path: state["data"])

    def allow_current():
        monkeypatch.setattr(
            ep, "ALLOWED_ENDPOINT_MANIFEST_SHA256",
            frozenset({hashlib.sha256(state["data"]).hexdigest()}),
        )

    state["allow"] = allow_current
    allow_current()
    monkeypatch.setattr(ep, "port_in_use", lambda host, port: state["port_busy"])
    monkeypatch.setattr(ep, "probe_banner", lambda host, port: state["banner"])
    monkeypatch.setattr(win, "START_CONFIRM_SECONDS", 0.2)
    state["fake"] = fake_windows
    return state


def _plan(**kw):
    kw.setdefault("force", False)
    kw.setdefault("start", True)
    kw.setdefault("api", FakeApi())
    return win.plan_install(WIN_HELPER, WIN_CONFIG, endpoint_manifest=MANIFEST_PATH, **kw)


# --- manifest ------------------------------------------------------------------------


def test_reviewed_allow_list_starts_empty():
    assert ep.ALLOWED_ENDPOINT_MANIFEST_SHA256 == frozenset()


def test_unreviewed_manifest_is_refused(endpoint_env, monkeypatch):
    monkeypatch.setattr(ep, "ALLOWED_ENDPOINT_MANIFEST_SHA256", frozenset())
    with pytest.raises(ServiceError, match="not a reviewed endpoint manifest"):
        _plan()


@pytest.mark.parametrize(
    "overrides, message",
    [
        ({"schema": 2}, "schema"),
        ({"extra": 1}, "unknown key"),
        ({"guardian_shell": "cmd.exe"}, "unknown guardian key"),
        ({"guardian_command": r"C:\Windows\System32\cmd.bat"}, ".exe"),
        ({"guardian_command": r"guardian.exe"}, "absolute"),
        ({"guardian_command": r"\\server\share\guardian.exe"}, "absolute"),
        ({"guardian_arguments": ['a"b']}, "double quote"),
        ({"guardian_arguments": ["%PATH%"]}, "double quote, '%'"),
        ({"guardian_arguments": ["a\nb"]}, "control"),
        ({"guardian_sha256": "ABC"}, "64 lowercase hex"),
        ({"listen": "0.0.0.0:22024"}, "loopback"),
        ({"listen": "[::1]:22024"}, "loopback"),
        ({"listen": "127.0.0.1:0"}, "port"),
        ({"listen": "127.0.0.1:022024"}, "port"),
        ({"host_key_fingerprint": "MD5:aa"}, "fingerprint"),
        ({"pinned_files": [{"path": EP_DIR, "sha256": QUALIFIED, "x": 1}]}, "exactly"),
    ],
)
def test_manifest_structure_refusals(endpoint_env, overrides, message):
    endpoint_env["data"] = encode(manifest(**overrides))
    endpoint_env["allow"]()
    with pytest.raises(ServiceError, match=message):
        _plan()


def test_manifest_size_and_json_refusals(endpoint_env):
    endpoint_env["data"] = b"{" + b" " * ep.MAX_MANIFEST_BYTES + b"}"
    endpoint_env["allow"]()
    with pytest.raises(ServiceError, match="64 KiB"):
        _plan()
    endpoint_env["data"] = b"\xff\xfe{}"
    endpoint_env["allow"]()
    with pytest.raises(ServiceError, match="UTF-8 JSON"):
        _plan()


def test_disk_digests_must_match_the_manifest(endpoint_env, monkeypatch):
    monkeypatch.setattr(win, "file_sha256", lambda p: "0" * 64 if p == GUARDIAN else QUALIFIED)
    with pytest.raises(ServiceError, match="guardian's sha256"):
        _plan()
    monkeypatch.setattr(win, "file_sha256", lambda p: "0" * 64 if p.endswith("sshd.exe") else QUALIFIED)
    with pytest.raises(ServiceError, match="pinned endpoint file"):
        _plan()


def test_endpoint_must_be_the_enrolled_local_sshd(endpoint_env):
    endpoint_env["fake"].show_out = SHOW_22024.replace("22024", "22023")
    with pytest.raises(ServiceError, match="enrolled local ssh is 127.0.0.1:22023"):
        _plan()
    endpoint_env["fake"].show_out = SHOW_22024
    endpoint_env["data"] = encode(manifest(host_key_fingerprint="SHA256:" + "A" * 43))
    endpoint_env["allow"]()
    with pytest.raises(ServiceError, match="not the enrolled pinned host key"):
        _plan()


def test_endpoint_tree_must_be_owned_by_the_user(endpoint_env):
    with pytest.raises(ServiceError, match="endpoint task runs as you"):
        _plan(api=FakeApi(owners={GUARDIAN: OTHER_SID}))


def test_held_endpoint_on_the_port_is_never_touched(endpoint_env):
    endpoint_env["port_busy"] = True
    with pytest.raises(ServiceError, match="already served by another process"):
        _plan()
    assert all(v[0] != "/Create" for v in _task_verbs(endpoint_env["fake"]))
    plan = _plan(start=False)  # --no-start: register disabled, nothing started
    assert "<Enabled>false</Enabled>" in plan.endpoint.xml


# --- task definition ---------------------------------------------------------------------


def test_endpoint_task_is_a_direct_same_user_launch(endpoint_env):
    plan = _plan()
    fields = win.parse_task_xml(plan.endpoint.xml)
    assert fields["command"] == GUARDIAN
    assert win.parse_arguments(fields["arguments"]) == manifest()["guardian"]["arguments"]
    assert fields["working_directory"] == EP_DIR
    assert fields["user_id"] == USER_SID and fields["logon_type"] == "S4U"
    assert fields["run_level"] == "LeastPrivilege" and fields["exec_count"] == 1
    assert "<Delay>PT10S</Delay>" in plan.endpoint.xml
    assert win.MANAGED_MARKER in fields["description"]
    assert "127.0.0.1:22024" in fields["description"]
    low = plan.endpoint.xml.lower()
    assert "cmd.exe" not in low and "powershell" not in low


# --- install order -------------------------------------------------------------------------


def test_install_registers_and_confirms_the_endpoint_before_the_link(endpoint_env):
    plan = _plan()
    win.apply_install(plan, api=FakeApi())
    verbs = [v for v in _task_verbs(endpoint_env["fake"]) if v[0] in ("/Create", "/Run")]
    assert verbs == [
        ("/Create", "GatewayEndpoint"), ("/Run", "GatewayEndpoint"),
        ("/Create", "GatewayLink"), ("/Run", "GatewayLink"),
    ]


def test_endpoint_without_banner_is_not_started_and_link_is_not_registered(endpoint_env):
    endpoint_env["banner"] = (False, "no SSH banner on 127.0.0.1:22024")
    plan = _plan()
    with pytest.raises(common.NotStartedError, match="GatewayEndpoint is registered but NOT started"):
        win.apply_install(plan, api=FakeApi())
    assert "GatewayEndpoint" in endpoint_env["fake"].tasks
    assert "GatewayLink" not in endpoint_env["fake"].tasks


def test_endpoint_bad_readback_is_rolled_back_before_run(endpoint_env):
    endpoint_env["fake"].mutate_on_create = lambda x: x.replace("S4U", "InteractiveToken")
    plan = _plan()
    with pytest.raises(ServiceError, match="does not match"):
        win.apply_install(plan, api=FakeApi())
    assert ("/Run", "GatewayEndpoint") not in _task_verbs(endpoint_env["fake"])
    assert endpoint_env["fake"].tasks == {}


def test_cli_dry_run_prints_both_tasks_and_writes_nothing(endpoint_env, monkeypatch):
    result = _windows_cli(
        monkeypatch, "install", "--helper", WIN_HELPER, "--config-dir", WIN_CONFIG,
        "--with-endpoint", MANIFEST_PATH, "--dry-run",
    )
    assert result.exit_code == 0, result.output
    assert result.stdout.count("<LogonType>S4U</LogonType>") == 2
    assert json.dumps([GUARDIAN, *manifest()["guardian"]["arguments"]]) in result.stdout
    assert endpoint_env["fake"].tasks == {}
    assert endpoint_env["fake"].xml_path is None


def test_cli_with_endpoint_is_refused_on_linux(monkeypatch):
    from click.testing import CliRunner

    from pocketshell.cli import cli

    monkeypatch.setattr("sys.platform", "linux")
    result = CliRunner().invoke(cli, ["gateway", "service", "install", "--with-endpoint", "/x.json"])
    assert result.exit_code == 1 and "Windows-only" in result.stderr


# --- status / uninstall ---------------------------------------------------------------------


def _installed(endpoint_env):
    win.apply_install(_plan(), api=FakeApi())
    return endpoint_env["fake"]


def test_status_running_needs_both_tasks_and_the_banner(endpoint_env):
    fake = _installed(endpoint_env)
    assert win.status(api=FakeApi()).exit_code == 0
    endpoint_env["banner"] = (False, "no SSH banner on 127.0.0.1:22024")
    st = win.status(api=FakeApi())
    assert st.running is False and st.exit_code == 3
    assert st.details["endpoint"]["banner_ok"] is False
    endpoint_env["banner"] = (True, "SSH-2.0-x")
    fake.tasks["GatewayEndpoint"]["state"] = "Ready"
    assert win.status(api=FakeApi()).exit_code == 3


def test_status_endpoint_only_is_installed_not_running(endpoint_env):
    fake = _installed(endpoint_env)
    del fake.tasks["GatewayLink"]
    st = win.status(api=FakeApi())
    assert st.installed and not st.running and st.exit_code == 3


def test_uninstall_removes_link_then_endpoint_only(endpoint_env):
    fake = _installed(endpoint_env)
    fake.calls.clear()
    message = win.uninstall(api=FakeApi())
    deletes = [v for v in _task_verbs(fake) if v[0] == "/Delete"]
    assert deletes == [("/Delete", "GatewayLink"), ("/Delete", "GatewayEndpoint")]
    assert "endpoint files untouched" in message
    assert fake.tasks == {}
    for argv in fake.calls:
        assert EP_DIR.lower() not in " ".join(argv).lower()
    assert "nothing to do" in win.uninstall(api=FakeApi())


def test_uninstall_refuses_a_foreign_endpoint_task(endpoint_env):
    fake = _installed(endpoint_env)
    fake.tasks["GatewayEndpoint"]["xml"] = fake.tasks["GatewayEndpoint"]["xml"].replace(
        win.MANAGED_MARKER, "hand made"
    )
    with pytest.raises(ServiceError, match="not written by"):
        win.uninstall(api=FakeApi())


# --- probes ----------------------------------------------------------------------------------


def test_probe_banner_reads_only_the_identification_line():
    import socket
    import threading

    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    def serve():
        conn, _ = server.accept()
        conn.sendall(b"SSH-2.0-Fake_1.0\r\n")
        conn.close()

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        ok, detail = ep.probe_banner("127.0.0.1", port)
    finally:
        thread.join(5)
        server.close()
    assert ok and detail == "SSH-2.0-Fake_1.0"
    assert ep.probe_banner("127.0.0.1", port)[0] is False
