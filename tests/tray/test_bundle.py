from pocketshell import tray_bundle as bundle
import pytest


def test_manual_stop_survives_restart(tmp_path, monkeypatch):
    monkeypatch.setattr(bundle, "home", lambda: tmp_path)
    assert bundle.enabled()
    bundle.set_enabled(False)
    assert not bundle.enabled()
    bundle.set_enabled(True)
    assert bundle.enabled()


def test_background_refuses_unenrolled_install(monkeypatch):
    monkeypatch.setattr(bundle, "own_binding", lambda: {"enrolled": False})
    with pytest.raises(RuntimeError, match="Enroll and bind"):
        bundle.run_background()


@pytest.mark.skipif(__import__("sys").platform != "win32", reason="native Windows ACL validation")
def test_enrollment_config_is_protected_and_unsafe_existing_folder_is_refused(tmp_path):
    from pocketshell.gateway import service_agent_install, service_windows
    path = tmp_path / "enrollment"
    bundle.prepare_enrollment_directory(path)
    api = service_windows.WindowsApi()
    service_agent_install.NativePaths(api).directory(str(path), api.current_sid(), root=str(path))
    unsafe = tmp_path / "existing"
    unsafe.mkdir()
    with pytest.raises(OSError):
        bundle.prepare_enrollment_directory(unsafe)
    assert unsafe.is_dir()


def test_login_handoff_does_not_wait_on_interactive_owner(tmp_path, monkeypatch):
    from pocketshell.gateway import service_user_agent
    monkeypatch.setattr(bundle, "home", lambda: tmp_path)
    monkeypatch.setattr(service_user_agent, "_guardian_launch", lambda: {"session": 1})
    bundle.handoff_background()
    assert (tmp_path / "background-exit").exists()


def test_remote_outage_does_not_restart_local_endpoint():
    assert not bundle.needs_recovery({"state": "degraded", "outbound": {"state": "running", "connected": False},
                                      "endpoint": {"guardianLaunch": {"running": True}}})


def test_dead_child_and_stopped_generation_recover():
    assert bundle.needs_recovery({"state": "stopped"})
    assert bundle.needs_recovery({"endpoint": {"guardianLaunch": {"running": False}}})
    assert bundle.needs_recovery({"outbound": {"state": "stopped"}})
    assert bundle.needs_recovery({"endpoint": {"state": "stopped", "guardianLaunch": None}})
    assert not bundle.needs_recovery({"state": "error", "outbound": {"state": "unknown"}})


def test_receipt_cannot_redirect_launcher_outside_managed_root(tmp_path, monkeypatch):
    monkeypatch.setattr(bundle, "home", lambda: tmp_path)
    with pytest.raises(RuntimeError, match="unexpected"):
        bundle.installed_root({"location": {"root": str(tmp_path / "elsewhere")}, "release": "tray-123"})
    with pytest.raises(RuntimeError, match="unexpected"):
        bundle.installed_root({"location": {"root": str(tmp_path / "managed-runtime")}, "release": "../../evil"})
    assert bundle.installed_root({"location": {"root": str(tmp_path / "managed-runtime")},
                                  "release": "tray-123"}) == tmp_path / "managed-runtime/releases/tray-123"


def test_restart_uses_bound_agent_and_remembers_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(bundle, "home", lambda: tmp_path)
    monkeypatch.setattr(bundle, "own_binding", lambda: {})
    actions = []
    def call(action, *args, **kwargs):
        actions.append(action)
    monkeypatch.setattr(bundle, "agent", call)
    def start():
        actions.append("start")
        raise RuntimeError("refused startup")
    monkeypatch.setattr(bundle, "start_gateway", start)
    assert bundle.control("restart") == (False, "refused startup")
    assert actions == ["stop", "start"]
    assert not bundle.enabled()
    monkeypatch.setattr(bundle, "agent", lambda action, *args, **kw: actions.append(action))
    monkeypatch.setattr(bundle, "start_gateway", lambda: actions.append("start"))
    assert bundle.control("start")[0]
    assert bundle.enabled()


def test_status_failure_returns_json_data_without_a_modal(monkeypatch):
    def fail():
        raise RuntimeError("agent busy")
    monkeypatch.setattr(bundle, "managed_status", fail)
    monkeypatch.setattr(bundle, "message", lambda *args, **kw: pytest.fail("polling must not open a dialog"))
    assert bundle.status_document()["state"] == "error"
    assert bundle.status_document()["errors"] == ["agent busy"]


def test_login_start_failure_is_visible_and_recovers_on_retry(tmp_path, monkeypatch):
    from pocketshell.tray.app import TrayApp
    from pocketshell.tray.model import TrayModel
    from pocketshell.tray.status_client import GatewayStatusClient
    monkeypatch.setattr(bundle, "home", lambda: tmp_path)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    monkeypatch.setattr(bundle, "observe_agent", lambda: {"state": "stopped"})
    monkeypatch.setattr(bundle, "agent", lambda *a, **kw: {})
    clock = [100.0]
    monkeypatch.setattr(bundle.time, "monotonic", lambda: clock[0])
    starts = []
    def start():
        starts.append(True)
        if len(starts) == 1:
            raise RuntimeError("authority-invalid: bundled file changed")
    monkeypatch.setattr(bundle, "start_gateway", start)
    monkeypatch.setattr(GatewayStatusClient, "fetch_status", lambda *a, **kw: TrayModel(state="online"))
    def run(app):
        client = app.status_client
        assert "Starting gateway" in client.fetch_status().summary
        failed = client.fetch_status()
        assert failed.state == "error" and "authority-invalid" in failed.summary
        assert "Gateway Setup" in failed.summary
        clock[0] += 5
        assert client.fetch_status().state == "error"
        assert len(starts) == 1
        clock[0] += 30
        assert client.fetch_status().state == "online"
        assert len(starts) == 2
    monkeypatch.setattr(TrayApp, "run", run)
    bundle.run_tray(tmp_path)


def test_tray_cannot_adopt_another_installations_binding(tmp_path, monkeypatch):
    monkeypatch.setattr(bundle, "home", lambda: tmp_path)
    with pytest.raises(RuntimeError, match="another installation"):
        bundle.check_own_binding({"authority": str(tmp_path / "some-other-runtime/authority.json")})
    bundle.check_own_binding({"authority": str(tmp_path / "managed-runtime/authority.json")})


def test_status_uses_this_gateways_enrollment_not_global_defaults(tmp_path, monkeypatch):
    import json
    from types import SimpleNamespace
    from pocketshell.gateway import status
    monkeypatch.setattr(bundle, "home", lambda: tmp_path)
    monkeypatch.setenv("SystemRoot", str(tmp_path / "Windows"))  # managed_status names the Windows PowerShell path
    root = tmp_path / "managed-runtime"
    root.mkdir()
    manifest = root / "manifest.json"
    manifest.write_text(json.dumps({"configBindings": {"setEnv": {
        "APLEXER_STATE_DIR": "C:/Users/test/AppData/Local/aplexer/state",
        "APLEXER_RUNTIME_DIR": "C:/Users/test/AppData/Local/aplexer/run"}}}))
    (root / "authority.json").write_text(json.dumps({"location": {"root": str(root)}, "release": "tray-test",
        "endpoint": {"state": str(root / "endpoint/state"), "manifest": str(manifest)}, "keys": {"authorizedKeys": str(root / "keys")}}))
    enrollment = str(root / "enrollment")
    monkeypatch.setattr(bundle, "observe_agent", lambda: {"binding": {"configDir": enrollment},
        "outbound": {"state": "running", "pid": 123}})
    monkeypatch.setattr(bundle.subprocess, "run", lambda *a, **kw: SimpleNamespace(stdout=b"", returncode=0))
    monkeypatch.setattr(status, "load_authorized_keys_comments", lambda *a: {})
    calls = []
    def collect(**kwargs):
        calls.append(kwargs["config_dir"])
        return {"device_id": "this-device", "agent": {"connected": False}, "sshd": {"reachable": False}}
    monkeypatch.setattr(status, "collect_gateway_status", collect)
    assert bundle.managed_status()["device_id"] == "this-device"
    assert calls == [enrollment]
