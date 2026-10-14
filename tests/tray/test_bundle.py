from pocketshell import tray_bundle as bundle
import pytest


def test_manual_stop_survives_restart(tmp_path, monkeypatch):
    monkeypatch.setattr(bundle, "home", lambda: tmp_path)
    assert bundle.enabled()
    bundle.set_enabled(False)
    assert not bundle.enabled()
    bundle.set_enabled(True)
    assert bundle.enabled()


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
    (root / "authority.json").write_text(json.dumps({"location": {"root": str(root)}, "release": "tray-test",
        "endpoint": {"state": str(root / "endpoint/state")}, "keys": {"authorizedKeys": str(root / "keys")}}))
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
