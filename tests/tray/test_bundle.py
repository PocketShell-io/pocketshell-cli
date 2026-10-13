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
    actions = []
    def call(action, *args, **kwargs):
        actions.append(action)
        if action == "start":
            raise RuntimeError("refused startup")
    monkeypatch.setattr(bundle, "agent", call)
    assert bundle.control("restart") == (False, "refused startup")
    assert actions == ["stop", "start"]
    assert not bundle.enabled()
    monkeypatch.setattr(bundle, "agent", lambda action, *args, **kw: actions.append(action))
    assert bundle.control("start")[0]
    assert bundle.enabled()


def test_status_failure_returns_json_data_without_a_modal(monkeypatch):
    def fail():
        raise RuntimeError("agent busy")
    monkeypatch.setattr(bundle, "managed_status", fail)
    monkeypatch.setattr(bundle, "message", lambda *args, **kw: pytest.fail("polling must not open a dialog"))
    assert bundle.status_document()["state"] == "error"
    assert bundle.status_document()["errors"] == ["agent busy"]
