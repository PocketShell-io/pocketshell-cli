from pocketshell import tray_bundle as bundle


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
