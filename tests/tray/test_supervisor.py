import hashlib
import os
from pathlib import Path
import sys
import time

import pytest

from pocketshell.gateway.service_windows import TargetJobError, WindowsApi


@pytest.mark.parametrize("session,mode", [(0, "s4u-session0"), (1, "active-console")])
def test_background_selects_only_the_measured_guardian_context(monkeypatch, session, mode):
    from pocketshell import tray_supervisor
    from pocketshell.gateway import service_user_agent
    from types import SimpleNamespace
    monkeypatch.setattr(tray_supervisor, "api", lambda: SimpleNamespace(current_session=lambda: session))
    monkeypatch.setattr(service_user_agent, "MODE", "active-console")
    tray_supervisor.configure_background()
    assert service_user_agent.MODE == mode


def test_normal_cli_still_refuses_inherited_jobs():
    with pytest.raises(TargetJobError):
        WindowsApi()._job_policy(None, caller_in_job=True, broke_away=False,
                                child_in_job=True, nearest_kill=True)


@pytest.mark.parametrize("session,desktop", [(0, None), (1, "WinSta0\\Default")])
def test_spawn_desktop_preserves_the_callers_session_context(monkeypatch, session, desktop):
    api = WindowsApi()
    monkeypatch.setattr(api, "current_session", lambda: session)
    assert api._spawn_desktop() == desktop


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows job ownership")
def test_tray_owns_and_reaps_a_verified_worker(tmp_path):
    from pocketshell.tray_supervisor import TrayWindowsApi
    exe = Path(sys._base_executable).resolve()
    digest = hashlib.sha256(exe.read_bytes()).hexdigest()
    api = TrayWindowsApi()
    try:
        meta = api.spawn_hidden([str(exe), "-I", "-B", "-c", "import time; time.sleep(60)"],
                                str(tmp_path), None, image_sha256=digest)
        assert meta["inJob"] is True
        assert meta["supervision"]["pid"] == os.getpid()
        assert meta["supervision"]["killOnClose"] is True
        assert api.process_identity(meta["pid"])["state"] == "present"
        api.close()
        for _ in range(50):
            if api.process_identity(meta["pid"])["state"] == "absent":
                break
            time.sleep(0.1)
        assert api.process_identity(meta["pid"])["state"] == "absent"
    finally:
        api.close()


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows image hold")
def test_owned_mode_keeps_the_image_digest_gate(tmp_path):
    from pocketshell.tray_supervisor import TrayWindowsApi
    from pocketshell.gateway.service_common import ServiceError
    api = TrayWindowsApi()
    try:
        with pytest.raises(ServiceError, match="pinned sha256"):
            api.spawn_hidden([str(Path(sys._base_executable).resolve()), "-c", "raise SystemExit(0)"],
                             str(tmp_path), None, image_sha256="0" * 64)
    finally:
        api.close()
