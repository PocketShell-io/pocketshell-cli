import hashlib
import os
from pathlib import Path
import sys
import time

import pytest

from pocketshell.gateway.service_windows import TargetJobError, WindowsApi


@pytest.mark.parametrize("session,mode", [(0, "s4u-session0"), (1, "interactive-session"), (2, "interactive-session")])
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


def test_interactive_guardian_is_a_pinned_successor_with_own_session_policy():
    import runpy
    from pocketshell.gateway import service_endpoint as ep
    source = Path(__file__).parents[2] / 'release/inputs/guardian-interactive'
    triple = tuple(hashlib.sha256((source / name).read_bytes()).hexdigest() for name in ep.SOURCE_NAMES)
    assert triple in ep.ALLOWED_GUARDIAN_SOURCES
    assert triple[0] == ep.INTERACTIVE_GUARDIAN_SHA256
    assert triple[2] == ep.INTERACTIVE_POLICY_SHA256
    validate = runpy.run_path(str(source / 'policy.py'))['validate_context']
    owner = 'S-1-5-21-1-2-3-1001'
    context = {'ownerSID': owner, 'session': 2, 'activeConsoleSession': 1,
               'station': 'WinSta0', 'stationVisible': True, 'desktop': 'Default'}
    assert validate(context, owner) == context
    for change in ({'ownerSID': 'S-1-5-21-1-2-3-999'}, {'session': -1},
                   {'session': True}, {'station': 'foreign'}, {'stationVisible': False},
                   {'desktop': 'Winlogon'}):
        with pytest.raises(ValueError):
            validate({**context, **change}, owner)
    assert validate({**context, 'session': 0, 'station': 'Service-0x0-1$', 'stationVisible': False}, owner)
