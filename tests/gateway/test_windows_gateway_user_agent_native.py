# ruff: noqa: F811
"""Native Windows: the ordinary-user agent with the fake guardian, for real.

Runs in the runner's own (interactive, if it has one) session: `gateway agent
bind/start/status/stop` spawn the fake guardian and the fake link hidden,
read the guardian's truthful READY context (session, WinSta0, desktop at
launch), prove the enrolled host key against the fake's real SSH daemon, and
stop through STOP.json + the exact link identity. No scheduled task, no
elevation step (the runner account happens to be an administrator; nothing
here requires it). Protocol-only: not a qualification of the real guardian.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.name != "nt"
    or os.environ.get("POCKETSHELL_WINDOWS_SERVICE_E2E") != "1"
    or not os.environ.get("POCKETSHELL_TEST_FAKE_LINK")
    or not os.environ.get("POCKETSHELL_TEST_FAKE_GUARDIAN"),
    reason="native agent round trip: CI windows-latest job only",
)

from pocketshell.gateway import service_windows as win  # noqa: E402

from test_windows_gateway_service_native import (  # noqa: E402,F401
    ENDPOINT_TASK, _build_endpoint, _free_port, _query_xml, layout, listening,
)


HARNESS = Path(__file__).parent / "agent_harness.py"


def _in_job(pid):
    import ctypes as c
    from ctypes import wintypes as w

    k = c.WinDLL("kernel32", use_last_error=True)
    k.OpenProcess.restype = w.HANDLE
    h = k.OpenProcess(0x1000, False, pid)
    assert h, f"cannot open {pid}"
    try:
        flag = w.BOOL()
        assert k.IsProcessInJob(w.HANDLE(h), None, c.byref(flag))
        return bool(flag.value)
    finally:
        k.CloseHandle(w.HANDLE(h))


def test_ordinary_user_agent_round_trip(layout, monkeypatch, tmp_path):
    """Run the CLI UNELEVATED (SAFER normal-user token; the runner itself is an
    elevated administrator) through the test-only seam harness."""
    import sys

    from pocketshell.gateway import service_endpoint as ep
    from unelevated import run_outside_job, run_unelevated

    api = win.WindowsApi()
    session = api.current_session()
    print("runner session:", session)
    if session == 0:
        pytest.skip("the runner process is in session 0 (no interactive session to host the active-console mode)")
    port = _free_port()
    endpoint = _build_endpoint(layout, monkeypatch, port=port, enrolled_port=port, name="agent")
    seams = tmp_path / "seams.json"
    seams.write_text(json.dumps({
        "helper": sorted(win.ALLOWED_HELPER_SHA256),
        "manifest": sorted(ep.ALLOWED_ENDPOINT_MANIFEST_SHA256),
        "sources": [list(t) for t in ep.ALLOWED_GUARDIAN_SOURCES],
    }))
    env = dict(os.environ, XDG_CONFIG_HOME=str(tmp_path / "agent-config"), PYTHONIOENCODING="utf-8")

    where = {"mode": "in-runner-job"}

    def agent(*args):
        argv = [sys.executable, str(HARNESS), str(seams), "gateway", "agent", *args, "--json"]
        if where["mode"] == "outside-job":
            code, out, meta = run_outside_job(argv, env=env, cwd=str(tmp_path))
            assert meta is not None and "code" in meta, f"outside-job harness failed: {meta}"
            # the harness server may itself sit in seclogon's job; the CLI
            # measures and decides for its own children (target-job if not free)
            print("outside-job server parent:", meta.get("parent"), "serverInJob:", meta.get("serverInJob"))
            print("outside-job token selection:", meta.get("token"))
        else:
            code, out = run_unelevated(argv, env=env, cwd=str(tmp_path))
            from unelevated import DIAGNOSTICS

            print("token selection:", DIAGNOSTICS)
        text = out.decode("utf-8", "replace")
        print(f"$ ({where['mode']}, unelevated) pocketshell gateway agent {' '.join(args)} --json -> exit {code}")
        print(text)
        start = text.find("{")
        return code, (json.loads(text[start:]) if start >= 0 else None)

    code, data = agent("bind", "--manifest", endpoint["manifest"], "--config-dir", layout["config"],
                       "--helper", layout["helper"])
    assert code == 0, data
    code, data = agent("status")
    assert code == 4 and data["state"] == "stopped"

    accepted_job = False
    code, data = agent("start", "--timeout", "60")
    if code == 1 and data and data["error"]["code"] == "target-job":
        # measured, honest refusal inside the runner's step job (KILL_ON_JOB_CLOSE,
        # breakaway forbidden): the CLI must not claim independence ...
        assert "KILL_ON_JOB_CLOSE" in data["error"]["message"]
        print("MEASURED: the runner step job forbids breakaway and has KILL_ON_JOB_CLOSE; start refused")
        # ... then run it the way the Desktop app does: outside any foreign job
        where["mode"] = "outside-job"
        code, data = agent("status")
        assert code == 4, data
        code, data = agent("start", "--timeout", "60")
        if code == 1 and data and data["error"]["code"] == "target-job":
            # no job-free launch path exists on this runner (measured twice).
            # Exercise READY/STOP with the TEST-ONLY seam that accepts the job
            # while reporting it (product default refuses).
            print("MEASURED: the seclogon path is jobbed too; continuing with the test-only acceptJob seam")
            where["mode"] = "in-runner-job"
            seams.write_text(json.dumps({**json.loads(seams.read_text()), "acceptJob": True}))
            code, data = agent("start", "--timeout", "60")
            accepted_job = True
    if code != 0:
        for p in sorted(Path(endpoint["state"]).rglob("*.json")):
            print(p, p.read_text(encoding="utf-8", errors="replace")[:1500])
    assert code == 0, data
    e = data["endpoint"]
    assert data["state"] == "ready" and data["mode"] == "active-console"
    assert e["context"]["station"] == "WinSta0" and e["context"]["session"] == session
    assert e["hostKey"]["proven"] is True and data["outbound"]["state"] == "running"
    # root item 2: the reported job membership is the MEASURED one
    assert e["launch"]["elevated"] is False and data["outbound"]["launch"]["elevated"] is False
    assert e["launch"]["inJob"] == _in_job(e["guardian"]["pid"])
    assert data["outbound"]["launch"]["inJob"] == _in_job(data["outbound"]["pid"])
    if accepted_job:
        assert e["launch"]["inJob"] is True and e["launch"]["brokeAway"] is False  # reported, never claimed
    else:
        assert e["launch"]["inJob"] is False
    print("launch metadata:", e["launch"], data["outbound"]["launch"])
    assert _query_xml() is None and _query_xml(ENDPOINT_TASK) is None

    code, again = agent("start")
    assert code == 0 and again["endpoint"]["daemon"] == e["daemon"]

    code, data = agent("stop", "--timeout", "45")
    assert code == 0, data
    assert data["state"] == "stopped" and not listening(port)
    assert api.process_birth(again["outbound"]["pid"]) != again["outbound"]["creationFILETIME"]
    code, data = agent("status")
    assert code == 4


def test_elevated_caller_children_are_refused(layout, tmp_path):
    """The runner process is elevated: spawn_hidden refuses its elevated child."""
    import ctypes as c

    from pocketshell.gateway.service_common import ServiceError

    if not c.windll.shell32.IsUserAnAdmin():
        pytest.skip("runner not elevated")
    api = win.WindowsApi()
    with pytest.raises(ServiceError, match="ordinary, same-session token"):  # checked before the job
        api.spawn_hidden([os.environ["POCKETSHELL_TEST_FAKE_LINK"], "version", "--json"], str(tmp_path), None)


def _kernel_image_of_self():
    """The OS's own record of this process's image (GetModuleFileNameW(NULL)),
    independent of sys.executable (a venv launcher re-executes the base)."""
    import ctypes as c

    buf = c.create_unicode_buffer(32768)
    n = c.windll.kernel32.GetModuleFileNameW(None, buf, 32768)
    assert n > 0
    return buf.value


def test_process_identity_is_tri_state():
    """absent only when proven; images are grounded in what the OS reports."""
    import subprocess

    api = win.WindowsApi()
    me = api.process_identity(os.getpid())
    assert me["state"] == "present" and win._same_path(me["image"], _kernel_image_of_self())
    assert me["birth"] == api.process_birth(os.getpid())
    # a process spawned from a KNOWN absolute image
    ping = os.path.join(os.environ["SystemRoot"], "System32", "PING.EXE")
    child = subprocess.Popen([ping, "-n", "30", "127.0.0.1"], stdout=subprocess.DEVNULL,
                             creationflags=0x08000000)
    try:
        ident = api.process_identity(child.pid)
        assert ident["state"] == "present" and win._same_path(ident["image"], ping), ident
    finally:
        child.kill()
        child.wait()  # Popen still holds the handle: an exited, unreaped process object
    assert api.process_identity(child.pid)["state"] == "absent"
    # the System process (pid 4) exists but its image is not ours to read
    assert api.process_identity(4)["state"] in ("present", "unknown")


def test_held_image_refuses_writers_renames_and_a_wrong_digest(tmp_path):
    """v3.1: the image is held (FILE_SHARE_READ only) from hashing through spawn."""
    import ctypes as c
    import hashlib
    import shutil

    from pocketshell.gateway.service_common import ServiceError

    api = win.WindowsApi()
    image = tmp_path / "held.exe"
    shutil.copyfile(os.path.join(os.environ["SystemRoot"], "System32", "PING.EXE"), image)
    digest = hashlib.sha256(image.read_bytes()).hexdigest()
    with pytest.raises(ServiceError, match="does not match its pinned sha256"):
        api.spawn_hidden([str(image), "-n", "1", "127.0.0.1"], str(tmp_path), None, image_sha256="0" * 64)
    handle, _identity = api._hold_image(str(image), digest)
    try:
        with pytest.raises(PermissionError):
            open(image, "r+b")
        with pytest.raises(PermissionError):
            os.replace(image, tmp_path / "moved.exe")
        with pytest.raises(PermissionError):
            os.unlink(image)
    finally:
        c.WinDLL("kernel32").CloseHandle(c.c_void_p(handle))
    os.replace(image, tmp_path / "moved.exe")  # released: allowed again


def test_r3_refused_cleanup_keeps_the_suspended_child_identity(tmp_path, monkeypatch):
    """dd792b5 R3: the elevated runner's child is refused (token); if its
    termination is refused too, the exact live identity is returned as recovery
    custody and its handles are not released silently."""
    import ctypes as c

    from pocketshell.gateway.service_common import ServiceError

    if not c.windll.shell32.IsUserAnAdmin():
        pytest.skip("runner not elevated")
    api = win.WindowsApi()
    monkeypatch.setattr(win.WindowsApi, "_terminate_suspended", lambda self, k, handle: False, raising=False)
    image = os.path.join(os.environ["SystemRoot"], "System32", "PING.EXE")
    with pytest.raises(ServiceError) as info:
        api.spawn_hidden([image, "-n", "1", "127.0.0.1"], str(tmp_path), None)
    err = info.value
    assert isinstance(err, win.SpawnCleanupError), err
    rec = err.recovery
    print("recovery custody:", rec)
    assert api.process_birth(rec["pid"]) == rec["creationFILETIME"]  # still alive (suspended)
    assert win._same_path(rec["image"], image)
    assert api.terminate_exact(rec["pid"], rec["creationFILETIME"], image)  # test cleanup, exact identity
