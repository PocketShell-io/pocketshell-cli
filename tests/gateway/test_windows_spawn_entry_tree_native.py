"""--spawn-entry against the REAL closure shape (Go entry -> bundled Python):
the whole command tree is owned and nothing runs before native acceptance.
(Review of d056604: NB2, BI1.)"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="native Windows verifier")

OUT = os.environ.get("POCKETSHELL_TEST_RELEASE_OUT", "")
VERIFY = os.environ.get("POCKETSHELL_TEST_VERIFY_EXE", "")

PROBE = r'''
import os, subprocess, sys, time
tag = sys.argv[1] if len(sys.argv) > 1 else "x"
marker = os.path.join(os.environ["TEMP"], "probe-%s.txt" % tag)
with open(marker, "w") as f:
    f.write(str(os.getpid()))
if len(sys.argv) > 3 and sys.argv[3] == "persist":
    # like the CLI's guardian/link: a PERSISTENT child created with breakaway
    host = os.path.join(os.environ["TEMP"], "probe-%s-host.txt" % tag)
    try:
        child = subprocess.Popen([sys.executable, "-I", "-S", "-c", "import time; time.sleep(45)"],
                                 creationflags=0x01000000 | 0x08000000)
        with open(host, "w") as f:
            f.write(str(child.pid))
    except OSError as exc:
        with open(host, "w") as f:
            f.write("refused %s" % exc.winerror)
time.sleep(float(sys.argv[2]) if len(sys.argv) > 2 else 0)
print("probe done")
'''


@pytest.fixture
def probe_release(tmp_path):
    if not (OUT and VERIFY and os.path.isdir(OUT)):
        pytest.skip("release closure / verifier not built")
    src = Path(OUT) / "root-a" / "releases" / "staged"
    base = tmp_path / "res"
    root = base / "probe-release"
    shutil.copytree(src, root)
    pkg = root / "probe" / "pocketshell"
    pkg.mkdir(parents=True)
    (pkg / "__init__.py").write_text("")
    (pkg / "__main__.py").write_text(PROBE)
    (root / "python" / "python312._pth").write_text("..\\probe\npython312.zip\nDLLs\n")
    temp = tmp_path / "temp"
    temp.mkdir()
    return {"base": base, "root": root, "temp": temp, "entry": str(root / "pocketshell.exe")}


def env_for(temp):
    keep = ("SystemDrive", "SystemRoot", "ProgramData", "USERPROFILE", "LOCALAPPDATA")
    return {**{k: os.environ[k] for k in keep}, "TEMP": str(temp), "TMP": str(temp)}


def sid():
    from pocketshell.gateway import service_windows as win

    return win.WindowsApi().current_sid()


def files_of(root):
    return sorted(p for p in root.rglob("*") if p.is_file())


def run_spawn(probe_release, args, timeout_s, *, expect=None, entry=None):
    """C-Fleet-native-entry-v1: the ordered requests (every content request
    natively pinned) arrive as the FIRST stdin line (--requests-stdin: no
    command-line limit), then ONE correlated authorize."""
    import hashlib

    root = probe_release["root"]
    files = files_of(root)
    expect = expect or {str(f): hashlib.sha256(f.read_bytes()).hexdigest() for f in files}
    inv = hashlib.sha256("\n".join(sorted(f.relative_to(root).as_posix().lower() for f in files)).encode()).hexdigest()
    requests = [{"kind": "inventory", "path": str(root), "expect": inv}]
    requests += [{"kind": "binary", "path": str(f), "expect": expect[str(f)]} for f in files]
    argv = [VERIFY, "verify", "--operation-id", "op-t", "--owner-sid", sid(), "--resources-root",
            str(probe_release["base"]), "--requests-stdin", "--hold", "--entry", entry or probe_release["entry"],
            "--spawn-entry", *[x for a in args for x in ("--entry-arg", a)], "--entry-timeout", str(timeout_s)]
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env_for(probe_release["temp"]),
                            creationflags=0x08000000)
    proc.stdin.write(json.dumps({"version": 2, "operationId": "op-t", "requests": requests}).encode() + b"\n")
    proc.stdin.flush()
    first = json.loads(proc.stdout.readline())
    lines = [first]
    if first["ok"]:
        proc.stdin.write(b'{"version":2,"operationId":"op-t","op":"authorize"}\n')
        proc.stdin.flush()
        lines += [json.loads(x) for x in proc.stdout]
    code = proc.wait(timeout=120)
    proc.stdin.close()
    print(code, [line.get("event") for line in lines[1:]], json.dumps(lines[1:])[:800])
    return code, lines


def test_nb2_timeout_ends_the_whole_tree_including_python(probe_release):
    from pocketshell.gateway import service_windows as win

    code, lines = run_spawn(probe_release, ["nb2", "120"], timeout_s=8)
    assert lines[-1]["event"] == "timeout", lines
    marker = probe_release["temp"] / "probe-nb2.txt"
    assert marker.exists(), "the bundled Python never started"
    pid = int(marker.read_text())
    time.sleep(1)
    assert win.WindowsApi().process_identity(pid)["state"] == "absent", f"the bundled Python {pid} survived"


def test_bi1_altered_app_zip_never_runs(probe_release):
    """A hash-altered module (here: the probe marker package added to app.zip's
    place) must NOT execute before native expected-digest acceptance."""
    import hashlib

    root = probe_release["root"]
    pinned = {str(f): hashlib.sha256(f.read_bytes()).hexdigest() for f in files_of(root)}  # the reviewed closure
    altered = root / "python" / "app.zip"
    with open(altered, "ab") as f:
        f.write(b"tampered")  # ACL-valid, hash-altered after the pins were taken
    code, lines = run_spawn(probe_release, ["bi1", "0"], timeout_s=30, expect=pinned)
    assert code == 1 and not lines[0]["ok"] and len(lines) == 1, lines
    assert not (probe_release["temp"] / "probe-bi1.txt").exists(), "a tampered closure executed"


def test_nb4_real_entry_output_is_complete(probe_release):
    """Go entry -> Python: the result exists only after both pipes reached EOF."""
    import base64

    code, lines = run_spawn(probe_release, ["nb4", "0"], timeout_s=60)
    events = [line.get("event") for line in lines[1:]]
    assert code == 0 and events == ["launched", "exited", "released"], lines
    out = base64.b64decode(lines[2]["stdoutBase64"]).decode()
    assert "probe done" in out and lines[2]["exitCode"] == 0


# --- NB2 clarification: transient command tree vs persistent host ----------------------


def test_status_like_command_leaves_no_process_behind(probe_release):
    from pocketshell.gateway import service_windows as win

    code, lines = run_spawn(probe_release, ["status", "0"], timeout_s=60)
    assert code == 0 and lines[-1]["event"] == "released"
    pid = int((probe_release["temp"] / "probe-status.txt").read_text())
    assert win.WindowsApi().process_identity(pid)["state"] == "absent"


def test_start_like_command_leaves_the_persistent_host_running(probe_release):
    """The persistent child is created with breakaway and must SURVIVE the
    transient tree's cleanup, outside any job. On a runner whose own job
    forbids breakaway this is measured and reported (the CLI then refuses
    with target-job); it is never solved by killing the host."""
    import ctypes as c
    from ctypes import wintypes as w

    from pocketshell.gateway import service_windows as win

    code, lines = run_spawn(probe_release, ["start", "0", "persist"], timeout_s=60)
    assert code == 0 and lines[-1]["event"] == "released"
    host = (probe_release["temp"] / "probe-start-host.txt").read_text()
    if host.startswith("refused"):
        pytest.skip(f"MEASURED: breakaway refused by an ancestor job on this runner ({host})")
    pid = int(host)
    api = win.WindowsApi()
    try:
        assert api.process_identity(pid)["state"] == "present", "the persistent host was killed"
        k = c.WinDLL("kernel32", use_last_error=True)
        k.OpenProcess.restype = w.HANDLE
        h = k.OpenProcess(0x1000, False, pid)
        flag = w.BOOL()
        assert k.IsProcessInJob(w.HANDLE(h), None, c.byref(flag)) and not flag.value
        k.CloseHandle(w.HANDLE(h))
    finally:
        subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True)


# --- NE1 native: a child that cannot be created is a positive absence ----------------


def test_ne1_not_started_when_no_child_can_be_created(probe_release):
    bogus = probe_release["root"] / "bogus.exe"
    bogus.write_bytes(b"not a PE image")
    code, lines = run_spawn(probe_release, [], timeout_s=30, entry=str(bogus))
    last = lines[-1]
    assert code == 1 and last["event"] == "not-started" and last["childCreated"] is False, lines
    assert "pid" not in last and last["operationId"] == "op-t"
