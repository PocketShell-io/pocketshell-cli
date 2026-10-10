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
import os, sys, time
marker = os.path.join(os.environ["TEMP"], "probe-%s.txt" % (sys.argv[1] if len(sys.argv) > 1 else "x"))
with open(marker, "w") as f:
    f.write(str(os.getpid()))
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


def run_old(probe_release, args, timeout_s):
    """The d056604 (pre-fix) argv shape: no digests, no authorize."""
    root = probe_release["root"]
    reqs = [x for f in files_of(root) for x in ("--request", f"binary={f}")]
    argv = [VERIFY, "verify", "--operation-id", "op-t", "--owner-sid", sid(), "--resources-root",
            str(probe_release["base"]), *reqs, "--hold", "--entry", probe_release["entry"], "--spawn-entry",
            *[x for a in args for x in ("--entry-arg", a)], "--entry-timeout", str(timeout_s)]
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env_for(probe_release["temp"]),
                            creationflags=0x08000000)
    lines = [json.loads(x) for x in proc.stdout]
    code = proc.wait(timeout=120)
    proc.stdin.close()
    print(code, [line.get("event") for line in lines[1:]])
    return code, lines


def test_nb2_timeout_ends_the_whole_tree_including_python(probe_release):
    from pocketshell.gateway import service_windows as win

    code, lines = run_old(probe_release, ["nb2", "120"], timeout_s=8)
    assert lines[-1]["event"] == "timeout", lines
    marker = probe_release["temp"] / "probe-nb2.txt"
    assert marker.exists(), "the bundled Python never started"
    pid = int(marker.read_text())
    time.sleep(1)
    assert win.WindowsApi().process_identity(pid)["state"] == "absent", f"the bundled Python {pid} survived"


def test_bi1_altered_app_zip_never_runs(probe_release):
    """A hash-altered module (here: the probe marker package added to app.zip's
    place) must NOT execute before native expected-digest acceptance."""
    altered = probe_release["root"] / "python" / "app.zip"
    with open(altered, "ab") as f:
        f.write(b"tampered")  # ACL-valid, hash-altered
    run_old(probe_release, ["bi1", "0"], timeout_s=30)
    assert not (probe_release["temp"] / "probe-bi1.txt").exists(), "a tampered closure executed"
