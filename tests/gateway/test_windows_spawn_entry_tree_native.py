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


def run_spawn(probe_release, args, timeout_s, *, expect=None):
    """C-Fleet-native-entry-v1: every content request natively pinned, then ONE
    correlated authorize. `expect` maps files to their EXPECTED digests (the
    consumer's pinned catalog); default: the files as they are now."""
    import hashlib

    root = probe_release["root"]
    files = files_of(root)
    expect = expect or {str(f): hashlib.sha256(f.read_bytes()).hexdigest() for f in files}
    inv = hashlib.sha256("\n".join(sorted(f.relative_to(root).as_posix().lower() for f in files)).encode()).hexdigest()
    reqs = ["--request", f"inventory:{inv}={root}"]
    reqs += [x for f in files for x in ("--request", f"binary:{expect[str(f)]}={f}")]
    argv = [VERIFY, "verify", "--operation-id", "op-t", "--owner-sid", sid(), "--resources-root",
            str(probe_release["base"]), *reqs, "--hold", "--entry", probe_release["entry"], "--spawn-entry",
            *[x for a in args for x in ("--entry-arg", a)], "--entry-timeout", str(timeout_s)]
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env_for(probe_release["temp"]),
                            creationflags=0x08000000)
    first = json.loads(proc.stdout.readline())
    lines = [first]
    if first["ok"]:
        proc.stdin.write(b'{"version":2,"operationId":"op-t","op":"authorize"}\n')
        proc.stdin.flush()
        lines += [json.loads(x) for x in proc.stdout]
    code = proc.wait(timeout=120)
    proc.stdin.close()
    print(code, [line.get("event") for line in lines[1:]])
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
