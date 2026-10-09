"""pocketshell-verify.exe (agreement v3.1 §11.3/§11.4) on a real Windows host:
protocol-v2 parity with the reference oracle, refusals, and the --hold
handshake (held closure refuses writers/renames/deletes while an ORDINARY
spawn of the held entry still works; spawned-image identity; release,
timeout and controller-gone semantics). Disposable CI runner only."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="native Windows verifier")

VERIFY = os.environ.get("POCKETSHELL_TEST_VERIFY_EXE", "")


@pytest.fixture
def tree(tmp_path):
    if not VERIFY or not os.path.isfile(VERIFY):
        pytest.skip("POCKETSHELL_TEST_VERIFY_EXE not built")
    from pocketshell import windows_security as ws
    from pocketshell.gateway import service_windows as win

    root = tmp_path / "Roaming" / "PocketShell" / "managed-runtime"
    release = root / "releases" / "r1"
    ping = Path(os.environ["SystemRoot"]) / "System32" / "PING.EXE"
    ws.write_private(release / "pocketshell.exe", ping.read_bytes())
    ws.write_private(release / "python" / "mod.py", b"print('x')\n")
    ws.write_private(root / "authority.json", b'{"version": 2}')
    resources = tmp_path / "Programs" / "resources"
    resources.mkdir(parents=True)
    (resources / "host-runtime-catalog.json").write_bytes(b'{"version": 2}')
    sid = win.WindowsApi().current_sid()
    return {"root": str(root), "release": str(release), "entry": str(release / "pocketshell.exe"),
            "authority": str(root / "authority.json"), "resources": str(resources),
            "catalog": str(resources / "host-runtime-catalog.json"), "sid": sid}


def argv(t, requests, *, extra=(), sid=None, op="op-1"):
    out = [VERIFY, "verify", "--operation-id", op, "--owner-sid", sid or t["sid"],
           "--private-root", t["root"], "--resources-root", t["resources"]]
    for kind, path in requests:
        out += ["--request", f"{kind}={path}"]
    return out + list(extra)


def verify(t, requests, **kw):
    p = subprocess.run(argv(t, requests, **kw), capture_output=True, timeout=60, creationflags=0x08000000)
    return p.returncode, json.loads(p.stdout.decode("utf-8").splitlines()[0])


def oracle(t, requests):
    from pocketshell.gateway import service_agent_install as inst
    from pocketshell.gateway import service_windows as win

    api = win.WindowsApi()
    return inst.verify_paths(owner_sid=t["sid"], operation_id="op-1", private_roots=[t["root"]],
                             resources_roots=[t["resources"]], requests=requests, paths=inst.NativePaths(api),
                             current_sid=t["sid"])


def test_parity_with_the_reference_oracle(tree):
    reqs = [("document", tree["authority"]), ("binary", tree["entry"]), ("directory", tree["root"]),
            ("inventory", tree["release"]), ("document", tree["catalog"])]
    code, reply = verify(tree, reqs)
    print(json.dumps(reply, indent=1)[:3000])
    assert code == 0 and reply["ok"], reply
    oreply, ocode = oracle(tree, reqs)
    assert ocode == 0
    for got, want in zip(reply["results"], oreply["results"]):
        want = dict(want)
        if want["files"] is not None:
            want["files"] = sorted(want["files"])
            got = dict(got, files=sorted(got["files"]))
        assert got == want, (got, want)
    assert sorted(reply) == ["ok", "operationId", "ownerSid", "results", "version"]


def test_refusals(tree):
    code, reply = verify(tree, [("document", os.path.join(os.environ["SystemRoot"], "win.ini"))])
    assert code == 1 and "exactly one declared root" in reply["results"][0]["problem"]
    code, reply = verify(tree, [("document", tree["entry"])])
    assert code == 1 and ".json" in reply["results"][0]["problem"]
    code, reply = verify(tree, [("document", tree["authority"])], sid="S-1-5-21-1-2-3-4")
    assert code == 1 and reply["results"] == []
    code, reply = verify(tree, [("document", tree["authority"])] * 2)
    assert code == 2
    subprocess.run(["icacls", tree["authority"], "/grant", "*S-1-1-0:R"], check=True, capture_output=True)
    code, reply = verify(tree, [("document", tree["authority"])])
    assert code == 1 and "outside your account" in reply["results"][0]["problem"], reply
    junction = os.path.join(tree["release"], "python", "evil")
    subprocess.run(["cmd", "/c", "mklink", "/J", junction, os.environ["SystemRoot"]], check=True,
                   capture_output=True)
    code, reply = verify(tree, [("inventory", tree["release"])])
    assert code == 1 and "reparse" in reply["results"][0]["problem"], reply


def _hold(tree, timeout="60"):
    reqs = [("binary", tree["entry"]), ("inventory", tree["release"]), ("document", tree["authority"])]
    proc = subprocess.Popen(argv(tree, reqs, extra=["--hold", "--entry", tree["entry"], "--hold-timeout", timeout]),
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, creationflags=0x08000000)
    first = json.loads(proc.stdout.readline())
    assert first["ok"] and first["operationId"] == "op-1", first
    return proc


def _send(proc, msg):
    proc.stdin.write((json.dumps(msg) + "\n").encode())
    proc.stdin.flush()
    return json.loads(proc.stdout.readline())


def test_hold_spawned_identity_and_release(tree):
    proc = _hold(tree)
    try:
        entry = tree["entry"]
        with pytest.raises(PermissionError):
            open(entry, "r+b")
        with pytest.raises(PermissionError):
            os.replace(entry, entry + ".moved")
        with pytest.raises(PermissionError):
            os.unlink(tree["authority"])
        with pytest.raises(PermissionError):
            os.replace(tree["release"], tree["release"] + "-moved")
        # an ORDINARY spawn (as Node child_process.spawn does) of the held entry works
        child = subprocess.Popen([entry, "-n", "5", "127.0.0.1"], stdout=subprocess.DEVNULL,
                                 creationflags=0x08000000)
        try:
            ev = _send(proc, {"op": "spawned", "operationId": "op-1", "pid": child.pid})
            assert ev["event"] == "spawned" and ev["imageMatches"] is True and ev["problem"] is None, ev
        finally:
            child.kill()
            child.wait()
        other = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(5)"], creationflags=0x08000000)
        try:
            ev = _send(proc, {"op": "spawned", "operationId": "op-1", "pid": other.pid})
            assert ev["imageMatches"] is False and ev["problem"], ev
        finally:
            other.kill()
            other.wait()
        ev = _send(proc, {"op": "release", "operationId": "op-1"})
        assert ev["event"] == "released"
        assert proc.wait(timeout=10) == 0
    finally:
        if proc.poll() is None:
            proc.kill()
    with open(tree["entry"], "r+b"):
        pass  # released: writable again


def test_hold_timeout_and_controller_gone(tree):
    proc = _hold(tree, timeout="1")
    ev = json.loads(proc.stdout.readline())
    assert ev["event"] == "timeout" and proc.wait(timeout=10) == 5
    proc = _hold(tree)
    proc.stdin.close()
    ev = json.loads(proc.stdout.readline())
    assert ev["event"] == "closed" and proc.wait(timeout=10) == 4
    proc = _hold(tree)
    ev = _send(proc, {"op": "release", "operationId": "someone-else"})
    assert ev["event"] == "refused" and proc.wait(timeout=10) == 2


def test_hold_is_refused_when_verification_fails(tree):
    reqs = [("binary", tree["entry"]), ("document", os.path.join(os.environ["SystemRoot"], "win.ini"))]
    p = subprocess.run(argv(tree, reqs, extra=["--hold", "--entry", tree["entry"]]), capture_output=True, timeout=60,
                       creationflags=0x08000000)
    assert p.returncode == 1 and len(p.stdout.decode().splitlines()) == 1  # no hold: exit, nothing held


# --- review 1501b0fe N2: every directory at/below a private root is owner-only ----------


@pytest.mark.parametrize("which", ["root", "intermediate"])
def test_n2_unprotected_private_root_or_intermediate_is_refused(tree, which):
    target = tree["root"] if which == "root" else os.path.join(tree["root"], "releases")
    # re-enable inheritance: the DACL is no longer protected (owner-only shape broken)
    subprocess.run(["icacls", target, "/inheritance:e"], check=True, capture_output=True)
    reqs = [("binary", tree["entry"]), ("directory", tree["release"]), ("inventory", tree["release"])]
    code, reply = verify(tree, reqs)
    print(json.dumps(reply, indent=1)[:2000])
    assert code == 1
    assert all(not r["ok"] for r in reply["results"]), reply
    oreply, ocode = oracle(tree, reqs)
    assert ocode == 1 and all(not r["ok"] for r in oreply["results"]), oreply  # the oracle agrees


def _set_dacl(path, sddl):
    import ctypes as c
    from ctypes import wintypes as w

    a = c.WinDLL("advapi32", use_last_error=True)
    sd = c.c_void_p()
    if not a.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, c.byref(sd), None):
        return f"SDDL refused ({c.get_last_error()})"
    present, dacl, defaulted = w.BOOL(), c.c_void_p(), w.BOOL()
    a.GetSecurityDescriptorDacl(sd, c.byref(present), c.byref(dacl), c.byref(defaulted))
    a.SetNamedSecurityInfoW.argtypes = [w.LPCWSTR, c.c_int, w.DWORD, c.c_void_p, c.c_void_p, c.c_void_p, c.c_void_p]
    code = a.SetNamedSecurityInfoW(path, 1, 0x4 | 0x80000000, None, None, dacl, None)  # DACL | PROTECTED
    return None if code == 0 else f"SetNamedSecurityInfo refused ({code})"


@pytest.mark.parametrize("extra", [
    "(OA;;FA;bf967aba-0de6-11d0-a285-00aa003049e2;;WD)",           # object ACE (type 5)
    "(XA;;FA;;;WD;(Member_of {SID(BA)}))",                            # callback ACE (type 9)
])
def test_n1_object_and_callback_aces_are_refused(tree, extra):
    problem = _set_dacl(tree["authority"], f"D:P(A;;FA;;;{tree['sid']}){extra}")
    if problem:
        pytest.skip(f"this NTFS refuses that ACE: {problem}")
    code, reply = verify(tree, [("document", tree["authority"])])
    print(reply)
    assert code == 1 and "ACE" in reply["results"][0]["problem"], reply
