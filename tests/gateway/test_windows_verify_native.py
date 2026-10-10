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
    for req in requests:
        kind, path = req[0], req[1]
        expect = f":{req[2]}" if len(req) > 2 and req[2] else ""
        out += ["--request", f"{kind}{expect}={path}"]
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
        # release, then end-of-input (N3: only EOF is accepted after release)
        proc.stdin.write((json.dumps({"op": "release", "operationId": "op-1"}) + "\n").encode())
        proc.stdin.close()
        ev = json.loads(proc.stdout.readline())
        assert ev["event"] == "released", ev
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


def test_n3_data_after_release_is_refused(tree):
    proc = _hold(tree)
    proc.stdin.write(b'{"op":"release","operationId":"op-1"}\n{"op":"release","operationId":"op-1"}\n')
    proc.stdin.close()
    ev = json.loads(proc.stdout.readline())
    assert ev["event"] == "refused" and proc.wait(timeout=10) == 2, ev


def test_r1_oversized_line_after_release_is_refused(tree):
    """dd792b5 R1: a scanner error after release is not end-of-input."""
    proc = _hold(tree)
    proc.stdin.write(b'{"op":"release","operationId":"op-1"}\n' + b"x" * 5000 + b"\n")
    proc.stdin.close()
    ev = json.loads(proc.stdout.readline())
    assert ev["event"] == "refused" and proc.wait(timeout=10) == 2, ev


# --- v4.2 final bootstrap bridge: the verifier creates the entry from the HELD file ----


def _spawn_entry(tree, entry_args, *, extra=(), stdin_close_early=False, timeout=120):
    import base64

    requests = [{"kind": "binary", "path": tree["entry"], "expect": file_sha(tree["entry"])},
                {"kind": "inventory", "path": tree["release"], "expect": inventory_digest(tree["release"])},
                {"kind": "document", "path": tree["authority"], "expect": file_sha(tree["authority"])}]
    argv_ = argv(tree, [], extra=["--requests-stdin", "--hold", "--entry", tree["entry"], "--spawn-entry",
                                  *[x for a in entry_args for x in ("--entry-arg", a)], *extra])
    proc = subprocess.Popen(argv_, stdin=subprocess.PIPE, stdout=subprocess.PIPE, creationflags=0x08000000)
    proc.stdin.write(json.dumps({"version": 2, "operationId": "op-1", "requests": requests}).encode() + b"\n")
    proc.stdin.flush()
    first = json.loads(proc.stdout.readline())
    assert first["ok"], first
    # C-Fleet-native-entry-v1: ONE correlated authorize line after the consumer's own check
    proc.stdin.write(b'{"version":2,"operationId":"op-1","op":"authorize"}\n')
    proc.stdin.flush()
    events = []
    launched = json.loads(proc.stdout.readline())
    events.append(launched)
    if stdin_close_early:
        proc.stdin.close()
    for line in proc.stdout:
        events.append(json.loads(line))
    code = proc.wait(timeout=timeout)
    for e in events:
        if "stdoutBase64" in e:
            e["stdout"] = base64.b64decode(e["stdoutBase64"]).decode(errors="replace")
    print(code, json.dumps(events)[:1500])
    return code, events


def test_spawn_entry_runs_the_held_file_and_reports_its_result(tree):
    from pocketshell.gateway import service_windows as win

    code, ev = _spawn_entry(tree, ["-n", "1", "127.0.0.1"])
    assert code == 0 and [e["event"] for e in ev] == ["launched", "exited", "released"], ev
    launched, exited = ev[0], ev[1]
    assert launched["imageMatches"] is True and launched["pid"] == exited["pid"]
    # PING prints nothing without a console (CREATE_NO_WINDOW); captured stdout is
    # proven with the real CLI in test_verifier_spawns_the_held_release_entry
    assert exited["exitCode"] == 0 and isinstance(exited["stdoutBytes"], int)
    assert win.WindowsApi().process_identity(launched["pid"])["state"] == "absent"
    with open(tree["entry"], "r+b"):
        pass  # released


def test_spawn_entry_timeout_ends_the_exact_child(tree):
    from pocketshell.gateway import service_windows as win

    code, ev = _spawn_entry(tree, ["-n", "60", "127.0.0.1"], extra=["--entry-timeout", "2"])
    assert code == 5 and ev[-1]["event"] == "timeout", ev
    assert win.WindowsApi().process_identity(ev[0]["pid"])["state"] == "absent"


def test_spawn_entry_controller_gone_ends_the_child(tree):
    from pocketshell.gateway import service_windows as win

    code, ev = _spawn_entry(tree, ["-n", "60", "127.0.0.1"], stdin_close_early=True)
    assert code == 4 and ev[-1]["event"] == "closed", ev
    assert win.WindowsApi().process_identity(ev[0]["pid"])["state"] == "absent"


def test_spawn_entry_requires_hold(tree):
    p = subprocess.run(argv(tree, [("binary", tree["entry"], file_sha(tree["entry"]))], extra=["--spawn-entry"]),
                       capture_output=True,
                       timeout=60, creationflags=0x08000000)
    assert p.returncode == 2


def file_sha(path):
    import hashlib

    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def inventory_digest(root):
    import hashlib

    names = sorted(p.relative_to(root).as_posix().lower() for p in Path(root).rglob("*") if p.is_file())
    return hashlib.sha256("\n".join(names).encode()).hexdigest()


def test_spawn_entry_without_authorize_creates_nothing(tree):
    """BI1: closing stdin instead of authorizing -> nothing was started."""
    reqs = [("binary", tree["entry"], file_sha(tree["entry"]))]
    proc = subprocess.Popen(argv(tree, reqs, extra=["--hold", "--entry", tree["entry"], "--spawn-entry",
                                                     "--entry-arg", "-n", "--entry-arg", "30"]),
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, creationflags=0x08000000)
    assert json.loads(proc.stdout.readline())["ok"]
    proc.stdin.write(b'{"version":2,"operationId":"someone-else","op":"authorize"}\n')
    proc.stdin.close()
    ev = json.loads(proc.stdout.readline())
    assert ev["event"] == "refused" and "nothing was started" in ev["problem"] and proc.wait(timeout=10) == 2


def test_spawn_entry_refuses_a_closure_whose_digest_is_not_expected(tree):
    """BI1: an ACL-valid but hash-altered entry is refused natively; nothing runs."""
    reqs = [("binary", tree["entry"], "0" * 64)]
    p = subprocess.run(argv(tree, reqs, extra=["--hold", "--entry", tree["entry"], "--spawn-entry"]),
                       capture_output=True, timeout=60, creationflags=0x08000000)
    reply = json.loads(p.stdout.decode().splitlines()[0])
    assert p.returncode == 1 and not reply["ok"] and "expected digest" in reply["results"][0]["problem"]


# --- §16.7 the read-only context operation (empty environment, closed stdin) ----------


def _expected_context():
    import ctypes as c

    from pocketshell.gateway import service_agent_install as inst
    from pocketshell.gateway import service_windows as win

    api = win.WindowsApi()
    f = inst.known_folders()
    return {"ownerSid": api.current_sid(), "session": api.current_session(),
            "windows": {k: f[k] for k in ("SystemDrive", "SystemRoot", "ProgramData", "USERPROFILE", "LOCALAPPDATA")},
            "elevated": bool(c.windll.shell32.IsUserAnAdmin())}


def test_context_with_an_empty_environment():
    if not VERIFY or not os.path.isfile(VERIFY):
        pytest.skip("verifier not built")
    from unelevated import run_unelevated

    want = _expected_context()
    if want["elevated"]:
        # the elevated runner itself is refused (the ordinary-user runtime never runs elevated) …
        p = subprocess.run([VERIFY, "context", "--operation-id", "ctx-e"], env={}, stdin=subprocess.DEVNULL,
                           capture_output=True, timeout=30, creationflags=0x08000000)
        refusal = json.loads(p.stdout)
        assert p.returncode == 1 and refusal["ok"] is False and "elevated" in refusal["problem"], refusal
        # … and an unelevated token of the same user, EMPTY environment, closed stdin, is measured
        code, out = run_unelevated([VERIFY, "context", "--operation-id", "ctx-1"], env={})
    else:
        p = subprocess.run([VERIFY, "context", "--operation-id", "ctx-1"], env={}, stdin=subprocess.DEVNULL,
                           capture_output=True, timeout=30, creationflags=0x08000000)
        code, out = p.returncode, p.stdout
    print(code, out[:2000])
    assert code == 0 and len(out) <= 8192
    reply = json.loads(out)
    assert sorted(reply) == ["elevated", "operationId", "ownerSid", "session", "version", "windows"]
    assert reply["version"] == 2 and reply["operationId"] == "ctx-1" and reply["elevated"] is False
    assert reply["ownerSid"] == want["ownerSid"] and reply["session"] == want["session"]
    for k, v in want["windows"].items():
        assert reply["windows"][k].lower() == v.lower(), (k, reply["windows"][k], v)


def test_context_usage_errors():
    if not VERIFY or not os.path.isfile(VERIFY):
        pytest.skip("verifier not built")
    p = subprocess.run([VERIFY, "context"], env={}, stdin=subprocess.DEVNULL, capture_output=True, timeout=30,
                       creationflags=0x08000000)
    assert p.returncode == 2 and json.loads(p.stdout)["ok"] is False


# --- diagnostic 7a: ACL authority starts at the declared request ROOT ---------------
# Measured on the user's laptop (runner 27552): every request refused at the
# ABOVE-root ancestor C:\Users\<u>\AppData because of a capability-SID
# full-control ACE. Shape, reparse, canonical checks and held no-delete
# handles still cover the whole path; ACL role policy starts at the root.

CAPABILITY = "S-1-15-3-2968813833-811790644-2202111208-3784096404-1081847329-2708967783-1438471679"


def _grant(path, sid, rights="F"):
    p = subprocess.run(["icacls", str(path), "/grant", f"*{sid}:({rights})"], capture_output=True, text=True)
    if p.returncode != 0:
        pytest.skip(f"icacls cannot grant {sid}: {p.stdout} {p.stderr}")


@pytest.fixture
def scoped(tmp_path):
    if not VERIFY or not os.path.isfile(VERIFY):
        pytest.skip("verifier not built")
    from pocketshell import windows_security as ws
    from pocketshell.gateway import service_windows as win

    above = tmp_path / "AppDataLike"
    res = above / "resources"
    (res / "runtime" / "sub").mkdir(parents=True)
    (res / "host-runtime-catalog.json").write_bytes(b"{}")
    (res / "runtime" / "sub" / "m.bin").write_bytes(b"module")
    private = above / "private-root"
    ws.write_private(private / "tmp" / "keep", b"x")
    return {"above": above, "res": res, "private": private, "sid": win.WindowsApi().current_sid()}


def _verify_scoped(s, requests):
    argv_ = [VERIFY, "verify", "--operation-id", "op-7a", "--owner-sid", s["sid"],
             "--resources-root", str(s["res"]), "--private-root", str(s["private"])]
    for kind, path in requests:
        argv_ += ["--request", f"{kind}={path}"]
    p = subprocess.run(argv_, capture_output=True, timeout=60, creationflags=0x08000000)
    reply = json.loads(p.stdout.decode().splitlines()[0])
    print(p.returncode, json.dumps(reply)[:1200])
    return p.returncode, reply


def test_7a_capability_ace_above_the_root_is_outside_the_acl_scope(scoped):
    _grant(scoped["above"], CAPABILITY)  # the measured laptop shape, ABOVE both roots
    code, reply = _verify_scoped(scoped, [("document", scoped["res"] / "host-runtime-catalog.json"),
                                          ("binary", scoped["res"] / "runtime" / "sub" / "m.bin"),
                                          ("directory", scoped["private"]), ("directory", scoped["private"] / "tmp")])
    assert code == 0 and reply["ok"], reply


@pytest.mark.parametrize("where", ["resources-root", "inside-resources", "private-root", "private-intermediate"])
def test_7a_the_same_ace_at_or_below_a_root_still_refuses(scoped, where):
    target = {"resources-root": scoped["res"], "inside-resources": scoped["res"] / "runtime" / "sub",
              "private-root": scoped["private"], "private-intermediate": scoped["private"] / "tmp"}[where]
    _grant(target, CAPABILITY)
    req = ([("binary", scoped["res"] / "runtime" / "sub" / "m.bin")] if "resources" in where
           else [("directory", scoped["private"] / "tmp")])
    code, reply = _verify_scoped(scoped, req)
    assert code == 1 and not reply["results"][0]["ok"], reply


@pytest.mark.parametrize("sid", ["S-1-5-32-545", "S-1-1-0"])  # Users, Everyone
def test_7a_foreign_mutation_inside_the_resources_root_still_refuses(scoped, sid):
    _grant(scoped["res"] / "runtime", sid, "M")
    code, reply = _verify_scoped(scoped, [("binary", scoped["res"] / "runtime" / "sub" / "m.bin")])
    assert code == 1 and "foreign mutation authority" in reply["results"][0]["problem"], reply


def test_7a_reparse_above_the_root_still_refuses(scoped, tmp_path):
    junction = tmp_path / "jroot"
    subprocess.run(["cmd", "/c", "mklink", "/J", str(junction), str(scoped["above"])], check=True, capture_output=True)
    s = dict(scoped, res=junction / "resources", private=junction / "private-root")
    code, reply = _verify_scoped(s, [("document", s["res"] / "host-runtime-catalog.json")])
    assert code == 1 and "reparse" in reply["results"][0]["problem"], reply


def test_7a_held_root_cannot_be_replaced_while_held(scoped):
    """Why no parent-ACL exception is needed: every component, the root
    included, is held without delete sharing for the whole hold."""
    reqs = [("binary", scoped["res"] / "runtime" / "sub" / "m.bin",
             __import__("hashlib").sha256(b"module").hexdigest())]
    argv_ = [VERIFY, "verify", "--operation-id", "op-7b", "--owner-sid", scoped["sid"], "--resources-root",
             str(scoped["res"]), "--request", f"binary:{reqs[0][2]}={reqs[0][1]}", "--hold", "--entry", str(reqs[0][1])]
    proc = subprocess.Popen(argv_, stdin=subprocess.PIPE, stdout=subprocess.PIPE, creationflags=0x08000000)
    try:
        assert json.loads(proc.stdout.readline())["ok"]
        with pytest.raises(PermissionError):
            os.replace(scoped["res"], scoped["above"] / "swapped")
    finally:
        proc.stdin.close()
        proc.wait(timeout=10)
