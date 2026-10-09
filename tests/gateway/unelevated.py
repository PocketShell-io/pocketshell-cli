"""CI-only harness: run a command with an UNELEVATED (SAFER normal-user,
medium-integrity) token of the same user and session, capturing its stdout.

The windows-latest runner account is an administrator whose processes are
elevated; the ordinary-user agent refuses elevated children by design. This
test harness (never product code) lowers the token the way `runas
/trustlevel:0x20000` does, so the agent can be exercised as an ordinary user.
"""

from __future__ import annotations

import ctypes as c
import msvcrt
import os
import subprocess
import tempfile
from ctypes import wintypes as w

k = c.WinDLL("kernel32", use_last_error=True)
a = c.WinDLL("advapi32", use_last_error=True)
a.GetTokenInformation.argtypes = [w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.POINTER(w.DWORD)]
a.SetTokenInformation.argtypes = [w.HANDLE, c.c_int, c.c_void_p, w.DWORD]


class SI(c.Structure):
    _fields_ = [("cb", w.DWORD), ("lpReserved", w.LPWSTR), ("lpDesktop", w.LPWSTR), ("lpTitle", w.LPWSTR),
                ("dwX", w.DWORD), ("dwY", w.DWORD), ("dwXSize", w.DWORD), ("dwYSize", w.DWORD),
                ("dwXCountChars", w.DWORD), ("dwYCountChars", w.DWORD), ("dwFillAttribute", w.DWORD),
                ("dwFlags", w.DWORD), ("wShowWindow", w.WORD), ("cbReserved2", w.WORD),
                ("lpReserved2", c.c_void_p), ("hStdInput", w.HANDLE), ("hStdOutput", w.HANDLE),
                ("hStdError", w.HANDLE)]


class PI(c.Structure):
    _fields_ = [("hProcess", w.HANDLE), ("hThread", w.HANDLE), ("dwProcessId", w.DWORD), ("dwThreadId", w.DWORD)]


class SID_AND_ATTRIBUTES(c.Structure):
    _fields_ = [("Sid", c.c_void_p), ("Attributes", w.DWORD)]


def _elevated(token) -> bool:
    value, size = w.DWORD(), w.DWORD()
    if not a.GetTokenInformation(token, 20, c.byref(value), 4, c.byref(size)):
        raise c.WinError(c.get_last_error())
    return bool(value.value)


def _medium(token):
    sid = c.c_void_p()
    if not a.ConvertStringSidToSidW("S-1-16-8192", c.byref(sid)):  # medium integrity
        raise c.WinError(c.get_last_error())
    label = SID_AND_ATTRIBUTES(sid, 0x20)  # SE_GROUP_INTEGRITY
    if not a.SetTokenInformation(token, 25, c.byref(label), c.sizeof(label) + a.GetLengthSid(sid)):
        raise c.WinError(c.get_last_error())


def _lua_token(medium=True):
    """CreateRestrictedToken(LUA_TOKEN | DISABLE_MAX_PRIVILEGE) with the
    Administrators alias made deny-only: the UAC-style filtered token."""
    k.GetCurrentProcess.restype = w.HANDLE
    a.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, c.POINTER(w.HANDLE)]
    base = w.HANDLE()
    if not a.OpenProcessToken(k.GetCurrentProcess(), 0x0002 | 0x0008 | 0x0001 | 0x0080 | 0x0100,
                              c.byref(base)):
        raise c.WinError(c.get_last_error())
    admins = c.c_void_p()
    a.ConvertStringSidToSidW("S-1-5-32-544", c.byref(admins))
    deny = (SID_AND_ATTRIBUTES * 1)(SID_AND_ATTRIBUTES(admins, 0))
    token = w.HANDLE()
    a.CreateRestrictedToken.argtypes = [w.HANDLE, w.DWORD, w.DWORD, c.c_void_p, w.DWORD, c.c_void_p, w.DWORD,
                                        c.c_void_p, c.POINTER(w.HANDLE)]
    if not a.CreateRestrictedToken(base, 0x1 | 0x4, 1, c.cast(deny, c.c_void_p), 0, None, 0, None,
                                   c.byref(token)):
        raise c.WinError(c.get_last_error())
    k.CloseHandle(base)
    _own_defaults(token)
    if medium:
        _medium(token)
    return token


def _own_defaults(token):
    """With UAC off an administrator's token has default owner Administrators
    and a default DACL without the user; once Administrators is deny-only the
    new process could not open its own objects (DLL init 0xc0000142). Make the
    user the default owner and grant user + SYSTEM in the default DACL."""
    size = w.DWORD()
    a.GetTokenInformation(token, 1, None, 0, c.byref(size))
    buf = c.create_string_buffer(size.value)
    if not a.GetTokenInformation(token, 1, buf, size.value, c.byref(size)):
        raise c.WinError(c.get_last_error())
    user = c.cast(buf, c.POINTER(c.c_void_p))[0]
    owner = c.c_void_p(user)
    if not a.SetTokenInformation(token, 4, c.byref(owner), c.sizeof(owner)):  # TokenOwner
        raise c.WinError(c.get_last_error())
    text = c.c_wchar_p()
    a.ConvertSidToStringSidW(c.c_void_p(user), c.byref(text))
    sd = c.c_void_p()
    if not a.ConvertStringSecurityDescriptorToSecurityDescriptorW(f"D:(A;;GA;;;{text.value})(A;;GA;;;SY)", 1,
                                                                   c.byref(sd), None):
        raise c.WinError(c.get_last_error())
    present, dacl, defaulted = w.BOOL(), c.c_void_p(), w.BOOL()
    a.GetSecurityDescriptorDacl(sd, c.byref(present), c.byref(dacl), c.byref(defaulted))
    default = c.c_void_p(dacl.value)
    if not a.SetTokenInformation(token, 6, c.byref(default), c.sizeof(default)):  # TokenDefaultDacl
        raise c.WinError(c.get_last_error())


CHOSEN = {}


def _candidates():
    return (("lua-high", lambda: _lua_token(medium=False)), ("lua-medium", _lua_token), ("safer", _safer_token))


def _unelevated_token():
    """The first candidate token that is measured unelevated AND can start a
    Python probe on this host (logged in DIAGNOSTICS)."""
    import sys

    if "name" in CHOSEN:
        return dict(_candidates())[CHOSEN["name"]]()
    for name, make in _candidates():
        try:
            token = make()
        except OSError as exc:
            DIAGNOSTICS.append(f"{name}: {exc}")
            continue
        if _elevated(token):
            DIAGNOSTICS.append(f"{name}: TokenElevation 1")
            k.CloseHandle(token)
            continue
        code, out = _launch(token, [sys.executable, "-c", "print('probe')"], None, None, 60)
        DIAGNOSTICS.append(f"{name}: probe exit {code:#x} {out[:80]!r}")
        if code == 0:
            CHOSEN["name"] = name
            return make()
    raise RuntimeError("no usable unelevated token: " + "; ".join(DIAGNOSTICS))


DIAGNOSTICS = []


def _safer_token():
    level = w.HANDLE()  # (kept as a last candidate)
    if not a.SaferCreateLevel(2, 0x20000, 1, c.byref(level), None):  # USER scope, NORMALUSER
        raise c.WinError(c.get_last_error())
    token = w.HANDLE()
    try:
        if not a.SaferComputeTokenFromLevel(level, None, c.byref(token), 0, None):
            raise c.WinError(c.get_last_error())
    finally:
        a.SaferCloseLevel(level)
    _medium(token)
    return token


def run_unelevated(argv, *, env=None, cwd=None, timeout=300):
    """(exit code, stdout bytes) of ``argv`` run with an unelevated token."""
    return _launch(_unelevated_token(), argv, env, cwd, timeout)


def _launch(token, argv, env, cwd, timeout):
    a.CreateProcessAsUserW.argtypes = [w.HANDLE, w.LPCWSTR, w.LPWSTR, c.c_void_p, c.c_void_p, w.BOOL, w.DWORD,
                                       c.c_void_p, w.LPCWSTR, c.POINTER(SI), c.POINTER(PI)]
    k.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]
    k.TerminateProcess.argtypes = [w.HANDLE, w.UINT]
    k.GetExitCodeProcess.argtypes = [w.HANDLE, c.POINTER(w.DWORD)]
    k.CloseHandle.argtypes = [w.HANDLE]
    out = tempfile.TemporaryFile()
    os.set_inheritable(out.fileno(), True)
    handle = msvcrt.get_osfhandle(out.fileno())
    si = SI()
    si.cb = c.sizeof(SI)
    si.dwFlags = 0x100 | 0x1  # USESTDHANDLES | USESHOWWINDOW
    si.hStdOutput = si.hStdError = handle
    si.lpDesktop = "winsta0\\default"
    block = None
    if env is not None:
        block = c.create_unicode_buffer("\0".join(f"{kk}={v}" for kk, v in sorted(env.items())) + "\0\0")
    pi = PI()
    cmd = c.create_unicode_buffer(subprocess.list2cmdline(argv))
    try:
        if not a.CreateProcessAsUserW(token, argv[0], cmd, None, None, True, 0x08000000 | 0x400,
                                      c.cast(block, c.c_void_p) if block is not None else None, cwd,
                                      c.byref(si), c.byref(pi)):
            raise c.WinError(c.get_last_error())
        try:
            if k.WaitForSingleObject(pi.hProcess, int(timeout * 1000)) != 0:
                k.TerminateProcess(pi.hProcess, 99)
                raise TimeoutError("unelevated child timed out")
            code = w.DWORD()
            k.GetExitCodeProcess(pi.hProcess, c.byref(code))
        finally:
            k.CloseHandle(pi.hThread)
            k.CloseHandle(pi.hProcess)
    finally:
        k.CloseHandle(token)
    out.seek(0)
    return code.value, out.read()


# --- outside the runner's job (CI only) -------------------------------------------------
#
# The windows-latest step processes live in a job with KILL_ON_JOB_CLOSE that
# forbids breakaway (measured). To exercise the agent the way the Desktop app
# runs it (a user process NOT inside any job), the harness starts this module in
# --serve mode RE-PARENTED (PROC_THREAD_ATTRIBUTE_PARENT_PROCESS) under a
# process of ours in our session that is in no job (explorer.exe preferred), so
# it inherits that parent's job state; --serve then runs the CLI with the
# unelevated token above.


def _jobless_parent():
    """(pid, name) of a process of this user, in this session, in no job."""
    import ctypes as cc

    k.OpenProcess.restype = w.HANDLE
    k.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
    k.IsProcessInJob.argtypes = [w.HANDLE, w.HANDLE, cc.POINTER(w.BOOL)]
    k.ProcessIdToSessionId.argtypes = [w.DWORD, cc.POINTER(w.DWORD)]
    mine = w.DWORD()
    k.ProcessIdToSessionId(os.getpid(), cc.byref(mine))
    listing = subprocess.run(["tasklist", "/fo", "csv", "/nh"], capture_output=True, text=True,
                             creationflags=0x08000000).stdout.splitlines()
    rows = []
    for line in listing:
        parts = [x.strip('"') for x in line.split('","')]
        if len(parts) >= 2 and parts[1].isdigit():
            rows.append((parts[0], int(parts[1])))
    rows.sort(key=lambda r: r[0].lower() != "explorer.exe")
    tried = []
    for name, pid in rows:
        session = w.DWORD()
        if not k.ProcessIdToSessionId(pid, cc.byref(session)) or session.value != mine.value:
            continue
        h = k.OpenProcess(0x0080 | 0x1000, False, pid)  # CREATE_PROCESS | QUERY_LIMITED_INFORMATION
        if not h:
            continue
        flag = w.BOOL()
        ok = k.IsProcessInJob(h, None, cc.byref(flag))
        k.CloseHandle(w.HANDLE(h))
        tried.append(f"{name}:{pid}:{'job' if flag.value else 'nojob'}")
        if ok and not flag.value:
            return pid, name, tried
    return None, None, tried


def _spawn_with_parent(parent_pid, argv, cwd):
    import ctypes as cc

    class SIEX(cc.Structure):
        _fields_ = [("StartupInfo", SI), ("lpAttributeList", cc.c_void_p)]

    k.InitializeProcThreadAttributeList.argtypes = [cc.c_void_p, w.DWORD, w.DWORD, cc.POINTER(cc.c_size_t)]
    k.UpdateProcThreadAttribute.argtypes = [cc.c_void_p, w.DWORD, cc.c_size_t, cc.c_void_p, cc.c_size_t,
                                            cc.c_void_p, cc.c_void_p]
    k.CreateProcessW.argtypes = [w.LPCWSTR, w.LPWSTR, cc.c_void_p, cc.c_void_p, w.BOOL, w.DWORD, cc.c_void_p,
                                 w.LPCWSTR, cc.c_void_p, cc.POINTER(PI)]
    parent = w.HANDLE(k.OpenProcess(0x0080 | 0x1000, False, parent_pid))
    size = cc.c_size_t()
    k.InitializeProcThreadAttributeList(None, 1, 0, cc.byref(size))
    attrs = cc.create_string_buffer(size.value)
    if not k.InitializeProcThreadAttributeList(attrs, 1, 0, cc.byref(size)):
        raise cc.WinError(cc.get_last_error())
    if not k.UpdateProcThreadAttribute(attrs, 0, 0x00020000, cc.byref(parent), cc.sizeof(parent), None, None):
        raise cc.WinError(cc.get_last_error())
    si = SIEX()
    si.StartupInfo.cb = cc.sizeof(SIEX)
    si.StartupInfo.dwFlags = 0x1
    si.StartupInfo.lpDesktop = "winsta0\\default"
    si.lpAttributeList = cc.cast(attrs, cc.c_void_p)
    pi = PI()
    cmd = cc.create_unicode_buffer(subprocess.list2cmdline(argv))
    if not k.CreateProcessW(argv[0], cmd, None, None, False, 0x00080000 | 0x08000000, None, cwd,
                            cc.byref(si), cc.byref(pi)):
        raise cc.WinError(cc.get_last_error())
    k.CloseHandle(w.HANDLE(pi.hThread))
    k.CloseHandle(w.HANDLE(pi.hProcess))
    k.CloseHandle(parent)


def run_outside_job(argv, *, env, cwd, timeout=300, poll=0.5):
    import json
    import sys
    import time
    import uuid

    pid, name, tried = _jobless_parent()
    if pid is None:
        return None, b"", {"error": "no jobless process of ours in this session", "tried": tried[:40]}
    work = os.path.join(cwd, "outside-" + uuid.uuid4().hex)
    os.makedirs(work)
    request = os.path.join(work, "request.json")
    result = os.path.join(work, "result.json")
    with open(request, "w", encoding="utf-8") as handle:
        json.dump({"argv": argv, "env": env, "cwd": cwd, "result": result}, handle)
    _spawn_with_parent(pid, [sys.executable, os.path.abspath(__file__), "--serve", request], work)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.exists(result):
            time.sleep(0.2)
            with open(result, encoding="utf-8") as handle:
                data = json.load(handle)
            data["parent"] = f"{name}:{pid}"
            return data["code"], data["stdout"].encode("utf-8"), data
        time.sleep(poll)
    return None, b"", {"error": "timed out", "parent": f"{name}:{pid}"}


def _serve(request_path):
    import json

    import ctypes as cc

    with open(request_path, encoding="utf-8") as handle:
        req = json.load(handle)
    in_job = w.BOOL()
    k.GetCurrentProcess.restype = w.HANDLE
    k.IsProcessInJob.argtypes = [w.HANDLE, w.HANDLE, cc.POINTER(w.BOOL)]
    k.IsProcessInJob(k.GetCurrentProcess(), None, cc.byref(in_job))
    try:
        code, out = run_unelevated(req["argv"], env=req["env"], cwd=req["cwd"])
        data = {"code": code, "stdout": out.decode("utf-8", "replace"), "serverInJob": bool(in_job.value),
                "token": DIAGNOSTICS}
    except Exception as exc:  # noqa: BLE001 - reported to the waiting test
        data = {"code": None, "stdout": "", "error": repr(exc), "serverInJob": bool(in_job.value)}
    tmp = req["result"] + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(data, handle)
    os.replace(tmp, req["result"])


if __name__ == "__main__":
    import sys

    if len(sys.argv) == 3 and sys.argv[1] == "--serve":
        _serve(sys.argv[2])
