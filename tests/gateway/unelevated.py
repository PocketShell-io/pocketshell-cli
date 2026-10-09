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


def _lua_token():
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
    _medium(token)
    return token


def _unelevated_token():
    errors = []
    for make in (_safer_token, _lua_token):
        try:
            token = make()
        except OSError as exc:
            errors.append(f"{make.__name__}: {exc}")
            continue
        if not _elevated(token):
            return token
        errors.append(f"{make.__name__}: TokenElevation still 1")
        k.CloseHandle(token)
    raise RuntimeError("no unelevated token: " + "; ".join(errors))


def _safer_token():
    level = w.HANDLE()
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
    a.CreateProcessAsUserW.argtypes = [w.HANDLE, w.LPCWSTR, w.LPWSTR, c.c_void_p, c.c_void_p, w.BOOL, w.DWORD,
                                       c.c_void_p, w.LPCWSTR, c.POINTER(SI), c.POINTER(PI)]
    token = _unelevated_token()
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
        k.CloseHandle(token)
    out.seek(0)
    return code.value, out.read()


# --- outside the runner's job (CI only) -------------------------------------------------
#
# The windows-latest step processes live in a job with KILL_ON_JOB_CLOSE that
# forbids breakaway (measured). To exercise the agent the way the Desktop app
# runs it (a user process NOT inside a foreign kill-on-close job), the test asks
# the interactive shell (explorer, via Shell.Application.ShellExecute) to start
# this module in --serve mode; that process is outside the runner's job and runs
# the CLI with the unelevated token above.


def run_outside_job(argv, *, env, cwd, timeout=300, poll=0.5):
    import json
    import sys
    import time
    import uuid

    work = os.path.join(cwd, "outside-" + uuid.uuid4().hex)
    os.makedirs(work)
    request = os.path.join(work, "request.json")
    result = os.path.join(work, "result.json")
    with open(request, "w", encoding="utf-8") as handle:
        json.dump({"argv": argv, "env": env, "cwd": cwd, "result": result}, handle)
    args = subprocess.list2cmdline([os.path.abspath(__file__), "--serve", request])

    def ps(value):
        return "'" + value.replace("'", "''") + "'"

    script = (f"(New-Object -ComObject Shell.Application).ShellExecute({ps(sys.executable)},{ps(args)},"
              f"{ps(work)},'open',0)")
    subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                   capture_output=True, timeout=60, creationflags=0x08000000)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.exists(result):
            time.sleep(0.2)
            with open(result, encoding="utf-8") as handle:
                data = json.load(handle)
            return data["code"], data["stdout"].encode("utf-8"), data
        time.sleep(poll)
    return None, b"", None


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
        data = {"code": code, "stdout": out.decode("utf-8", "replace"), "serverInJob": bool(in_job.value)}
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
