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


def _unelevated_token():
    level = w.HANDLE()
    if not a.SaferCreateLevel(2, 0x20000, 1, c.byref(level), None):  # USER scope, NORMALUSER
        raise c.WinError(c.get_last_error())
    token = w.HANDLE()
    try:
        if not a.SaferComputeTokenFromLevel(level, None, c.byref(token), 0, None):
            raise c.WinError(c.get_last_error())
    finally:
        a.SaferCloseLevel(level)
    sid = c.c_void_p()
    if not a.ConvertStringSidToSidW("S-1-16-8192", c.byref(sid)):  # medium integrity
        raise c.WinError(c.get_last_error())
    label = SID_AND_ATTRIBUTES(sid, 0x20)  # SE_GROUP_INTEGRITY
    a.SetTokenInformation(token, 25, c.byref(label), c.sizeof(label) + a.GetLengthSid(sid))
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
