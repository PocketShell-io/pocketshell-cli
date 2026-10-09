"""Native Windows behavior of pocketshell.gateway.winssh (skipped elsewhere).

Console-event tests run inside a HIDDEN new console that the test owns
(``CREATE_NEW_CONSOLE`` + ``SW_HIDE``), and the event is broadcast with
``GenerateConsoleCtrlEvent(…, 0)`` from inside that console only, so the
test runner's own console (if any) is never signalled and no window is
shown.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import time

import pytest

pytestmark = pytest.mark.skipif(os.name != "nt", reason="native Windows only")

SYNCHRONIZE = 0x00100000


def _pid_alive(pid: int) -> bool:
    import ctypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.restype = ctypes.c_void_p
    h = k32.OpenProcess(SYNCHRONIZE, False, pid)
    if not h:
        return False
    try:
        return k32.WaitForSingleObject(ctypes.c_void_p(h), 0) == 0x102  # WAIT_TIMEOUT
    finally:
        k32.CloseHandle(ctypes.c_void_p(h))


def _hidden_console():
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = 0  # SW_HIDE
    return dict(creationflags=subprocess.CREATE_NEW_CONSOLE, startupinfo=si)


def _script(tmp_path, name, body):
    path = tmp_path / name
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return str(path)


def test_inbox_ssh_is_found_and_reports_version():
    from pocketshell.gateway import winssh

    ssh = winssh.find_windows_ssh({})
    assert ssh.lower().endswith(r"\openssh\ssh.exe")
    assert os.path.isfile(ssh)
    assert winssh.ssh_version(ssh).startswith("OpenSSH_for_Windows")


def test_override_must_exist(tmp_path):
    from pocketshell.gateway import winssh

    with pytest.raises(winssh.WindowsSshError):
        winssh.find_windows_ssh({"POCKETSHELL_SSH": str(tmp_path / "nope.exe")})
    with pytest.raises(winssh.WindowsSshError):
        winssh.find_windows_ssh({"POCKETSHELL_SSH": "ssh.exe"})


def test_run_ssh_propagates_exit_status():
    from pocketshell.gateway import winssh

    assert winssh.run_ssh([sys.executable, "-c", "import sys; sys.exit(7)"]) == 7


def test_run_ssh_survives_console_ctrl_c_and_reports_child_status(tmp_path):
    """Ctrl+C in the console reaches the child (ssh.exe's role) and the
    waiter, which must neither die nor change the child's status."""
    out = tmp_path / "out.txt"
    child = _script(tmp_path, "child.py", """
        import signal, sys, time
        got = []
        signal.signal(signal.SIGINT, lambda *a: got.append(1))
        print("ready", flush=True)
        deadline = time.monotonic() + 20
        while not got and time.monotonic() < deadline:
            time.sleep(0.05)
        sys.exit(5 if got else 6)
    """)
    harness = _script(tmp_path, "harness.py", f"""
        import ctypes, subprocess, sys, threading, time
        from pocketshell.gateway import winssh
        out = open({str(out)!r}, "w")
        # A runner may start us with Ctrl+C processing disabled (inherited
        # from a CREATE_NEW_PROCESS_GROUP ancestor); re-enable it for this
        # owned console so the event really reaches the child.
        ctypes.windll.kernel32.SetConsoleCtrlHandler(None, False)
        def fire():
            time.sleep(1.5)
            ok = ctypes.windll.kernel32.GenerateConsoleCtrlEvent(0, 0)  # CTRL_C_EVENT
            out.write(f"fired {{ok}}\\n"); out.flush()
        threading.Thread(target=fire, daemon=True).start()
        code = winssh.run_ssh([sys.executable, {child!r}])
        out.write(f"code {{code}}\\n"); out.close()
        sys.exit(code)
    """)
    proc = subprocess.Popen([sys.executable, harness], **_hidden_console())
    assert proc.wait(60) == 5, out.read_text() if out.exists() else "no output"
    assert "fired 1" in out.read_text()


def test_run_ssh_children_die_with_the_waiter(tmp_path):
    pidfile = tmp_path / "pid"
    child = _script(tmp_path, "sleeper.py", f"""
        import os, time
        open({str(pidfile)!r}, "w").write(str(os.getpid()))
        time.sleep(120)
    """)
    harness = _script(tmp_path, "harness.py", f"""
        import sys
        from pocketshell.gateway import winssh
        sys.exit(winssh.run_ssh([sys.executable, {child!r}]))
    """)
    proc = subprocess.Popen([sys.executable, harness], creationflags=subprocess.CREATE_NO_WINDOW)
    deadline = time.monotonic() + 30
    while not (pidfile.exists() and pidfile.read_text()) and time.monotonic() < deadline:
        time.sleep(0.1)
    pid = int(pidfile.read_text())
    assert _pid_alive(pid)
    proc.kill()  # TerminateProcess: no handler runs in the waiter
    proc.wait(10)
    deadline = time.monotonic() + 10
    while _pid_alive(pid) and time.monotonic() < deadline:
        time.sleep(0.1)
    assert not _pid_alive(pid), "ssh stand-in outlived its killed waiter"


def test_proxy_ignores_console_ctrl_c_and_ctrl_break(tmp_path):
    out = tmp_path / "out.txt"
    harness = _script(tmp_path, "harness.py", f"""
        import ctypes, time
        from pocketshell.gateway.winssh import ignore_console_interrupts
        k = ctypes.windll.kernel32
        k.SetConsoleCtrlHandler(None, False)  # undo any inherited "ignore"
        ignore_console_interrupts()
        a = k.GenerateConsoleCtrlEvent(0, 0)  # CTRL_C_EVENT to this console
        b = k.GenerateConsoleCtrlEvent(1, 0)  # CTRL_BREAK_EVENT
        time.sleep(1.5)
        open({str(out)!r}, "w").write(f"alive {{a}} {{b}}")
    """)
    proc = subprocess.Popen([sys.executable, harness], **_hidden_console())
    assert proc.wait(30) == 0
    assert out.read_text() == "alive 1 1"
