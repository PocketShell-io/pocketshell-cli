"""The production aplexer probe launch on a real Windows host: a console-
subsystem child started by _probe_captured from a WINDOWLESS parent (spawned
DETACHED_PROCESS, like the Desktop/launcher) has no console window
(GetConsoleWindow() == 0), and a hanging child is killed and reaped."""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="native Windows console qualifier")

CHILD = ("import ctypes,json,os;k=ctypes.WinDLL('kernel32');k.GetConsoleWindow.restype=ctypes.c_void_p;"
         "print(json.dumps({'console':k.GetConsoleWindow() or 0,'pid':os.getpid()}))")

PARENT = textwrap.dedent('''
    import json, subprocess, sys
    from pocketshell.runtime import aplexer as ap
    real = subprocess.Popen
    mode = sys.argv[1]
    code = {CHILD!r} if mode == "console" else "import time; time.sleep(60)"
    # the production _probe_captured and its launch kwargs; only the argv is the probe's
    ap._Popen = lambda argv, **kw: real([sys.executable, "-c", code], **kw)
    out, failure = ap._probe_captured("a.exe", ["engines"], env={{}}, timeout=2 if mode == "hang" else 30)
    print(json.dumps({{"out": out, "failure": None if failure is None else [failure.kind, failure.detail]}}))
''').format(CHILD=CHILD)


def _parent(mode):
    p = subprocess.run([sys.executable, "-c", PARENT, mode], capture_output=True, timeout=120,
                       creationflags=0x00000008)  # DETACHED_PROCESS: the parent has no console
    print(p.returncode, p.stdout[-800:], p.stderr[-800:])
    assert p.returncode == 0
    return json.loads(p.stdout.decode().strip().splitlines()[-1])


def test_the_probe_child_has_no_console_window():
    got = _parent("console")
    assert got["failure"] is None
    child = json.loads(got["out"])
    assert child["console"] == 0, f"the probe child has a console window: {child}"


def test_a_hanging_probe_is_killed_and_reaped_on_windows():
    got = _parent("hang")
    assert got["out"] is None and got["failure"][0] == "timeout"
