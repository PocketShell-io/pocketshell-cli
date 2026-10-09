"""The release entry `pocketshell.exe` is quiet (no console window): the
launcher is a GUI-subsystem binary (no console is allocated for it) and it
starts its Python child with CREATE_NO_WINDOW, so the child has no console
either (GetConsoleWindow() == 0). Measured with the CI-built release closure
and a probe module placed first on the copied closure's ._pth."""

from __future__ import annotations

import json
import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="native Windows launcher")

OUT = os.environ.get("POCKETSHELL_TEST_RELEASE_OUT", "")

PROBE = r'''
import ctypes, json, os, sys
k = ctypes.WinDLL("kernel32")
k.GetConsoleWindow.restype = ctypes.c_void_p
print(json.dumps({"console": k.GetConsoleWindow() or 0, "pid": os.getpid(), "argv": sys.argv[1:],
                  "executable": sys.executable}))
'''


def pe_subsystem(path: Path) -> int:
    data = path.read_bytes()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    assert data[pe:pe + 4] == b"PE\0\0"
    return struct.unpack_from("<H", data, pe + 24 + 68)[0]  # OptionalHeader.Subsystem


@pytest.fixture
def layout(tmp_path):
    if not OUT or not os.path.isdir(OUT):
        pytest.skip("POCKETSHELL_TEST_RELEASE_OUT not built")
    src = Path(OUT) / "root-a" / "releases" / "staged"
    root = tmp_path / "probe-release"
    shutil.copytree(src, root)
    probe = root / "probe" / "pocketshell"
    probe.mkdir(parents=True)
    (probe / "__init__.py").write_text("")
    (probe / "__main__.py").write_text(PROBE)
    # test layout only: the probe package shadows the real CLI
    (root / "python" / "python312._pth").write_text("..\\probe\npython312.zip\nDLLs\n")
    return root


def test_launcher_is_a_gui_subsystem_binary(layout):
    assert pe_subsystem(layout / "pocketshell.exe") == 2  # IMAGE_SUBSYSTEM_WINDOWS_GUI: no console allocated


def test_python_child_has_no_console_window(layout):
    """Spawned like the Desktop (a GUI process): the launcher gets NO console
    (DETACHED_PROCESS), so a console-subsystem child started without
    CREATE_NO_WINDOW would get a NEW, visible console; with it, none."""
    p = subprocess.run([str(layout / "pocketshell.exe"), "gateway", "agent", "status", "--json"],
                       capture_output=True, timeout=60, creationflags=0x00000008)  # DETACHED_PROCESS
    print(p.returncode, p.stdout, p.stderr[-500:])
    out = json.loads(p.stdout.decode().strip().splitlines()[-1])
    assert p.returncode == 0
    assert out["argv"] == ["gateway", "agent", "status", "--json"]  # argv passed through exactly
    assert out["console"] == 0, f"the Python child has a console window: {out}"
