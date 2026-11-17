"""NONSHIPPING compile-and-run unit of the overlay's registry PATH helper.

The helper source is taken verbatim from scripts/release/private_shell_overlay.py
and run against a temporary HKCU key, in a deliberately CLOSED environment (only
SystemRoot), which is what sshd-session inherits from the guardian. The packaged
SSH gate separately proves the same behaviour through the shipped sshd-session.
"""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import uuid

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows registry and MSVC")

HARNESS = r'''
#include <windows.h>
#include <stdio.h>
@HELPER@
static void emit(const wchar_t *text)
{
    char out[65536];
    int n = WideCharToMultiByte(CP_UTF8, 0, text, -1, out, sizeof(out), NULL, NULL);
    if (n > 0) fwrite(out, 1, n - 1, stdout);
}
int wmain(int argc, wchar_t **argv)
{
    static wchar_t path[16384];
    HKEY key = NULL;
    if (argc < 5) return 2;
    if (!wcscmp(argv[1], L"plain")) {  /* the pre-fix expansion, for the RED oracle */
        ExpandEnvironmentStringsW(argv[2], path, 16384);
        emit(path);
        return 0;
    }
    if (RegOpenKeyExW(HKEY_CURRENT_USER, argv[2], 0, KEY_READ, &key) != ERROR_SUCCESS) return 3;
    wcscpy_s(path, 16384, argv[3]);
    pocketshell_append_path_value(key, path, (size_t)_wtoi(argv[4]));
    RegCloseKey(key);
    emit(path);
    return 0;
}
'''


def _overlay():
    repo = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location("private_shell_overlay", repo / "scripts/release/private_shell_overlay.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _msvc(tmp_path):
    vswhere = Path(os.environ["ProgramFiles(x86)"]) / "Microsoft Visual Studio/Installer/vswhere.exe"
    vs = Path(subprocess.check_output([str(vswhere), "-products", "*", "-latest", "-version", "[17.0,18.0)",
              "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"], text=True).strip())
    vc = sorted((vs / "VC/Tools/MSVC").iterdir())[-1]
    sdk = Path(os.environ["ProgramFiles(x86)"]) / "Windows Kits/10"
    version = sorted(d.name for d in (sdk / "Include").iterdir()
                     if d.name.startswith("10.0.") and (d / "um/windows.h").is_file())[-1]
    env = dict(os.environ, INCLUDE=";".join(map(str, [vc / "include", *[
        sdk / "Include" / version / part for part in ("ucrt", "shared", "um")]])),
        LIB=";".join(map(str, [vc / "lib/x64", *[sdk / "Lib" / version / part / "x64" for part in ("ucrt", "um")]])))
    source = tmp_path / "path-unit.c"
    source.write_text(HARNESS.replace("@HELPER@", _overlay().REGISTRY_PATH), encoding="utf8")
    exe = tmp_path / "path-unit.exe"
    result = subprocess.run([str(vc / "bin/Hostx64/x64/cl.exe"), "/nologo", "/W3", "/O2", "/MT", str(source),
                             "/Fe:" + str(exe), "/link", "advapi32.lib", "userenv.lib"], cwd=tmp_path, env=env,
                            capture_output=True, timeout=120, creationflags=0x08000000)
    assert result.returncode == 0, result.stdout.decode(errors="replace") + result.stderr.decode(errors="replace")
    return exe


def _run(exe, *args):
    closed = {"SystemRoot": os.environ["SystemRoot"]}  # what sshd-session inherits: no USERPROFILE/LOCALAPPDATA
    result = subprocess.run([str(exe), *args], env=closed, capture_output=True, timeout=30, creationflags=0x08000000)
    assert result.returncode == 0, (args, result.returncode, result.stderr)
    return result.stdout.decode("utf8")


def test_registry_path_expands_against_the_user_not_the_closed_session_env(tmp_path):
    import winreg
    exe = _msvc(tmp_path)
    profile, local = os.environ["USERPROFILE"], os.environ["LOCALAPPDATA"]
    # RED oracle: expansion against the closed env (the pre-fix behaviour) leaves the variable.
    assert _run(exe, "plain", "%USERPROFILE%\\x", "-", "0") == "%USERPROFILE%\\x"
    name = "Software\\PocketShellPathTest-" + uuid.uuid4().hex
    entries = ["%USERPROFILE%\\a b\\bin", "%LOCALAPPDATA%\\Programs\\tool\\", "C:/Fwd/Slash", "relative\\dir",
               "%PS_UNDEFINED_VAR_" + uuid.uuid4().hex[:6] + "%\\z", "", "D:", "C:/Dup/Dir/", "C:\\Dup\\Dir2",
               "C:\\Program Files\\With Space", "C:\\" + "L" * 300]
    try:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, name) as key:
            winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, ";".join(entries))
        got = _run(exe, "append", name, "C:\\Managed;C:\\Dup\\Dir", "4096").split(";")
        assert got == ["C:\\Managed", "C:\\Dup\\Dir", profile + "\\a b\\bin", local + "\\Programs\\tool",
                       "C:\\Fwd\\Slash", "C:\\Dup\\Dir2", "C:\\Program Files\\With Space", "C:\\" + "L" * 300]
        # A bounded PATH never overflows: the oversize entry is skipped, later short ones still fit.
        base = "C:\\Managed;C:\\Dup\\Dir"
        small = _run(exe, "append", name, base, str(len(base) + 60)).split(";")
        assert "C:\\" + "L" * 300 not in small and small[:2] == base.split(";") and len(small) > 2
        assert len(";".join(small)) < len(base) + 60
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, name) as key:
            winreg.SetValueEx(key, "Path", 0, winreg.REG_SZ, "%USERPROFILE%\\literal;C:\\Plain\\Dir")
        # Like Windows itself, a plain REG_SZ is never expanded: the % entry is dropped.
        assert _run(exe, "append", name, "C:\\Managed", "4096").split(";") == ["C:\\Managed", "C:\\Plain\\Dir"]
    finally:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, name)
