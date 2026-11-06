"""NONSHIPPING C unit: the exact encoder against Windows' actual argv decoder.

This does not compile or qualify the production OpenSSH backend. Its normal
Spectre-enabled producer and packaged SSH runtime gate remain mandatory.
"""
import importlib.util
import os
from pathlib import Path
import random
import subprocess
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows argv decoder")


def test_private_pty_encoder_preserves_one_exact_windows_operand(tmp_path):
    repo = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location("private_shell_overlay", repo / "scripts/release/private_shell_overlay.py")
    overlay = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(overlay)
    vswhere = Path(os.environ["ProgramFiles(x86)"]) / "Microsoft Visual Studio/Installer/vswhere.exe"
    vs = Path(subprocess.check_output([str(vswhere), "-products", "*", "-latest", "-version", "[17.0,18.0)",
              "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"], text=True).strip())
    assert vs.is_absolute(), "A native x64 C compiler is required for this nonshipping unit"
    versions = sorted((vs / "VC/Tools/MSVC").iterdir())
    assert versions
    vc = versions[-1]
    sdk = Path(os.environ["ProgramFiles(x86)"]) / "Windows Kits/10"
    version = "10.0.26100.0"
    env = dict(os.environ, INCLUDE=";".join(map(str, [vc / "include", *[
        sdk / "Include" / version / part for part in ("ucrt", "shared", "um")]])),
        LIB=";".join(map(str, [vc / "lib/x64", *[sdk / "Lib" / version / part / "x64" for part in ("ucrt", "um")]])))
    source = tmp_path / "argv-unit.c"
    source.write_text('#include <windows.h>\n#include <shellapi.h>\n#include <stdint.h>\n'
                      '#include <stdlib.h>\n#include <stdio.h>\n#include <string.h>\n#include <errno.h>\n'
                      + overlay.PTY_ARGV + r'''
int wmain(int argc, wchar_t **argv) {
    if (argc < 2) return 10;
    int bytes = WideCharToMultiByte(CP_UTF8, 0, argv[1], -1, NULL, 0, NULL, NULL);
    char *raw = malloc(bytes);
    if (!raw || !WideCharToMultiByte(CP_UTF8, 0, argv[1], -1, raw, bytes, NULL, NULL)) return 11;
    char *encoded = argc == 3 ? _strdup(raw) : pocketshell_quote_pty_script(raw);
    if (!encoded) return 12;
    int length = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, encoded, -1, NULL, 0);
    wchar_t *wide = calloc(length + 16, sizeof(wchar_t));
    if (!wide) return 13;
    wcscpy_s(wide, length + 16, L"probe.exe ");
    if (!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, encoded, -1, wide + 10, length)) return 14;
    int count = 0;
    wchar_t **decoded = CommandLineToArgvW(wide, &count);
    int ok = decoded && count == 2 && wcscmp(decoded[1], argv[1]) == 0;
    if (decoded) LocalFree(decoded);
    free(raw); free(encoded); free(wide);
    return ok ? 0 : 15;
}
''', encoding="utf8")
    executable = tmp_path / "argv-unit.exe"
    command = [str(vc / "bin/Hostx64/x64/cl.exe"), "/nologo", "/W4", "/O2", "/MT", str(source),
               "/Fe:" + str(executable), "/link", "shell32.lib"]
    result = subprocess.run(command, cwd=tmp_path, env=env, capture_output=True, timeout=90)
    assert result.returncode == 0, result.stdout.decode(errors="replace") + result.stderr.decode(errors="replace")
    # Exact former concatenation: a multiword SSH script becomes multiple argv.
    assert subprocess.run([str(executable), "exec pocketshell sessions attach -- 'immutable-id'", "old"],
                          timeout=10).returncode != 0
    samples = ["", "exec pocketshell sessions attach -- 'immutable-id'", 'printf "%s" "$HOME"',
               "C:\\space dir\\tail\\", '\\"quoted\\"', "Ω 日本 😀", "line one\nline two", "&|;$(echo literal)"]
    randomizer = random.Random(44)
    alphabet = 'abc \\"\t\n$;&|Ω😀'
    samples += ["".join(randomizer.choice(alphabet) for _ in range(randomizer.randrange(100))) for _ in range(100)]
    for script in samples:
        assert subprocess.run([str(executable), script], timeout=10).returncode == 0, repr(script)
