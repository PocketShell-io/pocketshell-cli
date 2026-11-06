"""NONSHIPPING C transport unit against the actual measured MSYS Bash decoder.

The normal Spectre backend build and packaged SSH gate remain mandatory.
"""
import importlib.util
import json
import os
from pathlib import Path
import random
import shlex
import subprocess
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="actual Windows/MSYS decoder")


def test_private_pty_encoder_preserves_one_exact_windows_operand(tmp_path):
    repo = Path(__file__).resolve().parents[2]
    spec = importlib.util.spec_from_file_location("private_shell_overlay", repo / "scripts/release/private_shell_overlay.py")
    overlay = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(overlay)
    payload = Path(os.environ["POCKETSHELL_TRAY_TERMINAL_PAYLOAD"])
    catalog = json.loads((payload / "host-runtime-catalog.json").read_bytes())
    rows = {row["path"]: row["sha256"] for row in catalog["files"]}
    import hashlib
    bash = payload / "runtime/endpoint/shell/usr/bin/bash.exe"
    python = payload / "runtime/python/python.exe"
    for path in (bash, python):
        assert hashlib.sha256(path.read_bytes()).hexdigest() == rows[path.relative_to(payload / "runtime").as_posix()]
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
    source.write_text('#include <windows.h>\n#include <stdint.h>\n#include <stdlib.h>\n'
                      '#include <stdio.h>\n#include <string.h>\n#include <errno.h>\n'
                      # Executable-prefix stub only: actual production uses the unchanged
                      # upstream resolver. No generic argv codec is mocked as an oracle.
                      + r'''
static char *build_commandline_string(const char *cmd, char *const argv[], BOOLEAN prepend) {
    if (argv || prepend) return NULL;
    size_t n = strlen(cmd);
    char *p = malloc(n + 3);
    if (!p) return NULL;
    p[0] = '"'; memcpy(p + 1, cmd, n); p[n + 1] = '"'; p[n + 2] = 0;
    return p;
}
''' + overlay.PTY_ARGV + overlay.MSYS_COMMANDLINE + r'''
static char *utf8(const wchar_t *value) {
    int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, -1, NULL, 0, NULL, NULL);
    char *p = n ? malloc(n) : NULL;
    if (!p || !WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value, -1, p, n, NULL, NULL)) return NULL;
    return p;
}
int wmain(int argc, wchar_t **argv) {
    char *line = NULL;
    if (argc == 3 && wcscmp(argv[1], L"literal") == 0) line = utf8(argv[2]);
    else if (argc == 4) {
        char *bash = utf8(argv[2]), *script = utf8(argv[3]);
        if (!bash || !script) return 11;
        if (wcscmp(argv[1], L"spawn") == 0) {
            char *args[] = {"--noprofile", "--norc", "-c", script, NULL};
            line = pocketshell_msys_commandline(bash, args, FALSE);
        } else if (wcscmp(argv[1], L"pty") == 0) {
            char *prefix = build_commandline_string(bash, NULL, FALSE);
            char *encoded = pocketshell_quote_pty_script(script);
            if (!prefix || !encoded) return 12;
            size_t size = strlen(prefix) + strlen(encoded) + 32;
            line = malloc(size);
            if (line) sprintf_s(line, size, "%s --noprofile --norc -c %s", prefix, encoded);
            free(prefix); free(encoded);
        }
        free(bash); free(script);
    }
    if (!line) return 13;
    int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, line, -1, NULL, 0);
    wchar_t *wide = n ? malloc(n * sizeof(wchar_t)) : NULL;
    if (!wide || !MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, line, -1, wide, n)) return 14;
    STARTUPINFOW si = {0}; PROCESS_INFORMATION pi = {0}; si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE); si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    BOOL created = CreateProcessW(NULL, wide, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    free(wide); free(line);
    if (!created) return 15;
    DWORD code = 16;
    if (WaitForSingleObject(pi.hProcess, 20000) != WAIT_OBJECT_0) {
        TerminateProcess(pi.hProcess, 17); WaitForSingleObject(pi.hProcess, 5000);
    } else GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return (int)code;
}
''', encoding="utf8")
    executable = tmp_path / "argv-unit.exe"
    command = [str(vc / "bin/Hostx64/x64/cl.exe"), "/nologo", "/W4", "/O2", "/MT", str(source), "/Fe:" + str(executable)]
    result = subprocess.run(command, cwd=tmp_path, env=env, capture_output=True, timeout=90, creationflags=0x08000000)
    assert result.returncode == 0, result.stdout.decode(errors="replace") + result.stderr.decode(errors="replace")
    run_env = dict(env, HOME=str(tmp_path), PYTHONUTF8="1", PYTHONIOENCODING="utf-8", LC_ALL="C.UTF-8", LANG="C.UTF-8",
                   PATH=";".join(map(str, [bash.parent, payload / "runtime/endpoint/shell/mingw64/bin",
                                         Path(os.environ["SystemRoot"]) / "System32"])))
    for name in ("BASH_ENV", "ENV"):
        run_env.pop(name, None)
    def run(*args):
        return subprocess.run([str(executable), *args], env=run_env, capture_output=True, timeout=30, creationflags=0x08000000)
    def script(value):
        return '"' + python.as_posix() + '" -I -B -c ' + shlex.quote('import json,sys;print(json.dumps(sys.argv[1]))') + ' ' + shlex.quote(value)
    # Actual former CRT codec loses paired backslashes at the real Bash decoder.
    paired = r"C:\\Users\\Public\\synthetic"
    old = run("literal", subprocess.list2cmdline([str(bash), "--noprofile", "--norc", "-c", script(paired)]))
    assert old.returncode != 0 or json.loads(old.stdout) != paired
    samples = ["", "space arg", "C:\\space dir\\tail\\", r"paired\\slashes", r"four\\\\slashes",
               '\\"quoted\\"', "single' and double\"", "Ω 日本 😀", "line one\nline two", "&|;$(echo literal)"]
    randomizer = random.Random(44)
    alphabet = 'abc \\"\t\n$;&|Ω😀'
    samples += ["".join(randomizer.choice(alphabet) for _ in range(randomizer.randrange(100))) for _ in range(100)]
    for mode in ("pty", "spawn"):
        for value in samples:
            answer = run(mode, str(bash), script(value))
            assert answer.returncode == 0, (mode, repr(value), answer.stderr.decode(errors="replace"))
            assert json.loads(answer.stdout) == value, (mode, repr(value), answer.stdout)