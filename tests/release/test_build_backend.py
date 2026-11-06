"""Source controls for the owned backend build driver (review 094ef92c):
the MSYS configure triplet and its emitted DLL path, and an accepted:false
receipt (with the accumulated process records) for EVERY failure class."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "release" / "build_backend_windows.py"


@pytest.fixture
def bb():
    spec = importlib.util.spec_from_file_location("build_backend_windows", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_msys_configure_declares_the_cygwin_build_triplet_and_the_matching_dll_path(bb, tmp_path):
    script = bb.msys_build_script("/C/bw/src")
    assert "--build=x86_64-pc-cygwin" in script and "--with-msys2-runtime-commit=" + bb.MSYS["commit"] in script
    assert "x86_64-w64-mingw32-gcc" in script and "--with-cross-bootstrap" in script and "--disable-dumper" in script  # the winsup cross compiler is checked, never assumed
    assert bb.msys_dll(tmp_path) == tmp_path / "x86_64-pc-cygwin" / "winsup" / "cygwin" / "new-msys-2.0.dll"
    assert "x86_64-pc-msys" not in str(bb.msys_dll(tmp_path))


def _run_main(bb, monkeypatch, tmp_path, fail):
    def build(work, out, rec):
        rec.run("first-step", [sys.executable, "-c", "print('ok')"])
        fail()

    monkeypatch.setattr(bb, "build_msys", build)
    monkeypatch.setattr(sys, "argv", ["x", "--part", "msys", "--work", str(tmp_path / "w"), "--out",
                                      str(tmp_path / "o")])
    code = bb.main()
    receipt = json.loads((tmp_path / "o" / "msys-build-receipt.json").read_text())
    return code, receipt


def _missing_dll():
    raise FileNotFoundError(2, "No such file", "new-msys-2.0.dll")


def _popen():
    raise subprocess.SubprocessError("cannot start")


def _oserror():
    raise PermissionError(13, "Access is denied", "copy")


def _exit():
    raise SystemExit("make failed with natural exit 2")


@pytest.mark.parametrize("fail", [_missing_dll, _popen, _oserror, _exit],
                         ids=["missing-output", "process-creation", "copy-error", "natural-failure"])
def test_every_failure_class_writes_a_refused_receipt_with_the_processes(bb, monkeypatch, tmp_path, fail):
    code, receipt = _run_main(bb, monkeypatch, tmp_path, fail)
    assert code == 1 and receipt["accepted"] is False and "outputs" not in receipt
    assert [p["label"] for p in receipt["processes"]] == ["first-step"]
    assert receipt["processes"][0]["naturalExit"] == 0
    assert receipt["error"]["type"] and len(receipt["error"]["message"]) <= 2000


def test_the_null_path_overlay_guards_every_path_value_use(bb):
    """NULL-PATH-FIX.md: the daemon entry points never dereference a NULL PATH."""
    inputs = Path(bb.INPUTS) / "openssh-quiet-e302fe1"
    for rel in ("contrib/win32/win32compat/wmain_sshd.c", "contrib/win32/win32compat/wmain_sshd-session.c",
                "contrib/win32/win32compat/wmain_sshd-auth.c"):
        assert rel in bb.OPENSSH["overlay"]
        text = (inputs / Path(rel).name).read_text(encoding="utf-8")
        import hashlib

        assert hashlib.sha256((inputs / Path(rel).name).read_bytes()).hexdigest() == bb.OPENSSH["overlay"][rel][1]
        assert "wcslen(path_value)" not in text  # every length uses the guarded value
        assert text.count('path_value ? path_value : L""') == 2


def test_managed_session_path_prefers_tools_and_excludes_user_path(bb):
    from private_shell_overlay import patch_session
    source = ('strncmp(env_name, "PATH=", strlen("PATH="));\n'
              '\t/* PATH is a special case. */\n L"Environment", L"PATH";\n}\n'
              'static int\nsetup_session_env(struct ssh *ssh, Session* s)\n{\n\tret = 0;\n}\n'
              '\nint do_exec_windows\n'
              '\t\tif (command) {\n'
              '\t\t\tsize_t len = strlen(shell) + 1 + strlen(shell_command_option_local) + 1 + strlen(command) + 1;\n'
              'strcat_s(pty_cmd, len, command);\n'
              '\t\t} else {\n\t\t\tif (shell_arguments) {\n}\n}\n'
              'char *spawn_argv[4] = { NULL, };\n'
              '\t\t\tif (exec_command) {\n'
              '\t\t\t\tspawn_argv[1] = shell_command_option_local;\n'
              '\t\t\t\tspawn_argv[2] = exec_command;\n\t\t\t}\n'
              'posix_spawn(&pid, spawn_argv[0], &actions, NULL, spawn_argv, NULL);\n')
    patched = patch_session(source)
    assert 'L"%s\\\\python;%s;%s\\\\endpoint\\\\shell\\\\usr\\\\bin;' in patched
    assert 'L"Environment", L"PATH"' not in patched
    assert 'GetSystemDirectoryW' in patched
    assert '_strnicmp(env_name, "PATH=", strlen("PATH="))' in patched
    assert 'spawn_argv[6]' in patched
    assert 'spawn_argv[1] = "--noprofile"' in patched
    assert 'spawn_argv[2] = "--norc"' in patched
    assert 'spawn_argv[4] = exec_command' in patched
    assert 'SetEnvironmentVariableW(L"BASH_ENV", NULL)' in patched
    assert 'BASH_FUNC_pocketshell%%' in patched
    assert 'BASH_FUNC_a%%' in patched
    assert 'BASH_FUNC_aplexer%%' in patched
    assert 'set_managed_commands();\n\tret = 0;' in patched
    assert 'shell_type == SH_BASH ? pocketshell_quote_pty_script(command)' in patched
    assert 'strcat_s(pty_cmd, len, command);' not in patched
    assert 'strcat_s(pty_cmd, len, pty_script);' in patched
    assert 'free(encoded_script);' in patched
    assert 'shell_type == SH_BASH ? &msys_attrs : NULL' in patched
    assert 'msys_attrs.flags = POCKETSHELL_SPAWN_MSYS_ARGV' in patched


def test_private_msys_spawn_preserves_unselected_codec_and_entire_child_lifecycle(bb):
    from private_shell_overlay import patch_spawn
    source = (SCRIPT.parents[2] / "release/inputs/openssh-quiet-e302fe1/w32fd.c").read_text(encoding="utf8")
    patched = patch_spawn(source)
    anchor = "static int\nspawn_child_internal("
    def function(text, start):
        begin = text.index(start)
        return text[begin:text.index("\n}", begin) + 2]
    child = function(patched, anchor)
    child = child.replace("BOOLEAN load_user_env, BOOLEAN msys_argv)", "BOOLEAN load_user_env)")
    child = child.replace("(msys_argv ? pocketshell_msys_commandline(cmd, argv, prepend_module_path) : "
                          "build_commandline_string(cmd, argv, prepend_module_path))",
                          "build_commandline_string(cmd, argv, prepend_module_path)")
    assert child == function(source, anchor)  # flags, handles, tokens and environment byte-for-byte
    spawn = function(patched, "int\nposix_spawn_internal(")
    spawn = spawn.replace("load_user_env,\n        attrp && (attrp->flags & POCKETSHELL_SPAWN_MSYS_ARGV))", "load_user_env)")
    spawn = spawn.replace("(attrp->flags & ~POCKETSHELL_SPAWN_MSYS_ARGV)", "attrp->flags")
    assert spawn == function(source, "int\nposix_spawn_internal(")
    # Public APIs/ABI and every caller's default path are unchanged.
    assert patched[patched.index("int\nposix_spawn(pid_t"): ] == source[source.index("int\nposix_spawn(pid_t"): ]
    assert "build_commandline_string(cmd, NULL, prepend_module_path)" in patched
    assert "#define POCKETSHELL_SPAWN_MSYS_ARGV 0x4000" in patched
    assert 'for name in ("pwd.c", "w32-doexec.c", "w32fd.c")' in SCRIPT.read_text()


@pytest.mark.parametrize("anchor", ["spawn_child_internal(path, argv + 1", "attrp->flags == POSIX_SPAWN_SETPGROUP",
                                   "build_commandline_string(cmd, argv, prepend_module_path)"])
def test_private_msys_spawn_refuses_changed_upstream_anchors(anchor, bb):
    from private_shell_overlay import patch_spawn
    source = (SCRIPT.parents[2] / "release/inputs/openssh-quiet-e302fe1/w32fd.c").read_text(encoding="utf8")
    with pytest.raises(ValueError):
        patch_spawn(source.replace(anchor, "unexpected-upstream", 1))


@pytest.mark.parametrize("overlay", [None, "0" * 64, "current"])
def test_closure_rejects_backends_without_current_private_shell_path(overlay, tmp_path):
    spec = importlib.util.spec_from_file_location("build_closure", SCRIPT.with_name("build_closure.py"))
    closure = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(closure)
    receipt = {"accepted": True, "executedOutputs": False, "outputs": {}, "inputs": {}}
    if overlay is not None:
        receipt["inputs"]["privateShellOverlaySHA256"] = (
            closure.sha256(SCRIPT.with_name("private_shell_overlay.py")) if overlay == "current" else overlay
        )
    (tmp_path / "openssh-build-receipt.json").write_text(json.dumps(receipt))
    if overlay == "current":
        assert closure._verified_receipt(tmp_path, "openssh") == receipt
    else:
        with pytest.raises(SystemExit, match="current private shell/PATH overlay"):
            closure._verified_receipt(tmp_path, "openssh")
