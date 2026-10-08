"""Native gateway process boundaries; no POSIX emulation or live enrollment."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import pytest

from pocketshell.gateway import helper, client_cli

NATIVE = pytest.mark.skipif(sys.platform != "win32", reason="real Windows pipes/console required")


def test_windows_missing_pin_never_uses_path(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(helper.shutil, "which", lambda *a: pytest.fail("PATH lookup"))
    with pytest.raises(helper.HelperNotFoundError, match="no wheel or PATH fallback"):
        helper.resolve_helper()


def test_windows_wrong_digest_never_runs(tmp_path, monkeypatch):
    candidate = tmp_path / "pocketshell-link.exe"
    candidate.write_bytes(b"untrusted")
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv(helper.HELPER_ENV_VAR, str(candidate))
    monkeypatch.setattr(helper.shutil, "which", lambda *a: pytest.fail("PATH lookup"))
    with pytest.raises(helper.HelperNotFoundError, match="digest"):
        helper.resolve_helper()


def test_windows_verified_explicit_pin(tmp_path, monkeypatch):
    candidate = tmp_path / "pocketshell-link.exe"
    candidate.write_bytes(b"reviewed fixture bytes")
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv(helper.HELPER_ENV_VAR, str(candidate))
    monkeypatch.setattr(helper, "WINDOWS_HELPER_SHA256", hashlib.sha256(candidate.read_bytes()).hexdigest())
    monkeypatch.setattr(helper.shutil, "which", lambda *a: pytest.fail("PATH lookup"))
    assert helper.resolve_helper() == str(candidate)


@NATIVE
def test_native_exact_reviewed_helper_protocol(monkeypatch):
    path = os.environ.get("POCKETSHELL_TEST_WINDOWS_HELPER")
    if not path:
        pytest.skip("parent must supply exact reviewed 8cb Windows helper")
    monkeypatch.setenv(helper.HELPER_ENV_VAR, path)
    resolved = helper.resolve_helper()
    assert hashlib.sha256(Path(resolved).read_bytes()).hexdigest() == helper.WINDOWS_HELPER_SHA256
    helper.verify_helper(resolved)


def _run(script, *, data=None):
    return subprocess.run([sys.executable, "-c", script], input=data,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)


@NATIVE
@pytest.mark.parametrize("command", ["enroll", "run", "show"])
def test_native_helper_inherited_streams_and_exit(command):
    child = "import sys; assert sys.stdin.buffer.read()==b'input-bytes'; print('child-output'); sys.stderr.write('child-error'); sys.exit(23)"
    wrapper = f"from pocketshell.gateway.helper import wait_windows_child; import sys; wait_windows_child([sys.executable,'-c',{child!r},{command!r}])"
    result = _run(wrapper, data=b"input-bytes")
    assert result.returncode == 23
    assert result.stdout.strip() == b"child-output"
    assert result.stderr == b"child-error"


@NATIVE
def test_native_minted_token_only_in_stdin():
    secret = "audit-token-not-a-real-credential"
    child = "import sys,os; t=sys.stdin.buffer.read(); assert t==b'audit-token-'+b'not-a-real-credential\\n'; s=t.decode().strip(); assert all(s not in a for a in sys.argv); assert all(s not in v for v in os.environ.values()); print('stdin-only'); sys.exit(19)"
    wrapper = f"import sys,hashlib; from pocketshell.gateway import helper as h; h.WINDOWS_HELPER_SHA256=hashlib.sha256(open(sys.executable,'rb').read()).hexdigest(); h.exec_helper_with_stdin_token(sys.executable,['-c',{child!r}],{secret!r})"
    # Fixture secret exists in Python test code, but helper argv/env must not
    # carry it. Real enrollment tokens are never used by this test.
    result = _run(wrapper)
    assert result.returncode == 19
    assert result.stdout.strip() == b"stdin-only"
    assert result.stderr == b""


@NATIVE
def test_native_ssh_waits_and_propagates_exit():
    child = "import sys,os; assert os.environ['AUDIT_MARKER']=='kept'; print('ssh-stream'); sys.exit(17)"
    wrapper = f"import sys,os; from pocketshell.gateway.client_cli import _exec_ssh; e=dict(os.environ,AUDIT_MARKER='kept'); _exec_ssh(sys.executable,[sys.executable,'-c',{child!r}],e)"
    result = _run(wrapper)
    assert result.returncode == 17
    assert result.stdout.strip() == b"ssh-stream"


@NATIVE
def test_native_proxy_preserves_binary_crlf_and_ctrl_z():
    wrapper = """
import os
from pocketshell.gateway import proxy
from pocketshell.cli import main
def bridge(*args, **kwargs):
    while True:
        data=os.read(0,4096)
        if not data: break
        os.write(1,data)
    return 0
proxy.run_proxy=bridge
raise SystemExit(main(['gateway','proxy','audit','--server','ws://127.0.0.1:9','--insecure-dev']))
"""
    payload = b"\x00SSH\r\n\x1aafter-ctrl-z\n\xff"
    result = _run(wrapper, data=payload)
    assert result.returncode == 0, result.stderr
    assert result.stdout == payload


@NATIVE
@pytest.mark.parametrize("mode", ["valid", "overflow", "timeout", "closed-stdout"])
def test_native_bounded_metadata_pipe(mode, monkeypatch):
    original = subprocess.Popen
    valid = json.dumps({"version":"audit", "protocol":helper.EXPECTED_PROTOCOL, "commit":"audit"})
    scripts = {
        "valid": f"print({valid!r})",
        "overflow": "import sys,time; sys.stdout.write('x'*100000); sys.stdout.flush(); time.sleep(10)",
        "timeout": "import time; time.sleep(10)",
        "closed-stdout": "import os,time; os.close(1); time.sleep(10)",
    }
    children = []
    def start(argv, **kwargs):
        assert kwargs["stdin"] == subprocess.DEVNULL
        p = original([sys.executable, "-c", scripts[mode]], **kwargs)
        children.append(p)
        return p
    monkeypatch.setattr(helper.subprocess, "Popen", start)
    monkeypatch.setattr(helper, "METADATA_TIMEOUT_SECONDS", 0.5)
    if mode == "valid":
        code, output = helper._probe_version_json_windows("audit fixture")
        assert code == 0
        helper._parse_version_metadata(output)
    else:
        with pytest.raises(helper.HelperIncompatibleError):
            helper._probe_version_json_windows("audit fixture")
    assert children[0].poll() is not None


def test_windows_ssh_never_execve(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(client_cli.os, "execve", lambda *a: pytest.fail("POSIX execve"))
    def waited(argv, *, env=None):
        assert argv == ["ssh.exe", "host"] and env == {"marker":"kept"}
        raise SystemExit(31)
    monkeypatch.setattr(helper, "wait_windows_child", waited)
    with pytest.raises(SystemExit) as result:
        client_cli._exec_ssh("ssh.exe", ["ssh.exe", "host"], {"marker":"kept"})
    assert result.value.code == 31


def test_child_spawn_error_does_not_echo_argv_or_token(monkeypatch, capsys):
    def failed(*args, **kwargs):
        raise OSError("sensitive child args should never be printed")
    monkeypatch.setattr(helper.subprocess, "Popen", failed)
    with pytest.raises(SystemExit) as result:
        helper.wait_windows_child(["missing.exe"], stdin_data=b"secret-token\n")
    assert result.value.code == 127
    output = capsys.readouterr()
    assert output.out == ""
    assert "sensitive" not in output.err and "secret-token" not in output.err


@NATIVE
def test_native_console_cancellation_reaps_child(tmp_path):
    import signal
    import ctypes
    from ctypes import wintypes

    pid_file = tmp_path / "child-pid"
    child = f"import os,time,signal,pathlib; signal.signal(signal.SIGBREAK,signal.SIG_IGN); pathlib.Path({str(pid_file)!r}).write_text(str(os.getpid())); time.sleep(60)"
    wrapper = f"import sys,signal; from pocketshell.gateway.helper import wait_windows_child; signal.signal(signal.SIGBREAK,signal.default_int_handler); wait_windows_child([sys.executable,'-c',{child!r}])"
    proc = subprocess.Popen([sys.executable, "-c", wrapper], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    handle = None
    try:
        deadline = time.monotonic() + 10
        while not pid_file.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert pid_file.exists(), "child never reached ready state"
        handle = kernel.OpenProcess(0x00100001, False, int(pid_file.read_text()))
        assert handle
        proc.send_signal(signal.CTRL_BREAK_EVENT)
        proc.communicate(timeout=10)
        assert proc.returncode == 130
        assert kernel.WaitForSingleObject(handle, 1000) == 0, "child survived cancellation"
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        if handle:
            if kernel.WaitForSingleObject(handle, 0) == 258:
                kernel.TerminateProcess(handle, 1)  # Only this audit child.
                kernel.WaitForSingleObject(handle, 1000)
            kernel.CloseHandle(handle)
