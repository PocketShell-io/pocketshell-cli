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
def test_native_token_pipe_timeout_does_not_repeat_input():
    token = "audit-" + "x" * 16384
    digest = hashlib.sha256((token + "\n").encode()).hexdigest()
    child = f"import sys,time,hashlib,os; time.sleep(0.3); d=sys.stdin.buffer.read(); assert hashlib.sha256(d).hexdigest()=={digest!r}; s=d.decode().strip(); assert all(s not in a for a in sys.argv); assert all(s not in v for v in os.environ.values()); print('single-input')"
    wrapper = f"import sys,hashlib; from pocketshell.gateway import helper as h; h.WINDOWS_HELPER_SHA256=hashlib.sha256(open(sys.executable,'rb').read()).hexdigest(); h.exec_helper_with_stdin_token(sys.executable,['-c',{child!r}],'audit-'+'x'*16384)"
    result = _run(wrapper)
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == b"single-input"


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
raise SystemExit(main(['gateway','proxy','audit','--server','ws://127.0.0.1:9','--insecure-dev','--trust-gateway','127.0.0.1']))
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


def _verified_direct_base_python():
    """Verify isolated base interpreter identity and direct process PID."""
    base = Path(sys._base_executable).resolve()
    assert base.is_file()
    script = "import sys,os,platform,json; print(json.dumps({'pid':os.getpid(),'exe':sys.executable,'version':list(sys.version_info[:3]),'implementation':platform.python_implementation()}))"
    probe = subprocess.Popen([str(base), "-I", "-c", script], stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        output, error = probe.communicate(timeout=5)
        assert probe.returncode == 0, error
        result = json.loads(output)
        assert result["pid"] == probe.pid, "Base executable is itself a redirector"
        assert Path(result["exe"]).resolve() == base
        assert result["version"] == list(sys.version_info[:3])
        assert result["implementation"] == "CPython"
    finally:
        if probe.poll() is None:
            probe.kill()
            probe.wait()
    return str(base)


def _trusted_helper_import_script():
    candidate = Path(helper.__file__).resolve()
    package_root = candidate.parents[2]
    digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
    return f"""
import sys,pathlib,hashlib,importlib.util
sys.path.insert(0,{str(package_root)!r})
candidate=pathlib.Path({str(candidate)!r})
source_bytes=candidate.read_bytes()
assert hashlib.sha256(source_bytes).hexdigest()=={digest!r}
spec=importlib.util.spec_from_file_location("_pocketshell_candidate_helper",candidate)
assert spec is not None and spec.loader is not None
tested_helper=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=tested_helper
exec(compile(source_bytes,str(candidate),"exec"),tested_helper.__dict__)
assert pathlib.Path(tested_helper.__file__).resolve()==candidate
wait_windows_child=tested_helper.wait_windows_child
"""


@NATIVE
def test_native_console_cancellation_reaps_child(tmp_path):
    import signal
    import ctypes
    from ctypes import wintypes

    pid_file = tmp_path / "child-pid"
    witness = tmp_path / "break-delivered"
    membership_file = tmp_path / "owned-console-membership.json"
    ready_file = tmp_path / "wrapper-ready-pid"
    base = _verified_direct_base_python()
    child = f"import os,time,signal,pathlib,json; signal.signal(signal.SIGBREAK,signal.SIG_IGN); p=pathlib.Path({str(pid_file)!r}); q=p.with_suffix('.tmp'); q.write_text(json.dumps({{'pid':os.getpid(),'parentPid':os.getppid()}})); q.replace(p); time.sleep(60)"
    # Observe the production handler's invocation, not just Generate's success.
    # The handler itself still owns the cancellation state and child cleanup.
    wrapper = _trusted_helper_import_script() + f"""
import os,signal,pathlib
original=signal.signal
def observed(signum,handler):
    if signum==signal.SIGBREAK and callable(handler):
        def delivered(s,f):
            pathlib.Path({str(witness)!r}).write_text(str(s))
            return handler(s,f)
        return original(signum,delivered)
    return original(signum,handler)
signal.signal=observed
pathlib.Path({str(ready_file)!r}).write_text(str(os.getpid()))
wait_windows_child([{base!r},'-I','-c',{child!r}])
"""
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = 0  # SW_HIDE: own console, no visible window.
    proc = subprocess.Popen([base, "-I", "-c", wrapper], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, startupinfo=startup,
                            creationflags=subprocess.CREATE_NEW_CONSOLE)
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
        assert int(ready_file.read_text()) == proc.pid
        child_ready = json.loads(pid_file.read_text())
        assert child_ready['parentPid'] == proc.pid
        audit_child_pid = child_ready['pid']
        handle = kernel.OpenProcess(0x00100001, False, audit_child_pid)
        assert handle
        assert kernel.WaitForSingleObject(handle, 0) == 258
        # Attach a separate hidden emitter ONLY to this audit-owned console.
        # NEW_PROCESS_GROUP is ignored with NEW_CONSOLE, so use group0 only
        # after verifying ALL console members belong to this private fixture.
        emitter = f"""
import ctypes,os,json,pathlib
from ctypes import wintypes
k=ctypes.WinDLL('kernel32',use_last_error=True)
handler_type=ctypes.WINFUNCTYPE(wintypes.BOOL,wintypes.DWORD)
ignore=handler_type(lambda event: True)
k.AttachConsole.argtypes=[wintypes.DWORD]; k.AttachConsole.restype=wintypes.BOOL
k.SetConsoleCtrlHandler.argtypes=[handler_type,wintypes.BOOL]; k.SetConsoleCtrlHandler.restype=wintypes.BOOL
k.GenerateConsoleCtrlEvent.argtypes=[wintypes.DWORD,wintypes.DWORD]; k.GenerateConsoleCtrlEvent.restype=wintypes.BOOL
k.GetConsoleProcessList.argtypes=[ctypes.POINTER(wintypes.DWORD),wintypes.DWORD]; k.GetConsoleProcessList.restype=wintypes.DWORD
k.FreeConsole.argtypes=[]; k.FreeConsole.restype=wintypes.BOOL
assert k.AttachConsole({proc.pid}), 'AttachConsole failed'
try:
    assert k.SetConsoleCtrlHandler(ignore,True), 'Emitter handler failed'
    members=(wintypes.DWORD*16)()
    count=k.GetConsoleProcessList(members,len(members))
    expected={{{proc.pid},{audit_child_pid},os.getpid()}}
    assert count==3 and set(members[:count])==expected, 'Console contains unexpected processes; refusing broadcast'
    pathlib.Path({str(membership_file)!r}).write_text(json.dumps({{'wrapper':{proc.pid},'auditChild':{audit_child_pid},'emitter':os.getpid(),'members':sorted(expected)}}))
    assert k.GenerateConsoleCtrlEvent(1,0), 'Private owned-console CTRL_BREAK generation failed'
finally:
    k.FreeConsole()
"""
        emitted = subprocess.run([base, "-I", "-c", emitter], capture_output=True,
                                 timeout=5, creationflags=subprocess.CREATE_NO_WINDOW)
        assert emitted.returncode == 0, emitted.stderr
        membership = json.loads(membership_file.read_text())
        assert membership['wrapper'] == proc.pid
        assert membership['auditChild'] == audit_child_pid
        assert set(membership['members']) == {proc.pid, audit_child_pid, membership['emitter']}
        delivery_deadline = time.monotonic() + 5
        while not witness.exists() and time.monotonic() < delivery_deadline:
            time.sleep(0.01)
        if not witness.exists():
            kernel.TerminateProcess(handle, 1)
            kernel.WaitForSingleObject(handle, 1000)
            if proc.poll() is None:
                proc.kill()
            _, stderr = proc.communicate(timeout=5)
            pytest.fail("CTRL_BREAK delivery to the actual handler was not observed; "
                        f"exit={proc.returncode}; audit stderr={stderr[:4096]!r}", pytrace=False)
        assert witness.read_text() == str(signal.SIGBREAK)
        try:
            proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            # The child's inherited pipes keep communicate blocked even if
            # the wrapper already failed. Reap ONLY this audit child, then
            # collect fixture stderr so a failure identifies the real cause.
            kernel.TerminateProcess(handle, 1)
            kernel.WaitForSingleObject(handle, 1000)
            if proc.poll() is None:
                proc.kill()
            _, stderr = proc.communicate(timeout=5)
            pytest.fail(f"wrapper cancellation timed out; exit={proc.returncode}; "
                        f"audit stderr={stderr[:4096]!r}", pytrace=False)
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


@NATIVE
def test_native_no_console_local_sigterm_reaps_child(tmp_path):
    import ctypes
    from ctypes import wintypes

    pid_file = tmp_path / "no-console-child-pid"
    witness = tmp_path / "local-term-raised"
    request_file = tmp_path / "request-local-term"
    ready_file = tmp_path / "no-console-wrapper-ready-pid"
    base = _verified_direct_base_python()
    child = f"import os,time,pathlib,json; p=pathlib.Path({str(pid_file)!r}); q=p.with_suffix('.tmp'); q.write_text(json.dumps({{'pid':os.getpid(),'parentPid':os.getppid()}})); q.replace(p); time.sleep(60)"
    # Process-local raise_signal queues the handler; Windows os.kill(15)
    # would hard-terminate and cannot prove Python's cleanup contract.
    wrapper = _trusted_helper_import_script() + f"""
import os,signal,threading,time,pathlib
def request():
    deadline=time.monotonic()+10
    while not pathlib.Path({str(request_file)!r}).exists() and time.monotonic()<deadline:
        time.sleep(0.01)
    assert pathlib.Path({str(request_file)!r}).exists(), 'No owned cancellation request'
    pathlib.Path({str(witness)!r}).write_text('process-local SIGTERM')
    signal.raise_signal(signal.SIGTERM)
threading.Thread(target=request,daemon=True).start()
pathlib.Path({str(ready_file)!r}).write_text(str(os.getpid()))
wait_windows_child([{base!r},'-I','-c',{child!r}])
"""
    proc = subprocess.Popen([base, "-I", "-c", wrapper], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = None
    try:
        deadline = time.monotonic() + 10
        while not pid_file.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert pid_file.exists()
        assert int(ready_file.read_text()) == proc.pid
        child_ready = json.loads(pid_file.read_text())
        assert child_ready['parentPid'] == proc.pid
        # The owned request is sent only after the observer pins this handle.
        handle = kernel.OpenProcess(0x00100001, False, child_ready['pid'])
        assert handle
        request_file.write_text('request')
        _, stderr = proc.communicate(timeout=10)
        assert witness.read_text() == 'process-local SIGTERM'
        assert proc.returncode == 143, stderr
        assert kernel.WaitForSingleObject(handle, 1000) == 0, 'child survived local SIGTERM'
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
        if handle:
            if kernel.WaitForSingleObject(handle, 0) == 258:
                kernel.TerminateProcess(handle, 1)
                kernel.WaitForSingleObject(handle, 1000)
            kernel.CloseHandle(handle)
