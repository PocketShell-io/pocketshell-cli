"""Native Windows end to end: real `pocketshell gateway ssh` → inbox ssh.exe →
real ProxyCommand (`python -P -m pocketshell gateway proxy`) → fake gateway
→ the Windows OpenSSH Server on 127.0.0.1.

Gated: runs only on Windows with ``POCKETSHELL_WINDOWS_E2E=1`` and a
prepared sshd (the windows-latest CI job does this; see
.github/workflows/ci.yml):

- ``POCKETSHELL_E2E_SSH_USER``  login name accepted by that sshd
- ``POCKETSHELL_E2E_SSH_KEY``   absolute path of an authorized private key
- ``POCKETSHELL_E2E_HOST_PUB``  the sshd host key line (``keytype base64``)
- ``POCKETSHELL_E2E_SSH_PORT``  default 22
- ``POCKETSHELL_E2E_SPACE_PYTHON`` optional: a python.exe (with pocketshell
  installed) whose path contains a space and non-ASCII characters

Nothing global is changed by the tests: every run uses its own
XDG_CONFIG_HOME, the fake broker and fake gateway live in this process.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    os.name != "nt" or os.environ.get("POCKETSHELL_WINDOWS_E2E") != "1",
    reason="native Windows e2e (set POCKETSHELL_WINDOWS_E2E=1 on a prepared Windows host)",
)

pytest.importorskip("websockets")

from fake_gateway import BridgeGateway  # noqa: E402
from gateway_keyblobs import ED25519_LINE  # noqa: E402
from tests.fake_broker import DEVICE_CODE, SESSION_TOKEN  # noqa: E402

DEVICE = "win-e2e"
CREATE_NO_WINDOW = 0x08000000

REMOTE_IO = r'''
import hashlib, msvcrt, os, sys, time
msvcrt.setmode(0, os.O_BINARY)
msvcrt.setmode(1, os.O_BINARY)
mode = sys.argv[1]
out = sys.stdout.buffer
if mode == "download":
    n = int(sys.argv[2])
    block = bytes(range(256)) * 256
    while n > 0:
        out.write(block[:n]); n -= len(block)
    out.flush()
elif mode == "upload":
    h, total = hashlib.sha256(), 0
    while True:
        chunk = os.read(0, 65536)
        if not chunk:
            break
        h.update(chunk); total += len(chunk)
    out.write(f"{total} {h.hexdigest()}\n".encode()); out.flush()
elif mode == "sleep":
    out.write(b"started\n"); out.flush()
    time.sleep(float(sys.argv[2]))
    out.write(b"finished\n"); out.flush()
elif mode == "exit":
    sys.exit(int(sys.argv[2]))
'''


def _need(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        pytest.fail(f"{name} must be set for the Windows e2e")
    return value


@pytest.fixture(scope="module")
def sshd():
    return {
        "user": _need("POCKETSHELL_E2E_SSH_USER"),
        "key": _need("POCKETSHELL_E2E_SSH_KEY"),
        "host_pub": " ".join(_need("POCKETSHELL_E2E_HOST_PUB").split()[:2]),
        "port": int(os.environ.get("POCKETSHELL_E2E_SSH_PORT", "22")),
    }


@pytest.fixture
def gateway(sshd):
    gw = BridgeGateway(sshd["port"])
    yield gw
    gw.close()


@pytest.fixture
def remote_io(tmp_path):
    """A helper the REMOTE side (same machine, via sshd + cmd.exe) runs.
    Kept on a path without spaces: cmd /c quoting is not under test."""
    d = Path(os.environ.get("RUNNER_TEMP") or tmp_path) / "ps-remote-io"
    d.mkdir(exist_ok=True)
    script = d / "remote_io.py"
    script.write_text(REMOTE_IO, encoding="utf-8")
    assert " " not in str(script) and " " not in sys.executable
    return [sys.executable, str(script)]


class Client:
    """The user's side: one isolated config dir, one interpreter."""

    def __init__(self, base: Path, python: str, sshd: dict, gateway: BridgeGateway):
        self.base = base
        self.python = python
        self.sshd = sshd
        self.gateway = gateway
        self.config = base
        self.config.mkdir(parents=True, exist_ok=True)
        self.cwd = base.parent
        self.key = sshd["key"]

    def env(self) -> dict:
        env = {k: v for k, v in os.environ.items() if k not in ("SSH_AUTH_SOCK", "POCKETSHELL_SSH")}
        env["XDG_CONFIG_HOME"] = str(self.config)
        return env

    def run(self, *args, stdin: bytes = b"", timeout: float = 120) -> subprocess.CompletedProcess:
        return subprocess.run(
            [self.python, "-m", "pocketshell", *args], input=stdin, capture_output=True,
            env=self.env(), cwd=self.cwd, timeout=timeout,
        )

    def ssh_argv(self, *command, extra=()) -> list[str]:
        return [
            self.python, "-m", "pocketshell", "gateway", "ssh", DEVICE,
            "-l", self.sshd["user"], "-i", self.key,
            "--server", f"ws://127.0.0.1:{self.gateway.port}", "--insecure-dev",
            "--trust-gateway", "127.0.0.1", "--", *extra, *command,
        ]

    def ssh(self, *command, stdin: bytes = b"", extra=(), timeout: float = 120):
        return subprocess.run(
            self.ssh_argv(*command, extra=extra), input=stdin, capture_output=True,
            env=self.env(), cwd=self.cwd, timeout=timeout,
        )

    def login(self, broker) -> None:
        broker.start_response["interval"] = 1
        proc = self.run("login", "--no-open", "--label", "win-e2e@laptop")
        assert proc.returncode == 0, proc.stderr.decode(errors="replace")
        broker.requests.clear()

    def pin(self, line: str) -> None:
        proc = self.run("gateway", "pin", DEVICE, stdin=line.encode() + b"\n")
        assert proc.returncode == 0, proc.stderr.decode(errors="replace")


def _no_secrets(proc, broker) -> None:
    blob = (proc.stdout or b"") + (proc.stderr or b"")
    for secret in (SESSION_TOKEN, DEVICE_CODE, broker.gateway_jwt):
        assert secret.encode() not in blob


@pytest.fixture
def client(tmp_path, sshd, gateway, fake_broker):
    c = Client(tmp_path / "cfg", sys.executable, sshd, gateway)
    c.login(fake_broker)
    c.pin(sshd["host_pub"])
    return c


# --------------------------------------------------------------------------


def test_remote_command_output_and_exit_status(client, fake_broker, gateway, remote_io):
    proc = client.ssh("echo", "hello-windows-gateway")
    assert proc.returncode == 0, proc.stderr.decode(errors="replace")
    assert proc.stdout.strip() == b"hello-windows-gateway"
    _no_secrets(proc, fake_broker)
    assert gateway.seen["auth"] == {
        "type": "auth", "v": 1, "token": fake_broker.gateway_jwt, "device_id": DEVICE,
    }
    assert SESSION_TOKEN not in gateway.seen["raw"]

    proc = client.ssh(*remote_io, "exit", "7")
    assert proc.returncode == 7, proc.stderr.decode(errors="replace")


def test_binary_download_is_byte_exact(client, remote_io):
    n = 4 * 1024 * 1024 + 123
    proc = client.ssh(*remote_io, "download", str(n))
    assert proc.returncode == 0, proc.stderr.decode(errors="replace")
    block = bytes(range(256)) * 256
    expected = (block * (n // len(block) + 1))[:n]
    assert len(proc.stdout) == n
    assert hashlib.sha256(proc.stdout).hexdigest() == hashlib.sha256(expected).hexdigest()


def test_binary_upload_is_byte_exact(client, remote_io):
    data = os.urandom(3 * 1024 * 1024) + bytes(range(256)) * 64 + b"\r\n\x1a\x00\x03\x1a"
    proc = client.ssh(*remote_io, "upload", stdin=data)
    assert proc.returncode == 0, proc.stderr.decode(errors="replace")
    assert proc.stdout.split() == [str(len(data)).encode(), hashlib.sha256(data).hexdigest().encode()]


def test_wrong_pin_fails_closed(tmp_path, sshd, gateway, fake_broker):
    c = Client(tmp_path / "wrong", sys.executable, sshd, gateway)
    c.login(fake_broker)
    c.pin(ED25519_LINE)  # what the (hostile) gateway advertises, not the host's key
    proc = c.ssh("echo", "must-not-run")
    assert proc.returncode == 255
    assert b"must-not-run" not in proc.stdout
    err = proc.stderr
    assert b"HOST IDENTIFICATION HAS CHANGED" in err or b"verification failed" in err, err
    _no_secrets(proc, fake_broker)


def test_verbose_reports_native_ssh(client):
    proc = client.ssh("echo", "x", extra=("-v",))
    assert proc.returncode == 0, proc.stderr.decode(errors="replace")
    err = proc.stderr.decode(errors="replace")
    native = os.path.join(os.environ["SystemRoot"], "System32", "OpenSSH", "ssh.exe")
    line = next(ln for ln in err.splitlines() if ln.startswith("pocketshell: ssh executable "))
    assert line.lower().startswith(f"pocketshell: ssh executable {native} (openssh_for_windows".lower()), line


def test_interpreter_config_and_key_paths_with_spaces_and_non_ascii(tmp_path, sshd, gateway, fake_broker):
    python = os.environ.get("POCKETSHELL_E2E_SPACE_PYTHON")
    if not python:
        pytest.skip("POCKETSHELL_E2E_SPACE_PYTHON not provided")
    assert " " in python
    base = tmp_path / "Fïrst Lást's cfg"
    c = Client(base, python, sshd, gateway)
    keydir = tmp_path / "kéy dir"
    keydir.mkdir()
    shutil.copyfile(sshd["key"], keydir / "id key")
    c.key = str(keydir / "id key")
    c.login(fake_broker)
    c.pin(sshd["host_pub"])
    proc = c.ssh("echo", "hello-from-spaced-python", extra=("-v",))
    err = proc.stderr.decode(errors="replace")
    assert proc.returncode == 0, err[-3000:]
    assert proc.stdout.strip() == b"hello-from-spaced-python"
    # ssh -v logs the exact ProxyCommand line it executed.
    line = next(ln for ln in err.splitlines() if "Executing proxy command" in ln)
    assert ' -P -m pocketshell gateway proxy win-e2e ' in line, line
    assert 'exec "' in line and "py space" in line, line


def test_dropped_gateway_ends_the_session_promptly(client, gateway, remote_io):
    proc = subprocess.Popen(
        client.ssh_argv(*remote_io, "sleep", "90"), stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=client.env(), cwd=client.cwd,
    )
    try:
        line = proc.stdout.readline()
        assert line.strip() == b"started", proc.stderr.read()[-2000:] if not line else line
        assert gateway.live_count() == 1
        t0 = time.monotonic()
        gateway.drop_all()
        code = proc.wait(30)
        elapsed = time.monotonic() - t0
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()
    err = proc.stderr.read().decode(errors="replace")
    assert code == 255, err
    assert elapsed < 15, elapsed
    assert "Traceback" not in err
    assert "connection to the gateway was lost" in err or "Connection closed" in err or "closed" in err, err


# --------------------------------------------------------------------------
# Console topology: no new console, no visible window, Ctrl+C teardown

HARNESS = r'''
import ctypes, json, signal, subprocess, sys, time
from ctypes import wintypes

cfg = json.load(open(sys.argv[1], encoding="utf-8"))
k32 = ctypes.WinDLL("kernel32", use_last_error=True)
u32 = ctypes.WinDLL("user32", use_last_error=True)
result = {}

class PE(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wintypes.DWORD), ("szExeFile", ctypes.c_wchar * 260)]

k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
k32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PE)]
k32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PE)]

def processes():
    snap = k32.CreateToolhelp32Snapshot(2, 0)
    pe = PE(); pe.dwSize = ctypes.sizeof(PE)
    out = []
    ok = k32.Process32FirstW(snap, ctypes.byref(pe))
    while ok:
        out.append((pe.th32ProcessID, pe.th32ParentProcessID, pe.szExeFile))
        ok = k32.Process32NextW(snap, ctypes.byref(pe))
    k32.CloseHandle(snap)
    return out

def descendants(root):
    procs = processes()
    found, frontier = [], [root]
    while frontier:
        parent = frontier.pop()
        for pid, ppid, exe in procs:
            if ppid == parent and pid not in [f[0] for f in found] and pid != root:
                found.append((pid, ppid, exe)); frontier.append(pid)
    return found

def console_pids():
    buf = (wintypes.DWORD * 4096)()
    n = k32.GetConsoleProcessList(buf, 4096)
    return list(buf[:n])

def visible_window_pids():
    pids = []
    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def cb(hwnd, _):
        if u32.IsWindowVisible(hwnd):
            pid = wintypes.DWORD()
            u32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            pids.append(pid.value)
        return True
    u32.EnumWindows(cb, 0)
    return pids

if cfg.get("ctrl_c"):
    k32.SetConsoleCtrlHandler(None, False)       # children: Ctrl+C enabled
    signal.signal(signal.SIGINT, signal.SIG_IGN)  # this harness survives it

proc = subprocess.Popen(cfg["argv"], env=cfg["env"], cwd=cfg["cwd"], stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
result["first_line"] = proc.stdout.readline().decode(errors="replace").strip()
time.sleep(1.0)
tree = descendants(proc.pid)
result["root"] = proc.pid
result["tree"] = tree
result["console"] = console_pids()
result["visible"] = visible_window_pids()
if cfg.get("ctrl_c"):
    t0 = time.monotonic()
    result["fired"] = k32.GenerateConsoleCtrlEvent(0, 0)
    try:
        out, err = proc.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill(); out, err = proc.communicate()
    result["exit_seconds"] = time.monotonic() - t0
    deadline = time.monotonic() + 10
    pids = {p[0] for p in tree}
    alive = []
    while time.monotonic() < deadline:
        alive = [p for p in processes() if p[0] in pids and p[2] == next(t[2] for t in tree if t[0] == p[0])]
        if not alive:
            break
        time.sleep(0.2)
    result["survivors"] = alive
else:
    out, err = proc.communicate(timeout=120)
result["code"] = proc.returncode
result["stdout"] = out.decode(errors="replace")[-2000:]
result["stderr"] = err.decode(errors="replace")[-4000:]
json.dump(result, open(cfg["result"], "w", encoding="utf-8"))
'''


def _run_harness(tmp_path, client, argv, *, creationflags, startupinfo=None, ctrl_c=False) -> dict:
    harness = tmp_path / "harness.py"
    harness.write_text(HARNESS, encoding="utf-8")
    result = tmp_path / "result.json"
    cfg = tmp_path / "cfg.json"
    cfg.write_text(json.dumps({
        "argv": argv, "env": client.env(), "cwd": str(client.cwd),
        "result": str(result), "ctrl_c": ctrl_c,
    }), encoding="utf-8")
    proc = subprocess.Popen([sys.executable, str(harness), str(cfg)],
                            creationflags=creationflags, startupinfo=startupinfo)
    assert proc.wait(180) == 0
    return json.loads(result.read_text(encoding="utf-8"))


def _hidden_new_console():
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = 0  # SW_HIDE
    return dict(creationflags=subprocess.CREATE_NEW_CONSOLE, startupinfo=si)


@pytest.mark.parametrize("launch", ["hidden-console", "no-window"])
def test_proxy_shares_the_ssh_console_and_opens_no_window(tmp_path, client, remote_io, launch):
    kwargs = _hidden_new_console() if launch == "hidden-console" else dict(creationflags=CREATE_NO_WINDOW)
    res = _run_harness(tmp_path, client, client.ssh_argv(*remote_io, "sleep", "4"), **kwargs)
    assert res["code"] == 0, res
    assert res["first_line"] == "started", res
    exes = [t[2].lower() for t in res["tree"]]
    assert "ssh.exe" in exes, res
    ssh_pid = next(t[0] for t in res["tree"] if t[2].lower() == "ssh.exe")
    proxies = [t for t in res["tree"] if t[1] == ssh_pid]
    assert proxies and all(t[2].lower() == "python.exe" for t in proxies), res
    # No process in the tree got a console of its own (a new console
    # brings its own conhost.exe child) …
    assert "conhost.exe" not in exes, res
    # … every one of them is attached to the harness' console …
    assert res["console"], res
    missing = [t for t in res["tree"] if t[0] not in res["console"]]
    assert not missing, res
    # … and none owns a visible window.
    tree_pids = {t[0] for t in res["tree"]}
    assert not tree_pids & set(res["visible"]), res


def test_console_ctrl_c_ends_the_session_cleanly(tmp_path, client, remote_io):
    res = _run_harness(tmp_path, client, client.ssh_argv(*remote_io, "sleep", "60"),
                       ctrl_c=True, **_hidden_new_console())
    assert res["first_line"] == "started", res
    assert res["fired"] == 1, res
    assert res["exit_seconds"] < 20, res
    assert res["survivors"] == [], res
    assert "Traceback" not in res["stderr"] and "KeyboardInterrupt" not in res["stderr"], res
    assert "finished" not in res["stdout"], res


def test_fleet_qualifier_passes_against_this_host(tmp_path, client, sshd, gateway):
    """scripts/windows-gateway-qualify.py — what the fleet runs on its real
    laptops — must itself pass here, end to end, non-interactively."""
    script = Path(__file__).resolve().parents[2] / "scripts" / "windows-gateway-qualify.py"
    receipt = tmp_path / "receipt.json"
    log = tmp_path / "qualify.log"
    with open(log, "wb") as sink:
        proc = subprocess.Popen(
            [sys.executable, str(script), "--device-id", DEVICE, "--pinned-key", sshd["host_pub"],
             "--user", sshd["user"], "--identity", sshd["key"],
             "--server", f"ws://127.0.0.1:{gateway.port}", "--trust-gateway", "127.0.0.1", "--insecure-dev",
             "--remote-os", "windows", "--json", str(receipt)],
            stdin=subprocess.DEVNULL, stdout=sink, stderr=subprocess.STDOUT,
            env=client.env(), cwd=client.cwd,
        )
        try:
            proc.wait(600)
        except subprocess.TimeoutExpired:
            subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True)
            proc.wait()
    out = log.read_text(encoding="utf-8", errors="replace")
    print(out)
    assert proc.returncode == 0, out[-5000:]
    assert out.rstrip().splitlines()[-1].startswith("RESULT: PASS")
    doc = json.loads(receipt.read_text(encoding="utf-8"))
    assert doc["result"] == "PASS"
    assert {c["check"] for c in doc["checks"]} >= {
        "platform", "ssh.exe", "proxycommand", "login", "pin", "remote-echo", "exit-status",
        "binary-roundtrip", "wrong-pin", "console", "transport-loss", "ctrl-c",
    }
