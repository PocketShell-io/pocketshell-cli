#!/usr/bin/env python3
"""Qualify `pocketshell gateway ssh` on a real Windows client (laptop / Win35).

Run it with the SAME interpreter that runs pocketshell (the one whose
``python -m pocketshell`` you use), from a normal console, after
``pocketshell login`` and ``pocketshell gateway pin DEVICE``:

    & "C:\\path\\to\\python.exe" scripts\\windows-gateway-qualify.py `
        --device-id home-lab --pinned-key "ssh-ed25519 AAAA..." `
        --user me --identity C:\\Users\\me\\.ssh\\id_ed25519 `
        [--server wss://gw.example --trust-gateway gw.example] `
        [--remote-os posix|windows] [--json receipt.json]

It is non-interactive and read-only with respect to your configuration:
it never pins, logs in/out, edits ssh config, PATH, profiles, DefaultShell
or anything global. Every process it starts either shares this console
(no new window) or runs in a hidden console it owns (Ctrl+C check), so
nothing becomes visible and your own console never receives a signal.
The wrong-pin check uses a throwaway pin file in a private temp dir.

Prints one PASS/FAIL line per check and a final RESULT line; exit status
0 only when every check passed. No token is ever read or printed.

Checks: platform/interpreter, ssh.exe selection + version, ProxyCommand
quoting, login present, pin matches --pinned-key, remote echo, exit status
propagation, 4 MiB+ binary round trip (all byte values), wrong pin fails
closed, console membership / no new console or window, transport loss
ends the session promptly, console Ctrl+C tears down cleanly.
Interactive checks (resize, Ctrl+C inside a remote PTY, detach/reconnect)
are listed in docs/windows-gateway-client.md.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time

CREATE_NO_WINDOW = 0x08000000
MARK = "pocketshell-qualify"
WINDOWS_REMOTE_CAT = (
    'python -c "import msvcrt,os,shutil,sys;msvcrt.setmode(0,os.O_BINARY);'
    'msvcrt.setmode(1,os.O_BINARY);shutil.copyfileobj(sys.stdin.buffer,sys.stdout.buffer)"'
)


# --------------------------------------------------------------------------
# Win32 process/console helpers (ctypes, no dependencies)


def _k32():
    import ctypes

    return ctypes.WinDLL("kernel32", use_last_error=True)


def processes() -> list[tuple[int, int, str]]:
    import ctypes
    from ctypes import wintypes

    class PE(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_size_t),
                    ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", wintypes.DWORD), ("szExeFile", ctypes.c_wchar * 260)]

    k32 = _k32()
    k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    k32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PE)]
    k32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PE)]
    k32.CloseHandle.argtypes = [wintypes.HANDLE]
    snap = k32.CreateToolhelp32Snapshot(2, 0)
    pe = PE()
    pe.dwSize = ctypes.sizeof(PE)
    out = []
    ok = k32.Process32FirstW(snap, ctypes.byref(pe))
    while ok:
        out.append((pe.th32ProcessID, pe.th32ParentProcessID, pe.szExeFile))
        ok = k32.Process32NextW(snap, ctypes.byref(pe))
    k32.CloseHandle(snap)
    return out


def descendants(root: int) -> list[tuple[int, int, str]]:
    procs = processes()
    found: list[tuple[int, int, str]] = []
    frontier = [root]
    while frontier:
        parent = frontier.pop()
        for pid, ppid, exe in procs:
            if ppid == parent and pid != root and all(f[0] != pid for f in found):
                found.append((pid, ppid, exe))
                frontier.append(pid)
    return found


def console_pids() -> list[int]:
    from ctypes import wintypes

    buf = (wintypes.DWORD * 4096)()
    n = _k32().GetConsoleProcessList(buf, 4096)
    return list(buf[:n])


def visible_window_pids() -> list[int]:
    import ctypes
    from ctypes import wintypes

    u32 = ctypes.WinDLL("user32", use_last_error=True)
    pids: list[int] = []

    @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    def cb(hwnd, _):
        if u32.IsWindowVisible(hwnd):
            pid = wintypes.DWORD()
            u32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            pids.append(pid.value)
        return True

    u32.EnumWindows(cb, 0)
    return pids


def kill_tree(pid: int) -> None:
    subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True,
                   creationflags=CREATE_NO_WINDOW)


def _first_line(proc, timeout: float) -> str:
    """First stdout line of ``proc`` or "" after ``timeout`` (then the
    whole process tree is killed so nothing is left behind)."""
    import threading

    box: list = []
    t = threading.Thread(target=lambda: box.append(proc.stdout.readline()), daemon=True)
    t.start()
    t.join(timeout)
    if not box:
        kill_tree(proc.pid)
        return ""
    return box[0].decode(errors="replace").strip()


def hidden_console_kwargs() -> dict:
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = 0  # SW_HIDE
    return dict(creationflags=subprocess.CREATE_NEW_CONSOLE, startupinfo=si)


def _clean(text: str, limit: int = 300) -> str:
    text = "".join(c if (c.isprintable() or c == " ") else " " for c in text)
    return " ".join(text.split())[-limit:]


# --------------------------------------------------------------------------


class Qualifier:
    def __init__(self, args: argparse.Namespace) -> None:
        self.a = args
        self.python = args.python or sys.executable
        self.results: list[dict] = []
        self.env = dict(os.environ)
        self.env.pop("SSH_AUTH_SOCK", None)

    # ---- plumbing
    def record(self, name: str, ok: bool, detail: str = "") -> bool:
        self.results.append({"check": name, "ok": bool(ok), "detail": detail})
        print(f"{'PASS' if ok else 'FAIL'} {name}: {detail}", flush=True)
        return ok

    def server_args(self) -> list[str]:
        out = []
        if self.a.server:
            out += ["--server", self.a.server]
        if self.a.trust_gateway:
            out += ["--trust-gateway", self.a.trust_gateway]
        if self.a.insecure_dev:
            out.append("--insecure-dev")
        return out

    def ssh_argv(self, *remote: str, extra: tuple = ()) -> list[str]:
        argv = [self.python, "-m", "pocketshell", "gateway", "ssh", self.a.device_id]
        if self.a.user:
            argv += ["-l", self.a.user]
        if self.a.identity:
            argv += ["-i", self.a.identity]
        return argv + self.server_args() + ["--", *extra, *remote]

    def run(self, argv, stdin: bytes = b"", timeout: float = 0):
        """subprocess.run, but a timeout kills the WHOLE tree (ssh.exe and
        the proxy keep the pipes open otherwise) and is reported as exit
        -1 instead of hanging."""
        timeout = timeout or self.a.timeout
        proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=self.env)
        try:
            out, err = proc.communicate(stdin, timeout=timeout)
        except subprocess.TimeoutExpired:
            kill_tree(proc.pid)
            out, err = proc.communicate()
            return subprocess.CompletedProcess(argv, -1, out, err + b"\n(timed out)")
        return subprocess.CompletedProcess(argv, proc.returncode, out, err)

    def remote(self, kind: str, *arg: str) -> list[str]:
        win = self.a.remote_os == "windows"
        if kind == "echo":
            return ["echo", arg[0]]
        if kind == "exit":
            return ["exit", arg[0]]
        if kind == "cat":
            if self.a.remote_cat:
                return [self.a.remote_cat]
            if win:
                # A binary-safe stdin->stdout echo needs a real program on a
                # Windows host (cmd has none, and powershell.exe's host
                # interferes with redirected stdin): Python on PATH.
                return [WINDOWS_REMOTE_CAT]
            return ["cat"]
        if kind == "sleep":
            seconds = arg[0]
            if win:
                return [f"echo started& ping -n {int(seconds) + 1} 127.0.0.1 >NUL& echo finished"]
            return [f"echo started; sleep {seconds}; echo finished"]
        raise ValueError(kind)

    # ---- checks
    def check_platform(self) -> bool:
        ok = sys.platform == "win32" and sys.version_info >= (3, 11)
        base = os.path.basename(self.python).lower()
        ok = ok and base != "pythonw.exe"
        return self.record("platform", ok, f"{sys.platform} Python {sys.version.split()[0]} at {self.python}")

    def check_ssh(self) -> bool:
        from pocketshell.gateway import sshcmd, winssh

        try:
            ssh = sshcmd.find_ssh()
        except sshcmd.SshArgsError as exc:
            return self.record("ssh.exe", False, str(exc))
        version = winssh.ssh_version(ssh)
        self.ssh = ssh
        ok = version.startswith("OpenSSH_for_Windows")
        src = "POCKETSHELL_SSH" if os.environ.get(winssh.SSH_ENV_VAR) else "inbox System32"
        return self.record("ssh.exe", ok, f"{ssh} ({version}) via {src}")

    def check_proxy_command(self) -> bool:
        from pocketshell.gateway import endpoint, sshcmd

        try:
            ep = endpoint.resolve_endpoint(self.a.server, self.a.insecure_dev, self.a.trust_gateway)
            pc = sshcmd.proxy_command(self.a.device_id, ep, python=self.python, insecure_dev=self.a.insecure_dev)
        except Exception as exc:  # noqa: BLE001 - reported, not raised
            return self.record("proxycommand", False, _clean(str(exc)))
        return self.record("proxycommand", pc.startswith('"'), pc)

    def check_login(self) -> bool:
        p = self.run([self.python, "-m", "pocketshell", "whoami"])
        return self.record("login", p.returncode == 0,
                           "session present" if p.returncode == 0 else _clean(p.stderr.decode(errors="replace")))

    def check_pin(self) -> bool:
        from pocketshell.gateway import pins

        try:
            expected = pins.parse_host_key(self.a.pinned_key)
            entry = pins.require_pin_entry(self.a.device_id)
        except Exception as exc:  # noqa: BLE001
            return self.record("pin", False, _clean(str(exc)))
        self.alias = entry.alias
        ok = entry.key == expected
        return self.record("pin", ok, f"{entry.key.fingerprint} {'matches' if ok else 'DIFFERS from'} --pinned-key")

    def check_echo(self) -> bool:
        token = f"{MARK}-{os.urandom(4).hex()}"
        p = self.run(self.ssh_argv(*self.remote("echo", token)))
        ok = p.returncode == 0 and p.stdout.strip() == token.encode()
        return self.record("remote-echo", ok, f"exit {p.returncode}" + ("" if ok else " " + _clean(p.stderr.decode(errors="replace"))))

    def check_exit_status(self) -> bool:
        p = self.run(self.ssh_argv(*self.remote("exit", "7")))
        return self.record("exit-status", p.returncode == 7, f"remote exit 7 -> {p.returncode}")

    def check_binary(self) -> bool:
        data = bytes(range(256)) * 4096 + os.urandom(3 * 1024 * 1024) + b"\r\n\x1a\x00\x1b[8;50;132t"
        p = self.run(self.ssh_argv(*self.remote("cat")), stdin=data, timeout=self.a.timeout)
        ok = p.returncode == 0 and p.stdout == data
        detail = (f"{len(data)} bytes round trip sha256 {hashlib.sha256(data).hexdigest()[:16]} "
                  f"got {len(p.stdout)} bytes exit {p.returncode}")
        return self.record("binary-roundtrip", ok, detail)

    def check_wrong_pin(self) -> bool:
        """ssh.exe with this device's hardened argv but a throwaway pin file
        holding a different key: must refuse before authenticating."""
        from pocketshell.gateway import endpoint, sshcmd

        # A well-formed ed25519 key that is certainly not the host's.
        wrong = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpa"
        with tempfile.TemporaryDirectory(prefix="psq") as d:
            pin = os.path.join(d, "known_hosts")
            with open(pin, "w", encoding="ascii") as f:
                f.write(f"{self.alias} {wrong} {self.a.device_id}\n")
            try:
                ep = endpoint.resolve_endpoint(self.a.server, self.a.insecure_dev, self.a.trust_gateway)
                argv = sshcmd.build_ssh_argv(
                    ssh=self.ssh, device_id=self.a.device_id, endpoint=ep, pin_file=pin,
                    user=self.a.user, identity=self.a.identity,
                    extra=("echo", "must-not-run"), insecure_dev=self.a.insecure_dev,
                    python=self.python, alias=self.alias,
                )
            except Exception as exc:  # noqa: BLE001
                return self.record("wrong-pin", False, _clean(str(exc)))
            p = self.run(argv)
        err = p.stderr.decode(errors="replace")
        ok = (p.returncode == 255 and b"must-not-run" not in p.stdout
              and ("HOST IDENTIFICATION HAS CHANGED" in err or "verification failed" in err))
        return self.record("wrong-pin", ok, f"exit {p.returncode}, refused={'yes' if ok else 'NO'}")

    def _start_session(self, seconds: int, **popen):
        proc = subprocess.Popen(self.ssh_argv(*self.remote("sleep", str(seconds))), env=self.env,
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **popen)
        first = _first_line(proc, self.a.timeout)
        return proc, first

    def check_console(self) -> bool:
        own = console_pids()
        if not own:
            return self.record("console", False, "run the qualifier from a console")
        proc, first = self._start_session(6)
        time.sleep(1.0)
        tree = descendants(proc.pid)
        cons = set(console_pids())
        visible = set(visible_window_pids())
        try:
            out, err = proc.communicate(timeout=self.a.timeout)
        except subprocess.TimeoutExpired:
            kill_tree(proc.pid)
            out, err = proc.communicate()
        exes = [t[2].lower() for t in tree]
        ssh_pids = [t[0] for t in tree if t[2].lower() == "ssh.exe"]
        proxies = [t for t in tree if t[1] in ssh_pids]
        problems = []
        if first != "started":
            problems.append(f"no session ({_clean(err.decode(errors='replace'))})")
        if not ssh_pids:
            problems.append("no ssh.exe")
        if not proxies:
            problems.append("no ProxyCommand process")
        if "conhost.exe" in exes:
            problems.append("a child allocated its own console")
        if [t for t in tree if t[0] not in cons]:
            problems.append("a child is outside this console")
        if {t[0] for t in tree} & visible:
            problems.append("a child owns a visible window")
        tree_s = ", ".join(f"{t[2]}:{t[0]}" for t in tree)
        return self.record("console", not problems and proc.returncode == 0,
                           "; ".join(problems) or f"all in this console, no window [{tree_s}]")

    def check_transport_loss(self) -> bool:
        proc, first = self._start_session(90)
        try:
            if first != "started":
                return self.record("transport-loss", False, "session did not start")
            time.sleep(1.0)
            tree = descendants(proc.pid)
            ssh_pids = [t[0] for t in tree if t[2].lower() == "ssh.exe"]
            proxies = [t[0] for t in tree if t[1] in ssh_pids]
            if not proxies:
                return self.record("transport-loss", False, "no ProxyCommand process")
            t0 = time.monotonic()
            for pid in proxies:  # the transport dies (as on a gateway/network drop)
                kill_tree(pid)
            code = proc.wait(30)
            elapsed = time.monotonic() - t0
        finally:
            if proc.poll() is None:
                kill_tree(proc.pid)
                proc.wait()
        return self.record("transport-loss", code == 255 and elapsed < 15,
                           f"ssh ended with {code} {elapsed:.1f}s after the transport died")

    def check_ctrl_c(self) -> bool:
        """Inside a hidden console of our own: Ctrl+C reaches ssh.exe and
        the proxy; the proxy must not crash, and everything must go away."""
        cfg = {
            "argv": self.ssh_argv(*self.remote("sleep", "60")),
            "env": self.env,
        }
        with tempfile.TemporaryDirectory(prefix="psq") as d:
            cfg["result"] = os.path.join(d, "r.json")
            cfg_path = os.path.join(d, "c.json")
            with open(cfg_path, "w", encoding="utf-8") as f:
                json.dump(cfg, f)
            p = subprocess.Popen([self.python, os.path.abspath(__file__), "--_ctrl-c-harness", cfg_path],
                                 **hidden_console_kwargs())
            try:
                p.wait(self.a.timeout + 90)
            except subprocess.TimeoutExpired:
                kill_tree(p.pid)
                p.wait()
            try:
                with open(cfg["result"], encoding="utf-8") as f:
                    res = json.load(f)
            except OSError:
                return self.record("ctrl-c", False, f"harness exit {p.returncode}, no result")
        ok = (res.get("first") == "started" and res.get("fired") == 1 and res.get("seconds", 99) < 20
              and not res.get("survivors") and "Traceback" not in res.get("stderr", "")
              and "KeyboardInterrupt" not in res.get("stderr", ""))
        return self.record("ctrl-c", ok, f"exit {res.get('code')} after {res.get('seconds', 0):.1f}s, "
                                         f"survivors {len(res.get('survivors') or [])}")

    def run_all(self) -> int:
        print(f"{MARK}: device {self.a.device_id}, remote {self.a.remote_os}", flush=True)
        gate = self.check_platform() and self.check_ssh() and self.check_proxy_command()
        if gate:
            gate = self.check_login() and self.check_pin()
        if gate:
            for check in (self.check_echo, self.check_exit_status, self.check_binary, self.check_wrong_pin,
                          self.check_console, self.check_transport_loss, self.check_ctrl_c):
                try:
                    check()
                except Exception as exc:  # noqa: BLE001
                    self.record(check.__name__.replace("check_", ""), False, f"error {type(exc).__name__}: {_clean(str(exc))}")
        passed = sum(r["ok"] for r in self.results)
        ok = gate and passed == len(self.results)
        print(f"RESULT: {'PASS' if ok else 'FAIL'} ({passed}/{len(self.results)})", flush=True)
        if self.a.json:
            receipt = {"result": "PASS" if ok else "FAIL", "checks": self.results,
                       "python": self.python, "device_id": self.a.device_id,
                       "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
            with open(self.a.json, "w", encoding="utf-8") as f:
                json.dump(receipt, f, indent=2)
        return 0 if ok else 1


def _ctrl_c_harness(cfg_path: str) -> int:
    """Runs inside the hidden console: start a session, Ctrl+C the whole
    (owned) console, report how it ended."""
    import signal

    with open(cfg_path, encoding="utf-8") as f:
        cfg = json.load(f)
    k32 = _k32()
    k32.SetConsoleCtrlHandler(None, False)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    res: dict = {}
    proc = subprocess.Popen(cfg["argv"], env=cfg["env"], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    res["first"] = _first_line(proc, 90)
    time.sleep(1.0)
    tree = descendants(proc.pid)
    t0 = time.monotonic()
    res["fired"] = k32.GenerateConsoleCtrlEvent(0, 0)
    try:
        out, err = proc.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
    res["seconds"] = time.monotonic() - t0
    res["code"] = proc.returncode
    res["stderr"] = err.decode(errors="replace")[-3000:]
    res["stdout"] = out.decode(errors="replace")[-500:]
    names = {t[0]: t[2] for t in tree}
    alive: list = []
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        alive = [p for p in processes() if names.get(p[0]) == p[2]]
        if not alive:
            break
        time.sleep(0.2)
    res["survivors"] = alive
    with open(cfg["result"], "w", encoding="utf-8") as f:
        json.dump(res, f)
    return 0


def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if argv[:1] == ["--_ctrl-c-harness"]:
        return _ctrl_c_harness(argv[1])
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--device-id", required=True)
    ap.add_argument("--pinned-key", required=True, help="the 'keytype base64' line you pinned")
    ap.add_argument("--user", help="remote login name (-l)")
    ap.add_argument("--identity", help="private key file (-i)")
    ap.add_argument("--server")
    ap.add_argument("--trust-gateway")
    ap.add_argument("--insecure-dev", action="store_true", help="DEV ONLY loopback ws://")
    ap.add_argument("--remote-os", choices=("posix", "windows"), default="posix")
    ap.add_argument("--remote-cat", help="remote command echoing stdin to stdout byte-exactly "
                    "(default: `cat`; Windows hosts: `python -c ...` from PATH)")
    ap.add_argument("--python", help="interpreter running pocketshell (default: this one)")
    ap.add_argument("--json", help="also write the receipt as JSON here")
    ap.add_argument("--timeout", type=float, default=90, help="per-session timeout in seconds (default 90)")
    args = ap.parse_args(argv)
    if sys.platform != "win32":
        print("FAIL platform: this qualifier is for native Windows clients", flush=True)
        return 1
    return Qualifier(args).run_all()


if __name__ == "__main__":
    sys.exit(main())
