"""Windows installer entry point; the CLI and UI use the same bundled Python.

The gateway's guardian owns the endpoint and helper. This UI only requests its
documented lifecycle, and remembers a deliberate Stop across login and crashes.
"""
from __future__ import annotations

import ctypes
import json
import logging
import re
import os
from pathlib import Path
import subprocess
import sys
import threading
import time
import uuid
import webbrowser


def home() -> Path:
    return Path(os.environ["LOCALAPPDATA"]) / "PocketShellGateway"


def run_cli(args, *, timeout=600, input=None, pending=False, accepted=(0,)):
    proc = subprocess.run(
        [sys.executable, "-I", "-B", "-m", "pocketshell", *args],
        input=input, capture_output=True, timeout=timeout,
        creationflags=0x08000000 if sys.platform == "win32" else 0,
    )
    try:
        doc = json.loads(proc.stdout)
    except (ValueError, UnicodeDecodeError):
        raise RuntimeError(f"PocketShell command failed (exit {proc.returncode})") from None
    if proc.returncode not in accepted and not (pending and proc.returncode == 3):
        error = doc.get("error") or {}
        raise RuntimeError(error.get("message") or f"PocketShell command failed (exit {proc.returncode})")
    return doc


def agent(action, *args, **kw):
    kw.setdefault("accepted", {"status": (0, 3, 4), "stop": (0, 4), "start": (0, 3)}.get(action, (0,)))
    return run_cli(["gateway", "agent", action, *args, "--json", "--operation-id", uuid.uuid4().hex], **kw)


def message(text, *, question=False):
    return ctypes.windll.user32.MessageBoxW(None, text, "PocketShell Gateway", 0x40 | (1 if question else 0))


def setup(root: Path):
    """Generate a private endpoint; browser approval supplies account identity.

    Interrupted setup resumes from authority.json; it never regenerates a key.
    An existing unrelated agent binding is refused instead of replaced.
    """
    from pocketshell.gateway.service_user_agent import agent_dir

    authority = home() / "managed-runtime" / "authority.json"
    binding_path = Path(agent_dir()) / "binding.json"
    if binding_path.exists():
        binding = json.loads(binding_path.read_text())
        if Path(binding.get("authority") or "").resolve() != authority.resolve():
            raise RuntimeError("An existing gateway belongs to another installation. Use its existing tray or migrate it first.")
    if not authority.exists():
        message("PocketShell will install its bundled aplexer, Git Bash and private SSH endpoint. This can take a few minutes.")
        agent("install", "--user-data", str(home()), "--catalog", str(root.parent / "host-runtime-catalog.json"),
              "--staged", str(root), "--endpoint-keys", "generate", "--port", "22235", timeout=1800)
    receipt = json.loads(authority.read_text())
    installed = installed_root(receipt)
    # All subsequent commands use the measured installed closure.
    global_interpreter = installed / "python" / "python.exe"
    if Path(sys.executable).resolve() != global_interpreter.resolve():
        subprocess.Popen([str(installed / "GatewayTray.exe"), "--setup"], creationflags=0x08000000)
        return False
    if not binding_path.exists():
        agent("bind", "--manifest", receipt["endpoint"]["manifest"], "--authority", str(authority),
              "--expect-binding-sha256", "none")
    binding = json.loads(binding_path.read_text())
    if not binding.get("enrolled"):
        login = agent("login-start", "--label", "PocketShell Windows Gateway")
        if login.get("state") != "already-logged-in":
            public = login["login"]
            webbrowser.open(public["verificationUri"])
            if message(f"Approve this gateway in your browser. Code: {public['userCode']}\n\nClick OK after approving, or Cancel to finish later.", question=True) != 1:
                return False
            for _ in range(10):
                result = agent("login-complete", "--login", login["operationId"], "--timeout", "60", pending=True)
                if result.get("state") == "approved":
                    break
            else:
                raise RuntimeError("Sign-in is still pending. Run Gateway Setup again after approving.")
        agent("start", "--timeout", "300", timeout=900)  # enrollment probes the generated endpoint
        config = home() / "managed-runtime" / "enrollment"
        helper = installed / "bin" / "pocketshell-link.exe"
        agent("enroll", "--config-dir", str(config), "--helper", str(helper))
        agent("bind", "--manifest", receipt["endpoint"]["manifest"], "--authority", str(authority),
              "--config-dir", str(config), "--helper", str(helper))
    if not Path(receipt["keys"]["authorizedKeys"]).read_text().strip():
        message("The gateway is enrolled. Select your CLIENT's SSH public key (.pub) next. Only that key will be allowed to connect. Never select a private key.")
        key = select_public_key()
        if not key:
            return False
        agent("authorize-key", "--public-key-stdin", "--confirmed", input=key.encode("utf-8"))
    agent("start", "--timeout", "300", timeout=900)
    set_enabled(True)
    from pocketshell.tray.autostart import install_autostart
    ok, detail = install_autostart(command=f'"{installed / "GatewayTray.exe"}"')
    if not ok:
        raise RuntimeError(detail)
    message("PocketShell Gateway is ready and will start at login. Right-click its tray icon for status, sessions and controls.")
    return True


def select_public_key():
    """Use the native file picker; no shell, profile or command interpolation."""
    from ctypes import wintypes as w

    class OPENFILENAME(ctypes.Structure):
        _fields_ = [("size", w.DWORD), ("owner", w.HWND), ("instance", w.HINSTANCE),
                    ("filter", w.LPCWSTR), ("custom", w.LPWSTR), ("maxCustom", w.DWORD),
                    ("index", w.DWORD), ("file", w.LPWSTR), ("maxFile", w.DWORD),
                    ("fileTitle", w.LPWSTR), ("maxTitle", w.DWORD), ("initial", w.LPCWSTR),
                    ("title", w.LPCWSTR), ("flags", w.DWORD), ("offset", w.WORD),
                    ("extension", w.WORD), ("defaultExt", w.LPCWSTR), ("data", w.LPARAM),
                    ("hook", ctypes.c_void_p), ("template", w.LPCWSTR), ("reserved", ctypes.c_void_p),
                    ("reserved2", w.DWORD), ("flagsEx", w.DWORD)]
    path = ctypes.create_unicode_buffer(32768)
    dialog = OPENFILENAME()
    dialog.size = ctypes.sizeof(dialog)
    dialog.filter = "SSH public keys (*.pub)\0*.pub\0\0"
    dialog.file = ctypes.cast(path, w.LPWSTR)
    dialog.maxFile = len(path)
    dialog.title = "Select the SSH PUBLIC key of your connecting client"
    dialog.flags = 0x1000 | 0x800 | 0x8  # existing file/path; do not change cwd
    if not ctypes.windll.comdlg32.GetOpenFileNameW(ctypes.byref(dialog)):
        return None
    chosen = Path(path.value)
    if chosen.suffix.lower() != ".pub" or chosen.stat().st_size > 16384:
        raise RuntimeError("Select a small OpenSSH .pub file, not a private key.")
    return chosen.read_text(encoding="utf-8").strip()


def enabled():
    try:
        return json.loads((home() / "tray-preferences.json").read_text())["enabled"] is True
    except (OSError, ValueError, KeyError):
        return True


def installed_root(receipt):
    expected = home() / "managed-runtime"
    if (Path(receipt["location"]["root"]).resolve() != expected.resolve()
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", receipt["release"])):
        raise RuntimeError("The gateway installation receipt names an unexpected location.")
    return expected / "releases" / receipt["release"]


def set_enabled(value):
    home().mkdir(parents=True, exist_ok=True)
    target = home() / "tray-preferences.json"
    temp = target.with_suffix(".tmp")
    temp.write_text(json.dumps({"enabled": bool(value)}))
    temp.replace(target)


def needs_recovery(doc):
    """Remote offline is handled by the helper; only dead local children recover."""
    endpoint = doc.get("endpoint") or {}
    outbound = doc.get("outbound") or {}
    return (doc.get("state") == "stopped" or endpoint.get("state") == "stopped"
            or (endpoint.get("guardianLaunch") or {}).get("running") is False
            or outbound.get("state") == "stopped")


def control(action):
    """Only the bound guardian controls this endpoint; no PATH/task fallback."""
    try:
        if action in ("stop", "restart"):
            set_enabled(False)
            agent("stop", timeout=120)
        if action in ("start", "restart"):
            agent("start", "--timeout", "300", timeout=900)
            set_enabled(True)
        return True, f"Gateway {action} completed"
    except (RuntimeError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)


def observe_agent():
    """Read custody and native process identities for display, without launching.

    Full closure and authority validation still gates every start/bind. A tray
    refresh observes the protected binding, manifest hash, process births and
    pinned SSH host key, rather than re-hashing 10,000 unopened files each time.
    """
    from pocketshell.gateway import service_common, service_user_agent, service_windows
    api = service_windows.WindowsApi()
    with service_user_agent._OperationLock():
        binding, manifest, key = service_user_agent.load_binding(api=api, runner=service_common.run_child,
                                                                revalidate=False)
        owner, endpoint, outbound, state, _ = service_user_agent._collect(
            binding, manifest, key, api, service_common.run_child)
    return {"owner": owner, "endpoint": endpoint, "outbound": outbound, "state": state}


def managed_status():
    from pocketshell.gateway import status
    from pocketshell.gateway.service_agent_endpoint import BACKEND_DIRS
    from pocketshell.runtime import sessions

    receipt = json.loads((home() / "managed-runtime/authority.json").read_text())
    installed_root(receipt)
    local = observe_agent()
    endpoint = Path(receipt["endpoint"]["state"]).parent
    env = dict(os.environ, APLEXER_CONFIG=str(endpoint / "aplexer.toml"))
    env.update({k: str(endpoint / "backend" / v) for k, v in BACKEND_DIRS.items()})
    def enumerate_sessions():
        managed, errors = sessions.enumerate_live_sessions(env=env)
        existing, other_errors = sessions.enumerate_live_sessions()
        rows = {s.aplexer_id: s for s in [*existing, *managed]}
        return list(rows.values()), [*errors, *other_errors]
    # Read recent authentication records, not an unbounded log. OpenSSH normally
    # emits to its Operational event channel on Windows, including our endpoint.
    log_text = ""
    for log in Path(receipt["endpoint"]["state"]).glob("*/daemon.stderr.log"):
        with log.open("rb") as stream:
            stream.seek(max(0, log.stat().st_size - (1 << 20)))
            log_text += stream.read(1 << 20).decode("utf-8", "replace")
    try:
        events = subprocess.run([
            str(Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"),
            "-NoProfile", "-NonInteractive", "-Command",
            "Get-WinEvent -LogName 'OpenSSH/Operational' -MaxEvents 200 -ErrorAction Stop | ForEach-Object { $_.Message }"],
            capture_output=True, timeout=8, creationflags=0x08000000)
        log_text += events.stdout.decode("utf-8", "replace")
    except (OSError, subprocess.TimeoutExpired):
        pass
    keys = status.load_authorized_keys_comments([receipt["keys"]["authorizedKeys"]])
    doc = status.collect_gateway_status(auth_log_text=log_text, auth_keys_comments=keys,
                                        enumerate_sessions_fn=enumerate_sessions)
    outbound = local.get("outbound") or {}
    doc["agent"].update(installed=True, running=outbound.get("state") == "running", pid=outbound.get("pid"))
    doc["state"], doc["summary"] = status.derive_state(doc["agent"], doc["sshd"], doc["device_id"])
    return doc


def status_document():
    # Polling failures are data for the tray, never a modal dialog in a child.
    try:
        return managed_status()
    except Exception as exc:
        logging.exception("Managed status unavailable")
        return {"v": 1, "state": "error", "summary": f"Gateway status unavailable: {str(exc)[:300]}",
                "clients": [], "sessions": [], "errors": [str(exc)[:300]]}


def run_tray(root):
    from pocketshell.tray.app import TrayApp
    from pocketshell.tray.autostart import install_autostart
    from pocketshell.tray.single_instance import SingleInstance
    from pocketshell.tray.status_client import GatewayStatusClient

    class ManagedClient(GatewayStatusClient):
        def __init__(self):
            super().__init__(status_command=[sys.executable, "-I", "-B", "-m", "pocketshell.tray_bundle", "--status"])
            self.guard = threading.Lock()
            self.last_retry = 0.0

        def fetch_status(self, timeout=120):
            with self.guard:
                if enabled() and time.monotonic() - self.last_retry >= 30:
                    self.last_retry = time.monotonic()
                    try:
                        status = observe_agent()
                        if needs_recovery(status):
                            # STOP reaps measured custody before replacing a dead generation.
                            agent("stop", timeout=90)
                            if enabled():
                                agent("start", "--timeout", "300", timeout=900)
                    except (RuntimeError, subprocess.TimeoutExpired):
                        logging.exception("Gateway recovery refused; will retry")
                return super().fetch_status(timeout=timeout)

        def start_gateway(self, timeout=120):
            with self.guard:
                return control("start")

        def stop_gateway(self, timeout=90):
            with self.guard:
                return control("stop")

        def restart_gateway(self, timeout=180):
            with self.guard:
                return control("restart")

    class ManagedApp(TrayApp):
        def do_open_logs(self):
            os.startfile(home())

        def do_control(self, action):
            ok, detail = getattr(self.status_client, action + "_gateway")()
            if not ok:
                self.notify(detail, "Gateway needs attention")
                logging.error("Gateway %s failed: %s", action, detail)
            self.poll_once()

        def do_start(self):
            self.do_control("start")

        def do_stop(self):
            self.do_control("stop")

        def do_restart(self):
            self.do_control("restart")

        def _poll_worker(self):
            while not self._stop_event.is_set():
                if (home() / "tray-exit").exists():
                    self.quit()
                    return
                try:
                    self.poll_once()
                except Exception:
                    logging.exception("Tray status refresh failed")
                self._stop_event.wait(self.poll_interval)

    instance = SingleInstance()
    if not instance.acquire():
        return
    try:
        ManagedApp(status_client=ManagedClient(), autostart_installer=lambda: install_autostart(
            command=f'"{root / "GatewayTray.exe"}"')).run()
    finally:
        instance.release()


def main():
    if sys.platform != "win32":
        raise SystemExit("The bundled tray installer supports Windows x64.")
    root = Path(sys.executable).parent.parent
    home().mkdir(parents=True, exist_ok=True)
    logging.basicConfig(filename=home() / "tray.log", level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    try:
        if "--uninstall" in sys.argv:
            set_enabled(False)
            (home() / "tray-exit").touch()
            agent("stop", timeout=120)
            return
        if "--status" in sys.argv:
            print(json.dumps(status_document()))
            return
        authority = home() / "managed-runtime/authority.json"
        if authority.exists():
            installed = installed_root(json.loads(authority.read_text()))
            if root.resolve() != installed.resolve():
                subprocess.Popen([str(installed / "GatewayTray.exe"), *sys.argv[1:]], creationflags=0x08000000)
                return
        if "--setup" in sys.argv or not (home() / "managed-runtime" / "authority.json").exists():
            if not setup(root):
                return
        (home() / "tray-exit").unlink(missing_ok=True)
        run_tray(root)
    except Exception as exc:
        logging.exception("Gateway tray failed")
        message(f"PocketShell Gateway needs attention: {exc}\n\nRun Gateway Setup again to resume. Logs: {home()}")
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
