"""Windows installer entry point; the CLI and UI use the same bundled Python.

The gateway's guardian owns the endpoint and helper. This UI only requests its
documented lifecycle, and remembers a deliberate Stop across login and crashes.
"""
from __future__ import annotations

import ctypes
import json
import logging
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


def run_cli(args, *, timeout=180, input=None, pending=False, accepted=(0,)):
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
              "--staged", str(root), "--endpoint-keys", "generate", "--port", "22235", timeout=600)
    receipt = json.loads(authority.read_text())
    installed = Path(receipt["location"]["root"]) / "releases" / receipt["release"]
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
        agent("start")  # enrollment must probe the actual generated endpoint
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
    agent("start")
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


def run_tray(root):
    from pocketshell.tray.app import TrayApp
    from pocketshell.tray.autostart import install_autostart
    from pocketshell.tray.single_instance import SingleInstance
    from pocketshell.tray.status_client import GatewayStatusClient

    class ManagedClient(GatewayStatusClient):
        def __init__(self):
            super().__init__()
            self.guard = threading.Lock()
            self.last_retry = 0.0

        def fetch_status(self, timeout=20):
            with self.guard:
                if enabled() and time.monotonic() - self.last_retry >= 30:
                    self.last_retry = time.monotonic()
                    try:
                        status = agent("status", timeout=30)
                        if needs_recovery(status):
                            # STOP reaps measured custody before replacing a dead generation.
                            agent("stop", timeout=90)
                            agent("start", timeout=120)
                    except (RuntimeError, subprocess.TimeoutExpired):
                        logging.exception("Gateway recovery refused; will retry")
                return super().fetch_status(timeout=timeout)

        def start_gateway(self, timeout=120):
            with self.guard:
                result = super().start_gateway(timeout)
                if result[0]:
                    set_enabled(True)
                return result

        def stop_gateway(self, timeout=90):
            with self.guard:
                set_enabled(False)
                return super().stop_gateway(timeout)

        def restart_gateway(self, timeout=180):
            with self.guard:
                result = super().restart_gateway(timeout)
                if result[0]:
                    set_enabled(True)
                return result

    class ManagedApp(TrayApp):
        def do_open_logs(self):
            os.startfile(home())

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
        if "--setup" in sys.argv or not (home() / "managed-runtime" / "authority.json").exists():
            if not setup(root):
                return
        run_tray(root)
    except Exception as exc:
        logging.exception("Gateway tray failed")
        message(f"PocketShell Gateway needs attention: {exc}\n\nRun Gateway Setup again to resume. Logs: {home()}")
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
