"""Client for polling `pocketshell gateway status --json` and invoking actions."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional, Sequence

from pocketshell.tray.model import TrayModel

# Flag to prevent flashing console windows on Windows
_CREATE_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0


class GatewayStatusClient:
    """Manages CLI subprocess execution for gateway status and control."""

    def __init__(self, status_command: Optional[Sequence[str]] = None) -> None:
        self.status_command = status_command

    def _default_status_command(self) -> list[str]:
        return [sys.executable, "-m", "pocketshell", "gateway", "status", "--json"]

    def fetch_status(self, timeout: float = 4.0) -> TrayModel:
        """Poll gateway status by executing the CLI command."""
        cmd = list(self.status_command or self._default_status_command())
        try:
            kwargs: dict = {
                "stdin": subprocess.DEVNULL,
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
                "timeout": timeout,
            }
            if _CREATE_NO_WINDOW:
                kwargs["creationflags"] = _CREATE_NO_WINDOW

            proc = subprocess.run(cmd, **kwargs)
            stdout = proc.stdout.decode("utf-8", "replace").strip()

            if stdout:
                try:
                    data = json.loads(stdout)
                    if isinstance(data, dict):
                        return TrayModel.from_status_dict(data)
                except json.JSONDecodeError:
                    pass

            if proc.returncode != 0:
                stderr = proc.stderr.decode("utf-8", "replace").strip()
                error_msg = stderr or f"gateway status exited with code {proc.returncode}"
                return TrayModel.from_error(error_msg)

            return TrayModel.from_error("gateway status returned empty output")

        except subprocess.TimeoutExpired:
            return TrayModel.from_error("Gateway status probe timed out")
        except FileNotFoundError as exc:
            return TrayModel.from_error(f"Cannot run status command: {exc}")
        except Exception as exc:
            return TrayModel.from_error(f"Failed to query gateway status: {exc}")

    def start_gateway(self, timeout: float = 15.0) -> tuple[bool, str]:
        """Invoke `pocketshell gateway start`."""
        return self._run_command(["gateway", "start"], timeout=timeout)

    def stop_gateway(self, timeout: float = 15.0) -> tuple[bool, str]:
        """Invoke `pocketshell gateway stop`."""
        return self._run_command(["gateway", "stop"], timeout=timeout)

    def restart_gateway(self, timeout: float = 20.0) -> tuple[bool, str]:
        """Invoke `pocketshell gateway restart` (or stop then start)."""
        ok, msg = self._run_command(["gateway", "restart"], timeout=timeout)
        if ok:
            return True, msg
        # If 'gateway restart' is not a recognized verb, fallback to stop then start
        if "No such command 'restart'" in msg or "unrecognized subcommand 'restart'" in msg:
            self._run_command(["gateway", "stop"], timeout=timeout)
            return self._run_command(["gateway", "start"], timeout=timeout)
        return False, msg

    def _run_command(self, args: Sequence[str], timeout: float = 15.0) -> tuple[bool, str]:
        cmd = [sys.executable, "-m", "pocketshell", *args]
        try:
            kwargs: dict = {
                "stdin": subprocess.DEVNULL,
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
                "timeout": timeout,
            }
            if _CREATE_NO_WINDOW:
                kwargs["creationflags"] = _CREATE_NO_WINDOW

            proc = subprocess.run(cmd, **kwargs)
            out = proc.stdout.decode("utf-8", "replace").strip()
            err = proc.stderr.decode("utf-8", "replace").strip()
            combined = f"{out}\n{err}".strip() if out and err else (out or err)

            return proc.returncode == 0, combined or f"Command {' '.join(args)} finished (exit {proc.returncode})"
        except Exception as exc:
            return False, f"Failed to run pocketshell {' '.join(args)}: {exc}"


def copy_to_clipboard(text: str) -> bool:
    """Copy a string to the system clipboard across platforms."""
    if not text:
        return False

    if sys.platform == "win32":
        try:
            # Use clip.exe on Windows (built into Windows since Vista)
            kwargs: dict = {"stdin": subprocess.PIPE, "capture_output": True}
            if _CREATE_NO_WINDOW:
                kwargs["creationflags"] = _CREATE_NO_WINDOW
            proc = subprocess.run(["clip"], input=text.encode("utf-16le"), check=False, **kwargs)
            return proc.returncode == 0
        except Exception:
            pass

    # Linux / Wayland / X11
    tools = [
        ("wl-copy", []),
        ("xclip", ["-selection", "clipboard"]),
        ("xsel", ["--clipboard", "--input"]),
    ]
    for prog, args in tools:
        if shutil.which(prog):
            try:
                proc = subprocess.run([prog, *args], input=text.encode("utf-8"), check=False, capture_output=True)
                if proc.returncode == 0:
                    return True
            except Exception:
                continue

    # Fallback to tkinter if available
    try:
        import tkinter as tk

        root = tk.Tk()
        root.withdraw()
        root.clipboard_clear()
        root.clipboard_append(text)
        root.update()
        root.destroy()
        return True
    except Exception:
        pass

    return False


def resolve_logs_dir() -> Path:
    """Resolve the directory where PocketShell and gateway logs are stored."""
    if sys.platform == "win32":
        local_app = os.environ.get("LOCALAPPDATA")
        if local_app:
            candidate = Path(local_app) / "PocketShell" / "logs"
            if candidate.exists():
                return candidate
        app_data = os.environ.get("APPDATA")
        if app_data:
            candidate = Path(app_data) / "pocketshell" / "logs"
            if candidate.exists():
                return candidate

    try:
        from pocketshell.logs.paths import resolve_paths

        return resolve_paths().logs_dir
    except Exception:
        xdg_state = os.environ.get("XDG_STATE_HOME")
        state_root = Path(xdg_state) if xdg_state else Path.home() / ".local" / "state"
        return state_root / "pocketshell" / "logs"


def open_logs_folder() -> tuple[bool, str]:
    """Open the logs directory in the default system file manager."""
    folder = resolve_logs_dir()
    try:
        folder.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return False, f"Could not create logs directory: {exc}"

    try:
        if sys.platform == "win32":
            os.startfile(folder)  # type: ignore[attr-defined]
            return True, str(folder)
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(folder)])
            return True, str(folder)
        else:
            subprocess.Popen(["xdg-open", str(folder)])
            return True, str(folder)
    except Exception as exc:
        return False, f"Failed to open logs folder {folder}: {exc}"
