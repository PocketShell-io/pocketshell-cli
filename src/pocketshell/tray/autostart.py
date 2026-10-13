"""Autostart management for the PocketShell system tray application.

Supported platforms:
- Windows: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run (value: PocketShellTray)
- Linux: ~/.config/autostart/pocketshell-tray.desktop
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Optional

RUN_KEY_NAME = "PocketShellTray"
WINDOWS_REG_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
LINUX_DESKTOP_FILENAME = "pocketshell-tray.desktop"


def get_default_autostart_command() -> str:
    """Generate the command line to invoke `pocketshell tray` without a console window."""
    exe = Path(sys.executable)
    # On Windows, prefer `pythonw.exe` to run without a console window
    if exe.name.lower() == "python.exe":
        pythonw = exe.with_name("pythonw.exe")
        if pythonw.exists():
            return f'"{pythonw}" -m pocketshell tray'
    return f'"{exe}" -m pocketshell tray'


# --- Linux implementation ---


def get_linux_autostart_dir(home: Optional[Path] = None) -> Path:
    if home is not None:
        return home / ".config" / "autostart"
    xdg_config = os.environ.get("XDG_CONFIG_HOME")
    if xdg_config:
        return Path(xdg_config) / "autostart"
    return Path.home() / ".config" / "autostart"


def get_linux_desktop_file_path(home: Optional[Path] = None) -> Path:
    return get_linux_autostart_dir(home) / LINUX_DESKTOP_FILENAME


def generate_desktop_entry(exec_cmd: Optional[str] = None) -> str:
    cmd = exec_cmd or get_default_autostart_command()
    return (
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=PocketShell Tray\n"
        "Comment=PocketShell Gateway Tray App\n"
        f"Exec={cmd}\n"
        "Icon=utilities-terminal\n"
        "Terminal=false\n"
        "Categories=Utility;\n"
    )


# --- Windows implementation ---


def _win_open_run_key(write: bool = False, winreg_mod: Any = None):
    reg = winreg_mod or sys.modules.get("winreg")
    if reg is None:
        import winreg as reg
    access = reg.KEY_SET_VALUE if write else reg.KEY_READ
    return reg.OpenKey(reg.HKEY_CURRENT_USER, WINDOWS_REG_KEY, 0, access)


# --- Public Cross-Platform API ---


def is_autostart_installed(
    *,
    platform: Optional[str] = None,
    home: Optional[Path] = None,
    winreg_mod: Any = None,
) -> bool:
    """Check if autostart is currently configured for the user."""
    plat = platform or sys.platform
    if plat == "win32":
        try:
            reg = winreg_mod or sys.modules.get("winreg")
            if reg is None:
                import winreg as reg
            with _win_open_run_key(write=False, winreg_mod=reg) as key:
                reg.QueryValueEx(key, RUN_KEY_NAME)
                return True
        except (OSError, FileNotFoundError):
            return False
    else:
        path = get_linux_desktop_file_path(home)
        return path.is_file()


def install_autostart(
    *,
    command: Optional[str] = None,
    platform: Optional[str] = None,
    home: Optional[Path] = None,
    winreg_mod: Any = None,
) -> tuple[bool, str]:
    """Configure the system tray app to start at user login."""
    plat = platform or sys.platform
    cmd = command or get_default_autostart_command()

    if plat == "win32":
        try:
            reg = winreg_mod or sys.modules.get("winreg")
            if reg is None:
                import winreg as reg
            with _win_open_run_key(write=True, winreg_mod=reg) as key:
                reg.SetValueEx(key, RUN_KEY_NAME, 0, reg.REG_SZ, cmd)
            return True, f"Installed autostart registry entry '{RUN_KEY_NAME}'"
        except OSError as exc:
            return False, f"Failed to set Windows autostart registry key: {exc}"
    else:
        try:
            target = get_linux_desktop_file_path(home)
            target.parent.mkdir(parents=True, exist_ok=True)
            content = generate_desktop_entry(cmd)
            target.write_text(content, encoding="utf-8")
            return True, f"Installed autostart desktop entry at {target}"
        except OSError as exc:
            return False, f"Failed to create desktop autostart entry: {exc}"


def remove_autostart(
    *,
    platform: Optional[str] = None,
    home: Optional[Path] = None,
    winreg_mod: Any = None,
) -> tuple[bool, str]:
    """Remove the system tray app from user login autostart."""
    plat = platform or sys.platform

    if plat == "win32":
        try:
            reg = winreg_mod or sys.modules.get("winreg")
            if reg is None:
                import winreg as reg
            with _win_open_run_key(write=True, winreg_mod=reg) as key:
                try:
                    reg.DeleteValue(key, RUN_KEY_NAME)
                except FileNotFoundError:
                    pass
            return True, f"Removed autostart registry entry '{RUN_KEY_NAME}'"
        except OSError as exc:
            return False, f"Failed to remove Windows autostart registry key: {exc}"
    else:
        try:
            target = get_linux_desktop_file_path(home)
            if target.exists():
                target.unlink()
            return True, f"Removed autostart desktop entry at {target}"
        except OSError as exc:
            return False, f"Failed to remove desktop autostart entry: {exc}"
