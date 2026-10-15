"""Small native dialogs for tray actions that need the user's confirmation.

Windows uses MessageBoxW and the clipboard via PowerShell. Linux uses zenity
when present, else tkinter. When no dialog backend exists, ``confirm`` returns
False, so an action that needs consent never proceeds silently.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

TITLE = "PocketShell Gateway"
_CREATE_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0
MAX_READ_BYTES = 64 * 1024 + 1


def _message_box(text: str, flags: int) -> int:
    import ctypes

    return ctypes.windll.user32.MessageBoxW(None, text, TITLE, flags)  # type: ignore[attr-defined]


def _tk():
    import tkinter as tk

    root = tk.Tk()
    root.withdraw()
    return root


def info(text: str) -> None:
    if sys.platform == "win32":
        _message_box(text, 0x40)
        return
    if shutil.which("zenity"):
        subprocess.run(["zenity", "--info", "--no-markup", f"--title={TITLE}", f"--text={text}"], check=False)
        return
    try:
        from tkinter import messagebox

        root = _tk()
        messagebox.showinfo(TITLE, text, parent=root)
        root.destroy()
    except Exception:
        pass


def confirm(text: str) -> bool:
    if sys.platform == "win32":
        return _message_box(text, 0x20 | 0x1 | 0x100) == 1  # question, OK/Cancel, default Cancel
    if shutil.which("zenity"):
        proc = subprocess.run(["zenity", "--question", "--no-markup", f"--title={TITLE}", f"--text={text}"],
                              check=False)
        return proc.returncode == 0
    try:
        from tkinter import messagebox

        root = _tk()
        answer = messagebox.askokcancel(TITLE, text, parent=root, default="cancel")
        root.destroy()
        return bool(answer)
    except Exception:
        return False


def read_clipboard() -> Optional[str]:
    """Clipboard text, or None when it cannot be read."""
    if sys.platform == "win32":
        commands = [["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "Get-Clipboard -Raw"]]
    else:
        commands = [["wl-paste", "--no-newline"], ["xclip", "-selection", "clipboard", "-o"],
                    ["xsel", "--clipboard", "--output"]]
    for cmd in commands:
        if not shutil.which(cmd[0]):
            continue
        try:
            kwargs: dict = {"capture_output": True, "timeout": 10}
            if _CREATE_NO_WINDOW:
                kwargs["creationflags"] = _CREATE_NO_WINDOW
            proc = subprocess.run(cmd, **kwargs)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if proc.returncode == 0:
            return proc.stdout[:MAX_READ_BYTES].decode("utf-8", "replace")
    return None


def choose_file(title: str) -> Optional[str]:
    """Text of a user-chosen file (bounded), or None when cancelled."""
    path: Optional[str] = None
    if shutil.which("zenity"):
        proc = subprocess.run(["zenity", "--file-selection", f"--title={title}"], capture_output=True, check=False)
        if proc.returncode != 0:
            return None
        path = proc.stdout.decode("utf-8", "replace").strip()
    else:
        try:
            from tkinter import filedialog

            root = _tk()
            path = filedialog.askopenfilename(parent=root, title=title) or None
            root.destroy()
        except Exception:
            return None
    if not path:
        return None
    with Path(path).open("rb") as stream:
        return stream.read(MAX_READ_BYTES).decode("utf-8", "replace")
