"""Single-instance protection for the PocketShell tray app.

Uses a named mutex on Windows and an advisory file lock (fcntl.flock) on Linux.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional


class SingleInstance:
    """Ensure only one instance of the tray application runs per user."""

    def __init__(
        self,
        name: str = "pocketshell_tray",
        lock_dir: Optional[Path] = None,
        platform: Optional[str] = None,
    ) -> None:
        self.name = name
        self.platform = platform or sys.platform
        self.lock_dir = lock_dir
        self._mutex_handle = None
        self._lock_file = None
        self._fd: Optional[int] = None
        self.is_acquired = False

    def acquire(self) -> bool:
        """Attempt to acquire the single-instance lock. Returns True on success."""
        if self.platform == "win32":
            return self._acquire_windows()
        return self._acquire_posix()

    def _acquire_windows(self) -> bool:
        try:
            import ctypes

            kernel32 = ctypes.windll.kernel32
            mutex_name = f"Local\\{self.name}"
            # CreateMutexW(security_attributes, initial_owner, name)
            handle = kernel32.CreateMutexW(None, False, mutex_name)
            error = kernel32.GetLastError()
            ERROR_ALREADY_EXISTS = 183
            if error == ERROR_ALREADY_EXISTS:
                if handle:
                    kernel32.CloseHandle(handle)
                return False
            self._mutex_handle = handle
            self.is_acquired = True
            return True
        except Exception:
            # Fallback to file lock if ctypes/win32 api fails
            return self._acquire_posix()

    def _acquire_posix(self) -> bool:
        import fcntl

        if self.lock_dir:
            lock_dir = self.lock_dir
        else:
            xdg_runtime = os.environ.get("XDG_RUNTIME_DIR")
            if xdg_runtime:
                lock_dir = Path(xdg_runtime) / "pocketshell"
            else:
                xdg_config = os.environ.get("XDG_CONFIG_HOME")
                base = Path(xdg_config) if xdg_config else Path.home() / ".config"
                lock_dir = base / "pocketshell"

        try:
            lock_dir.mkdir(parents=True, exist_ok=True)
            self._lock_file = lock_dir / f"{self.name}.lock"
            self._fd = os.open(
                str(self._lock_file),
                os.O_CREAT | os.O_RDWR | os.O_TRUNC,
                0o600,
            )
            fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.write(self._fd, f"{os.getpid()}\n".encode("ascii"))
            self.is_acquired = True
            return True
        except (BlockingIOError, OSError):
            if self._fd is not None:
                try:
                    os.close(self._fd)
                except OSError:
                    pass
                self._fd = None
            return False

    def release(self) -> None:
        """Release the acquired lock and clean up resources."""
        if not self.is_acquired:
            return

        if self.platform == "win32" and self._mutex_handle is not None:
            try:
                import ctypes

                ctypes.windll.kernel32.CloseHandle(self._mutex_handle)
            except Exception:
                pass
            self._mutex_handle = None

        if self._fd is not None:
            try:
                import fcntl

                fcntl.flock(self._fd, fcntl.LOCK_UN)
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None

        if self._lock_file is not None and self._lock_file.exists():
            try:
                self._lock_file.unlink()
            except OSError:
                pass
            self._lock_file = None

        self.is_acquired = False

    def __enter__(self) -> bool:
        return self.acquire()

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.release()
