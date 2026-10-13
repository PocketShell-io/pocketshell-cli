"""Tests for single instance enforcement."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock
import sys
import pytest

from pocketshell.tray.single_instance import SingleInstance


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX flock requires fcntl")
def test_posix_single_instance_acquisition(tmp_path: Path):
    lock1 = SingleInstance(name="test_app", lock_dir=tmp_path, platform="linux")
    assert lock1.acquire() is True
    assert lock1.is_acquired is True

    # Concurrent attempt fails
    lock2 = SingleInstance(name="test_app", lock_dir=tmp_path, platform="linux")
    assert lock2.acquire() is False
    assert lock2.is_acquired is False

    # Release first instance
    lock1.release()
    assert lock1.is_acquired is False

    # Now second instance can acquire
    assert lock2.acquire() is True
    lock2.release()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX flock requires fcntl")
def test_posix_context_manager(tmp_path: Path):
    with SingleInstance(name="ctx_app", lock_dir=tmp_path, platform="linux") as acquired:
        assert acquired is True
        # Within block, second attempt fails
        lock2 = SingleInstance(name="ctx_app", lock_dir=tmp_path, platform="linux")
        assert lock2.acquire() is False

    # Exiting block releases the lock
    lock3 = SingleInstance(name="ctx_app", lock_dir=tmp_path, platform="linux")
    assert lock3.acquire() is True
    lock3.release()


def test_windows_named_mutex(monkeypatch):
    mock_kernel32 = MagicMock()
    mock_ctypes = MagicMock()
    mock_ctypes.windll.kernel32 = mock_kernel32

    monkeypatch.setattr("ctypes.windll", mock_ctypes.windll, raising=False)
    import sys

    monkeypatch.setitem(sys.modules, "ctypes", mock_ctypes)

    # 1. Success on Windows
    mock_kernel32.CreateMutexW.return_value = 12345
    mock_kernel32.GetLastError.return_value = 0

    win_lock1 = SingleInstance(name="win_test", platform="win32")
    assert win_lock1.acquire() is True
    assert win_lock1.is_acquired is True

    mock_kernel32.CreateMutexW.return_value = 0
    assert SingleInstance(name="failed", platform="win32").acquire() is False

    # 2. Collision (ERROR_ALREADY_EXISTS = 183)
    mock_kernel32.CreateMutexW.return_value = 12345
    mock_kernel32.GetLastError.return_value = 183

    win_lock2 = SingleInstance(name="win_test", platform="win32")
    assert win_lock2.acquire() is False

    # 3. Release
    win_lock1.release()
    mock_kernel32.CloseHandle.assert_called_with(12345)


@pytest.mark.skipif(sys.platform != "win32", reason="native Windows mutex test")
def test_native_windows_mutex():
    import uuid
    name = "tray-test-" + uuid.uuid4().hex
    first, second = SingleInstance(name=name), SingleInstance(name=name)
    try:
        assert first.acquire()
        assert not second.acquire()
        first.release()
        assert second.acquire()
    finally:
        first.release()
        second.release()
