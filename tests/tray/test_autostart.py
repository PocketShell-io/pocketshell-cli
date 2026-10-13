"""Tests for cross-platform autostart management."""

from __future__ import annotations

from pathlib import Path

from pocketshell.tray.autostart import (
    LINUX_DESKTOP_FILENAME,
    RUN_KEY_NAME,
    generate_desktop_entry,
    get_default_autostart_command,
    install_autostart,
    is_autostart_installed,
    remove_autostart,
)


def test_default_autostart_command():
    cmd = get_default_autostart_command()
    assert "-m pocketshell tray" in cmd or "pocketshell tray" in cmd


def test_generate_desktop_entry():
    entry = generate_desktop_entry("my-custom-tray-cmd")
    assert "[Desktop Entry]" in entry
    assert "Type=Application" in entry
    assert "Exec=my-custom-tray-cmd" in entry
    assert "Terminal=false" in entry


def test_linux_autostart_lifecycle(tmp_path: Path):
    fake_home = tmp_path / "user"
    desktop_file = fake_home / ".config" / "autostart" / LINUX_DESKTOP_FILENAME

    # Initially not installed
    assert is_autostart_installed(platform="linux", home=fake_home) is False

    # Install
    ok, msg = install_autostart(command="pocketshell tray", platform="linux", home=fake_home)
    assert ok is True
    assert "Installed autostart desktop entry" in msg
    assert desktop_file.is_file()
    content = desktop_file.read_text(encoding="utf-8")
    assert "Exec=pocketshell tray" in content

    # Check installed
    assert is_autostart_installed(platform="linux", home=fake_home) is True

    # Remove
    ok, msg = remove_autostart(platform="linux", home=fake_home)
    assert ok is True
    assert "Removed autostart desktop entry" in msg
    assert not desktop_file.exists()
    assert is_autostart_installed(platform="linux", home=fake_home) is False

    # Remove again (idempotent)
    ok, msg = remove_autostart(platform="linux", home=fake_home)
    assert ok is True


class FakeWinreg:
    HKEY_CURRENT_USER = 1
    KEY_SET_VALUE = 2
    KEY_READ = 3
    REG_SZ = 1

    def __init__(self):
        self.store = {}

    def OpenKey(self, root, path, reserved, access):
        class KeyCtx:
            def __enter__(_s):
                return self

            def __exit__(_s, *args):
                pass

        return KeyCtx()

    def SetValueEx(self, key, value_name, reserved, val_type, value):
        self.store[value_name] = value

    CreateKeyEx = OpenKey

    def QueryValueEx(self, key, value_name):
        if value_name not in self.store:
            raise FileNotFoundError("Value not found")
        return self.store[value_name], self.REG_SZ

    def DeleteValue(self, key, value_name):
        if value_name not in self.store:
            raise FileNotFoundError("Value not found")
        del self.store[value_name]


def test_windows_autostart_lifecycle(tmp_path):
    fake_reg = FakeWinreg()

    # Initially not installed
    assert is_autostart_installed(platform="win32", winreg_mod=fake_reg, home=tmp_path) is False

    ok, msg = install_autostart(command=r'"C:\pythonw.exe" -m pocketshell tray',
                                platform="win32", winreg_mod=fake_reg, home=tmp_path)
    assert ok is True
    assert fake_reg.store.get(RUN_KEY_NAME) == r'"C:\pythonw.exe" -m pocketshell tray'
    assert is_autostart_installed(platform="win32", winreg_mod=fake_reg, home=tmp_path) is True
    assert remove_autostart(platform="win32", winreg_mod=fake_reg, home=tmp_path)[0]
    assert RUN_KEY_NAME not in fake_reg.store
    assert is_autostart_installed(platform="win32", winreg_mod=fake_reg, home=tmp_path) is False


def test_readonly_run_key_uses_startup_folder(tmp_path, monkeypatch):
    from pocketshell.tray import autostart
    class ReadOnlyRun(FakeWinreg):
        def SetValueEx(self, *args):
            raise PermissionError("Run key is read-only")
        def CreateKeyEx(self, *args):
            raise PermissionError("Run key is read-only")
    def make_shortcut(command, path):
        assert command == '"C:\\Program Files\\PocketShell\\GatewayTray.exe"'
        path.parent.mkdir(parents=True)
        path.write_bytes(b"native shortcut fixture")
    monkeypatch.setattr(autostart, "_create_startup_shortcut", make_shortcut)
    reg = ReadOnlyRun()
    ok, _ = autostart.install_autostart(command='"C:\\Program Files\\PocketShell\\GatewayTray.exe"',
                                      platform="win32", home=tmp_path, winreg_mod=reg)
    assert ok
    assert autostart.is_autostart_installed(platform="win32", home=tmp_path, winreg_mod=reg)
    assert autostart.remove_autostart(platform="win32", home=tmp_path, winreg_mod=reg)[0]
    assert not autostart.is_autostart_installed(platform="win32", home=tmp_path, winreg_mod=reg)

