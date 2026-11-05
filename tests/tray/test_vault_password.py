"""No interactive windows: verify native credential-dialog custody contract."""
from __future__ import annotations

import ctypes

import pytest

from pocketshell.tray import vault_password as prompt


@pytest.mark.parametrize("code", [0, prompt.ERROR_CANCELLED, 5])
def test_native_entry_never_persists_and_wipes_its_buffer(code):
    held = []
    def api(info, target, reserved, auth_error, user, user_len, password, length, save, flags):
        assert flags & prompt.DO_NOT_PERSIST and flags & prompt.KEEP_USERNAME
        assert flags & prompt.GENERIC_CREDENTIALS and flags & prompt.ALWAYS_SHOW_UI
        assert not flags & 0x40  # no save checkbox
        assert target == "PocketShell vault" and length == len(password)
        password.value = "invented fixture passphrase"
        held.append(password)
        return code
    if code == 5:
        with pytest.raises(RuntimeError, match="could not be opened"):
            prompt.prompt_password("Vault passphrase", api=api)
    else:
        result = prompt.prompt_password("Vault passphrase", api=api)
        assert result == ("invented fixture passphrase" if code == 0 else None)
    assert held[0].value == ""


@pytest.mark.skipif(__import__("sys").platform != "win32", reason="native Windows API symbol")
def test_native_credui_symbol_exists_without_opening_a_window():
    assert ctypes.WinDLL("credui").CredUIPromptForCredentialsW
