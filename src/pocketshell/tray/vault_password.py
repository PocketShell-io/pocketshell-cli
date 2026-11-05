"""Native masked vault entry for the embedded Windows Python distribution.

Uses Windows CredUI in generic, non-persistent mode; it does not authenticate
to Windows and never saves the vault secret in Credential Manager.
"""
from __future__ import annotations

import ctypes
from ctypes import wintypes as w

DO_NOT_PERSIST = 0x00002
ALWAYS_SHOW_UI = 0x00080
GENERIC_CREDENTIALS = 0x40000
KEEP_USERNAME = 0x100000
ERROR_CANCELLED = 1223


class CredUiInfo(ctypes.Structure):
    _fields_ = [("cbSize", w.DWORD), ("hwndParent", w.HWND),
                ("pszMessageText", w.LPCWSTR), ("pszCaptionText", w.LPCWSTR),
                ("hbmBanner", w.HANDLE)]


def prompt_password(prompt: str, *, api=None) -> str | None:
    if api is None:
        library = ctypes.WinDLL("credui", use_last_error=True)
        api = library.CredUIPromptForCredentialsW
        api.argtypes = [ctypes.POINTER(CredUiInfo), w.LPCWSTR, w.HANDLE, w.DWORD,
                        w.LPWSTR, w.ULONG, w.LPWSTR, w.ULONG, ctypes.POINTER(w.BOOL), w.DWORD]
        api.restype = w.DWORD
    info = CredUiInfo(ctypes.sizeof(CredUiInfo), None,
                      prompt + "\nThis unlocks your PocketShell vault locally, not your Windows account.",
                      "PocketShell vault", None)
    username = ctypes.create_unicode_buffer("PocketShell vault", 513)
    password = ctypes.create_unicode_buffer(513)
    save = w.BOOL(False)
    try:
        code = api(ctypes.byref(info), "PocketShell vault", None, 0,
                   username, len(username), password, len(password), ctypes.byref(save),
                   DO_NOT_PERSIST | ALWAYS_SHOW_UI | GENERIC_CREDENTIALS | KEEP_USERNAME)
        if code == ERROR_CANCELLED:
            return None
        if code != 0:
            raise RuntimeError("The native vault passphrase dialog could not be opened.")
        return password.value
    finally:
        ctypes.memset(ctypes.addressof(password), 0, ctypes.sizeof(password))
