"""Setup ABI v3 on a real Windows host (disposable CI runner): the key files are
measured by metadata only and are NEVER read. Synthetic, non-secret bytes; no
endpoint is generated or started here."""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="native Windows key-file measurement")


def _exclusive(path):
    """Hold ``path`` open with GENERIC_READ and share mode 0: any later open
    requesting DATA access fails with a sharing violation; a metadata-only
    open (attributes + READ_CONTROL) is not share-checked."""
    k = ctypes.WinDLL("kernel32", use_last_error=True)
    k.CreateFileW.restype = wintypes.HANDLE
    k.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID, wintypes.DWORD,
                              wintypes.DWORD, wintypes.HANDLE]
    h = k.CreateFileW(str(path), 0x80000000, 0, None, 3, 0, None)
    assert h != wintypes.HANDLE(-1).value, ctypes.get_last_error()
    return k, h


def test_key_files_are_measured_without_any_data_access(tmp_path):
    from pocketshell import windows_security as ws
    from pocketshell.gateway import service_agent_install as inst
    from pocketshell.gateway import service_windows as win

    api = win.WindowsApi()
    sid = api.current_sid()
    keys = tmp_path / "endpoint-keys"
    ws.write_private(keys / "ssh_host_ed25519_key", b"SYNTHETIC NOT A KEY\n")
    paths = inst.NativePaths(api)
    target = str(keys / "ssh_host_ed25519_key")
    k, h = _exclusive(target)
    try:
        # control: a reading measurement is refused while the file is held exclusively
        with pytest.raises(OSError):
            paths.file(target, sid, private=True, max_bytes=0, private_root=str(keys))
        got = paths.metadata(target, sid)
        assert got["canonicalPath"].casefold() == target.casefold()
    finally:
        k.CloseHandle(h)


def test_an_unprotected_key_file_is_refused(tmp_path):
    from pocketshell import windows_security as ws
    from pocketshell.gateway import service_agent_install as inst
    from pocketshell.gateway import service_windows as win

    api = win.WindowsApi()
    keys = tmp_path / "endpoint-keys"
    ws.write_private(keys / "authorized_keys", b"SYNTHETIC\n")
    loose = keys / "inherited"
    loose.write_bytes(b"SYNTHETIC\n")  # inherits the private dir's ACL: not protected
    with pytest.raises(Exception):
        inst.NativePaths(api).metadata(str(loose), api.current_sid())


def test_system_roles_are_measured_natively_with_the_servicing_authority():
    from pocketshell.gateway import service_agent_endpoint as eps
    from pocketshell.gateway import service_endpoint as ep
    from pocketshell.gateway import service_windows as win

    api = win.WindowsApi()
    roles = eps.measure_system_roles(api, api.current_sid())
    assert {k.casefold() for k in roles} == set(ep.SERVICING_IMAGES)
    import os

    assert eps.check_system_roles(roles, os.environ["SystemRoot"]) and all(len(v) == 64 for v in roles.values())
