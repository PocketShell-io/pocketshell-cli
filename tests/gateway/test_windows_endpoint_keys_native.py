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


def _measured():
    """The production install path: known_folders() (native SystemRoot) +
    measure_system_roles. Never env or a literal."""
    from pocketshell.gateway import service_agent_endpoint as eps
    from pocketshell.gateway import service_agent_install as inst
    from pocketshell.gateway import service_windows as win

    api = win.WindowsApi()
    return inst.known_folders()["SystemRoot"], eps.measure_system_roles(api, api.current_sid())


def test_system_roles_are_measured_natively_with_the_servicing_authority():
    from pocketshell.gateway import service_agent_endpoint as eps
    from pocketshell.gateway import service_endpoint as ep

    system_root, roles = _measured()
    assert {k.casefold() for k in roles} == set(ep.SERVICING_IMAGES)  # keys are full System32 PATHS
    checked = eps.check_system_roles(roles, system_root)
    assert sorted(checked.values()) == sorted(roles.values()) and all(len(v) == 64 for v in roles.values())
    assert [r["name"] for r in eps.system_references(checked)] == ["cmd.exe", "conhost.exe"]


def _syswow64(roles, system_root):
    import re

    # GetSystemDirectoryW spells "system32": substitute case-insensitively, and prove it happened
    wow = {re.sub("(?i)system32", "SysWOW64", k): v for k, v in roles.items()}
    assert all("SysWOW64" in k for k in wow)
    return wow, system_root


def _syswow64_root(roles, system_root):
    # the SAME measured hashes claimed under a SysWOW64-shaped system root
    return roles, system_root + "\\SysWOW64"


def _one(roles, system_root):
    return dict(list(roles.items())[:1]), system_root


def _not_hex(roles, system_root):
    return {**roles, next(iter(roles)): "X" * 64}, system_root


@pytest.mark.parametrize("mutate", [_syswow64, _syswow64_root, _one, _not_hex],
                         ids=["syswow64-paths", "syswow64-system-root", "one-role", "non-hex-digest"])
def test_system_roles_refusals_on_the_production_check(mutate):
    from pocketshell.gateway import service_agent_endpoint as eps
    from pocketshell.gateway import service_agent_install as inst

    system_root, roles = _measured()
    bad, root = mutate(roles, system_root)
    with pytest.raises(inst.InstallError):
        eps.check_system_roles(bad, root)


@pytest.mark.parametrize("extra,ok", [(0, True), (1, False)])
def test_native_inventory_full_closure_bound(tmp_path, extra, ok):
    """NativePaths.inventory at exactly the agreed 16 384 files, and one over."""
    from pocketshell import windows_security as ws
    from pocketshell.gateway import service_agent_install as inst
    from pocketshell.gateway import service_windows as win

    api = win.WindowsApi()
    sid = api.current_sid()
    root = tmp_path / "managed-runtime"
    ws.write_private(root / "seed", b"0")
    rel = root / "release"
    for i in range(inst.CATALOG3_MAX_FILES + extra):
        ws.write_private(rel / f"d{i // 1000:02d}" / f"f{i:05d}", b"x")
    paths = inst.NativePaths(api)
    if ok:
        got = paths.inventory(str(rel), sid, private_root=str(root), max_files=inst.CATALOG3_MAX_FILES)
        assert len(got) == inst.CATALOG3_MAX_FILES
    else:
        with pytest.raises(inst.ServiceError, match="16384"):
            paths.inventory(str(rel), sid, private_root=str(root), max_files=inst.CATALOG3_MAX_FILES)
