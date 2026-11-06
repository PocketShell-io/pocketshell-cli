"""Actual helper-writer ACL -> trusted enrollment reader, with synthetic keys."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from pocketshell.account.shared_vault import VaultError, b64
from pocketshell.gateway import endpoint, vault_enrollment as enrollment

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="actual Windows file authority")


def icacls(*args):
    binary = Path(os.environ["SystemRoot"]) / "System32/icacls.exe"
    result = subprocess.run([str(binary), *map(str, args)], capture_output=True, creationflags=0x08000000)
    assert result.returncode == 0, (result.stdout + result.stderr).decode(errors="replace")


def public(key):
    return key.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                         serialization.PublicFormat.OpenSSH).decode()


@pytest.fixture
def local(tmp_path):
    from pocketshell import windows_security as ws
    from pocketshell.gateway.service_windows import WindowsApi
    api = WindowsApi()
    # Create the same explicit owner-only fixture ancestry as the tray. Python
    # 3.13+ mode-0700 pytest directories also add OWNER_RIGHTS, which the gateway
    # deliberately does not treat as a named owner SID. Touch only these owned
    # disposable test directories, never AppData or another shared ancestor.
    for directory in (tmp_path.parent, tmp_path):
        icacls(directory, "/inheritance:r", "/grant:r", f"*{api.current_sid()}:(OI)(CI)F",
               "/remove:g", "*S-1-3-4")
    root = tmp_path / "enrollment"
    device = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    host = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
    pem = device.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption())
    ws.write_private(root / "device_ed25519.pem", pem)
    data = {"server": endpoint.DEFAULT_SERVER, "device_id": "fixture-windows",
            "ssh_host_key": public(host)}
    path = root / "config.json"
    api.write_owned_file(str(path), json.dumps(data).encode(), api.current_sid())
    return root, path, api, data, device


def test_real_gateway_writer_config_is_accepted_and_exact_device_key_is_derived(local):
    root, path, api, data, device = local
    actual = enrollment.local_identity(root)
    assert actual == {"serverUrl": data["server"], "deviceId": data["device_id"],
                      "sshHostKey": data["ssh_host_key"], "config": data,
                      "devicePublicKey": b64(device.public_key().public_bytes(
                          serialization.Encoding.Raw, serialization.PublicFormat.Raw))}
    # Acceptance is limited to the public config, not a global relaxation.
    from pocketshell.windows_security import PrivateFileError
    with pytest.raises(PrivateFileError):
        enrollment.read_private(path)


@pytest.mark.parametrize("permission", ["R", "M"])
def test_foreign_read_or_mutation_config_acl_is_refused(local, permission):
    root, path, *_ = local
    icacls(path, "/grant", f"*S-1-1-0:{permission}")
    with pytest.raises(VaultError, match="protected by its owner"):
        enrollment.local_identity(root)


def test_inherited_config_acl_is_refused(local):
    root, path, *_ = local
    icacls(path, "/inheritance:e")
    with pytest.raises(VaultError, match="protected by its owner"):
        enrollment.local_identity(root)


def test_hardlinked_config_is_refused(local):
    root, path, *_ = local
    os.link(path, root / "second-config.json")
    with pytest.raises(VaultError, match="protected by its owner"):
        enrollment.local_identity(root)


def test_junction_ancestor_is_refused(local, tmp_path):
    root, *_ = local
    link = tmp_path / "junction"
    def quoted(value):
        return "'" + str(value).replace("'", "''") + "'"
    powershell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    result = subprocess.run([str(powershell), "-NoProfile", "-NonInteractive", "-Command",
                             f"New-Item -ItemType Junction -Path {quoted(link)} -Target {quoted(root)} | Out-Null"],
                            capture_output=True, creationflags=0x08000000)
    assert result.returncode == 0, (result.stdout + result.stderr).decode(errors="replace")
    try:
        with pytest.raises(VaultError, match="protected by its owner"):
            enrollment.local_identity(link)
    finally:
        link.rmdir()  # remove this junction itself, never recursively its target


def test_foreign_acl_swapped_after_protected_path_gate_is_refused(local, monkeypatch):
    from pocketshell.gateway.service_windows import WindowsApi
    root, path, *_ = local
    real = WindowsApi.read_private_file
    def swap_then_read(self, candidate, sid, limit):
        assert Path(candidate) == path
        icacls(path, "/grant", "*S-1-1-0:R")
        return real(self, candidate, sid, limit)
    monkeypatch.setattr(WindowsApi, "read_private_file", swap_then_read)
    with pytest.raises(VaultError, match="protected by its owner"):
        enrollment.local_identity(root)


def test_foreign_mutation_on_config_parent_is_refused(local):
    root, *_ = local
    icacls(root, "/grant", "*S-1-1-0:M")
    with pytest.raises(VaultError, match="protected by its owner"):
        enrollment.local_identity(root)


def test_privileged_acl_is_still_refused_for_the_device_private_key(local):
    from pocketshell.windows_security import PrivateFileError
    root, *_ = local
    icacls(root / "device_ed25519.pem", "/grant", "*S-1-5-32-544:F")
    with pytest.raises(PrivateFileError):
        enrollment.local_identity(root)


@pytest.mark.parametrize("changed", ["device_id", "ssh_host_key", "device_key"])
def test_valid_but_changed_local_identity_is_refused_before_publication(local, changed):
    from pocketshell import windows_security as ws
    root, path, api, data, device = local
    original = enrollment.local_identity(root)
    replacement = Ed25519PrivateKey.from_private_bytes(bytes(reversed(range(32))))
    if changed == "device_key":
        ws.write_private(root / "device_ed25519.pem", replacement.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    else:
        data[changed] = "fixture-other" if changed == "device_id" else public(replacement)
        path.unlink()
        api.write_owned_file(str(path), json.dumps(data).encode(), api.current_sid())
    with pytest.raises(VaultError, match="identity changed"):
        enrollment.same_local_identity(root, original)
