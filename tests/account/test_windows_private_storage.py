"""Native Windows security behavior. Unix skips are not Windows acceptance."""
import os
from pathlib import Path
import subprocess
import time

import pytest

pytestmark = pytest.mark.skipif(os.name != 'nt', reason='native Win32 DACL/handle tests')


def test_roundtrip_credentials_pins_and_delete(tmp_path, monkeypatch):
    from pocketshell.account import credentials
    from pocketshell.gateway import pins
    import base64, struct
    monkeypatch.setenv('XDG_CONFIG_HOME', str(tmp_path))
    value = credentials.Credentials('https://broker.example', 'psc_' + 'a' * 43,
                                    'abc123', 'user@example.com', int(time.time()) + 3600, 'Windows')
    path = credentials.save(value)
    assert credentials.load() == value
    blob = struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 32) + bytes(range(32))
    key = pins.parse_host_key('ssh-ed25519 ' + base64.b64encode(blob).decode())
    assert pins.add_pin('win-host', key)
    assert pins.require_pin('win-host') == key
    assert pins.remove_pin('win-host') == key
    assert pins.load_pins() == {}
    assert credentials.delete()
    assert not credentials.delete()
    assert not path.exists()


def test_acl_creation_and_broad_acl_refusal(tmp_path):
    from pocketshell import windows_security as secure
    path = tmp_path / 'private' / 'credentials.json'
    secure.write_private(path, b'secret')
    assert secure.read_private(path, 100) == b'secret'
    # Change only this test file's ACL, not any real account/host-agent file.
    result = subprocess.run(['icacls', str(path), '/grant', '*S-1-1-0:(R)'],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    with pytest.raises(secure.PrivateFileError):
        secure.read_private(path, 100)
    with pytest.raises(secure.PrivateFileError):
        secure.write_private(path, b'replacement')
    with pytest.raises(secure.PrivateFileError):
        secure.delete_private(path)


def test_directory_junction_is_refused(tmp_path):
    from pocketshell import windows_security as secure
    target = tmp_path / 'target'
    secure.write_private(target / 'data', b'secret')
    link = tmp_path / 'junction'
    result = subprocess.run(['cmd', '/c', 'mklink', '/J', str(link), str(target)],
                            capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    try:
        with pytest.raises(secure.PrivateFileError):
            secure.read_private(link / 'data', 100)
        with pytest.raises(secure.PrivateFileError):
            secure.write_private(link / 'new', b'secret')
    finally:
        os.rmdir(link)


def test_pinned_directory_cannot_be_renamed(tmp_path):
    from pocketshell import windows_security as secure
    directory = tmp_path / 'private'
    secure.write_private(directory / 'data', b'secret')
    with secure._directory(directory):
        with pytest.raises(OSError):
            directory.rename(tmp_path / 'moved')
        assert secure.read_private(directory / 'data', 100) == b'secret'
    directory.rename(tmp_path / 'moved')


def test_hardlinks_are_refused(tmp_path):
    from pocketshell import windows_security as secure
    path = tmp_path / 'private' / 'data'
    secure.write_private(path, b'secret')
    os.link(path, path.with_name('alias'))
    with pytest.raises(secure.PrivateFileError):
        secure.read_private(path, 100)


def test_alternate_stream_and_device_paths_are_refused(tmp_path):
    from pocketshell import windows_security as secure
    for path in (tmp_path / 'data:stream', tmp_path / 'CON', Path(r'\\.\C:\data')):
        with pytest.raises(secure.PrivateFileError):
            secure.write_private(path, b'secret')
