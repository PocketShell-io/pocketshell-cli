"""Windows import refusal and native startup tests; no fake fcntl modules."""
import os
from pathlib import Path
import subprocess
import sys

import pytest


def test_windows_dispatcher_does_not_import_unix_commands():
    # On Unix exercise only dispatcher selection, not Windows file security.
    # Preload its allowed dependencies under the real platform, then forbid
    # Unix modules and clear any accidental earlier imports before selection.
    script = '''
import os, sys, pathlib, click
import pocketshell.account.cli, pocketshell.gateway
import importlib.abc
class RefuseUnix(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in ('fcntl', 'termios'):
            raise AssertionError('Unix-only module imported: ' + fullname)
sys.meta_path.insert(0, RefuseUnix())
for name in ('fcntl', 'termios'):
    sys.modules.pop(name, None)
real = os.name
os.name = 'nt'
try:
    import pocketshell.cli as command
finally:
    os.name = real
assert command.main(['--version']) == 0
assert command.main(['--help']) == 0
assert command.main(['gateway', '--help']) == 0
assert command.main(['sessions', 'list', '--json']) == 1
assert 'pocketshell.cards.store' not in sys.modules
assert 'pocketshell.tree.storage' not in sys.modules
assert 'pocketshell.link.daemon' not in sys.modules
'''
    result = subprocess.run([sys.executable, '-c', script], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr


@pytest.mark.skipif(os.name != 'nt', reason='requires real Windows CPython')
def test_native_startup_help_and_local_whoami(tmp_path):
    env = dict(os.environ, XDG_CONFIG_HOME=str(tmp_path))
    for args in (['--version'], ['--help'], ['login', '--help'], ['gateway', '--help'],
                 ['gateway', 'ssh', '--help'], ['gateway', 'enroll', '--help']):
        result = subprocess.run([sys.executable, '-m', 'pocketshell', *args], env=env,
                                capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stderr
    result = subprocess.run([sys.executable, '-m', 'pocketshell', 'whoami', '--json'], env=env,
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 1
    assert '"logged_in": false' in result.stdout
    assert 'Traceback' not in result.stderr


@pytest.mark.skipif(os.name != 'nt', reason='requires real Windows CPython')
def test_native_unix_daemon_is_explicitly_unsupported():
    result = subprocess.run([sys.executable, '-m', 'pocketshell', 'daemon', 'status'],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 1
    assert 'not supported on Windows' in result.stderr
    assert 'Traceback' not in result.stderr
