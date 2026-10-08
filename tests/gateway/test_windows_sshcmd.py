import os
from pathlib import Path
import sys

import pytest

pytestmark = pytest.mark.skipif(os.name != 'nt', reason='native Windows path/argv handling')


def test_native_windows_proxy_and_paths():
    from pocketshell.gateway import sshcmd
    from pocketshell.gateway.endpoint import resolve_endpoint
    endpoint = resolve_endpoint(None, False)
    command = sshcmd.proxy_command('win-host', endpoint, python=r'C:\Program Files\Python\python.exe')
    assert command.startswith('"C:/Program Files/Python/python.exe" -P -m pocketshell')
    assert "'" not in command
    argv = sshcmd.build_ssh_argv(ssh=r'C:\Windows\System32\OpenSSH\ssh.exe',
        device_id='win-host', endpoint=endpoint, pin_file=Path(r'C:\Users\me\.config\pocketshell\gateway_known_hosts'),
        python=r'C:\Python\python.exe')
    assert 'UserKnownHostsFile=C:/Users/me/.config/pocketshell/gateway_known_hosts' in argv
    assert 'ForwardAgent=no' in argv
    assert 'StrictHostKeyChecking=yes' in argv
    env = sshcmd.ssh_environment({'SHELL': 'original'})
    assert env['SHELL'] == 'original'


def test_native_windows_proxy_refuses_command_expansion():
    from pocketshell.gateway import sshcmd
    from pocketshell.gateway.endpoint import resolve_endpoint
    for value in (r'C:\Python\%USERPROFILE%\python.exe', r'C:\Python\bad&name.exe', r'C:\Python\bad!name.exe'):
        with pytest.raises(sshcmd.SshArgsError):
            sshcmd.proxy_command('win-host', resolve_endpoint(None, False), python=value)
