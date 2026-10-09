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
    # Win32-OpenSSH starts the ProxyCommand with CreateProcessW, never
    # cmd.exe (see pocketshell.gateway.winssh): '%' is doubled for ssh's
    # own token expansion, '&'/'!' are inert. What could end the quote or
    # be expanded by an MSYS /bin/sh is refused.
    from pocketshell.gateway import sshcmd
    from pocketshell.gateway.endpoint import resolve_endpoint
    ep = resolve_endpoint(None, False)
    command = sshcmd.proxy_command('win-host', ep, python=r'C:\Python\%USERPROFILE%\python.exe')
    assert command.startswith('"C:/Python/%%USERPROFILE%%/python.exe" -P -m pocketshell')
    for value in (r'C:\Python\bad&name.exe', r'C:\Python\bad!name.exe'):
        assert sshcmd.proxy_command('win-host', ep, python=value).startswith('"C:/Python/bad')
    for value in (r'C:\Python\$HOME\python.exe', r'C:\Python\`x`\python.exe', 'C:\\Py\nthon.exe'):
        with pytest.raises(sshcmd.SshArgsError):
            sshcmd.proxy_command('win-host', ep, python=value)
