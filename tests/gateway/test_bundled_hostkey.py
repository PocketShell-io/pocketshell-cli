from pocketshell.gateway import service_hostkey as hostkey


def test_private_hostkey_probe_needs_no_inbox_client(monkeypatch):
    expected = r"C:\Users\dev\gateway\endpoint\shell\usr\bin\ssh.exe"
    monkeypatch.setattr(hostkey.sys, "platform", "win32")
    monkeypatch.setattr(hostkey.sys, "executable", r"C:\Users\dev\gateway\python\python.exe")
    monkeypatch.setattr(hostkey.os.path, "isfile", lambda p: p == expected)
    assert hostkey.find_ssh() == expected
    argv = hostkey.probe_argv(expected, 22235, r"C:\Users\dev\known_hosts", "ssh-ed25519")
    assert "StrictHostKeyChecking=yes" in argv
    assert "PubkeyAuthentication=no" in argv
    assert "PasswordAuthentication=no" in argv
