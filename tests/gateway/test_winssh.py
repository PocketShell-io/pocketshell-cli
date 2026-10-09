"""Windows code paths of `gateway ssh` / `gateway proxy`, runnable on any OS.

Every Windows decision takes an explicit ``platform`` (never a global
``sys.platform`` patch), and the quoting is checked against independent
oracles for each layer the ProxyCommand passes through on Windows:

1. OpenSSH ``readconf.c`` ``argv_split`` (syntax check of the -o line);
2. ``percent_expand`` (``%%`` -> ``%``);
3. Win32-OpenSSH ``build_commandline_string``: a string starting with ``"``
   reaches ``CreateProcessW`` verbatim (no cmd.exe);
4. the Microsoft C runtime command-line split in python.exe;
5. (for an explicit MSYS/Git ssh override) POSIX ``/bin/sh -c``.
"""

from __future__ import annotations

import os
import shlex
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from pocketshell.gateway import sshcmd, winssh
from pocketshell.gateway.endpoint import resolve_endpoint

# Imported before any fake_account fixture replaces pocketshell.account.
import test_gateway_proxy  # noqa: E402

WIN = "win32"
SSH_EXE = r"C:\Windows\System32\OpenSSH\ssh.exe"


# --------------------------------------------------------------------------
# Independent oracles


def openssh_argv_split(s: str) -> list[str]:
    """Port of OpenSSH misc.c argv_split(s, …, terminate_on_comment=1)."""
    out = []
    i, n = 0, len(s)
    while i < n:
        if s[i] in " \t":
            i += 1
            continue
        if s[i] == "#":
            break
        quote = None
        arg = []
        while i < n:
            ch = s[i]
            if ch == "\\":
                nxt = s[i + 1] if i + 1 < n else ""
                if nxt in ("'", '"', "\\") or (quote is None and nxt == " "):
                    i += 1
                    arg.append(s[i])
                else:
                    arg.append(ch)
            elif quote is None and ch in " \t":
                break
            elif quote is None and ch in "\"'":
                quote = ch
            elif quote is not None and ch == quote:
                quote = None
            else:
                arg.append(ch)
            i += 1
        if i >= n and quote is not None:
            raise ValueError("invalid quotes")
        out.append("".join(arg))
    return out


def openssh_percent_expand(s: str) -> str:
    out, i = [], 0
    while i < len(s):
        if s[i] == "%":
            if i + 1 < len(s) and s[i + 1] == "%":
                out.append("%")
                i += 2
                continue
            raise ValueError(f"unexpected %-token in {s!r}")  # we use no tokens
        out.append(s[i])
        i += 1
    return "".join(out)


def win32_openssh_cmdline(command_string: str) -> str:
    """What reaches CreateProcessW (misc.c build_commandline_string with an
    empty argv). Only the leading-quote branch is modelled: anything else
    is reported, because it would be rewritten."""
    if not command_string.startswith('"'):
        raise AssertionError("Win32-OpenSSH would rewrite a command not starting with a quote")
    return '"' + command_string[1:]


def msvcrt_split(cmdline: str) -> list[str]:
    """Microsoft C runtime (2008+) argv parsing, incl. the argv[0] rule."""
    args = []
    i, n = 0, len(cmdline)
    # argv[0]: up to the next quote if quoted, else up to whitespace; no escapes
    if cmdline.startswith('"'):
        j = cmdline.index('"', 1)
        args.append(cmdline[1:j])
        i = j + 1
    else:
        while i < n and cmdline[i] not in " \t":
            i += 1
        args.append(cmdline[:i])
    while True:
        while i < n and cmdline[i] in " \t":
            i += 1
        if i >= n:
            return args
        arg, quoted = [], False
        while i < n:
            if cmdline[i] == "\\":
                j = i
                while j < n and cmdline[j] == "\\":
                    j += 1
                count = j - i
                if j < n and cmdline[j] == '"':
                    arg.append("\\" * (count // 2))
                    if count % 2:
                        arg.append('"')
                        i = j + 1
                    else:
                        i = j
                else:
                    arg.append("\\" * count)
                    i = j
                continue
            ch = cmdline[i]
            if ch == '"':
                if quoted and i + 1 < n and cmdline[i + 1] == '"':
                    arg.append('"')
                    i += 2
                    continue
                quoted = not quoted
                i += 1
                continue
            if not quoted and ch in " \t":
                break
            arg.append(ch)
            i += 1
        args.append("".join(arg))


def through_win32_openssh(proxy_command: str) -> list[str]:
    openssh_argv_split(proxy_command)  # must not raise ("invalid quotes")
    expanded = openssh_percent_expand(proxy_command)
    return msvcrt_split(win32_openssh_cmdline(expanded))


def through_posix_sh(proxy_command: str) -> list[str]:
    return shlex.split(openssh_percent_expand(proxy_command), posix=True)


# --------------------------------------------------------------------------
# ProxyCommand


INTERPRETERS = [
    r"C:\Python311\python.exe",
    r"C:\Users\First Last\AppData\Local\Programs\Python\Python312\python.exe",
    r"C:\Users\José Ñandú\venvs\ps\Scripts\python.exe",
    r"C:\Users\O'Brien\100% (work) & play!\^caret\Scripts\python.exe",
    r"C:\Program Files (x86)\a;b,c=d#e\python.exe",
    r"D:\FIRSTL~1\py\python.exe",
    r"\\server\share\py\python.exe",
]


@pytest.mark.parametrize("python", INTERPRETERS)
@pytest.mark.parametrize(
    "server,insecure,trust",
    [
        (None, False, None),
        ("wss://relay.pocketshell.io", False, None),
        ("wss://gw.example.com:8443", False, "gw.example.com"),
        ("wss://[2001:db8::1]:8443", False, "2001:db8::1"),
        ("ws://127.0.0.1:8080", True, "127.0.0.1"),
    ],
)
def test_windows_proxy_command_round_trips_every_layer(python, server, insecure, trust):
    ep = resolve_endpoint(server, insecure, trust)
    cmd = sshcmd.proxy_command("Home-Lab.01", ep, python=python, insecure_dev=insecure, platform=WIN)
    assert cmd.startswith('"')
    expected = [python.replace("\\", "/"), "-P", "-m", "pocketshell", "gateway", "proxy", "Home-Lab.01"]
    if server and ep.ws_base != "wss://gateway.pocketshell.io":
        expected += ["--server", ep.ws_base]
    if trust:
        expected += ["--trust-gateway", ep.host]
    if insecure:
        expected.append("--insecure-dev")
    assert through_win32_openssh(cmd) == expected
    # Same string under an MSYS/Git ssh (sh -c), the only other way it is run.
    assert through_posix_sh(cmd) == expected
    # No backslash anywhere: nothing can escape the closing quote.
    assert "\\" not in cmd


def test_windows_proxy_command_doubles_percent_and_keeps_cmd_metachars_inert():
    ep = resolve_endpoint(None, False)
    cmd = sshcmd.proxy_command("win-host", ep, python=r"C:\a%USERPROFILE%b\python.exe", platform=WIN)
    assert cmd.startswith('"C:/a%%USERPROFILE%%b/python.exe" -P -m pocketshell gateway proxy win-host')
    assert through_win32_openssh(cmd)[0] == "C:/a%USERPROFILE%b/python.exe"


@pytest.mark.parametrize(
    "python",
    [
        r"C:\a\"b\python.exe",
        r"C:\a$HOME\python.exe",
        r"C:\a`id`\python.exe",
        "C:\\a\nb\\python.exe",
        "C:\\a\x7fb\\python.exe",
        r"C:\py\ ",
        r"python.exe",
        r"Scripts\python.exe",
        "/usr/bin/python3",
        "",
    ],
)
def test_windows_proxy_command_refuses_unsafe_interpreters(python):
    with pytest.raises(sshcmd.SshArgsError):
        sshcmd.proxy_command("win-host", resolve_endpoint(None, False), python=python, platform=WIN)


def test_windows_proxy_command_refuses_unsafe_tokens():
    for bad in ("a b", 'a"b', "a\\b", "a%b", "a$b", "a`b", "a'b", "a\tb", "a&b", "a|b"):
        with pytest.raises(winssh.WindowsSshError):
            winssh.quote_proxy_command([r"C:\py\python.exe", "-m", bad])


def test_pythonw_is_replaced_by_console_python(tmp_path):
    py = r"C:\Py\pythonw.exe"
    assert winssh.proxy_interpreter(py, isfile=lambda p: p == r"C:\Py\python.exe") == r"C:\Py\python.exe"
    with pytest.raises(winssh.WindowsSshError):
        winssh.proxy_interpreter(py, isfile=lambda p: False)
    assert winssh.proxy_interpreter(r"C:\Py\python.exe") == r"C:\Py\python.exe"


def test_posix_proxy_command_unchanged_by_platform_parameter():
    ep = resolve_endpoint(None, False)
    assert sshcmd.proxy_command("home-lab", ep, python="/usr/bin/python3", platform="linux") == (
        "/usr/bin/python3 -P -m pocketshell gateway proxy home-lab"
    )


# --------------------------------------------------------------------------
# Paths given to ssh.exe


@pytest.mark.parametrize(
    "path,value",
    [
        (r"C:\Users\me\.config\pocketshell\gateway_known_hosts", "C:/Users/me/.config/pocketshell/gateway_known_hosts"),
        (r"C:\Users\First Last\.config\pocketshell\gateway_known_hosts",
         '"C:/Users/First Last/.config/pocketshell/gateway_known_hosts"'),
        (r"C:\Users\José\.config\pocketshell\gateway_known_hosts", "C:/Users/José/.config/pocketshell/gateway_known_hosts"),
        (r"C:\Users\O'Brien\kh", '"C:/Users/O\'Brien/kh"'),
        (r"C:\Users\a#b\kh", '"C:/Users/a#b/kh"'),
        (r"C:\Users\FIRSTL~1\kh", "C:/Users/FIRSTL~1/kh"),
    ],
)
def test_windows_option_paths(path, value):
    assert winssh.ssh_option_path(path, "pin file") == value
    # readconf tokenizes the value: it must come back as one path.
    assert openssh_argv_split(value) == [path.replace("\\", "/")]


@pytest.mark.parametrize(
    "path",
    [r"C:\a%d\kh", r"C:\a$HOME\kh", r"C:\a${X}\kh", r"C:\a`b\kh", r"C:\a=b\kh",
     "C:\\a\nb\\kh", r"relative\kh", r"\no-drive\kh", "/posix/kh"],
)
def test_windows_paths_refused(path):
    with pytest.raises(winssh.WindowsSshError):
        winssh.ssh_path(path, "pin file")


# --------------------------------------------------------------------------
# ssh.exe selection


def test_find_ssh_prefers_inbox_openssh_and_never_path(monkeypatch, tmp_path):
    native = r"C:\Windows\System32\OpenSSH\ssh.exe"
    # A Git-for-Windows ssh on PATH must not matter at all.
    fake_path_ssh = tmp_path / "ssh"
    fake_path_ssh.write_text("#!/bin/sh\n")
    fake_path_ssh.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    found = winssh.find_windows_ssh({}, system_directory=r"C:\Windows\System32", wow64=False,
                                    isfile=lambda p: p == native)
    assert found == native
    with pytest.raises(winssh.WindowsSshError, match="OpenSSH Client"):
        winssh.find_windows_ssh({}, system_directory=r"C:\Windows\System32", wow64=False,
                                isfile=lambda p: False)


def test_find_ssh_wow64_uses_sysnative():
    sysnative = r"C:\Windows\Sysnative\OpenSSH\ssh.exe"
    assert winssh.find_windows_ssh({}, system_directory=r"C:\Windows\System32", wow64=True,
                                   isfile=lambda p: p == sysnative) == sysnative


def test_find_ssh_override_must_be_absolute_existing_file():
    ok = r"C:\Tools\OpenSSH-Win64\ssh.exe"
    assert winssh.find_windows_ssh({"POCKETSHELL_SSH": ok}, system_directory=r"C:\Windows\System32",
                                   isfile=lambda p: p == ok) == ok
    for bad in ("ssh.exe", r"OpenSSH\ssh.exe", "/usr/bin/ssh", r"C:\missing\ssh.exe", 'C:\\a"b\\ssh.exe'):
        with pytest.raises(winssh.WindowsSshError, match="POCKETSHELL_SSH"):
            winssh.find_windows_ssh({"POCKETSHELL_SSH": bad}, system_directory=r"C:\Windows\System32",
                                    isfile=lambda p: p == ok)


def test_sshcmd_find_ssh_dispatches_on_platform(monkeypatch):
    monkeypatch.setattr(winssh, "find_windows_ssh", lambda environ=None: SSH_EXE)
    assert sshcmd.find_ssh(platform=WIN) == SSH_EXE

    def missing(environ=None):
        raise winssh.WindowsSshError("not found")

    monkeypatch.setattr(winssh, "find_windows_ssh", missing)
    with pytest.raises(sshcmd.SshArgsError, match="not found"):
        sshcmd.find_ssh(platform=WIN)


# --------------------------------------------------------------------------
# Full argv


def _win_argv(**kw):
    defaults = dict(
        ssh=SSH_EXE, device_id="win-host", endpoint=resolve_endpoint(None, False),
        pin_file=Path(r"C:\Users\First Last\.config\pocketshell\gateway_known_hosts"),
        python=r"C:\Users\First Last\venv\Scripts\python.exe", platform=WIN,
    )
    defaults.update(kw)
    return sshcmd.build_ssh_argv(**defaults)


def _opt(argv, name):
    values = [argv[i + 1] for i, a in enumerate(argv) if a == "-o" and argv[i + 1].startswith(name + "=")]
    assert len(values) == 1, (name, values)
    return values[0][len(name) + 1:]


def test_windows_argv_keeps_every_hardening_option():
    argv = _win_argv(user="me", extra=("-t", "--", "pocketshell", "sessions", "attach", "main"))
    assert argv[:3] == [SSH_EXE, "-F", "none"]
    for opt in sshcmd.HARDENING_OPTIONS:
        i = argv.index(opt)
        assert argv[i - 1] == "-o"
    assert "ClearAllForwardings=yes" in argv
    assert _opt(argv, "UserKnownHostsFile") == '"C:/Users/First Last/.config/pocketshell/gateway_known_hosts"'
    assert _opt(argv, "HostKeyAlias").startswith("pocketshell-gateway.win-host-")
    pc = _opt(argv, "ProxyCommand")
    assert through_win32_openssh(pc)[:7] == [
        "C:/Users/First Last/venv/Scripts/python.exe", "-P", "-m", "pocketshell", "gateway", "proxy", "win-host",
    ]
    # The remote command (e.g. an aplexer re-attach) is passed intact after
    # the destination, as plain ssh would.
    dest = argv.index("--")
    assert argv[dest + 2:] == ["pocketshell", "sessions", "attach", "main"]
    assert argv[dest - 1] == "-t"


def test_windows_argv_survives_ssh_exe_command_line():
    """ssh.exe gets its argv through subprocess.list2cmdline + the CRT."""
    argv = _win_argv(extra=("--", "echo", 'a "b" c'))
    line = subprocess.list2cmdline(argv)
    assert msvcrt_split(line) == argv


def test_windows_identity_path(monkeypatch):
    monkeypatch.setattr(sshcmd.os.path, "isfile", lambda p: True)
    argv = _win_argv(identity=r"C:\Users\First Last\.ssh\id_ed25519")
    assert argv[argv.index("-i") + 1] == "C:/Users/First Last/.ssh/id_ed25519"
    with pytest.raises(sshcmd.SshArgsError):
        _win_argv(identity=r"C:\Users\a%u\.ssh\id_ed25519")


@pytest.mark.parametrize(
    "extra",
    [("-o", "ProxyCommand=calc.exe"), ("-oStrictHostKeyChecking=no",), ("-F", r"C:\x"), ("-J", "x"),
     ("-A",), ("-R", "1:a:2"), ("-E", r"C:\log"), ("-S", "x"), ("-W", "a:1")],
)
def test_windows_still_refuses_weakening_args(extra):
    with pytest.raises(sshcmd.SshArgsError):
        _win_argv(extra=extra)


def test_windows_refuses_pin_path_with_percent():
    with pytest.raises(sshcmd.SshArgsError):
        _win_argv(pin_file=Path(r"C:\Users\100%\gateway_known_hosts"))


def test_windows_verbose_reports_selected_ssh(monkeypatch, capsys):
    monkeypatch.setattr(winssh, "ssh_version", lambda ssh: "OpenSSH_for_Windows_9.5p1, LibreSSL 3.8.2")
    _win_argv(extra=("-v",))
    err = capsys.readouterr().err
    assert f"ssh executable {SSH_EXE} (OpenSSH_for_Windows_9.5p1, LibreSSL 3.8.2)" in err
    _win_argv()
    assert capsys.readouterr().err == ""


def test_windows_environment_leaves_shell_alone():
    assert sshcmd.ssh_environment({"SHELL": "x"}, platform=WIN) == {"SHELL": "x"}
    assert sshcmd.ssh_environment({}, platform="linux") == {"SHELL": "/bin/sh"}


# --------------------------------------------------------------------------
# Console signals / child flags


def test_proxy_ignores_console_interrupts_only_on_windows(monkeypatch):
    from pocketshell.gateway import proxy

    calls = []
    monkeypatch.setattr(winssh, "ignore_console_interrupts", lambda: calls.append(1))
    monkeypatch.setattr(proxy, "_run", lambda *a: 0)
    assert proxy.run_proxy("win-host", resolve_endpoint(None, False), lambda: None, platform=WIN) == 0
    assert calls == [1]
    assert proxy.run_proxy("win-host", resolve_endpoint(None, False), lambda: None, platform="linux") == 0
    assert calls == [1]


def test_ignore_console_interrupts_survives_sigint():
    code = (
        "import os, signal, time\n"
        "from pocketshell.gateway.winssh import ignore_console_interrupts\n"
        "ignore_console_interrupts()\n"
        "assert signal.getsignal(signal.SIGINT) is signal.SIG_IGN\n"
        "print('ready', flush=True)\n"
        "time.sleep(1.0)\n"
        "print('alive', flush=True)\n"
    )
    proc = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE)
    assert proc.stdout.readline().strip() == b"ready"
    if os.name != "nt":
        proc.send_signal(signal.SIGINT)
    assert proc.stdout.readline().strip() == b"alive"
    assert proc.wait(10) == 0


def test_child_creationflags():
    assert winssh.child_creationflags(True) == 0
    assert winssh.child_creationflags(False) == winssh.CREATE_NO_WINDOW


@pytest.mark.skipif(os.name == "nt", reason="POSIX signal delivery variant")
def test_run_ssh_ignores_sigint_and_returns_child_status(tmp_path):
    """The waiter outlives SIGINT and reports the child's own status."""
    code = (
        "import sys\n"
        "from pocketshell.gateway.winssh import run_ssh\n"
        "sys.exit(run_ssh([sys.executable, '-c', "
        "'import signal,time,sys; signal.signal(signal.SIGINT, signal.SIG_IGN); "
        "print(\"child\", flush=True); time.sleep(1.5); sys.exit(7)']))\n"
    )
    proc = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE)
    assert proc.stdout.readline() == b"child\n"
    time.sleep(0.2)
    proc.send_signal(signal.SIGINT)
    assert proc.wait(10) == 7


def _proxy_fakes():
    return test_gateway_proxy.DEVICE, test_gateway_proxy.FakeGateway, test_gateway_proxy.ready


# --------------------------------------------------------------------------
# Byte transparency of the bridge (window-size changes, escapes, CR/LF, ^Z)


def test_bridge_passes_terminal_and_resize_traffic_untouched(fake_account):
    """Resize is ssh.exe/ConPTY end to end (an encrypted SSH channel
    request); the proxy only ever sees bytes. Whatever they are — escape
    sequences, CR/LF, Ctrl+Z, NUL — they pass unchanged both ways, in
    ≤ 32 KiB messages, on the Windows code path too."""
    import threading

    from pocketshell.gateway import proxy as gw_proxy

    DEVICE, FakeGateway, ready = _proxy_fakes()
    escapes = b"\x1b[8;50;132t\x1b[?1049h\x1b]0;title\x07\x1b[6n\r\n\x1a\x00\x03\x1c\xff"
    down = (escapes + bytes(range(256))) * 300
    up = (bytes(range(255, -1, -1)) + escapes) * 300

    def script(ws, gw):
        ws.send(ready())
        for i in range(0, len(down), 32768):
            ws.send(down[i:i + 32768])
        gw.drain(ws)

    gw = FakeGateway(script)
    try:
        in_r, in_w = os.pipe()
        out_r, out_w = os.pipe()
        got = bytearray()
        result = {}

        def reader():
            while True:
                chunk = os.read(out_r, 65536)
                if not chunk:
                    return
                got.extend(chunk)

        def run():
            result["code"] = gw_proxy.run_proxy(
                DEVICE, gw.endpoint, fake_account.module.mint_gateway_token,
                stdin_fd=in_r, stdout_fd=out_w, handshake_timeout=5, platform=WIN,
            )
            os.close(out_w)

        rt = threading.Thread(target=reader, daemon=True)
        rt.start()
        t = threading.Thread(target=run, daemon=True)
        t.start()
        view = memoryview(up)
        while view:
            view = view[os.write(in_w, view):]
        deadline = time.monotonic() + 10
        while len(got) < len(down) and time.monotonic() < deadline:
            time.sleep(0.01)
        os.close(in_w)
        t.join(15)
        rt.join(5)
        gw.done.wait(5)
        assert result.get("code") == gw_proxy.EXIT_OK
        assert bytes(got) == down
        assert b"".join(gw.received) == up
        assert all(len(m) <= 32 * 1024 for m in gw.received)
    finally:
        gw.close()
