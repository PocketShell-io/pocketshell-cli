"""Native-Windows support for `gateway ssh` / `gateway proxy` (Win32-OpenSSH).

Everything here is selected by an explicit ``platform`` decision made in
:mod:`pocketshell.gateway.sshcmd` / :mod:`pocketshell.gateway.proxy`, so
the quoting rules are unit-testable on any OS. Functions that need the
real Win32 API (console, job objects, ``ssh -V``) are only called on
``win32``.

How Win32-OpenSSH runs a ProxyCommand
-------------------------------------

Source: github.com/PowerShell/openssh-portable, unchanged in this respect
from v7.7.x (the Windows 10 1809 inbox client) through v9.8.x:

1. ``readconf.c`` keeps the rest of the ``-o ProxyCommand=…`` line
   verbatim (since 8.7 it is first tokenized by ``argv_split`` purely as
   a syntax check: quotes must balance, ``\\`` escapes ``' " \\`` and
   space). See ``process_config_line_depth`` / ``case oProxyCommand``.
2. ``sshconnect.c`` ``expand_proxy_command`` prefixes ``exec `` and runs
   ``percent_expand`` (``%%`` -> ``%``; ``%h %p %r %n %k`` tokens).
3. ``ssh_proxy_connect`` (``#ifdef FORK_NOT_SUPPORTED``) does NOT use a
   shell: ``posix_spawnp(command_string + 5, argv={command_string+5})``.
4. ``contrib/win32/win32compat/w32fd.c`` ``spawn_child_internal`` builds
   the command line with ``misc.c`` ``build_commandline_string``: a string
   that starts with ``"`` is passed to ``CreateProcessW(NULL, cmdline,
   …, bInheritHandles=TRUE, flags without CREATE_NO_WINDOW, …)``
   **verbatim** (v7.7 passed every string verbatim; v8.1+ only rewrites
   strings that do not start with a quote, inserting quotes after the
   first ``.exe``+space, or around the whole string).

So there is no ``cmd.exe``: ``%VAR%``, ``^``, ``&``, ``|``, ``<``, ``>``
and ``!`` are inert. The child (python.exe) splits the command line with
the Microsoft C runtime rules. The ProxyCommand built here therefore
always starts with the double-quoted interpreter path (spaces and
non-ASCII are fine), uses ``/`` separators (no backslash can escape the
closing quote under ``argv_split`` or the CRT), doubles ``%`` for step 2,
and every other element is a validated token with no quote, backslash or
whitespace. The same string is also correct for ``/bin/sh -c`` (what an
MSYS/Git ssh would use), because ``$`` and backquote are refused in the
interpreter path.

The proxy child shares ssh.exe's console (no new window, no
``CREATE_NO_WINDOW``); see :func:`ignore_console_interrupts`.
"""

from __future__ import annotations

import ntpath
import os
import re
import signal
import subprocess
import sys
from typing import Callable, Mapping, Optional, Sequence

SSH_ENV_VAR = "POCKETSHELL_SSH"

CREATE_NO_WINDOW = 0x08000000

# Interpreter path inside the leading "…" of the ProxyCommand: refuse what
# could end the quote or be expanded by ssh / an MSYS /bin/sh.
_INTERPRETER_FORBIDDEN = re.compile(r'["$`\x00-\x1f\x7f]')
# Every later ProxyCommand element (flags, device id, URL, host).
_PLAIN_TOKEN = re.compile(r"\A[A-Za-z0-9._:/=+@-]+\Z")
_BRACKET_TOKEN = re.compile(r"\A[A-Za-z0-9._:/=+@\[\]-]+\Z")
# Paths handed to ssh as option values / -i: ssh expands %tokens and ${ENV}
# in them (the -i stat() happens before expansion, so %% cannot be used),
# readconf tokenizes the option line (quote, '=' in older strdelim).
_SSH_PATH_FORBIDDEN = re.compile(r'["%$`=\x00-\x1f\x7f]')
_DRIVE_ABS = re.compile(r"\A[A-Za-z]:/")


class WindowsSshError(ValueError):
    """Refused Windows ssh setup. Message is safe to print."""


# --------------------------------------------------------------------------
# ProxyCommand quoting


def proxy_interpreter(python: str, *, isfile: Callable[[str], bool] = os.path.isfile) -> str:
    """The interpreter for the ProxyCommand: never ``pythonw.exe``.

    pythonw is a GUI-subsystem binary; whether its stdio works depends on
    handle inheritance details, so the console ``python.exe`` next to it
    is used instead (it shares ssh.exe's console: no window).
    """
    if not python or not ntpath.isabs(python):
        raise WindowsSshError("cannot locate an absolute Python interpreter path")
    head, tail = ntpath.split(python)
    if tail.lower() == "pythonw.exe":
        sibling = ntpath.join(head, "python.exe")
        if not isfile(sibling):
            raise WindowsSshError(
                "running under pythonw.exe and no console python.exe next to it; "
                "the ProxyCommand needs a console interpreter"
            )
        return sibling
    return python


def quote_proxy_command(argv: Sequence[str]) -> str:
    """Quote a ProxyCommand argv for Win32-OpenSSH (see module docstring).

    ``argv[0]`` is an absolute Windows path; the rest are plain tokens.
    Raises :class:`WindowsSshError` for anything that cannot be expressed
    safely.
    """
    if not argv:
        raise WindowsSshError("empty ProxyCommand")
    exe = argv[0].replace("\\", "/")
    if not _DRIVE_ABS.match(exe) and not exe.startswith("//"):
        raise WindowsSshError("ProxyCommand interpreter must be an absolute Windows path")
    if _INTERPRETER_FORBIDDEN.search(exe) or exe.endswith("/") or exe != exe.rstrip():
        raise WindowsSshError(
            f"interpreter path {ascii(argv[0])[:120]} contains a double quote, "
            "'$', backquote or control character and cannot be used in a "
            "ProxyCommand; install pocketshell under a plainer path"
        )
    parts = ['"' + exe.replace("%", "%%") + '"']
    for item in argv[1:]:
        if _PLAIN_TOKEN.match(item):
            parts.append(item)
        elif _BRACKET_TOKEN.match(item):
            # e.g. wss://[::1]:8443 — quoted so an MSYS /bin/sh cannot glob it.
            parts.append('"' + item + '"')
        else:
            raise WindowsSshError(
                f"refusing to put {ascii(item)[:120]} in a Windows ProxyCommand"
            )
    return " ".join(parts)


def split_proxy_command(command: str) -> list[str]:
    """Inverse of :func:`quote_proxy_command` as the CRT would see it after
    ssh's ``%%`` expansion (test oracle; implements the subset of the
    Microsoft C runtime parsing rules that our output can contain)."""
    expanded = command.replace("%%", "%")
    out: list[str] = []
    i, n = 0, len(expanded)
    while i < n:
        while i < n and expanded[i] in " \t":
            i += 1
        if i >= n:
            break
        buf = []
        quoted = False
        while i < n and (quoted or expanded[i] not in " \t"):
            ch = expanded[i]
            if ch == '"':
                quoted = not quoted
            elif ch == "\\":
                raise ValueError("backslash not expected")
            else:
                buf.append(ch)
            i += 1
        if quoted:
            raise ValueError("unbalanced quote")
        out.append("".join(buf))
    return out


# --------------------------------------------------------------------------
# Paths handed to ssh.exe (UserKnownHostsFile, -i)


def ssh_path(path: str, what: str) -> str:
    """Validate an absolute Windows path for ssh and return it with ``/``.

    Spaces, apostrophes, ``~`` inside the path (8.3 short names) and
    non-ASCII are allowed: Win32-OpenSSH is UTF-8 inside and opens files
    with the wide API. Refused: ``" % $ ` =`` and control characters.
    """
    if not ntpath.isabs(path) or not _DRIVE_ABS.match(path.replace("\\", "/")):
        raise WindowsSshError(f"{what} path must be an absolute drive path (C:\\...)")
    value = path.replace("\\", "/")
    if _SSH_PATH_FORBIDDEN.search(value):
        raise WindowsSshError(
            f"{what} path {ascii(path)[:120]} contains a double quote, '%', '$', "
            "backquote, '=' or a control character, which OpenSSH would expand "
            "or split; move it (or set XDG_CONFIG_HOME) to a plainer path"
        )
    return value


def ssh_option_path(path: str, what: str) -> str:
    """:func:`ssh_path`, double-quoted when needed, for use as an
    ``-o Name=value`` value: readconf tokenizes values (``argv_split``:
    whitespace separates, ``'`` would open a quote, ``#`` a comment)."""
    value = ssh_path(path, what)
    if any(ch.isspace() or ch in "'#" for ch in value):
        return '"' + value + '"'
    return value


# --------------------------------------------------------------------------
# ssh.exe selection


def _real_system_directory() -> Optional[str]:
    if sys.platform != "win32":
        return None
    import ctypes

    buf = ctypes.create_unicode_buffer(32768)
    n = ctypes.windll.kernel32.GetSystemDirectoryW(buf, len(buf))
    return buf.value if 0 < n < len(buf) else None


def _is_wow64() -> bool:
    if sys.platform != "win32":
        return False
    import ctypes
    from ctypes import wintypes

    flag = wintypes.BOOL()
    k32 = ctypes.windll.kernel32
    try:
        ok = k32.IsWow64Process(k32.GetCurrentProcess(), ctypes.byref(flag))
    except AttributeError:
        return False
    return bool(ok and flag.value)


def native_ssh_candidates(
    system_directory: Optional[str] = None, *, wow64: Optional[bool] = None
) -> list[str]:
    """Absolute candidates for the inbox OpenSSH client, best first."""
    system_directory = system_directory or _real_system_directory()
    if not system_directory:
        return []
    out = [ntpath.join(system_directory, "OpenSSH", "ssh.exe")]
    if _is_wow64() if wow64 is None else wow64:
        # A 32-bit Python sees SysWOW64 as System32; the 64-bit inbox
        # client lives behind the Sysnative alias.
        root = ntpath.dirname(system_directory)
        out.append(ntpath.join(root, "Sysnative", "OpenSSH", "ssh.exe"))
    return out


def find_windows_ssh(
    environ: Optional[Mapping[str, str]] = None,
    *,
    system_directory: Optional[str] = None,
    wow64: Optional[bool] = None,
    isfile: Callable[[str], bool] = os.path.isfile,
) -> str:
    """The ssh.exe to run: ``%POCKETSHELL_SSH%`` (absolute, existing file)
    or the inbox ``System32\\OpenSSH\\ssh.exe``. PATH is never searched,
    so Git-for-Windows / MSYS / Cygwin ssh (which run ProxyCommand via
    their /bin/sh and handle consoles differently) is never picked
    silently."""
    env = os.environ if environ is None else environ
    override = env.get(SSH_ENV_VAR)
    if override:
        if not ntpath.isabs(override) or not _DRIVE_ABS.match(override.replace("\\", "/")):
            raise WindowsSshError(f"{SSH_ENV_VAR} must be an absolute path to ssh.exe")
        if any(ord(c) < 0x20 or c == '"' for c in override):
            raise WindowsSshError(f"{SSH_ENV_VAR} contains a control character or quote")
        if not isfile(override):
            raise WindowsSshError(f"{SSH_ENV_VAR}={ascii(override)[:120]} is not an existing file")
        return ntpath.normpath(override)
    for candidate in native_ssh_candidates(system_directory, wow64=wow64):
        if isfile(candidate):
            return candidate
    raise WindowsSshError(
        "the Windows OpenSSH client was not found at "
        "%SystemRoot%\\System32\\OpenSSH\\ssh.exe. Install it (Settings > "
        "System > Optional features > OpenSSH Client, or as administrator "
        "`Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0`), "
        f"or set {SSH_ENV_VAR} to the absolute path of a Win32-OpenSSH ssh.exe. "
        "ssh found on PATH (Git for Windows, MSYS2, Cygwin) is not used."
    )


def ssh_version(ssh: str, *, timeout: float = 5.0) -> str:
    """First line of ``ssh -V`` (sanitized), or ``"unknown"``. Runs with
    no window and no stdin."""
    flags = CREATE_NO_WINDOW if sys.platform == "win32" else 0
    try:
        proc = subprocess.run(
            [ssh, "-V"], stdin=subprocess.DEVNULL, capture_output=True,
            timeout=timeout, creationflags=flags,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    text = (proc.stderr or proc.stdout or b"").decode("ascii", "replace")
    line = text.strip().splitlines()[0] if text.strip() else "unknown"
    return "".join(c for c in line if 0x20 <= ord(c) < 0x7F)[:120]


# --------------------------------------------------------------------------
# Console signals (proxy) and the ssh.exe waiter (gateway ssh)


def ignore_console_interrupts() -> None:
    """Make Ctrl+C / Ctrl+Break console events a no-op for this process.

    ``gateway proxy`` shares ssh.exe's console, so every console control
    event reaches it too. ssh.exe owns those keys (in a PTY session it
    sends Ctrl+C as a byte; otherwise it decides itself whether to end);
    the proxy ends only on stdin EOF, a WebSocket close or its own error.
    The CRT's ``SIG_IGN`` is per process (unlike
    ``SetConsoleCtrlHandler(NULL, TRUE)`` it is not inherited)."""
    for name in ("SIGINT", "SIGBREAK"):
        signum = getattr(signal, name, None)
        if signum is None:
            continue
        try:
            signal.signal(signum, signal.SIG_IGN)
        except (ValueError, OSError):  # not the main thread: nothing to do
            pass


def has_console() -> bool:
    if sys.platform != "win32":
        return True
    import ctypes
    from ctypes import wintypes

    buf = (wintypes.DWORD * 1)()
    return ctypes.windll.kernel32.GetConsoleProcessList(buf, 1) != 0


def child_creationflags(console_attached: bool) -> int:
    """No console of our own → the child must not pop a new console window."""
    return 0 if console_attached else CREATE_NO_WINDOW


def _kill_on_close_job():
    """A job object that kills its members when its last handle closes
    (i.e. when this process dies, however it dies). The current process
    is assigned to it, so ssh.exe and the ProxyCommand it starts are born
    inside it without a race. Best effort: returns None if unavailable."""
    import ctypes
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateJobObjectW.restype = wintypes.HANDLE
    k32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    k32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
    ]
    k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    k32.GetCurrentProcess.restype = wintypes.HANDLE
    k32.CloseHandle.argtypes = [wintypes.HANDLE]

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [(n, ctypes.c_ulonglong) for n in (
            "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
            "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

    class BASIC(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class EXTENDED(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BASIC),
            ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    job = k32.CreateJobObjectW(None, None)
    if not job:
        return None
    info = EXTENDED()
    info.BasicLimitInformation.LimitFlags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    ok = k32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info))
    if ok and k32.AssignProcessToJobObject(job, k32.GetCurrentProcess()):
        return job  # deliberately never closed: it dies with this process
    k32.CloseHandle(job)
    return None


def run_ssh(argv: Sequence[str], env: Optional[dict] = None) -> int:
    """Run ssh.exe on Windows, wait, and return its exit status.

    - Console Ctrl+C / Ctrl+Break are ignored here while ssh runs (ssh.exe
      owns them, exactly like the exec'd ssh on POSIX), so this wrapper
      never dies before ssh and always reports ssh's own status.
    - This process joins a kill-on-close job first, so if it is killed
      (Task Manager, TerminateProcess, the console closing) ssh.exe and
      the ProxyCommand die with it instead of lingering.
    - No shell; stdio is inherited; a new console window is never created
      (CREATE_NO_WINDOW when this process has no console).
    """
    previous = {}
    for name in ("SIGINT", "SIGBREAK"):
        signum = getattr(signal, name, None)
        if signum is None:
            continue
        try:
            previous[signum] = signal.signal(signum, signal.SIG_IGN)
        except (ValueError, OSError):
            pass
    try:
        if sys.platform == "win32":
            _kill_on_close_job()
        flags = child_creationflags(has_console())
        try:
            proc = subprocess.Popen(list(argv), env=env, creationflags=flags)
        except OSError:
            sys.stderr.write("pocketshell: could not start ssh\n")
            return 127
        while True:
            try:
                return proc.wait()
            except KeyboardInterrupt:  # SIG_IGN could not be installed
                continue
    finally:
        for signum, handler in previous.items():
            try:
                signal.signal(signum, handler)
            except (ValueError, OSError):
                pass
