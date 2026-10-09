"""Windows backend of ``pocketshell gateway service``: ONE per-user task.

Registers ``\\PocketShell\\GatewayLink`` in Task Scheduler from an XML
definition (imported with ``schtasks /Create /XML``, launched with
``CREATE_NO_WINDOW``):

- principal = the CURRENT user's SID (the helper's key ACL is bound to it;
  an enrolled dir or key owned by another SID is refused), LogonType
  ``S4U`` (runs whether logged on or not, no stored password, in the
  non-interactive session 0 — nothing can ever be drawn on the desktop),
  RunLevel ``LeastPrivilege``;
- boot trigger (+30 s) and a 5-minute repeating watchdog trigger with
  ``MultipleInstancesPolicy=IgnoreNew``; no execution time limit; battery
  stops off; RestartOnFailure;
- ONE Exec action that launches the absolute, digest-allow-listed native
  helper DIRECTLY: ``Command`` = helper .exe, ``Arguments`` =
  ``run --config-dir "<dir>"``, ``WorkingDirectory`` = the helper's
  directory. No ``cmd.exe``, no shell, no redirection, anywhere
  (windows-host-agent-plan.md §3.2 + Revision 5).

Only the task itself is created, started, stopped or deleted; the
enrolled config dir, the device key and the device registration are never
modified (only their owner SID and existence are inspected).
"""

from __future__ import annotations

import base64
import hashlib
import json
import ntpath
import os
import re
import shutil
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Callable, Optional

from pocketshell.gateway import helper as gateway_helper
from pocketshell.gateway import service_common as common
from pocketshell.gateway import service_endpoint as ep
from pocketshell.gateway.service_common import (
    ChildResult,
    NotStartedError,
    ServiceError,
    ServiceStatus,
    decode,
    has_control_chars,
    run_child,
    sanitize,
)

TASK_FOLDER = "\\PocketShell\\"
TASK_LEAF = "GatewayLink"
TASK_NAME = TASK_FOLDER + TASK_LEAF
TASK_NS = "http://schemas.microsoft.com/windows/2004/02/mit/task"
MANAGED_MARKER = "Managed by `pocketshell gateway service install`"
DEFAULT_LOGON_TYPE = "S4U"
# A fixed past start boundary: the TimeTrigger exists only for its 5-minute
# repetition (the watchdog); the boot trigger is what starts it after reboot.
WATCHDOG_START_BOUNDARY = "2026-01-01T00:00:00"
# how long install waits for the task's own state to report Running
START_CONFIRM_SECONDS = 15.0

# ---------------------------------------------------------------------------
# Reviewed Windows helper allow-list (artifact trust gate).
#
# The task launches the native helper directly, so this digest check at
# install time (and in `status`) is the trust boundary for what the task
# runs. Every entry is a REVIEWED build; adding one is a reviewed source
# change, never a runtime option or environment variable.
#
#   f9582de6…dabe1  pocketshell-link-windows-amd64.exe, private qualified
#                   build of pocketshell-gateway cd7c6f6a0c7b (tree 08344a90),
#                   Go 1.27.2, 8488960 bytes (fleet Revision 3, 2026-10-09).
#
# Deliberately ABSENT (historical, must be refused): 8cbeb8f / 57f3a86e…,
# 771c9e1 / f6e357d8…. A signed release manifest replaces this list once
# the gateway pipeline publishes Windows builds (plan §4 P1/P5).
# ---------------------------------------------------------------------------
ALLOWED_HELPER_SHA256 = frozenset(
    {
        "f9582de6a3f635ec70e4daaf755479788f788d8d493c3ed1fd58812f555dabe1",
    }
)
HISTORICAL_HELPER_SHA256 = {
    "57f3a86e2166b079e99479a985fd8cbc56a91260cf3d8dee76c446e60189ac63": "8cbeb8f",
    "f6e357d8b43369b9f9de222fa9603ce523b37959b38cc4ca8bb04d68fa7c1c37": "771c9e1",
}

Runner = Callable[..., ChildResult]


# --- paths and quoting -------------------------------------------------------


def final_path(value: str) -> str:
    """Absolute, long, final form (Windows): a short 8.3 or junctioned
    spelling would not match the image path a running process reports."""
    value = os.path.realpath(os.path.abspath(value))
    if value.startswith("\\\\?\\") and value[5:6] == ":":
        value = value[4:]
    return value


def validate_path(value: str, what: str) -> str:
    """A local, absolute drive path safe to put into a task definition.

    Refuses ``"`` (it would end the quoted argument), control characters,
    and ``%`` (Task Scheduler expands ``%VAR%`` in Command / Arguments /
    WorkingDirectory), UNC/device paths (an S4U token has no network
    credentials) and relative paths.
    """
    def check_chars(candidate: str) -> None:
        if has_control_chars(candidate) or '"' in candidate or "%" in candidate:
            raise ServiceError(
                f"the {what} contains a double quote, '%' or a control character; "
                "refusing to put it into a scheduled task"
            )

    if not value:
        raise ServiceError(f"the {what} is empty")
    check_chars(value)

    def check_drive(candidate: str) -> None:
        drive, rest = ntpath.splitdrive(candidate)
        if len(drive) != 2 or drive[1] != ":" or not drive[0].isalpha() or not rest.startswith(("\\", "/")):
            raise ServiceError(f"the {what} must be an absolute local drive path (C:\\...)")

    check_drive(value)  # as given: no relative, drive-relative, UNC or \\?\ forms
    if sys.platform == "win32":
        value = final_path(value)
        check_drive(value)
    value = ntpath.normpath(value)
    check_chars(value)
    if any(":" in part for part in value[2:].split("\\")):
        raise ServiceError(f"the {what} must not name an alternate data stream")
    return value


def quote_arg(value: str) -> str:
    """Always-quoted argument, CommandLineToArgvW / Go os.Args compatible.

    Callers have already refused ``"``; only a trailing run of backslashes
    needs doubling so it does not escape the closing quote.
    """
    if '"' in value:
        raise ServiceError("refusing to quote a value containing a double quote")
    trailing = len(value) - len(value.rstrip("\\"))
    return '"' + value + "\\" * trailing + '"'


def task_arguments(config_dir: str) -> str:
    return "run --config-dir " + quote_arg(config_dir)


def action_argv(helper: str, config_dir: str) -> list:
    """The exact argv the task's process receives (no shell in between)."""
    return [helper, "run", "--config-dir", config_dir]


def parse_arguments(arguments: str) -> list:
    """Split a task Arguments string the way the helper (Go/MSVC) will."""
    args, current, in_quotes, has_token = [], [], False, False
    i = 0
    while i < len(arguments):
        ch = arguments[i]
        if ch == "\\":
            j = i
            while j < len(arguments) and arguments[j] == "\\":
                j += 1
            count = j - i
            if j < len(arguments) and arguments[j] == '"':
                current.append("\\" * (count // 2))
                if count % 2:
                    current.append('"')
                    i = j + 1
                else:
                    i = j
                has_token = True
                continue
            current.append("\\" * count)
            has_token = True
            i = j
            continue
        if ch == '"':
            in_quotes = not in_quotes
            has_token = True
        elif ch in " \t" and not in_quotes:
            if has_token:
                args.append("".join(current))
                current, has_token = [], False
        else:
            current.append(ch)
            has_token = True
        i += 1
    if has_token:
        args.append("".join(current))
    return args


# --- task XML ----------------------------------------------------------------


def _sub(parent, tag, text=None, **attrs):
    element = ET.SubElement(parent, f"{{{TASK_NS}}}{tag}", attrs)
    if text is not None:
        element.text = text
    return element


@dataclass(frozen=True)
class TaskSpec:
    """One managed task: a single direct Exec action, nothing else varies."""

    leaf: str
    command: str
    argv: tuple  # what the process receives after argv[0]
    arguments: str  # the Arguments string that yields exactly ``argv``
    working_directory: str
    boot_delay: str
    description: str

    @property
    def name(self) -> str:
        return TASK_FOLDER + self.leaf


def link_spec(helper: str, config_dir: str) -> TaskSpec:
    return TaskSpec(
        leaf=TASK_LEAF,
        command=helper,
        argv=("run", "--config-dir", config_dir),
        arguments=task_arguments(config_dir),
        working_directory=ntpath.dirname(helper),
        boot_delay="PT30S",
        description=(
            "PocketShell gateway host agent (pocketshell-link run): hidden, session 0, "
            f"runs as the enrolling user. {MANAGED_MARKER}."
        ),
    )


def build_task_xml(
    helper: str,
    config_dir: str,
    user_sid: str,
    *,
    logon_type: str = DEFAULT_LOGON_TYPE,
    enabled: bool = True,
) -> str:
    """The link task definition (plan §3.2 + Revision 5), as an XML string."""
    return build_spec_xml(
        link_spec(helper, config_dir), user_sid, logon_type=logon_type, enabled=enabled
    )


def build_spec_xml(
    spec: TaskSpec,
    user_sid: str,
    *,
    logon_type: str = DEFAULT_LOGON_TYPE,
    enabled: bool = True,
) -> str:
    """A managed task definition, as an XML string.

    Built with ElementTree, so every value is XML-escaped; the declared
    encoding is UTF-16, which :func:`task_xml_bytes` produces.
    """
    if not re.fullmatch(r"S-1-5-21(-\d+){4}|S-1-5-\d+(-\d+)*", user_sid or ""):
        raise ServiceError("refusing an unexpected principal SID")
    if logon_type not in {"S4U", "Password", "InteractiveToken"}:
        raise ServiceError(f"unsupported logon type {logon_type!r}")
    ET.register_namespace("", TASK_NS)
    task = ET.Element(f"{{{TASK_NS}}}Task", {"version": "1.4"})
    reg = _sub(task, "RegistrationInfo")
    _sub(reg, "URI", spec.name)
    _sub(reg, "Description", spec.description)

    triggers = _sub(task, "Triggers")
    boot = _sub(triggers, "BootTrigger")
    _sub(boot, "Enabled", "true")
    _sub(boot, "Delay", spec.boot_delay)
    watchdog = _sub(triggers, "TimeTrigger")
    repetition = _sub(watchdog, "Repetition")
    _sub(repetition, "Interval", "PT5M")
    _sub(repetition, "StopAtDurationEnd", "false")
    _sub(watchdog, "StartBoundary", WATCHDOG_START_BOUNDARY)
    _sub(watchdog, "Enabled", "true")

    principals = _sub(task, "Principals")
    principal = _sub(principals, "Principal", id="Author")
    _sub(principal, "UserId", user_sid)
    _sub(principal, "LogonType", logon_type)
    _sub(principal, "RunLevel", "LeastPrivilege")

    settings = _sub(task, "Settings")
    for tag, value in (
        ("MultipleInstancesPolicy", "IgnoreNew"),
        ("DisallowStartIfOnBatteries", "false"),
        ("StopIfGoingOnBatteries", "false"),
        ("AllowHardTerminate", "true"),
        ("StartWhenAvailable", "true"),
        ("RunOnlyIfNetworkAvailable", "false"),
    ):
        _sub(settings, tag, value)
    idle = _sub(settings, "IdleSettings")
    _sub(idle, "StopOnIdleEnd", "false")
    _sub(idle, "RestartOnIdle", "false")
    for tag, value in (
        ("AllowStartOnDemand", "true"),
        # --no-start registers the task DISABLED: otherwise the 5-minute
        # watchdog trigger would start it anyway within minutes.
        ("Enabled", "true" if enabled else "false"),
        ("Hidden", "false"),
        ("RunOnlyIfIdle", "false"),
        ("WakeToRun", "false"),
        ("ExecutionTimeLimit", "PT0S"),
        ("Priority", "7"),
    ):
        _sub(settings, tag, value)
    restart = _sub(settings, "RestartOnFailure")
    _sub(restart, "Interval", "PT1M")
    _sub(restart, "Count", "999")

    actions = _sub(task, "Actions", Context="Author")
    exe = _sub(actions, "Exec")
    _sub(exe, "Command", spec.command)
    _sub(exe, "Arguments", spec.arguments)
    _sub(exe, "WorkingDirectory", spec.working_directory)

    ET.indent(task, space="  ")
    body = ET.tostring(task, encoding="unicode")
    return '<?xml version="1.0" encoding="UTF-16"?>\n' + body + "\n"


def task_xml_bytes(xml_text: str) -> bytes:
    """UTF-16 with BOM, CRLF line ends — what ``schtasks /XML`` expects."""
    return xml_text.replace("\r\n", "\n").replace("\n", "\r\n").encode("utf-16")


def _strip_declaration(text: str) -> str:
    return re.sub(r"^\s*<\?xml[^>]*\?>", "", text.lstrip("\ufeff"), count=1)


def parse_task_xml(text: str) -> dict:
    """Fields of a registered task definition (``schtasks /Query /XML``)."""
    try:
        root = ET.fromstring(_strip_declaration(text))
    except ET.ParseError:
        raise ServiceError("the registered task definition is not parseable XML") from None
    ns = {"t": TASK_NS}

    def find(path):
        element = root.find(path, ns)
        return element.text if element is not None and element.text is not None else None

    execs = root.findall("t:Actions/t:Exec", ns)
    actions = root.find("t:Actions", ns)
    return {
        "description": find("t:RegistrationInfo/t:Description") or "",
        "user_id": find("t:Principals/t:Principal/t:UserId"),
        "logon_type": find("t:Principals/t:Principal/t:LogonType"),
        # Task Scheduler omits schema-default values when it exports a
        # registered task, so absent elements mean their documented default.
        "run_level": find("t:Principals/t:Principal/t:RunLevel") or "LeastPrivilege",
        "command": find("t:Actions/t:Exec/t:Command"),
        "arguments": find("t:Actions/t:Exec/t:Arguments") or "",
        "working_directory": find("t:Actions/t:Exec/t:WorkingDirectory"),
        "exec_count": len(execs),
        "action_count": len(list(actions)) if actions is not None else 0,
        "boot_trigger": root.find("t:Triggers/t:BootTrigger", ns) is not None,
        "watchdog_interval": find("t:Triggers/t:TimeTrigger/t:Repetition/t:Interval"),
        "multiple_instances": find("t:Settings/t:MultipleInstancesPolicy") or "IgnoreNew",
        "execution_time_limit": find("t:Settings/t:ExecutionTimeLimit") or "PT72H",
    }


# --- helper trust ------------------------------------------------------------


def file_sha256(path: str) -> str:
    try:
        with open(path, "rb") as handle:
            return hashlib.file_digest(handle, "sha256").hexdigest()
    except OSError:
        raise ServiceError(f"cannot read the helper {sanitize(path)}") from None


def check_digest(digest: str) -> None:
    if digest in ALLOWED_HELPER_SHA256:
        return
    if digest in HISTORICAL_HELPER_SHA256:
        raise ServiceError(
            f"the helper is the historical {HISTORICAL_HELPER_SHA256[digest]} build "
            f"(sha256 {digest[:12]}…), which must not be used; install the reviewed build"
        )
    raise ServiceError(
        f"the helper's sha256 {digest[:12]}… is not a reviewed Windows helper build"
    )


def _check_version(output: bytes) -> None:
    text = output.decode("utf-8", "replace").strip()
    try:
        fields = json.loads(text) if text and "\n" not in text else None
    except ValueError:
        fields = None
    if not isinstance(fields, dict) or fields.get("protocol") != gateway_helper.EXPECTED_PROTOCOL:
        raise ServiceError(
            "the helper did not report protocol "
            f"{gateway_helper.EXPECTED_PROTOCOL!r} from `version --json`"
        )


def resolve_helper(explicit: Optional[str], runner: Optional[Runner] = None) -> str:
    """Absolute .exe (``--helper`` or ``POCKETSHELL_GATEWAY_HELPER``), on the
    reviewed allow-list, answering the expected ``version --json`` protocol."""
    runner = runner or run_child
    candidate = explicit or os.environ.get(gateway_helper.HELPER_ENV_VAR)
    if not candidate:
        raise ServiceError(
            "pass --helper C:\\...\\pocketshell-link.exe (or set "
            f"{gateway_helper.HELPER_ENV_VAR}) — the absolute path of the reviewed helper"
        )
    helper = validate_path(candidate, "helper path")
    if not helper.lower().endswith(".exe"):
        raise ServiceError("the Windows helper must be an absolute .exe path")
    check_digest(file_sha256(helper))
    result = runner([helper, "version", "--json"], timeout=gateway_helper.METADATA_TIMEOUT_SECONDS)
    if result.returncode != 0:
        raise ServiceError(f"the helper's `version --json` exited {result.returncode}")
    _check_version(result.stdout[: gateway_helper.METADATA_MAX_OUTPUT_BYTES + 1])
    return helper


# --- native Windows queries (ctypes; imported lazily) ------------------------


class WindowsApi:
    """SID / owner / process queries. Swapped for a fake in Linux tests."""

    def current_sid(self) -> str:
        import ctypes as c
        from ctypes import wintypes as w

        k = c.WinDLL("kernel32", use_last_error=True)
        a = c.WinDLL("advapi32", use_last_error=True)
        k.GetCurrentProcess.restype = w.HANDLE
        a.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, c.POINTER(w.HANDLE)]
        a.GetTokenInformation.argtypes = [w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.POINTER(w.DWORD)]
        token = w.HANDLE()
        if not a.OpenProcessToken(k.GetCurrentProcess(), 0x0008, c.byref(token)):
            raise ServiceError("cannot open this process token to read your SID")
        try:
            size = w.DWORD()
            a.GetTokenInformation(token, 1, None, 0, c.byref(size))  # TokenUser
            buf = c.create_string_buffer(size.value)
            if not a.GetTokenInformation(token, 1, buf, size.value, c.byref(size)):
                raise ServiceError("cannot read your SID from the process token")
            return self._sid_text(c.cast(buf, c.POINTER(c.c_void_p))[0])
        finally:
            k.CloseHandle(token)

    @staticmethod
    def _sid_text(sid_ptr) -> str:
        import ctypes as c

        a = c.WinDLL("advapi32", use_last_error=True)
        k = c.WinDLL("kernel32", use_last_error=True)
        a.ConvertSidToStringSidW.argtypes = [c.c_void_p, c.POINTER(c.c_void_p)]
        k.LocalFree.argtypes = [c.c_void_p]
        out = c.c_void_p()
        if not a.ConvertSidToStringSidW(sid_ptr, c.byref(out)):
            raise ServiceError("cannot convert a SID to text")
        try:
            return c.wstring_at(out.value)
        finally:
            k.LocalFree(out)

    def owner_sid(self, path: str) -> str:
        """Owner SID from the security descriptor only (contents never read)."""
        import ctypes as c
        from ctypes import wintypes as w

        a = c.WinDLL("advapi32", use_last_error=True)
        k = c.WinDLL("kernel32", use_last_error=True)
        a.GetNamedSecurityInfoW.argtypes = [
            w.LPCWSTR, c.c_int, w.DWORD, c.POINTER(c.c_void_p), c.c_void_p,
            c.c_void_p, c.c_void_p, c.POINTER(c.c_void_p),
        ]
        a.GetNamedSecurityInfoW.restype = w.DWORD
        k.LocalFree.argtypes = [c.c_void_p]
        owner, sd = c.c_void_p(), c.c_void_p()
        # SE_FILE_OBJECT=1, OWNER_SECURITY_INFORMATION=1
        error = a.GetNamedSecurityInfoW(path, 1, 1, c.byref(owner), None, None, None, c.byref(sd))
        if error:
            raise ServiceError(f"cannot read the owner of {sanitize(path)} (error {error})")
        try:
            return self._sid_text(owner)
        finally:
            k.LocalFree(sd)

    def account_sid(self, name: str) -> str:
        """SID of an account name (LookupAccountNameW), for readback."""
        import ctypes as c
        from ctypes import wintypes as w

        a = c.WinDLL("advapi32", use_last_error=True)
        a.LookupAccountNameW.argtypes = [
            w.LPCWSTR, w.LPCWSTR, c.c_void_p, c.POINTER(w.DWORD), w.LPWSTR,
            c.POINTER(w.DWORD), c.POINTER(c.c_int),
        ]
        sid_size, dom_size, use = w.DWORD(0), w.DWORD(0), c.c_int()
        a.LookupAccountNameW(None, name, None, c.byref(sid_size), None, c.byref(dom_size), c.byref(use))
        if not sid_size.value:
            raise ServiceError(f"cannot resolve the account {sanitize(name)}")
        sid = c.create_string_buffer(sid_size.value)
        domain = c.create_unicode_buffer(max(dom_size.value, 1))
        if not a.LookupAccountNameW(None, name, sid, c.byref(sid_size), domain,
                                    c.byref(dom_size), c.byref(use)):
            raise ServiceError(f"cannot resolve the account {sanitize(name)}")
        return self._sid_text(c.cast(sid, c.c_void_p))

    def processes(self, image_name: str) -> list:
        """[{pid, session_id, path}] of processes named ``image_name``."""
        import ctypes as c
        from ctypes import wintypes as w

        class Entry(c.Structure):
            _fields_ = [
                ("dwSize", w.DWORD), ("cntUsage", w.DWORD), ("th32ProcessID", w.DWORD),
                ("th32DefaultHeapID", c.c_size_t), ("th32ModuleID", w.DWORD),
                ("cntThreads", w.DWORD), ("th32ParentProcessID", w.DWORD),
                ("pcPriClassBase", w.LONG), ("dwFlags", w.DWORD), ("szExeFile", w.WCHAR * 260),
            ]

        k = c.WinDLL("kernel32", use_last_error=True)
        k.CreateToolhelp32Snapshot.restype = w.HANDLE
        k.CreateToolhelp32Snapshot.argtypes = [w.DWORD, w.DWORD]
        k.Process32FirstW.argtypes = [w.HANDLE, c.POINTER(Entry)]
        k.Process32NextW.argtypes = [w.HANDLE, c.POINTER(Entry)]
        k.OpenProcess.restype = w.HANDLE
        k.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
        k.QueryFullProcessImageNameW.argtypes = [w.HANDLE, w.DWORD, w.LPWSTR, c.POINTER(w.DWORD)]
        k.ProcessIdToSessionId.argtypes = [w.DWORD, c.POINTER(w.DWORD)]
        k.CloseHandle.argtypes = [w.HANDLE]
        snapshot = k.CreateToolhelp32Snapshot(0x2, 0)
        if snapshot in (None, w.HANDLE(-1).value):
            return []
        found = []
        try:
            entry = Entry()
            entry.dwSize = c.sizeof(Entry)
            ok = k.Process32FirstW(snapshot, c.byref(entry))
            while ok:
                if entry.szExeFile.lower() == image_name.lower():
                    pid = entry.th32ProcessID
                    session = w.DWORD()
                    session_id = session.value if k.ProcessIdToSessionId(pid, c.byref(session)) else None
                    path = None
                    handle = k.OpenProcess(0x1000, False, pid)  # QUERY_LIMITED_INFORMATION
                    if handle:
                        try:
                            buf = c.create_unicode_buffer(32768)
                            size = w.DWORD(32768)
                            if k.QueryFullProcessImageNameW(handle, 0, buf, c.byref(size)):
                                path = buf.value
                        finally:
                            k.CloseHandle(handle)
                    found.append({"pid": pid, "session_id": session_id, "path": path})
                ok = k.Process32NextW(snapshot, c.byref(entry))
        finally:
            k.CloseHandle(snapshot)
        return found


# --- schtasks ------------------------------------------------------------------


def _system32(*parts: str) -> str:
    root = os.environ.get("SystemRoot") or os.environ.get("windir") or "C:\\Windows"
    return ntpath.join(root, "System32", *parts)


def schtasks(*args: str) -> list:
    return [_system32("schtasks.exe"), *args]


# IRegisteredTask.State
TASK_STATES = {0: "Unknown", 1: "Disabled", 2: "Queued", 3: "Ready", 4: "Running"}
# Confirmed absence: the task (ERROR_FILE_NOT_FOUND) or its \PocketShell
# folder (ERROR_PATH_NOT_FOUND) does not exist. Every other failure — access
# denied, the service unavailable, PowerShell itself failing — is UNKNOWN and
# must never be reported as "not installed" or as a successful deletion.
_NOT_FOUND_HRESULTS = {"0x80070002", "0x80070003"}

def _query_script(leaf: str) -> str:
    if not re.fullmatch(r"[A-Za-z]+", leaf):
        raise ServiceError("unexpected task name")
    return (
        "$ErrorActionPreference='Stop';"
        "try{"
        "$s=New-Object -ComObject Schedule.Service;$s.Connect();"
        f"$t=$s.GetFolder('{TASK_FOLDER.rstrip(chr(92))}').GetTask('{leaf}');"
        "$o=[ordered]@{found=$true;state=[int]$t.State;last_result=[int64]$t.LastTaskResult;"
        "xml=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($t.Xml))}"
        "}catch{"
        "$e=$_.Exception;while($e.InnerException){$e=$e.InnerException};"
        "$o=[ordered]@{found=$false;hresult=('0x{0:X8}' -f $e.HResult);message=[string]$e.Message}"
        "};"
        "$o|ConvertTo-Json -Compress"
    )


_QUERY_SCRIPT = _query_script(TASK_LEAF)


@dataclass
class TaskInfo:
    xml: str
    state: str
    last_result: Optional[int]


def _powershell(script: str) -> list:
    return [
        _system32("WindowsPowerShell", "v1.0", "powershell.exe"),
        "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script,
    ]


def query_task(runner: Optional[Runner] = None, leaf: str = TASK_LEAF) -> Optional[TaskInfo]:
    """The registered task, ``None`` ONLY when its absence is confirmed.

    Reads through the Task Scheduler COM API (locale-independent HRESULTs,
    numeric state, the definition base64-encoded so no console code page
    can mangle non-ASCII paths). Any query failure raises
    :class:`ServiceError` with a sanitized message.
    """
    runner = runner or run_child
    name = TASK_FOLDER + leaf
    result = runner(_powershell(_query_script(leaf)))
    try:
        data = json.loads(decode(result.stdout).strip() or "null")
    except ValueError:
        data = None
    if result.returncode != 0 or not isinstance(data, dict):
        detail = sanitize(decode(result.stderr or result.stdout), 300)
        raise ServiceError(
            f"could not query the scheduled task {name} (exit {result.returncode})"
            + (f": {detail}" if detail else "")
        )
    if not data.get("found"):
        hresult = str(data.get("hresult", "")).upper().replace("0X", "0x")
        if hresult in _NOT_FOUND_HRESULTS:
            return None
        raise ServiceError(
            f"could not query the scheduled task {name} (HRESULT {sanitize(hresult, 20)}: "
            f"{sanitize(str(data.get('message', '')), 300)})"
        )
    try:
        xml = base64.b64decode(str(data.get("xml", "")), validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        raise ServiceError(f"the definition of {name} could not be decoded") from None
    state = TASK_STATES.get(data.get("state"), "Unknown")
    last = data.get("last_result")
    return TaskInfo(xml, state, last if isinstance(last, int) else None)


def query_task_xml(runner: Optional[Runner] = None, leaf: str = TASK_LEAF) -> Optional[str]:
    """The registered definition; ``None`` only on confirmed absence."""
    info = query_task(runner, leaf)
    return info.xml if info is not None else None


ELEVATION_HINT = (
    "Registering a task with a boot trigger and the S4U logon type normally "
    "needs an elevated prompt (Run as administrator); the task itself still "
    "runs as you, with LeastPrivilege. Do not fall back to a logon trigger."
)


def _fail(result: ChildResult, what: str, hint: str = "") -> ServiceError:
    detail = sanitize(decode(result.stderr or result.stdout), 600)
    return ServiceError(
        f"{what} failed (exit {result.returncode})"
        + (f": {detail}" if detail else "")
        + (f"\n{hint}" if hint else "")
    )


# --- install / uninstall / status --------------------------------------------


@dataclass
class EndpointPlan:
    manifest: "ep.EndpointManifest"
    spec: TaskSpec
    xml: str
    replace: bool


@dataclass
class WindowsPlan:
    helper: str
    config_dir: str
    user_sid: str
    xml: str
    action_argv: list
    replace: bool
    start: bool
    show: str
    logon_type: str = DEFAULT_LOGON_TYPE
    endpoint: Optional[EndpointPlan] = None

    def commands(self, xml_dir: str = "<private temp dir>") -> list:
        """The schtasks sequence: endpoint task first (when any), then link."""
        commands = []
        tasks = []
        if self.endpoint is not None:
            tasks.append((self.endpoint.spec.name, self.endpoint.spec.leaf, self.endpoint.replace))
        tasks.append((TASK_NAME, TASK_LEAF, self.replace))
        for name, leaf, replace in tasks:
            if replace:
                commands.append(schtasks("/End", "/TN", name))
            create = schtasks("/Create", "/TN", name, "/XML", f"{xml_dir}\\{leaf}.xml")
            if replace:
                create.append("/F")
            commands.append(create)
            if self.start:
                commands.append(schtasks("/Run", "/TN", name))
        return commands


# Owners the helper itself accepts besides the user: what an ELEVATED
# process of that same user stamps on directories it creates.
_ELEVATED_CREATOR_OWNERS = {"S-1-5-32-544", "S-1-5-18"}  # Administrators, SYSTEM


def check_owner(api: WindowsApi, config_dir: str, user_sid: str) -> None:
    """The device key must be owned by the current user (the helper creates
    it with ``O:<user>`` and its ACL is bound to that SID); the directory by
    the user or by Administrators/SYSTEM (an elevated mkdir), never by
    another account."""
    checks = (
        (config_dir, {user_sid} | _ELEVATED_CREATOR_OWNERS),
        (ntpath.join(config_dir, common.KEY_FILE), {user_sid}),
    )
    for path, accepted in checks:
        owner = api.owner_sid(path)
        if owner not in accepted:
            raise ServiceError(
                f"{sanitize(path)} is owned by {sanitize(owner)}, not by you "
                f"({sanitize(user_sid)}); the helper's key ACL is bound to its "
                "owner, so the task must run as that account. Run this as the "
                "enrolling user."
            )


def plan_install(
    helper: Optional[str],
    config_dir: str,
    *,
    force: bool,
    start: bool,
    api: Optional[WindowsApi] = None,
    runner: Optional[Runner] = None,
    logon_type: str = DEFAULT_LOGON_TYPE,
    endpoint_manifest: Optional[str] = None,
) -> WindowsPlan:
    runner = runner or run_child
    api = api or WindowsApi()
    config_dir = validate_path(config_dir, "config dir")
    manifest_path = validate_path(endpoint_manifest, "endpoint manifest") if endpoint_manifest else None
    binary = resolve_helper(helper, runner)
    show = common.check_enrollment(binary, config_dir, runner)
    user_sid = api.current_sid()
    check_owner(api, config_dir, user_sid)
    xml = build_task_xml(binary, config_dir, user_sid, logon_type=logon_type, enabled=start)
    exists = query_task_xml(runner) is not None
    if exists and not force:
        raise ServiceError(
            f"the scheduled task {TASK_NAME} already exists; pass --force to "
            "replace it (or `pocketshell gateway service uninstall` first)"
        )
    endpoint = None
    if manifest_path:
        endpoint = plan_endpoint(
            manifest_path, show, user_sid,
            force=force, start=start, api=api, runner=runner, logon_type=logon_type,
        )
    return WindowsPlan(
        binary, config_dir, user_sid, xml, action_argv(binary, config_dir), exists, start, show,
        logon_type, endpoint,
    )


def endpoint_spec(manifest: "ep.EndpointManifest") -> TaskSpec:
    return TaskSpec(
        leaf=ep.ENDPOINT_LEAF,
        command=manifest.command,
        argv=manifest.arguments,
        arguments=ep.endpoint_arguments(manifest, quote_arg),
        working_directory=manifest.working_directory,
        boot_delay=ep.ENDPOINT_BOOT_DELAY,
        description=(
            f"PocketShell private loopback SSH endpoint {manifest.name} on {manifest.listen} "
            f"(guardian, direct launch): hidden, session 0, runs as the enrolling user. "
            f"Manifest sha256 {manifest.manifest_sha256}. {MANAGED_MARKER}."
        ),
    )


def read_manifest(path: str) -> bytes:
    try:
        with open(path, "rb") as handle:
            return handle.read(ep.MAX_MANIFEST_BYTES + 1)
    except OSError:
        raise ServiceError(f"cannot read the endpoint manifest {sanitize(path)}") from None


def plan_endpoint(
    manifest_path: str,
    show: str,
    user_sid: str,
    *,
    force: bool,
    start: bool,
    api: WindowsApi,
    runner: Runner,
    logon_type: str,
) -> EndpointPlan:
    """Validate the manifest (reviewed digest, on-disk digests, binding to the
    enrolled local sshd and host key, same-user ownership) and plan its task."""
    manifest = ep.parse_manifest(read_manifest(manifest_path), validate_path=validate_path)
    ep.check_trust(manifest, file_sha256=file_sha256)
    ep.check_binding(manifest, show)
    accepted = {user_sid} | _ELEVATED_CREATOR_OWNERS
    for path in (manifest.command, manifest.working_directory):
        owner = api.owner_sid(path)
        if owner not in accepted:
            raise ServiceError(
                f"{sanitize(path)} is owned by {sanitize(owner)}, not by you "
                f"({sanitize(user_sid)}); the endpoint task runs as you"
            )
    spec = endpoint_spec(manifest)
    xml = build_spec_xml(spec, user_sid, logon_type=logon_type, enabled=start)
    exists = query_task_xml(runner, ep.ENDPOINT_LEAF) is not None
    if exists and not force:
        raise ServiceError(
            f"the scheduled task {spec.name} already exists; pass --force to "
            "replace it (or `pocketshell gateway service uninstall` first)"
        )
    if start and not exists and ep.port_in_use(manifest.listen_host, manifest.listen_port):
        raise ServiceError(
            f"{manifest.listen} is already served by another process (e.g. the currently "
            "held endpoint). Have its owner stop it through its own controlled-stop "
            "mechanism first, or register with --no-start; this command never stops it."
        )
    return EndpointPlan(manifest, spec, xml, exists)


def readback_problems(fields: dict, plan: "WindowsPlan", api: WindowsApi) -> list:
    """Differences between the registered LINK task and the requested one."""
    return spec_readback_problems(
        fields, link_spec(plan.helper, plan.config_dir), plan.user_sid, plan.logon_type, api
    )


def spec_readback_problems(
    fields: dict, spec: TaskSpec, user_sid: str, logon_type: str, api: WindowsApi
) -> list:
    """Differences between a REGISTERED task and the requested ``spec``.

    Checked before the task is ever started: one direct Exec of the exact
    command and argv, the working directory, and the same-user,
    non-interactive principal (the current user's SID — an account-name form
    is accepted only if it resolves to that SID —, the requested logon type,
    and LeastPrivilege, which an export may omit as the schema default).
    """
    problems = []
    if fields["exec_count"] != 1 or fields["action_count"] != 1:
        problems.append("not exactly one Exec action")
    if not _same_path(fields["command"], spec.command):
        problems.append("command is not the requested executable")
    if parse_arguments(fields["arguments"]) != list(spec.argv):
        problems.append("arguments are not the requested argv")
    if not _same_path(fields["working_directory"], spec.working_directory):
        problems.append("working directory is not the requested one")
    user = fields["user_id"] or ""
    if user != user_sid:
        try:
            resolved = api.account_sid(user) if user else None
        except ServiceError:
            resolved = None
        if resolved != user_sid:
            problems.append(f"principal {sanitize(user, 100) or '(none)'} is not your SID {user_sid}")
    if fields["logon_type"] != logon_type:
        problems.append(f"logon type {sanitize(str(fields['logon_type']), 40)} is not {logon_type}")
    if fields["run_level"] != "LeastPrivilege":
        problems.append(f"run level {sanitize(str(fields['run_level']), 40)} is not LeastPrivilege")
    return problems


def _register(
    spec: TaskSpec,
    xml: str,
    *,
    replace: bool,
    user_sid: str,
    logon_type: str,
    runner: Runner,
    api: WindowsApi,
) -> None:
    """schtasks /Create /XML, read it back, delete it again on any mismatch."""
    tmpdir = tempfile.mkdtemp(prefix="pocketshell-task-")
    xml_path = os.path.join(tmpdir, spec.leaf + ".xml")
    try:
        with open(xml_path, "wb") as handle:
            handle.write(task_xml_bytes(xml))
        if replace:
            runner(schtasks("/End", "/TN", spec.name))
        create = schtasks("/Create", "/TN", spec.name, "/XML", xml_path)
        if replace:
            create.append("/F")
        result = runner(create)
        if result.returncode != 0:
            raise _fail(result, f"registering {spec.name}", ELEVATION_HINT)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    registered = query_task_xml(runner, spec.leaf)
    if registered is None:
        raise ServiceError(f"{spec.name} is not visible after registration")
    try:
        problems = spec_readback_problems(parse_task_xml(registered), spec, user_sid, logon_type, api)
    except ServiceError as exc:
        problems = [str(exc)]
    if problems:
        # Never start a task that is not what was requested: roll it back.
        removed = runner(schtasks("/Delete", "/TN", spec.name, "/F")).returncode == 0
        raise ServiceError(
            f"{spec.name} was registered but does not match the requested "
            f"same-user direct launch ({'; '.join(problems)}); it was "
            + ("removed again and never started" if removed else
               "NOT removed — run `pocketshell gateway service uninstall`")
        )


def apply_install(
    plan: "WindowsPlan", runner: Optional[Runner] = None, api: Optional[WindowsApi] = None
) -> list:
    runner = runner or run_child
    api = api or WindowsApi()
    if plan.endpoint is not None:
        # The endpoint first: a link without its loopback sshd only yields
        # "dial failed" routes. If the endpoint does not start, the link task
        # is not registered at all (exit 5, the endpoint task is kept).
        endpoint = plan.endpoint
        _register(
            endpoint.spec, endpoint.xml, replace=endpoint.replace,
            user_sid=plan.user_sid, logon_type=plan.logon_type, runner=runner, api=api,
        )
        if plan.start:
            host, port = endpoint.manifest.listen_host, endpoint.manifest.listen_port
            if endpoint.replace:
                deadline = time.monotonic() + 10
                while ep.port_in_use(host, port) and time.monotonic() < deadline:
                    time.sleep(0.5)
                if ep.port_in_use(host, port):
                    raise NotStartedError(
                        f"{endpoint.spec.name} is registered but NOT started: "
                        f"{endpoint.manifest.listen} is still served after ending the old task"
                    )
            _start_and_confirm(
                runner, ep.ENDPOINT_LEAF, ready=lambda: ep.probe_banner(host, port)
            )
    _register(
        link_spec(plan.helper, plan.config_dir), plan.xml, replace=plan.replace,
        user_sid=plan.user_sid, logon_type=plan.logon_type, runner=runner, api=api,
    )
    if plan.start:
        _start_and_confirm(runner)
    return []


def _start_and_confirm(runner: Runner, leaf: str = TASK_LEAF, ready=None) -> None:
    """``/Run``, then require the task's own state to reach Running (and,
    when given, ``ready()`` to hold) within :data:`START_CONFIRM_SECONDS`."""
    name = TASK_FOLDER + leaf
    result = runner(schtasks("/Run", "/TN", name))
    if result.returncode != 0:
        detail = sanitize(decode(result.stderr or result.stdout), 600)
        raise NotStartedError(
            f"{name} is registered but NOT started: /Run failed "
            f"(exit {result.returncode})" + (f": {detail}" if detail else "")
            + ". It will still start at boot or from its 5-minute watchdog; "
            "check `pocketshell gateway service status`."
        )
    deadline = time.monotonic() + START_CONFIRM_SECONDS
    state, last, extra = "Unknown", None, ""
    while True:
        try:
            info = query_task(runner, leaf)
        except ServiceError as exc:
            raise NotStartedError(
                f"{name} is registered but its start could not be confirmed: {exc}"
            ) from None
        if info is not None:
            state, last = info.state, info.last_result
            if state == "Running":
                if ready is None:
                    return
                ok, extra = ready()
                if ok:
                    return
        if time.monotonic() >= deadline:
            break
        time.sleep(0.5)
    raise NotStartedError(
        f"{name} is registered but NOT started: its state is {state} "
        f"after {START_CONFIRM_SECONDS:g}s (last result {last})"
        + (f"; {extra}" if extra else "")
        + "; check `pocketshell gateway service status`"
    )


def _uninstall_one(leaf: str, *, force: bool, runner: Runner, what: str) -> Optional[dict]:
    """End + delete one managed task. None if confirmed absent; else its fields."""
    name = TASK_FOLDER + leaf
    registered = query_task_xml(runner, leaf)
    if registered is None:
        return None
    try:
        fields = parse_task_xml(registered)
    except ServiceError:
        fields = {"description": "", "command": None}
    if MANAGED_MARKER not in fields["description"] and not force:
        raise ServiceError(
            f"{name} was not written by `pocketshell gateway service install`; "
            "refusing to stop or delete a task this command does not own (pass --force)"
        )
    runner(schtasks("/End", "/TN", name))
    result = runner(schtasks("/Delete", "/TN", name, "/F"))
    if result.returncode != 0:
        raise _fail(result, f"deleting {name}", ELEVATION_HINT)
    try:
        still_there = query_task(runner, leaf) is not None
    except ServiceError as exc:
        raise ServiceError(f"deleted {name} but could not verify its removal: {exc}") from None
    if still_there:
        raise ServiceError(f"{name} still exists after deletion")
    return fields


def uninstall(
    *, force: bool = False, runner: Optional[Runner] = None, api: Optional[WindowsApi] = None
) -> str:
    runner = runner or run_child
    # Link first (no new routes), then the endpoint it bridges to.
    fields = _uninstall_one(TASK_LEAF, force=force, runner=runner, what="link")
    endpoint = _uninstall_one(ep.ENDPOINT_LEAF, force=force, runner=runner, what="endpoint")
    if fields is None and endpoint is None:
        return f"not installed ({TASK_NAME} does not exist); nothing to do"
    removed = []
    if fields is not None:
        removed.append(TASK_NAME)
    if endpoint is not None:
        removed.append(TASK_FOLDER + ep.ENDPOINT_LEAF)
    message = (
        f"removed the scheduled task(s) {', '.join(removed)} (enrollment, config dir "
        "and endpoint files untouched)"
    )
    helper = fields.get("command") if fields is not None else None
    if helper:
        api = api or WindowsApi()
        deadline = time.monotonic() + 10
        left = _matching(api, helper)
        while left and time.monotonic() < deadline:
            time.sleep(0.5)
            left = _matching(api, helper)
        if left:
            message += (
                "; still running from that helper path (not started by the task "
                "or not yet exited): pid " + ", ".join(str(p["pid"]) for p in left)
            )
    return message


def _canon(path: str) -> str:
    if sys.platform == "win32":
        try:
            path = final_path(path)
        except OSError:
            pass
    return ntpath.normcase(ntpath.normpath(path))


def _same_path(a: Optional[str], b: Optional[str]) -> bool:
    return bool(a and b) and _canon(a) == _canon(b)


def _matching(api: WindowsApi, helper: str) -> list:
    try:
        procs = api.processes(ntpath.basename(helper))
    except Exception:  # noqa: BLE001 - status must never traceback
        return []
    return [p for p in procs if _same_path(p.get("path"), helper)]


def endpoint_status(runner: Runner, api: WindowsApi) -> Optional[dict]:
    """The endpoint task, if registered: state, contract, banner, processes.

    Running = the task's own state is Running AND the listen address answers
    with an SSH banner. Guardian processes are diagnostics only.
    """
    info = query_task(runner, ep.ENDPOINT_LEAF)
    if info is None:
        return None
    out = {"task": TASK_FOLDER + ep.ENDPOINT_LEAF, "state": info.state, "managed": False,
           "command": None, "listen": None, "banner_ok": False, "banner": "not probed",
           "processes": [], "running": False}
    try:
        fields = parse_task_xml(info.xml)
    except ServiceError as exc:
        out["error"] = str(exc)
        return out
    out["managed"] = MANAGED_MARKER in fields["description"]
    out["command"] = fields["command"]
    out["logon_type"] = fields["logon_type"]
    out["run_level"] = fields["run_level"]
    out["direct_launch"] = fields["exec_count"] == 1 and fields["action_count"] == 1
    match = re.search(r" on (127\.0\.0\.1):(\d{1,5}) ", fields["description"])
    if match:
        host, port = match.group(1), int(match.group(2))
        out["listen"] = f"{host}:{port}"
        out["banner_ok"], out["banner"] = ep.probe_banner(host, port)
    if fields["command"]:
        out["processes"] = _matching(api, fields["command"])
    out["running"] = info.state == "Running" and out["banner_ok"]
    return out


def status(runner: Optional[Runner] = None, api: Optional[WindowsApi] = None) -> ServiceStatus:
    runner = runner or run_child
    api = api or WindowsApi()
    st = ServiceStatus(platform="windows", name=TASK_NAME, installed=False)
    info = query_task(runner)
    endpoint = endpoint_status(runner, api)
    if endpoint is not None:
        st.details["endpoint"] = endpoint
    if info is None:
        if endpoint is not None:
            st.installed = True
            st.state = "absent (endpoint task only)"
            st.warnings.append(f"{TASK_NAME} is not installed but {endpoint['task']} is")
        return st
    registered = info.xml
    st.installed = True
    st.definition_path = TASK_NAME
    try:
        fields = parse_task_xml(registered)
    except ServiceError as exc:
        st.state = "unparseable"
        st.warnings.append(str(exc))
        return st
    st.managed = MANAGED_MARKER in fields["description"]
    st.helper = fields["command"]
    args = parse_arguments(fields["arguments"])
    if "--config-dir" in args and args.index("--config-dir") + 1 < len(args):
        st.config_dir = args[args.index("--config-dir") + 1]
    st.details.update({
        k: fields[k]
        for k in ("user_id", "logon_type", "run_level", "arguments", "working_directory",
                  "multiple_instances", "execution_time_limit", "watchdog_interval")
    })
    st.details["direct_launch"] = (
        fields["exec_count"] == 1
        and fields["action_count"] == 1
        and "cmd.exe" not in (st.helper or "").lower()
        and args[:1] == ["run"]
    )
    st.state = info.state
    st.details["last_task_result"] = info.last_result
    if st.helper:
        st.processes = _matching(api, st.helper)
        try:
            st.helper_sha256 = file_sha256(st.helper)
            st.helper_allowed = st.helper_sha256 in ALLOWED_HELPER_SHA256
        except ServiceError as exc:
            st.warnings.append(str(exc))
        if st.helper_allowed and st.config_dir:
            # Only an allow-listed helper is ever executed by `status`.
            try:
                st.show = common.check_enrollment(st.helper, st.config_dir, runner)
            except ServiceError as exc:
                st.show_error = str(exc)
        elif st.helper_allowed is False:
            st.warnings.append("the task's helper is not a reviewed build; not running its `show`")
    # Acceptance comes from the task itself. A process with the same image
    # path (e.g. a held fixture agent) is listed only as a diagnostic: it
    # may run another config/device, in another session, under another
    # supervisor.
    st.running = st.state == "Running"
    if endpoint is not None and not endpoint["running"]:
        st.running = False
        st.warnings.append(
            f"the endpoint task {endpoint['task']} is {endpoint['state']}"
            + ("" if endpoint["banner_ok"] else f"; {endpoint['banner']}")
        )
    if st.processes and not st.running:
        st.warnings.append(
            "process(es) from the task's helper path are running, but the task "
            f"is {st.state}: not proof the task runs the agent (diagnostic only)"
        )
    if st.processes and any(p.get("session_id") not in (0, None) for p in st.processes):
        st.warnings.append("a helper process runs in an interactive session (not session 0)")
    return st
