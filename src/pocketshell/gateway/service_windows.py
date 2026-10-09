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
from pocketshell.gateway.service_common import (
    ChildResult,
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


def build_task_xml(
    helper: str,
    config_dir: str,
    user_sid: str,
    *,
    logon_type: str = DEFAULT_LOGON_TYPE,
    enabled: bool = True,
) -> str:
    """The task definition (plan §3.2 + Revision 5), as an XML string.

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
    _sub(reg, "URI", TASK_NAME)
    _sub(reg, "Description",
         "PocketShell gateway host agent (pocketshell-link run): hidden, session 0, "
         f"runs as the enrolling user. {MANAGED_MARKER}.")

    triggers = _sub(task, "Triggers")
    boot = _sub(triggers, "BootTrigger")
    _sub(boot, "Enabled", "true")
    _sub(boot, "Delay", "PT30S")
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
    _sub(exe, "Command", helper)
    _sub(exe, "Arguments", task_arguments(config_dir))
    _sub(exe, "WorkingDirectory", ntpath.dirname(helper))

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


def query_task_xml(runner: Optional[Runner] = None) -> Optional[str]:
    """The registered definition, or None when the task does not exist."""
    runner = runner or run_child
    result = runner(schtasks("/Query", "/TN", TASK_NAME, "/XML"))
    if result.returncode != 0:
        return None
    text = decode(result.stdout)
    return text if "<Task" in text else None


def task_state(runner: Optional[Runner] = None) -> dict:
    """Task state via the ScheduledTasks module (best effort, never fatal)."""
    runner = runner or run_child
    script = (
        "$ErrorActionPreference='Stop';"
        f"$t=Get-ScheduledTask -TaskPath '{TASK_FOLDER}' -TaskName '{TASK_LEAF}';"
        "$i=$t|Get-ScheduledTaskInfo;"
        "[pscustomobject]@{State=[string]$t.State;LastTaskResult=$i.LastTaskResult;"
        "LastRunTime=[string]$i.LastRunTime}|ConvertTo-Json -Compress"
    )
    argv = [
        _system32("WindowsPowerShell", "v1.0", "powershell.exe"),
        "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script,
    ]
    try:
        result = runner(argv)
    except ServiceError as exc:
        return {"error": str(exc)}
    if result.returncode != 0:
        return {"error": sanitize(decode(result.stderr), 300) or f"exit {result.returncode}"}
    try:
        data = json.loads(decode(result.stdout).strip() or "null")
    except ValueError:
        return {"error": "unparseable task state"}
    if not isinstance(data, dict):
        return {"error": "unparseable task state"}
    return {k: sanitize(str(v), 100) for k, v in data.items()}


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
class WindowsPlan:
    helper: str
    config_dir: str
    user_sid: str
    xml: str
    action_argv: list
    replace: bool
    start: bool
    show: str

    def commands(self, xml_path: str = "<private temp dir>\\GatewayLink.xml") -> list:
        commands = []
        if self.replace:
            commands.append(schtasks("/End", "/TN", TASK_NAME))
        create = schtasks("/Create", "/TN", TASK_NAME, "/XML", xml_path)
        if self.replace:
            create.append("/F")
        commands.append(create)
        if self.start:
            commands.append(schtasks("/Run", "/TN", TASK_NAME))
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
) -> WindowsPlan:
    runner = runner or run_child
    api = api or WindowsApi()
    config_dir = validate_path(config_dir, "config dir")
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
    return WindowsPlan(
        binary, config_dir, user_sid, xml, action_argv(binary, config_dir), exists, start, show
    )


def apply_install(plan: WindowsPlan, runner: Optional[Runner] = None) -> list:
    runner = runner or run_child
    warnings = []
    tmpdir = tempfile.mkdtemp(prefix="pocketshell-task-")
    xml_path = os.path.join(tmpdir, "GatewayLink.xml")
    try:
        with open(xml_path, "wb") as handle:
            handle.write(task_xml_bytes(plan.xml))
        for argv in plan.commands(xml_path):
            verb = argv[1]
            if verb == "/Run":
                continue  # after verification below
            result = runner(argv)
            if verb == "/Create" and result.returncode != 0:
                raise _fail(result, f"registering {TASK_NAME}", ELEVATION_HINT)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    registered = query_task_xml(runner)
    if registered is None:
        raise ServiceError(f"{TASK_NAME} is not visible after registration")
    fields = parse_task_xml(registered)
    expected_args = action_argv(plan.helper, plan.config_dir)[1:]
    if (
        fields["exec_count"] != 1
        or fields["action_count"] != 1
        or (fields["command"] or "").lower() != plan.helper.lower()
        or parse_arguments(fields["arguments"]) != expected_args
        or fields["user_id"] is None
    ):
        raise ServiceError(
            f"{TASK_NAME} was registered but its action does not match the "
            "requested direct helper launch; run `pocketshell gateway service "
            "uninstall` and investigate"
        )
    if plan.start:
        result = runner(schtasks("/Run", "/TN", TASK_NAME))
        if result.returncode != 0:
            warnings.append(str(_fail(result, f"starting {TASK_NAME}")))
    return warnings


def uninstall(*, runner: Optional[Runner] = None, api: Optional[WindowsApi] = None) -> str:
    runner = runner or run_child
    registered = query_task_xml(runner)
    if registered is None:
        return f"not installed ({TASK_NAME} does not exist); nothing to do"
    try:
        helper = parse_task_xml(registered).get("command")
    except ServiceError:
        helper = None
    runner(schtasks("/End", "/TN", TASK_NAME))
    result = runner(schtasks("/Delete", "/TN", TASK_NAME, "/F"))
    if result.returncode != 0:
        raise _fail(result, f"deleting {TASK_NAME}", ELEVATION_HINT)
    if query_task_xml(runner) is not None:
        raise ServiceError(f"{TASK_NAME} still exists after deletion")
    message = f"removed the scheduled task {TASK_NAME} (enrollment and config dir untouched)"
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


def status(runner: Optional[Runner] = None, api: Optional[WindowsApi] = None) -> ServiceStatus:
    runner = runner or run_child
    st = ServiceStatus(platform="windows", name=TASK_NAME, installed=False)
    registered = query_task_xml(runner)
    if registered is None:
        return st
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
    st.details = {
        k: fields[k]
        for k in ("user_id", "logon_type", "run_level", "arguments", "working_directory",
                  "multiple_instances", "execution_time_limit", "watchdog_interval")
    }
    st.details["direct_launch"] = (
        fields["exec_count"] == 1
        and fields["action_count"] == 1
        and "cmd.exe" not in (st.helper or "").lower()
        and args[:1] == ["run"]
    )
    state = task_state(runner)
    st.details["task"] = state
    st.state = state.get("State", "unknown")
    api = api or WindowsApi()
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
    st.running = st.state == "Running" or bool(st.processes)
    if st.processes and any(p.get("session_id") not in (0, None) for p in st.processes):
        st.warnings.append("a helper process runs in an interactive session (not session 0)")
    return st
