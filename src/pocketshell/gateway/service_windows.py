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
    # The endpoint task must not be hard-terminable: its only stop is the
    # guardian's STOP protocol (Task Scheduler's End would bypass it).
    allow_hard_terminate: bool = True

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
    triggers: bool = True,
    execution_time_limit: str = "PT0S",
) -> str:
    """A managed task definition, as an XML string. ``triggers=False`` (the
    check-only qualification) registers an on-demand task with no triggers.

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

    if triggers:
        trigger_list = _sub(task, "Triggers")
        boot = _sub(trigger_list, "BootTrigger")
        _sub(boot, "Enabled", "true")
        _sub(boot, "Delay", spec.boot_delay)
        watchdog = _sub(trigger_list, "TimeTrigger")
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
        ("AllowHardTerminate", "true" if spec.allow_hard_terminate else "false"),
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
        ("ExecutionTimeLimit", execution_time_limit),
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
        "settings": _settings(root, ns),
        "triggers": _triggers(root, ns),
    }


# Task Scheduler schema defaults: an export omits elements at their default,
# so both the requested and the registered definition are compared with the
# defaults applied.
_SETTING_DEFAULTS = {
    "Enabled": "true", "AllowHardTerminate": "true", "Hidden": "false",
    "DisallowStartIfOnBatteries": "true", "StopIfGoingOnBatteries": "true",
    "StartWhenAvailable": "false", "RunOnlyIfNetworkAvailable": "false",
    "MultipleInstancesPolicy": "IgnoreNew", "ExecutionTimeLimit": "PT72H", "Priority": "7",
    "AllowStartOnDemand": "true", "WakeToRun": "false", "RunOnlyIfIdle": "false",
    "IdleSettings/StopOnIdleEnd": "true", "IdleSettings/RestartOnIdle": "false",
    "RestartOnFailure/Interval": None, "RestartOnFailure/Count": None,
}


def _settings(root, ns) -> dict:
    out = {}
    for key, default in _SETTING_DEFAULTS.items():
        element = root.find("t:Settings/" + "/".join("t:" + part for part in key.split("/")), ns)
        value = element.text.strip() if element is not None and element.text else None
        out[key] = value if value is not None else default
    return out


def _triggers(root, ns) -> list:
    out = []
    triggers = root.find("t:Triggers", ns)
    for trigger in list(triggers) if triggers is not None else []:
        def get(path, default=None, _t=trigger):
            element = _t.find(path, ns)
            return element.text.strip() if element is not None and element.text else default
        out.append({
            "type": trigger.tag.rsplit("}", 1)[-1],
            "enabled": get("t:Enabled", "true"),
            "delay": get("t:Delay"),
            "startBoundary": get("t:StartBoundary"),
            "endBoundary": get("t:EndBoundary"),
            "executionTimeLimit": get("t:ExecutionTimeLimit"),
            "interval": get("t:Repetition/t:Interval"),
            "duration": get("t:Repetition/t:Duration"),
            "stopAtDurationEnd": get("t:Repetition/t:StopAtDurationEnd", "false") if trigger.find(
                "t:Repetition", ns) is not None else None,
        })
    return out


def definition_drift(requested_xml: str, fields: dict, *, ignore_enabled: bool = False) -> list:
    """Settings and trigger differences between a requested definition and
    the registered one (F11): both normalized with the schema defaults."""
    want = parse_task_xml(requested_xml)
    problems = []
    for key, value in want["settings"].items():
        if ignore_enabled and key == "Enabled":
            continue
        have = fields["settings"].get(key)
        if have != value:
            problems.append(f"setting {key} is {have!r}, not {value!r}")
    if want["triggers"] != fields["triggers"]:
        problems.append(f"triggers {fields['triggers']} are not the requested {want['triggers']}")
    for which, triggers in (("requested", want["triggers"]), ("registered", fields["triggers"])):
        problems.extend(f"{which} {p}" for p in _trigger_canonical_problems(triggers))
    return problems


def _trigger_canonical_problems(triggers: list) -> list:
    """Canonical supported trigger values: no EndBoundary, no repetition
    Duration (indefinite), no per-trigger time limit, and a StartBoundary that
    is not in the future (else the watchdog would not run until then)."""
    import datetime

    problems = []
    now = datetime.datetime.now()
    for t in triggers:
        if t.get("endBoundary"):
            problems.append(f"{t['type']} has an EndBoundary {t['endBoundary']}")
        if t.get("duration"):
            problems.append(f"{t['type']} repetition has a Duration {t['duration']}")
        if t.get("executionTimeLimit"):
            problems.append(f"{t['type']} has a trigger ExecutionTimeLimit {t['executionTimeLimit']}")
        start = t.get("startBoundary")
        if start:
            try:
                when = datetime.datetime.fromisoformat(start.replace("Z", "+00:00"))
            except ValueError:
                problems.append(f"{t['type']} StartBoundary {start} is not ISO 8601")
                continue
            if when.astimezone() > now.astimezone():
                problems.append(f"{t['type']} StartBoundary {start} is in the future")
    return problems


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


class CallerJobError(ServiceError):
    """A spawned child stayed in the caller's KILL_ON_JOB_CLOSE job."""


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

    def process_birth(self, pid: int) -> Optional[str]:
        """Decimal creation FILETIME of a LIVE process, else None (gone,
        exited, or not openable). The identity is pid AND birth, never pid."""
        import ctypes as c
        from ctypes import wintypes as w

        k = c.WinDLL("kernel32", use_last_error=True)
        k.OpenProcess.restype = w.HANDLE
        k.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
        k.GetProcessTimes.argtypes = [w.HANDLE] + [c.POINTER(w.FILETIME)] * 4
        k.GetExitCodeProcess.argtypes = [w.HANDLE, c.POINTER(w.DWORD)]
        k.CloseHandle.argtypes = [w.HANDLE]
        handle = k.OpenProcess(0x1000, False, pid)  # QUERY_LIMITED_INFORMATION
        if not handle:
            return None
        try:
            code = w.DWORD()
            if not k.GetExitCodeProcess(handle, c.byref(code)) or code.value != 259:
                return None  # exited (STILL_ACTIVE is 259)
            times = [w.FILETIME() for _ in range(4)]
            if not k.GetProcessTimes(handle, *[c.byref(t) for t in times]):
                return None
            return str(times[0].dwHighDateTime << 32 | times[0].dwLowDateTime)
        finally:
            k.CloseHandle(handle)

    def current_session(self) -> int:
        """This process's Terminal Services session id (observed, never assumed)."""
        import ctypes as c
        from ctypes import wintypes as w

        k = c.WinDLL("kernel32", use_last_error=True)
        session = w.DWORD()
        if not k.ProcessIdToSessionId(k.GetCurrentProcessId(), c.byref(session)):
            raise ServiceError("cannot read this process's session id")
        return int(session.value)

    def spawn_hidden(self, argv: list, cwd: str, env: Optional[dict]) -> dict:
        """Start ``argv`` directly (no shell, no window) in the caller's session,
        SUSPENDED, and MEASURE the child before resuming it (the native owner's
        5844 launcher order): token user = ours, not elevated, session = ours,
        image = argv[0], creation FILETIME, and job membership.

        CREATE_BREAKAWAY_FROM_JOB is requested; if the caller's job forbids
        breakaway the child is created inside it. Independence is then never
        claimed: if the caller's job has JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE the
        suspended child is terminated (its exact handle) and CallerJobError is
        raised; otherwise the membership is reported as measured."""
        import ctypes as c
        import subprocess
        from ctypes import wintypes as w

        k = c.WinDLL("kernel32", use_last_error=True)
        a = c.WinDLL("advapi32", use_last_error=True)

        class SI(c.Structure):
            _fields_ = [("cb", w.DWORD), ("lpReserved", w.LPWSTR), ("lpDesktop", w.LPWSTR),
                        ("lpTitle", w.LPWSTR), ("dwX", w.DWORD), ("dwY", w.DWORD), ("dwXSize", w.DWORD),
                        ("dwYSize", w.DWORD), ("dwXCountChars", w.DWORD), ("dwYCountChars", w.DWORD),
                        ("dwFillAttribute", w.DWORD), ("dwFlags", w.DWORD), ("wShowWindow", w.WORD),
                        ("cbReserved2", w.WORD), ("lpReserved2", c.c_void_p), ("hStdInput", w.HANDLE),
                        ("hStdOutput", w.HANDLE), ("hStdError", w.HANDLE)]

        class PI(c.Structure):
            _fields_ = [("hProcess", w.HANDLE), ("hThread", w.HANDLE), ("dwProcessId", w.DWORD),
                        ("dwThreadId", w.DWORD)]

        k.CreateProcessW.argtypes = [w.LPCWSTR, w.LPWSTR, c.c_void_p, c.c_void_p, w.BOOL, w.DWORD,
                                     c.c_void_p, w.LPCWSTR, c.POINTER(SI), c.POINTER(PI)]
        k.IsProcessInJob.argtypes = [w.HANDLE, w.HANDLE, c.POINTER(w.BOOL)]
        k.ResumeThread.argtypes = [w.HANDLE]
        k.TerminateProcess.argtypes = [w.HANDLE, w.UINT]
        k.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]
        k.CloseHandle.argtypes = [w.HANDLE]
        k.QueryInformationJobObject.argtypes = [w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.c_void_p]
        k.QueryFullProcessImageNameW.argtypes = [w.HANDLE, w.DWORD, w.LPWSTR, c.POINTER(w.DWORD)]
        k.GetProcessTimes.argtypes = [w.HANDLE] + [c.POINTER(w.FILETIME)] * 4
        k.ProcessIdToSessionId.argtypes = [w.DWORD, c.POINTER(w.DWORD)]
        a.OpenProcessToken.argtypes = [w.HANDLE, w.DWORD, c.POINTER(w.HANDLE)]
        a.GetTokenInformation.argtypes = [w.HANDLE, c.c_int, c.c_void_p, w.DWORD, c.POINTER(w.DWORD)]

        command = c.create_unicode_buffer(subprocess.list2cmdline([str(x) for x in argv]))
        block = None
        if env is not None:
            block = c.create_unicode_buffer(
                "\0".join(f"{key}={value}" for key, value in sorted(env.items(), key=lambda kv: kv[0].casefold()))
                + "\0\0")
        base = 0x00000004 | 0x08000000 | 0x00000200 | 0x00000400  # SUSPENDED|NO_WINDOW|NEW_GROUP|UNICODE_ENV
        si = SI()
        si.cb = c.sizeof(SI)
        si.dwFlags = 0x1  # STARTF_USESHOWWINDOW
        si.wShowWindow = 0
        si.lpDesktop = "WinSta0\\Default"  # as the native 5844 launcher: the user's Default desktop
        pi = PI()
        broke_away = True
        ok = k.CreateProcessW(argv[0], command, None, None, False, base | 0x01000000,
                              c.cast(block, c.c_void_p) if block is not None else None, cwd,
                              c.byref(si), c.byref(pi))
        if not ok:
            broke_away = False  # e.g. ERROR_ACCESS_DENIED: the caller's job forbids breakaway
            ok = k.CreateProcessW(argv[0], command, None, None, False, base,
                                  c.cast(block, c.c_void_p) if block is not None else None, cwd,
                                  c.byref(si), c.byref(pi))
            if not ok:
                raise ServiceError(f"cannot start {sanitize(str(argv[0]))} (error {c.get_last_error()})")
        resumed = False
        try:
            # child token: our user, not elevated, our session
            token = w.HANDLE()
            if not a.OpenProcessToken(pi.hProcess, 0x0008, c.byref(token)):
                raise ServiceError("cannot open the child's token")
            try:
                size = w.DWORD()
                a.GetTokenInformation(token, 1, None, 0, c.byref(size))
                buf = c.create_string_buffer(size.value)
                if not a.GetTokenInformation(token, 1, buf, size.value, c.byref(size)):
                    raise ServiceError("cannot read the child's token user")
                child_sid = self._sid_text(c.cast(buf, c.POINTER(c.c_void_p))[0])
                elevation = w.DWORD()
                if not a.GetTokenInformation(token, 20, c.byref(elevation), 4, c.byref(size)):
                    raise ServiceError("cannot read the child's elevation")
            finally:
                k.CloseHandle(token)
            session = w.DWORD()
            if not k.ProcessIdToSessionId(pi.dwProcessId, c.byref(session)):
                raise ServiceError("cannot read the child's session")
            image = c.create_unicode_buffer(32768)
            n = w.DWORD(32768)
            if not k.QueryFullProcessImageNameW(pi.hProcess, 0, image, c.byref(n)) or \
                    not _same_path(image.value, str(argv[0])):
                raise ServiceError("the child's image is not the requested executable")
            mine = (self.current_sid(), self.current_session())
            if child_sid != mine[0] or elevation.value or session.value != mine[1]:
                raise ServiceError(
                    "the child token is not this user's ordinary, same-session token "
                    f"(user {'ok' if child_sid == mine[0] else 'differs'}, elevated {bool(elevation.value)}, "
                    f"session {session.value} vs {mine[1]})")
            in_job = w.BOOL()
            if not k.IsProcessInJob(pi.hProcess, None, c.byref(in_job)):
                raise ServiceError("cannot query the child's job membership")
            kill_on_close = False
            if in_job.value:
                # the child is in the CALLER's job (it could not break away):
                # inspect that job through our own membership (hJob = NULL)
                info = (c.c_byte * 144)()  # JOBOBJECT_EXTENDED_LIMIT_INFORMATION (x64)
                if not k.QueryInformationJobObject(None, 9, info, c.sizeof(info), None):
                    kill_on_close = True  # unknown limits: never claim independence
                else:
                    flags = c.c_uint32.from_buffer(info, 16).value  # BasicLimitInformation.LimitFlags
                    kill_on_close = bool(flags & 0x2000)
            if in_job.value and kill_on_close:
                raise CallerJobError(
                    "the child could not break away from the caller's job, which has "
                    "KILL_ON_JOB_CLOSE (its lifetime would end with the caller); the suspended "
                    "child was terminated before resume")
            times = [w.FILETIME() for _ in range(4)]
            if not k.GetProcessTimes(pi.hProcess, *[c.byref(t) for t in times]):
                raise ServiceError("cannot read the child's creation time")
            birth = str(times[0].dwHighDateTime << 32 | times[0].dwLowDateTime)
            if k.ResumeThread(pi.hThread) == 0xFFFFFFFF:
                raise ServiceError("cannot resume the child")
            resumed = True
            return {"pid": int(pi.dwProcessId), "creationFILETIME": birth, "inJob": bool(in_job.value),
                    "callerJobKillOnClose": kill_on_close, "brokeAway": broke_away and not in_job.value,
                    "elevated": False, "session": int(session.value)}
        finally:
            if not resumed:
                k.TerminateProcess(pi.hProcess, 1)  # the exact, still-suspended child we created
                k.WaitForSingleObject(pi.hProcess, 5000)
            k.CloseHandle(pi.hThread)
            k.CloseHandle(pi.hProcess)

    def terminate_exact(self, pid: int, birth: str, image: str) -> bool:
        """Terminate ONLY the process whose pid, creation FILETIME and image all
        match the recorded identity (a reused pid is never touched)."""
        import ctypes as c
        from ctypes import wintypes as w

        k = c.WinDLL("kernel32", use_last_error=True)
        k.OpenProcess.restype = w.HANDLE
        k.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
        k.GetProcessTimes.argtypes = [w.HANDLE] + [c.POINTER(w.FILETIME)] * 4
        k.QueryFullProcessImageNameW.argtypes = [w.HANDLE, w.DWORD, w.LPWSTR, c.POINTER(w.DWORD)]
        k.TerminateProcess.argtypes = [w.HANDLE, w.UINT]
        k.WaitForSingleObject.argtypes = [w.HANDLE, w.DWORD]
        k.CloseHandle.argtypes = [w.HANDLE]
        # PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE
        handle = k.OpenProcess(0x0001 | 0x1000 | 0x00100000, False, pid)
        if not handle:
            return False
        try:
            times = [w.FILETIME() for _ in range(4)]
            if not k.GetProcessTimes(handle, *[c.byref(t) for t in times]):
                return False
            if str(times[0].dwHighDateTime << 32 | times[0].dwLowDateTime) != birth:
                return False
            buf = c.create_unicode_buffer(32768)
            size = w.DWORD(32768)
            if not k.QueryFullProcessImageNameW(handle, 0, buf, c.byref(size)) or not _same_path(buf.value, image):
                return False
            if not k.TerminateProcess(handle, 1):
                return False
            return k.WaitForSingleObject(handle, 5000) == 0
        finally:
            k.CloseHandle(handle)

    def process_image(self, pid: int) -> Optional[str]:
        """Full image path of a live process (QueryFullProcessImageNameW)."""
        import ctypes as c
        from ctypes import wintypes as w

        k = c.WinDLL("kernel32", use_last_error=True)
        k.OpenProcess.restype = w.HANDLE
        k.OpenProcess.argtypes = [w.DWORD, w.BOOL, w.DWORD]
        k.QueryFullProcessImageNameW.argtypes = [w.HANDLE, w.DWORD, w.LPWSTR, c.POINTER(w.DWORD)]
        k.CloseHandle.argtypes = [w.HANDLE]
        handle = k.OpenProcess(0x1000, False, pid)
        if not handle:
            return None
        try:
            buf = c.create_unicode_buffer(32768)
            size = w.DWORD(32768)
            return buf.value if k.QueryFullProcessImageNameW(handle, 0, buf, c.byref(size)) else None
        finally:
            k.CloseHandle(handle)

    def path_authority(self, path: str, owner_sid: str, *, role: str, directory: bool = False,
                       protected: bool = False, servicing: bool = False) -> None:
        """The guardian's path_authority (6cf7ae85), as a refusal BEFORE the
        task can execute anything: no reparse point on the path or any
        ancestor, a regular single-link file (servicing System32 images may
        be hard-linked), every ancestor without foreign
        replace/delete/write-DAC authority (mask 0x500d0150), the object
        itself owned as its role requires and without foreign write
        authority (0x500d0116) — private objects: owned by ``owner_sid``,
        no foreign allow ACE at all."""
        import pathlib

        p = pathlib.Path(path)
        for item in [p, *p.parents]:
            try:
                st = item.lstat()
            except OSError:
                raise ServiceError(f"{sanitize(str(item))} is missing") from None
            if getattr(st, "st_file_attributes", 0) & 0x400:
                raise ServiceError(f"{sanitize(str(item))} is a reparse point")
        st = p.stat()
        if directory:
            if not p.is_dir():
                raise ServiceError(f"{sanitize(path)} must be a directory")
        else:
            if not p.is_file():
                raise ServiceError(f"{sanitize(path)} must be a regular file")
            if st.st_nlink != 1 and not (servicing and st.st_nlink >= 1):
                raise ServiceError(f"{sanitize(path)} must be a regular single-link file")
        for parent in reversed(p.parents):
            self._check_acl(str(parent), owner_sid, "ancestor")
        self._check_acl(str(p), owner_sid, "private" if role == "private" else "file",
                        protected=protected, servicing=servicing)

    def read_private_file(self, path: str, owner_sid: str, limit: int) -> Optional[bytes]:
        """A protocol file, or None if it does not exist (F9).

        The path must pass the same authority as the guardian's private role
        (no reparse point on it or any ancestor, protected ancestors without
        foreign mutation authority, owned by ``owner_sid``, no foreign allow
        ACE, single link). It is then opened with FILE_FLAG_OPEN_REPARSE_POINT
        and re-validated BY HANDLE (attributes, link count, owner) before the
        bounded read, so a swap between check and read is refused.
        """
        import ctypes as c
        import os as _os
        from ctypes import wintypes as w

        if not _os.path.lexists(path):
            return None
        self.path_authority(path, owner_sid, role="private")
        k = c.WinDLL("kernel32", use_last_error=True)
        a = c.WinDLL("advapi32", use_last_error=True)
        k.CreateFileW.restype = w.HANDLE
        k.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, c.c_void_p, w.DWORD, w.DWORD, w.HANDLE]
        k.ReadFile.argtypes = [w.HANDLE, c.c_void_p, w.DWORD, c.POINTER(w.DWORD), c.c_void_p]
        k.GetFileInformationByHandle.argtypes = [w.HANDLE, c.c_void_p]
        k.CloseHandle.argtypes = [w.HANDLE]
        k.LocalFree.argtypes = [c.c_void_p]
        a.GetSecurityInfo.argtypes = [w.HANDLE, c.c_int, w.DWORD] + [c.POINTER(c.c_void_p)] * 5
        a.GetSecurityInfo.restype = w.DWORD

        class Info(c.Structure):
            _fields_ = [("attributes", w.DWORD), ("created", w.FILETIME), ("accessed", w.FILETIME),
                        ("written", w.FILETIME), ("volume", w.DWORD), ("size_high", w.DWORD),
                        ("size_low", w.DWORD), ("links", w.DWORD), ("index_high", w.DWORD),
                        ("index_low", w.DWORD)]

        # GENERIC_READ | READ_CONTROL; share read only; OPEN_EXISTING;
        # FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN
        handle = k.CreateFileW(path, 0x80000000 | 0x00020000, 1, None, 3, 0x00200000 | 0x08000000, None)
        if handle in (None, w.HANDLE(-1).value):
            raise ServiceError(f"cannot open {sanitize(path)} (error {c.get_last_error()})")
        try:
            info = Info()
            if not k.GetFileInformationByHandle(handle, c.byref(info)):
                raise ServiceError(f"cannot inspect {sanitize(path)}")
            if info.attributes & 0x400 or info.attributes & 0x10 or info.links != 1:
                raise ServiceError(f"{sanitize(path)} is a reparse point, directory or multiply-linked file")
            # Re-validate the OPENED object (not the path): owner AND the full
            # DACL under the private role, so a swap after the path check is
            # refused (OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION).
            owner, dacl, sd = c.c_void_p(), c.c_void_p(), c.c_void_p()
            if a.GetSecurityInfo(handle, 1, 1 | 4, c.byref(owner), None, c.byref(dacl), None, c.byref(sd)):
                raise ServiceError(f"cannot read the security of the opened {sanitize(path)}")
            try:
                if self._sid_text(owner) != owner_sid:
                    raise ServiceError(f"the opened {sanitize(path)} is not owned by {owner_sid}")
                self._validate_security(f"the opened {path}", owner, dacl, sd, owner_sid, "private")
            finally:
                k.LocalFree(sd)
            buf = c.create_string_buffer(limit + 1)
            read = w.DWORD()
            if not k.ReadFile(handle, buf, limit + 1, c.byref(read), None):
                raise ServiceError(f"cannot read {sanitize(path)}")
            if read.value > limit:
                raise ServiceError(f"{sanitize(path)} is larger than {limit} bytes")
            return buf.raw[: read.value]
        finally:
            k.CloseHandle(handle)

    _TRUSTED_INSTALLER = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

    def _check_acl(self, path: str, owner_sid: str, role: str, *, protected: bool = False,
                   servicing: bool = False) -> None:
        import ctypes as c
        from ctypes import wintypes as w

        a = c.WinDLL("advapi32", use_last_error=True)
        k = c.WinDLL("kernel32", use_last_error=True)
        a.GetNamedSecurityInfoW.argtypes = [w.LPCWSTR, c.c_int, w.DWORD] + [c.POINTER(c.c_void_p)] * 5
        a.GetNamedSecurityInfoW.restype = w.DWORD
        a.GetSecurityDescriptorControl.argtypes = [c.c_void_p, c.POINTER(w.WORD), c.POINTER(w.DWORD)]
        a.GetAce.argtypes = [c.c_void_p, w.DWORD, c.POINTER(c.c_void_p)]
        k.LocalFree.argtypes = [c.c_void_p]
        owner, group, dacl, sacl, sd = (c.c_void_p() for _ in range(5))
        code = a.GetNamedSecurityInfoW(path, 1, 5, c.byref(owner), c.byref(group), c.byref(dacl),
                                       c.byref(sacl), c.byref(sd))
        if code:
            raise ServiceError(f"cannot read the security of {sanitize(path)} (error {code})")
        try:
            self._validate_security(path, owner, dacl, sd, owner_sid, role,
                                    protected=protected, servicing=servicing)
        finally:
            k.LocalFree(sd)

    def _validate_security(self, path: str, owner, dacl, sd, owner_sid: str, role: str, *,
                           protected: bool = False, servicing: bool = False) -> None:
        """The guardian's check_acl rules on an already-fetched descriptor
        (from a path or from an OPEN HANDLE)."""
        import ctypes as c
        from ctypes import wintypes as w

        a = c.WinDLL("advapi32", use_last_error=True)
        a.GetSecurityDescriptorControl.argtypes = [c.c_void_p, c.POINTER(w.WORD), c.POINTER(w.DWORD)]
        a.GetAce.argtypes = [c.c_void_p, w.DWORD, c.POINTER(c.c_void_p)]
        trusted = {owner_sid, "S-1-5-18", "S-1-5-32-544", self._TRUSTED_INSTALLER}
        if servicing:
            trusted.discard(owner_sid)
        actual = self._sid_text(owner)
        if actual not in ({owner_sid} if role == "private" else trusted):
            raise ServiceError(f"{sanitize(path)} owner {actual} has no {role} authority")
        ctrl, rev = w.WORD(), w.DWORD()
        if not a.GetSecurityDescriptorControl(sd, c.byref(ctrl), c.byref(rev)) or (
            protected and not ctrl.value & 0x1000
        ):
            raise ServiceError(f"{sanitize(path)} must have a protected DACL")
        if not dacl:
            raise ServiceError(f"{sanitize(path)} has a NULL DACL")
        count = c.c_ushort.from_address(dacl.value + 4).value
        mutation = 0x500D0150 if role == "ancestor" else 0x500D0116
        for i in range(count):
            ace = c.c_void_p()
            if not a.GetAce(dacl, i, c.byref(ace)):
                raise ServiceError(f"cannot read an ACE of {sanitize(path)}")
            header = (c.c_ubyte * 4).from_address(ace.value)
            if header[0] not in (0, 1):
                raise ServiceError(f"{sanitize(path)} has an unsupported ACE type")
            if header[0] != 0 or header[1] & 8:
                continue  # deny ACEs never grant; inherit-only does not apply here
            sid = self._sid_text(c.c_void_p(ace.value + 8))
            mask = w.DWORD.from_address(ace.value + 4).value
            if sid in trusted:
                continue
            if role == "private" or mask & mutation:
                raise ServiceError(
                    f"{sanitize(path)}: {sid} holds foreign mutation authority "
                    f"(role {role}, mask 0x{mask:08X})"
                )

    def listener_pids(self, port: int) -> list:
        """[(address, pid)] of IPv4 TCP listeners on ``port``."""
        import ctypes as c
        import socket as s
        from ctypes import wintypes as w

        class Row(c.Structure):
            _fields_ = [("state", w.DWORD), ("local", w.DWORD), ("lport", w.DWORD),
                        ("remote", w.DWORD), ("rport", w.DWORD), ("pid", w.DWORD)]

        ip = c.WinDLL("iphlpapi", use_last_error=True)
        ip.GetExtendedTcpTable.argtypes = [c.c_void_p, c.POINTER(w.DWORD), w.BOOL, w.DWORD, c.c_int, w.DWORD]
        size = w.DWORD(0)
        ip.GetExtendedTcpTable(None, c.byref(size), False, 2, 3, 0)  # AF_INET, OWNER_PID_LISTENER
        for _ in range(3):
            buf = c.create_string_buffer(max(size.value, 4))
            code = ip.GetExtendedTcpTable(buf, c.byref(size), False, 2, 3, 0)
            if code == 0:
                break
            if code != 122:  # ERROR_INSUFFICIENT_BUFFER
                raise ServiceError(f"cannot list TCP listeners (error {code})")
        else:
            raise ServiceError("cannot list TCP listeners (table keeps growing)")
        count = w.DWORD.from_buffer(buf).value
        rows = []
        for i in range(count):
            row = Row.from_buffer(buf, 4 + i * c.sizeof(Row))
            if s.ntohs(row.lport & 0xFFFF) == port:
                rows.append((s.inet_ntoa(int(row.local).to_bytes(4, "little")), int(row.pid)))
        return rows

    def write_owned_file(self, path: str, data: bytes, owner_sid: str) -> None:
        """Create ``path`` (must not exist) owned by ``owner_sid`` with a
        protected owner/SYSTEM/Administrators DACL, written to a temp name in
        the same directory and renamed into place (readers never see a
        partial file)."""
        import ctypes as c
        import secrets
        from ctypes import wintypes as w

        if not re.fullmatch(r"S-1-5-21-\d+-\d+-\d+-\d+", owner_sid):
            raise ServiceError("unexpected owner SID")
        a = c.WinDLL("advapi32", use_last_error=True)
        k = c.WinDLL("kernel32", use_last_error=True)
        a.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            w.LPCWSTR, w.DWORD, c.POINTER(c.c_void_p), c.c_void_p]
        k.CreateFileW.restype = w.HANDLE
        k.CreateFileW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, c.c_void_p, w.DWORD, w.DWORD, w.HANDLE]
        k.WriteFile.argtypes = [w.HANDLE, c.c_char_p, w.DWORD, c.POINTER(w.DWORD), c.c_void_p]
        k.CloseHandle.argtypes = [w.HANDLE]
        k.MoveFileExW.argtypes = [w.LPCWSTR, w.LPCWSTR, w.DWORD]
        k.DeleteFileW.argtypes = [w.LPCWSTR]
        k.LocalFree.argtypes = [c.c_void_p]

        class SA(c.Structure):
            _fields_ = [("length", w.DWORD), ("descriptor", c.c_void_p), ("inherit", w.BOOL)]

        sd = c.c_void_p()
        sddl = f"O:{owner_sid}D:P(A;;FA;;;{owner_sid})(A;;FA;;;SY)(A;;FA;;;BA)"
        if not a.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, c.byref(sd), None):
            raise ServiceError("cannot build the owner-only security descriptor")
        tmp = path + "." + secrets.token_hex(8) + ".tmp"
        try:
            sa = SA(c.sizeof(SA), sd, False)
            handle = k.CreateFileW(tmp, 0x40000000, 0, c.byref(sa), 1, 0x80, None)  # CREATE_NEW
            if handle in (None, w.HANDLE(-1).value):
                raise ServiceError(f"cannot create {sanitize(tmp)} (error {c.get_last_error()})")
            try:
                written = w.DWORD()
                if not k.WriteFile(handle, data, len(data), c.byref(written), None) or written.value != len(data):
                    raise ServiceError(f"cannot write {sanitize(tmp)}")
            finally:
                k.CloseHandle(handle)
            if not k.MoveFileExW(tmp, path, 0x8):  # WRITE_THROUGH, never replace
                raise ServiceError(f"cannot publish {sanitize(path)} (error {c.get_last_error()})")
        finally:
            k.DeleteFileW(tmp)
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


# IRegisteredTask.State
TASK_STATES = {0: "Unknown", 1: "Disabled", 2: "Queued", 3: "Ready", 4: "Running"}
# Confirmed absence: the task (ERROR_FILE_NOT_FOUND) or its \PocketShell
# folder (ERROR_PATH_NOT_FOUND) does not exist. Every other failure — access
# denied, the service unavailable, PowerShell itself failing — is UNKNOWN and
# must never be reported as "not installed" or as a successful deletion.
_NOT_FOUND_HRESULTS = {"0x80070002", "0x80070003"}

def _query_script(leaf: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9]+", leaf):
        raise ServiceError("unexpected task name")
    from pocketshell.gateway.service_task_acl import PS_SDJ

    return (
        "$ErrorActionPreference='Stop';" + PS_SDJ +
        "try{"
        "$s=New-Object -ComObject Schedule.Service;$s.Connect();"
        f"$f=$s.GetFolder('{TASK_FOLDER.rstrip(chr(92))}');$t=$f.GetTask('{leaf}');"
        "$tsd=$null;$fsd=$null;try{$tsd=SDJ([string]$t.GetSecurityDescriptor(7))}catch{};"
        "try{$fsd=SDJ([string]$f.GetSecurityDescriptor(7))}catch{};"
        "$o=[ordered]@{found=$true;state=[int]$t.State;last_result=[int64]$t.LastTaskResult;"
        "xml=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($t.Xml));taskSD=$tsd;folderSD=$fsd}"
        "}catch{"
        "$e=$_.Exception;while($e.InnerException){$e=$e.InnerException};"
        "$o=[ordered]@{found=$false;hresult=('0x{0:X8}' -f $e.HResult);message=[string]$e.Message}"
        "};"
        "$o|ConvertTo-Json -Compress -Depth 8"
    )


_QUERY_SCRIPT = _query_script(TASK_LEAF)


@dataclass
class TaskInfo:
    xml: str
    state: str
    last_result: Optional[int]
    task_sddl: object = None  # structured descriptor (service_task_acl) or None
    folder_sddl: object = None


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
    task_sd, folder_sd = data.get("taskSD"), data.get("folderSD")
    return TaskInfo(xml, state, last if isinstance(last, int) else None,
                    task_sd if isinstance(task_sd, (dict, str)) else None,
                    folder_sd if isinstance(folder_sd, (dict, str)) else None)


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
    endpoint: Optional[object] = None  # service_windows_endpoint.EndpointPlan
    include_link: bool = True

    def commands(self, xml_dir: str = "<private temp dir>") -> list:
        """The schtasks sequence: endpoint task first (when any), then link."""
        commands = []
        tasks = []
        if self.endpoint is not None:
            tasks.append((self.endpoint.name, self.endpoint.leaf, False))
        if self.include_link:
            tasks.append((TASK_NAME, TASK_LEAF, self.replace))
        for name, leaf, replace in tasks:
            if replace:
                commands.append(schtasks("/End", "/TN", name))
            commands.append(["<Task Scheduler COM>", "ITaskFolder.RegisterTask", name,
                             f"{xml_dir}\\{leaf}.xml",
                             "TASK_CREATE_OR_UPDATE" if replace else "TASK_CREATE",
                             self.user_sid, self.logon_type, "O:<own>D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;<own>)"])
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
    endpoint_only: bool = False,
    instance: Optional[str] = None,
    check_only: bool = False,
) -> WindowsPlan:
    runner = runner or run_child
    api = api or WindowsApi()
    if endpoint_only and not endpoint_manifest:
        raise ServiceError("--endpoint-only needs --with-endpoint MANIFEST")
    if instance is not None and not endpoint_only:
        raise ServiceError(
            "--instance is for an isolated qualification endpoint: use it with --endpoint-only "
            "(it never touches the production GatewayLink task)"
        )
    config_dir = validate_path(config_dir, "config dir")
    manifest_path = validate_path(endpoint_manifest, "endpoint manifest") if endpoint_manifest else None
    binary = resolve_helper(helper, runner)
    show = common.check_enrollment(binary, config_dir, runner)
    user_sid = api.current_sid()
    check_owner(api, config_dir, user_sid)
    xml = build_task_xml(binary, config_dir, user_sid, logon_type=logon_type, enabled=start)
    exists = False
    if not endpoint_only:
        exists = query_task_xml(runner) is not None
        if exists and not force:
            raise ServiceError(
                f"the scheduled task {TASK_NAME} already exists; pass --force to "
                "replace it (or `pocketshell gateway service uninstall` first)"
            )
    endpoint = None
    if manifest_path:
        from pocketshell.gateway import service_windows_endpoint as wep

        endpoint = wep.plan_endpoint(
            manifest_path, show, user_sid,
            instance=instance, start=start, api=api, runner=runner, logon_type=logon_type,
            check_only=check_only,
        )
    return WindowsPlan(
        binary, config_dir, user_sid, xml, action_argv(binary, config_dir), exists, start, show,
        logon_type, endpoint, not endpoint_only,
    )


def readback_problems(fields: dict, plan: "WindowsPlan", api: WindowsApi) -> list:
    """Differences between the registered LINK task and the requested one."""
    return spec_readback_problems(
        fields, link_spec(plan.helper, plan.config_dir), plan.user_sid, plan.logon_type, api
    )


def spec_readback_problems(
    fields: dict, spec: TaskSpec, user_sid: str, logon_type: str, api: WindowsApi,
    expected_xml: Optional[str] = None, ignore_enabled: bool = False,
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
    if expected_xml is not None:
        problems.extend(definition_drift(expected_xml, fields, ignore_enabled=ignore_enabled))
    return problems


TASK_CREATE, TASK_CREATE_OR_UPDATE = 2, 6
LOGON_TYPES = {"Password": 1, "S4U": 2, "InteractiveToken": 3}


def _com_payload_script(payload: dict, body: str, prelude: str = "") -> str:
    """A COM script whose inputs travel base64(JSON) (no quoting of paths,
    SIDs or SDDL into PowerShell source)."""
    import base64

    b64 = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
    return (
        "$ErrorActionPreference='Stop';" + prelude +
        f"$p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{b64}'))|ConvertFrom-Json;"
        "try{$s=New-Object -ComObject Schedule.Service;$s.Connect();" + body +
        "}catch{$e=$_.Exception;while($e.InnerException){$e=$e.InnerException};"
        "[ordered]@{ok=$false;hresult=('0x{0:X8}' -f $e.HResult);message=[string]$e.Message}|ConvertTo-Json -Compress}"
    )


def _com_json(runner: Runner, script: str, what: str) -> dict:
    result = runner(_powershell(script))
    try:
        data = json.loads(decode(result.stdout).strip() or "null")
    except ValueError:
        data = None
    if result.returncode != 0 or not isinstance(data, dict):
        raise ServiceError(f"{what} failed (exit {result.returncode}): "
                           f"{sanitize(decode(result.stderr or result.stdout), 300)}")
    if not data.get("ok"):
        raise ServiceError(f"{what} failed (HRESULT {sanitize(str(data.get('hresult')), 20)}: "
                           f"{sanitize(str(data.get('message', '')), 300)})\n{ELEVATION_HINT}")
    return data


def ensure_task_folder(runner: Runner, user_sid: str) -> str:
    """\\PocketShell exists with the protected own/SYSTEM/Administrators
    descriptor (contract ec8534aa), creating it with exactly that SD if absent.
    An existing folder that does not satisfy the contract is refused: the
    service never re-ACLs an existing folder."""
    from pocketshell.gateway import service_task_acl as acl

    script = _com_payload_script(
        {"folder": TASK_FOLDER.rstrip("\\"), "name": TASK_FOLDER.strip("\\"), "sddl": acl.folder_sddl(user_sid)},
        "$c=$false;try{$f=$s.GetFolder($p.folder)}catch{$h=$_.Exception;while($h.InnerException){$h=$h.InnerException};"
        "if($h.HResult -notin @(-2147024894,-2147024893)){throw};"
        "$f=$s.GetFolder('\\').CreateFolder($p.name,$p.sddl);$c=$true};"
        "[ordered]@{ok=$true;created=$c;sddl=(SDJ([string]$f.GetSecurityDescriptor(7)))}|ConvertTo-Json -Compress -Depth 6",
        prelude=acl.PS_SDJ,
    )
    data = _com_json(runner, script, f"preparing the task folder {TASK_FOLDER}")
    problems = acl._object_problems(data.get("sddl"), user_sid, folder=True)
    if problems:
        raise ServiceError(
            f"the task folder {TASK_FOLDER} does not satisfy the task-object security contract "
            f"({'; '.join(problems)}); refusing to register into it (it was "
            + ("created" if data.get("created") else "already present") + "; it is not changed)"
        )
    return data["sddl"]


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
    """COM RegisterTask with the explicit task SD into the protected folder,
    read back (definition AND task/folder security), delete on any mismatch."""
    from pocketshell.gateway import service_task_acl as acl

    ensure_task_folder(runner, user_sid)
    tmpdir = tempfile.mkdtemp(prefix="pocketshell-task-")
    xml_path = os.path.join(tmpdir, spec.leaf + ".xml")
    try:
        with open(xml_path, "wb") as handle:
            handle.write(task_xml_bytes(xml))
        if replace:
            runner(schtasks("/End", "/TN", spec.name))
        script = _com_payload_script(
            {"folder": TASK_FOLDER.rstrip("\\"), "name": spec.leaf, "xml": xml_path,
             "flags": TASK_CREATE_OR_UPDATE if replace else TASK_CREATE, "user": user_sid,
             "logon": LOGON_TYPES[logon_type], "sddl": acl.task_sddl(user_sid)},
            "$f=$s.GetFolder($p.folder);$x=[IO.File]::ReadAllText($p.xml,[Text.Encoding]::Unicode);"
            "$null=$f.RegisterTask($p.name,$x,[int]$p.flags,$p.user,$null,[int]$p.logon,$p.sddl);"
            "[ordered]@{ok=$true}|ConvertTo-Json -Compress",
        )
        try:
            _com_json(runner, script, f"registering {spec.name}")
        except ServiceError as exc:
            raise ServiceError(str(exc)) from None
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    info = query_task(runner, spec.leaf)
    if info is None:
        raise ServiceError(f"{spec.name} is not visible after registration")
    try:
        problems = spec_readback_problems(
            parse_task_xml(info.xml), spec, user_sid, logon_type, api, expected_xml=xml
        )
    except ServiceError as exc:
        problems = [str(exc)]
    problems += acl.task_object_problems(info.task_sddl, info.folder_sddl, user_sid)
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
        # "dial failed" routes. If the endpoint is not READY (CURRENT.json,
        # held daemon, exact host key), install exits 5 and the link task is
        # not registered (the endpoint task is kept, inspect with `status`).
        from pocketshell.gateway import service_windows_endpoint as wep

        _register(
            plan.endpoint.spec, plan.endpoint.xml, replace=False,
            user_sid=plan.user_sid, logon_type=plan.logon_type, runner=runner, api=api,
        )
        if plan.start:
            confirmed = wep.start_and_confirm(plan.endpoint, runner, api)
            if confirmed.get("checkOnly"):
                return [confirmed["detail"]]
    if not plan.include_link:
        return []
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
    *,
    force: bool = False,
    runner: Optional[Runner] = None,
    api: Optional[WindowsApi] = None,
    instance: Optional[str] = None,
) -> str:
    runner = runner or run_child
    api = api or WindowsApi()
    from pocketshell.gateway import service_windows_endpoint as wep

    if instance is not None:
        leaf = ep.leaf_for(instance)
        note = wep.stop_and_remove(leaf, force=force, runner=runner, api=api)
        if note is None:
            return f"not installed ({TASK_FOLDER + leaf} does not exist); nothing to do"
        return f"removed {TASK_FOLDER + leaf} ({note}); endpoint files untouched"
    # Link first (no new routes), then the endpoint it bridges to.
    fields = _uninstall_one(TASK_LEAF, force=force, runner=runner, what="link")
    endpoint_note = wep.stop_and_remove(ep.ENDPOINT_LEAF, force=force, runner=runner, api=api)
    if fields is None and endpoint_note is None:
        return f"not installed ({TASK_NAME} does not exist); nothing to do"
    removed = []
    if fields is not None:
        removed.append(TASK_NAME)
    if endpoint_note is not None:
        removed.append(f"{TASK_FOLDER + ep.ENDPOINT_LEAF} ({endpoint_note})")
    message = (
        f"removed the scheduled task(s) {', '.join(removed)} (enrollment, config dir "
        "and endpoint files untouched)"
    )
    helper = fields.get("command") if fields is not None else None
    if helper:
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


def status(
    runner: Optional[Runner] = None,
    api: Optional[WindowsApi] = None,
    instance: Optional[str] = None,
) -> ServiceStatus:
    runner = runner or run_child
    api = api or WindowsApi()
    from pocketshell.gateway import service_windows_endpoint as wep

    if instance is not None:
        leaf = ep.leaf_for(instance)
        st = ServiceStatus(platform="windows", name=TASK_FOLDER + leaf, installed=False)
        endpoint = wep.endpoint_status(leaf, runner, api)
        if endpoint is None:
            return st
        st.installed, st.managed = True, endpoint["managed"]
        st.definition_path, st.state = endpoint["task"], endpoint["state"]
        st.details["endpoint"] = endpoint
        st.running = endpoint["running"]
        return st
    st = ServiceStatus(platform="windows", name=TASK_NAME, installed=False)
    info = query_task(runner)
    endpoint = wep.endpoint_status(ep.ENDPOINT_LEAF, runner, api)
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
    from pocketshell.gateway import service_task_acl as acl

    try:
        acl_problems = acl.task_object_problems(info.task_sddl, info.folder_sddl, api.current_sid())
    except ServiceError as exc:
        acl_problems = [str(exc)]
    st.details["taskObjectAuthority"] = {"ok": not acl_problems, "problems": acl_problems,
                                        "taskSD": info.task_sddl, "folderSD": info.folder_sddl}
    if acl_problems:
        st.running = False
        st.warnings.append("task object security: " + "; ".join(acl_problems))
    if endpoint is not None and not endpoint["running"]:
        st.running = False
        problems = list(endpoint["contract"]) + list((endpoint["readiness"] or {}).get("problems", []))
        st.warnings.append(
            f"the endpoint task {endpoint['task']} is {endpoint['state']}"
            + (f": {'; '.join(problems)}" if problems else "")
        )
    if st.processes and not st.running:
        st.warnings.append(
            "process(es) from the task's helper path are running, but the task "
            f"is {st.state}: not proof the task runs the agent (diagnostic only)"
        )
    if st.processes and any(p.get("session_id") not in (0, None) for p in st.processes):
        st.warnings.append("a helper process runs in an interactive session (not session 0)")
    return st
