"""Shared pieces of ``pocketshell gateway service`` (both platforms).

Kept free of click and of platform imports so the Linux and Windows
backends, and their unit tests, can use them on any OS.
"""

from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Optional, Sequence

# Windows: never give a child its own console window. A console-less parent
# (pythonw, a GUI, a scheduled task) would otherwise make every console
# child (schtasks, powershell, the helper probes) flash a visible window.
CREATE_NO_WINDOW = 0x08000000

CHILD_TIMEOUT_SECONDS = 60.0
CHILD_MAX_OUTPUT_BYTES = 256 * 1024

# Files `pocketshell-link enroll` writes into the config dir. Only their
# EXISTENCE (and, on Windows, their owner SID) is ever inspected here; the
# contents are read by the helper's own `show`, never by this module.
CONFIG_FILE = "config.json"
KEY_FILE = "device_ed25519.pem"

# status exit codes (LSB-style: 0 running, 3 not running, 4 unknown/absent)
EXIT_RUNNING = 0
EXIT_NOT_RUNNING = 3
EXIT_NOT_INSTALLED = 4
# install: registered/enabled, but starting it failed or was not confirmed
EXIT_NOT_STARTED = 5


class ServiceError(Exception):
    """An operator-facing refusal; the message is safe to print."""

    exit_code = 1


class NotEnrolledError(ServiceError):
    exit_code = 1


class NotStartedError(ServiceError):
    """Installed and kept, but not (confirmed) started: a distinct result."""

    exit_code = EXIT_NOT_STARTED


@dataclass
class ChildResult:
    returncode: int
    stdout: bytes
    stderr: bytes


def run_child(
    argv: Sequence[str],
    *,
    timeout: float = CHILD_TIMEOUT_SECONDS,
    input_bytes: Optional[bytes] = None,
) -> ChildResult:
    """Run a child without a shell, stdin detached, output captured+capped.

    On Windows the child gets ``CREATE_NO_WINDOW`` (never a visible
    console). A child that cannot start or overruns ``timeout`` raises
    :class:`ServiceError` with a sanitized message — never a traceback.
    """
    kwargs = {}
    if sys.platform == "win32":
        kwargs["creationflags"] = CREATE_NO_WINDOW
    try:
        proc = subprocess.run(
            list(argv),
            input=input_bytes,
            stdin=None if input_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
            **kwargs,
        )
    except FileNotFoundError:
        raise ServiceError(f"{sanitize(os.path.basename(argv[0]))} was not found") from None
    except subprocess.TimeoutExpired:
        raise ServiceError(
            f"{sanitize(os.path.basename(argv[0]))} did not finish within {timeout:g}s"
        ) from None
    except OSError as exc:
        raise ServiceError(
            f"could not run {sanitize(os.path.basename(argv[0]))}: "
            f"{sanitize(exc.strerror or type(exc).__name__)}"
        ) from None
    return ChildResult(
        proc.returncode,
        proc.stdout[:CHILD_MAX_OUTPUT_BYTES],
        proc.stderr[:CHILD_MAX_OUTPUT_BYTES],
    )


def decode(data: bytes) -> str:
    """Decode child output: UTF-16 (BOM or NUL-interleaved), UTF-8, else OEM."""
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16", "replace")
    if len(data) >= 2 and b"\x00" in data[:200]:
        return data.decode("utf-16-le", "replace")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        pass
    if sys.platform == "win32":
        try:
            import ctypes

            return data.decode(f"cp{ctypes.windll.kernel32.GetOEMCP()}", "replace")
        except (LookupError, AttributeError, OSError):
            pass
    return data.decode("latin-1")


def sanitize(text: str, limit: int = 4000) -> str:
    """Make child-derived text safe to print: no control/escape sequences."""
    out = []
    for ch in text:
        if ch in "\n\t":
            out.append(ch)
        elif ch == "\r":
            continue
        elif ord(ch) < 0x20 or 0x7F <= ord(ch) < 0xA0 or ch in "  ﻿":
            out.append("?")
        else:
            out.append(ch)
    text = "".join(out).strip()
    if len(text) > limit:
        text = text[:limit] + " …"
    return text


def has_control_chars(value: str) -> bool:
    return any(ord(ch) < 0x20 or 0x7F <= ord(ch) < 0xA0 for ch in value)


def parse_show(text: str) -> dict:
    """``key: value`` lines of the helper's ``show`` (non-secret) output."""
    fields = {}
    for line in text.splitlines():
        name, sep, value = line.partition(":")
        if sep and name.strip():
            fields[name.strip()] = value.strip()
    return fields


@dataclass
class ServiceStatus:
    platform: str
    name: str
    installed: bool
    running: bool = False
    managed: bool = False
    state: str = "absent"
    definition_path: Optional[str] = None
    helper: Optional[str] = None
    config_dir: Optional[str] = None
    helper_sha256: Optional[str] = None
    helper_allowed: Optional[bool] = None
    processes: list = field(default_factory=list)
    details: dict = field(default_factory=dict)
    show: Optional[str] = None
    show_error: Optional[str] = None
    warnings: list = field(default_factory=list)

    @property
    def exit_code(self) -> int:
        if not self.installed:
            return EXIT_NOT_INSTALLED
        return EXIT_RUNNING if self.running else EXIT_NOT_RUNNING

    def as_dict(self) -> dict:
        return {
            "platform": self.platform,
            "name": self.name,
            "installed": self.installed,
            "running": self.running,
            "managed": self.managed,
            "state": self.state,
            "definition_path": self.definition_path,
            "helper": self.helper,
            "config_dir": self.config_dir,
            "helper_sha256": self.helper_sha256,
            "helper_allowed": self.helper_allowed,
            "processes": self.processes,
            "details": self.details,
            "show": self.show,
            "show_error": self.show_error,
            "warnings": self.warnings,
            "exit_code": self.exit_code,
        }


def check_enrollment(helper: str, config_dir: str, runner=None) -> str:
    """Refuse unless ``config_dir`` holds an enrollment the helper accepts.

    Checks that ``config.json`` and the device key EXIST (never opening the
    key), then runs ``<helper> show --config-dir DIR`` — the helper itself
    loads and validates the state (including, on Windows, the key's owner
    and protected DACL) and prints only non-secret fields. Returns that
    sanitized output. Never enrolls or modifies anything.
    """
    runner = runner or run_child
    missing = [
        name
        for name in (CONFIG_FILE, KEY_FILE)
        if not os.path.isfile(os.path.join(config_dir, name))
    ]
    if not os.path.isdir(config_dir) or missing:
        raise NotEnrolledError(
            f"{sanitize(config_dir)} is not an enrolled gateway config dir "
            f"(missing: {', '.join(missing) or 'the directory'}); "
            "run `pocketshell gateway enroll` first"
        )
    result = runner([helper, "show", "--config-dir", config_dir])
    if result.returncode != 0:
        detail = sanitize(decode(result.stderr or result.stdout), 600)
        raise NotEnrolledError(
            f"the helper's `show --config-dir` refused {sanitize(config_dir)} "
            f"(exit {result.returncode}"
            + (f": {detail}" if detail else "")
            + "); run `pocketshell gateway enroll` first"
        )
    text = sanitize(decode(result.stdout))
    if not parse_show(text).get("device id"):
        raise NotEnrolledError(
            "the helper's `show` printed no device id for "
            f"{sanitize(config_dir)}; run `pocketshell gateway enroll` first"
        )
    return text


def default_config_dir() -> str:
    """The helper's own default config dir, made absolute for the service."""
    if sys.platform == "win32":
        home = os.environ.get("USERPROFILE") or os.path.expanduser("~")
        return os.path.join(home, ".config", "pocketshell-link")
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
        os.path.expanduser("~"), ".config"
    )
    return os.path.join(base, "pocketshell-link")
