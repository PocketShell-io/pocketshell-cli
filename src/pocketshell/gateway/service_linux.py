"""Linux backend of ``pocketshell gateway service``: a systemd --user unit.

The unit runs the absolute, protocol-verified helper directly
(``ExecStart="<helper>" run --config-dir "<dir>"`` — no shell, no
``pocketshell`` wrapper in between), as the enrolling user, restarting on
failure. Only the unit file and the user manager's enable/start state are
ever changed; the enrolled config dir is passed explicitly and never
touched.
"""

from __future__ import annotations

import getpass
import hashlib
import os
import shutil
import tempfile
from dataclasses import dataclass
from typing import Callable, Optional

from pocketshell.gateway import helper as gateway_helper
from pocketshell.gateway.service_common import (
    ChildResult,
    NotStartedError,
    ServiceError,
    ServiceStatus,
    check_enrollment,
    decode,
    has_control_chars,
    run_child,
    sanitize,
)

UNIT_NAME = "pocketshell-gateway.service"
MANAGED_MARKER = "# Managed by `pocketshell gateway service install`"
LINGER_DIR = "/var/lib/systemd/linger"

Runner = Callable[..., ChildResult]


def unit_dir() -> str:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
        os.path.expanduser("~"), ".config"
    )
    return os.path.join(base, "systemd", "user")


def unit_path() -> str:
    return os.path.join(unit_dir(), UNIT_NAME)


def _unit_arg(value: str, what: str) -> str:
    """Quote one ExecStart argument for systemd's own (non-shell) parser."""
    if not os.path.isabs(value):
        raise ServiceError(f"the {what} must be an absolute path")
    if has_control_chars(value) or '"' in value or "\\" in value:
        raise ServiceError(
            f"the {what} contains a quote, backslash or control character; "
            "refusing to write it into a unit file"
        )
    # systemd expands %-specifiers and $VARS inside ExecStart, even quoted.
    return '"' + value.replace("%", "%%").replace("$", "$$") + '"'


def _unit_unarg(token: str) -> str:
    if len(token) >= 2 and token[0] == token[-1] == '"':
        token = token[1:-1]
    return token.replace("%%", "%").replace("$$", "$")


def render_unit(helper: str, config_dir: str) -> str:
    exec_start = (
        f"{_unit_arg(helper, 'helper path')} run --config-dir "
        f"{_unit_arg(config_dir, 'config dir')}"
    )
    return (
        f"{MANAGED_MARKER} — re-run it with --force to replace,\n"
        "# `pocketshell gateway service uninstall` to remove. The enrolled\n"
        "# config dir below is only ever read by the helper.\n"
        "[Unit]\n"
        "Description=PocketShell gateway host agent (pocketshell-link run)\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        f"ExecStart={exec_start}\n"
        "Restart=on-failure\n"
        "RestartSec=5\n"
        "\n"
        "[Install]\n"
        "WantedBy=default.target\n"
    )


def parse_unit(text: str) -> tuple[Optional[str], Optional[str]]:
    """(helper, config_dir) from a unit's ExecStart, best effort."""
    import shlex

    for line in text.splitlines():
        if line.startswith("ExecStart="):
            try:
                tokens = shlex.split(line[len("ExecStart="):], posix=False)
            except ValueError:
                return None, None
            tokens = [_unit_unarg(t) for t in tokens]
            helper = tokens[0].lstrip("-@:+!") if tokens else None
            config_dir = None
            if "--config-dir" in tokens:
                index = tokens.index("--config-dir")
                if index + 1 < len(tokens):
                    config_dir = tokens[index + 1]
            return helper, config_dir
    return None, None


def systemctl_argv(*args: str) -> list[str]:
    return ["systemctl", "--user", *args]


def linger_enabled(user: Optional[str] = None) -> Optional[bool]:
    try:
        user = user or getpass.getuser()
    except Exception:  # noqa: BLE001 - no passwd entry: unknown
        return None
    if not os.path.isdir(LINGER_DIR):
        return None
    return os.path.exists(os.path.join(LINGER_DIR, user))


@dataclass
class LinuxPlan:
    helper: str
    config_dir: str
    unit_path: str
    unit_text: str
    commands: list
    show: str


def resolve_helper(explicit: Optional[str]) -> str:
    """The existing wrapper resolution + version gate, or an explicit path."""
    try:
        if explicit:
            if not os.path.isabs(explicit):
                raise ServiceError("--helper must be an absolute path")
            if not (os.path.isfile(explicit) and os.access(explicit, os.X_OK)):
                raise ServiceError(f"--helper {sanitize(explicit)} is not an executable file")
            binary = explicit
        else:
            binary = gateway_helper.resolve_helper()
        gateway_helper.verify_helper(binary)
    except gateway_helper.HelperNotFoundError as exc:
        raise ServiceError(sanitize(str(exc))) from None
    except gateway_helper.HelperIncompatibleError as exc:
        raise ServiceError(sanitize(str(exc))) from None
    return os.path.abspath(binary)


def plan_install(
    helper: Optional[str],
    config_dir: str,
    *,
    force: bool,
    start: bool,
    runner: Optional[Runner] = None,
) -> LinuxPlan:
    runner = runner or run_child
    binary = resolve_helper(helper)
    config_dir = os.path.abspath(config_dir)
    unit_text = render_unit(binary, config_dir)
    show = check_enrollment(binary, config_dir, runner)
    path = unit_path()
    if os.path.lexists(path) and not force:
        raise ServiceError(
            f"{sanitize(path)} already exists; pass --force to replace it "
            "(or `pocketshell gateway service uninstall` first)"
        )
    commands = [systemctl_argv("daemon-reload"), systemctl_argv("enable", UNIT_NAME)]
    if start:
        # a separate step, so a failed start is reported as such (exit 5)
        verb = "restart" if os.path.lexists(path) else "start"
        commands.append(systemctl_argv(verb, UNIT_NAME))
    return LinuxPlan(binary, config_dir, path, unit_text, commands, show)


def _atomic_write(path: str, text: str) -> None:
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o755, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".pocketshell-gateway.", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _check(result: ChildResult, argv: list) -> None:
    if result.returncode != 0:
        detail = sanitize(decode(result.stderr or result.stdout), 600)
        raise ServiceError(
            f"`{' '.join(argv)}` failed (exit {result.returncode})"
            + (f": {detail}" if detail else "")
        )


def apply_install(plan: LinuxPlan, runner: Optional[Runner] = None) -> list:
    """Write the unit and enable it. Returns warnings."""
    runner = runner or run_child
    try:
        _atomic_write(plan.unit_path, plan.unit_text)
    except OSError as exc:
        raise ServiceError(
            f"could not write {sanitize(plan.unit_path)}: "
            f"{sanitize(exc.strerror or type(exc).__name__)}"
        ) from None
    for argv in plan.commands:
        result = runner(argv)
        if argv[2] in ("start", "restart") and result.returncode != 0:
            detail = sanitize(decode(result.stderr or result.stdout), 600)
            raise NotStartedError(
                f"{UNIT_NAME} is written and enabled but NOT started: `{' '.join(argv)}` "
                f"failed (exit {result.returncode})" + (f": {detail}" if detail else "")
                + f". See `journalctl --user -u {UNIT_NAME}`."
            )
        _check(result, argv)
    warnings = []
    if linger_enabled() is False:
        warnings.append(
            "lingering is off for this user: the unit starts only while you "
            "are logged in. To start it at boot: sudo loginctl enable-linger "
            + sanitize(getpass.getuser())
        )
    return warnings


def uninstall(*, force: bool, runner: Optional[Runner] = None) -> str:
    runner = runner or run_child
    path = unit_path()
    if not os.path.lexists(path):
        return f"not installed ({sanitize(path)} does not exist); nothing to do"
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            managed = MANAGED_MARKER in handle.read(65536)
    except OSError:
        managed = False
    if not managed and not force:
        raise ServiceError(
            f"{sanitize(path)} was not written by `pocketshell gateway service "
            "install`; refusing to remove a hand-written unit (pass --force)"
        )
    argv = systemctl_argv("disable", "--now", UNIT_NAME)
    result = runner(argv)
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise ServiceError(
            f"could not remove {sanitize(path)}: {sanitize(exc.strerror or '')}"
        ) from None
    _check(runner(systemctl_argv("daemon-reload")), systemctl_argv("daemon-reload"))
    runner(systemctl_argv("reset-failed", UNIT_NAME))
    note = ""
    if result.returncode != 0:
        note = " (systemctl disable --now reported: " + sanitize(
            decode(result.stderr or result.stdout), 300
        ) + ")"
    return f"removed {sanitize(path)}; the unit is stopped and disabled{note}"


def _file_sha256(path: str) -> Optional[str]:
    try:
        with open(path, "rb") as handle:
            return hashlib.file_digest(handle, "sha256").hexdigest()
    except OSError:
        return None


def status(runner: Optional[Runner] = None) -> ServiceStatus:
    runner = runner or run_child
    path = unit_path()
    st = ServiceStatus(platform="linux", name=UNIT_NAME, installed=False, definition_path=path)
    if not os.path.lexists(path):
        return st
    st.installed = True
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            text = handle.read(65536)
    except OSError:
        text = ""
    st.managed = MANAGED_MARKER in text
    st.helper, st.config_dir = parse_unit(text)
    if shutil.which("systemctl") is None:
        st.state = "unknown"
        st.warnings.append("systemctl not found; cannot query the user manager")
    else:
        props = "LoadState,ActiveState,SubState,MainPID,UnitFileState,NRestarts"
        try:
            result = runner(systemctl_argv("show", UNIT_NAME, f"--property={props}"))
        except ServiceError as exc:
            result = None
            st.warnings.append(str(exc))
        if result is not None:
            for line in decode(result.stdout).splitlines():
                key, sep, value = line.partition("=")
                if sep:
                    st.details[key] = sanitize(value, 200)
        active = st.details.get("ActiveState", "unknown")
        st.state = f"{active}/{st.details.get('SubState', '?')}"
        st.running = active == "active"
        pid = st.details.get("MainPID", "0")
        if pid.isdigit() and int(pid) > 0:
            st.processes.append({"pid": int(pid)})
    if st.helper:
        st.helper_sha256 = _file_sha256(st.helper)
        if st.config_dir and st.helper_sha256:
            try:
                st.show = check_enrollment(st.helper, st.config_dir, runner)
            except ServiceError as exc:
                st.show_error = str(exc)
    if linger_enabled() is False:
        st.warnings.append("lingering is off: the unit runs only while you are logged in")
    return st
