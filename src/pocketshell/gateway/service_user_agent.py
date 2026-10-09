"""`pocketshell gateway agent`: the ordinary-user Windows runtime (API v1).

The supported FINAL Windows path: PocketShell runs as the signed-in user,
Dropbox-like. The Desktop app (tray, started at sign-in by an Electron
current-user login item) calls this CLI with a fixed argv; there is no UAC,
no elevated shell, no service, no S4U and no scheduled task in this mode.

* ``bind`` (once, from the owner's setup flow): validates the guardian
  manifest exactly like the S4U path (reviewed manifest + reviewed
  guardian/native_api/policy triple, every pin re-hashed, config_guard,
  the guardian's protected path authority), the reviewed helper and the
  enrollment (``show``: device id, enrolled ``local ssh`` port, pinned host
  key), then writes a private binding file. Later calls take NO paths.
* ``start``: re-validates the binding; if not already ready, spawns hidden
  (CREATE_NO_WINDOW, no shell) in the caller's own session the guardian
  ``<python> -I -S -B <guardian.py> --manifest <manifest>`` (cwd = root, the
  manifest's closed environment) and the outbound link ``<helper> run
  --config-dir <dir>``; waits until ready or the deadline.
* ``status``: READY in the ACTIVE-CONSOLE mode (own SID, the caller's
  session = the active console session at launch, WinSta0, desktop Default
  at launch; the current input desktop is never consulted, so a locked
  workstation stays ready), held daemon pid+birth, the daemon as the only
  listener, the exact enrolled host-key proof, and the link by pid+birth+image.
* ``stop``: the guardian STOP protocol (exact held identity, accepted CLOSED
  bound to READY, daemon and listener gone), then the link by its exact
  recorded identity (pid + creation FILETIME + image); a reused pid is never
  touched.

Sign-out ends the user's processes (honest limit); the next sign-in's app
start calls ``start`` again. The S4U ``service`` path is unchanged.
"""

from __future__ import annotations

import json
import ntpath
import os
import re
import sys
import time
from typing import Optional

from pocketshell.gateway import service_common as common
from pocketshell.gateway import service_endpoint as ep
from pocketshell.gateway.service_common import ServiceError, sanitize

API_VERSION = 1
MODE = ep.MODE_ACTIVE_CONSOLE
EXIT_READY = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_NOT_READY = 3
EXIT_STOPPED = 4
EXIT_START_DEADLINE = 5
DEFAULT_START_TIMEOUT = 60.0
DEFAULT_STOP_TIMEOUT = 45.0
MAX_TIMEOUT = 300.0
LINK_SETTLE_SECONDS = 2.0
OPERATION_ID_RE = re.compile(r"[A-Za-z0-9._-]{1,64}")


class AgentError(ServiceError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


# --- private state -----------------------------------------------------------------


def agent_dir() -> str:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(
        os.environ.get("USERPROFILE") or os.path.expanduser("~"), ".config")
    return os.path.join(base, "pocketshell", "agent")


def _path(name: str) -> str:
    return os.path.join(agent_dir(), name)


def _write_private(path: str, data: bytes) -> None:
    if sys.platform == "win32" and os.name == "nt":
        from pathlib import Path

        from pocketshell import windows_security

        windows_security.write_private(Path(path), data)
        return
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    os.replace(tmp, path)


def _read_private(path: str, limit: int = 64 * 1024) -> Optional[bytes]:
    if sys.platform == "win32" and os.name == "nt":
        from pathlib import Path

        from pocketshell import windows_security

        if not os.path.lexists(path):
            return None
        return windows_security.read_private(Path(path), limit)
    try:
        with open(path, "rb") as handle:
            return handle.read(limit)
    except FileNotFoundError:
        return None


def _delete(path: str) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


class _OperationLock:
    """One agent operation at a time per user (bind/start/stop/status)."""

    def __init__(self):
        self.fd = None

    def __enter__(self):
        lock = _path("agent.lock")
        if not os.path.lexists(lock):
            # created through the private store, so the agent directory and the
            # lock get the owner-only protected DACL (Windows) / 0700+0600
            _write_private(lock, b"")
        self.fd = os.open(lock, os.O_RDWR)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(self.fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(self.fd)
            self.fd = None
            raise AgentError("busy", "another agent operation is in progress") from None
        return self

    def __exit__(self, *exc):
        if self.fd is not None:
            os.close(self.fd)


# --- binding ----------------------------------------------------------------------------


def bind(manifest_path: str, config_dir: str, helper: Optional[str], *, api, runner) -> dict:
    from pocketshell.gateway import service_windows as win
    from pocketshell.gateway import service_windows_endpoint as wep

    try:
        config_dir = win.validate_path(config_dir, "config dir")
        manifest_path = win.validate_path(manifest_path, "endpoint manifest")
        binary = win.resolve_helper(helper, runner)
        show = common.check_enrollment(binary, config_dir, runner)
        user_sid = api.current_sid()
        win.check_owner(api, config_dir, user_sid)
        m = wep.load_manifest(manifest_path)
        ep.check_trust(m, file_sha256=win.file_sha256)
        config = wep.read_bounded(m.config, ep.MAX_MANIFEST_BYTES)
        if config is None:
            raise ServiceError("the endpoint config does not exist")
        ep.config_guard(config.decode("utf-8", "strict"), m)
        host_key = ep.check_binding(m, show, user_sid, qualification=False)
        wep.check_authority(m, api)
    except (ServiceError, UnicodeDecodeError) as exc:
        raise AgentError("binding-refused", sanitize(str(exc), 600)) from None
    binding = {
        "version": API_VERSION,
        "manifest": m.path,
        "manifestSHA256": m.sha256,
        "configDir": config_dir,
        "helper": binary,
        "helperSHA256": win.file_sha256(binary),
        "deviceId": common.parse_show(show).get("device id", ""),
        "port": m.port,
        "ownerSID": user_sid,
        "hostKey": host_key.line,
    }
    _write_private(_path("binding.json"), json.dumps(binding, indent=1).encode("utf-8"))
    return binding


def load_binding(*, api, runner, revalidate: bool):
    """(binding, manifest, host_key): the stored binding, re-validated."""
    from pocketshell.gateway import pins as gateway_pins
    from pocketshell.gateway import service_windows as win
    from pocketshell.gateway import service_windows_endpoint as wep

    data = _read_private(_path("binding.json"))
    if data is None:
        raise AgentError("not-bound", "no agent binding; run `pocketshell gateway agent bind` first")
    try:
        b = json.loads(data.decode("utf-8"))
        assert isinstance(b, dict) and b.get("version") == API_VERSION
        m = wep.load_manifest(b["manifest"])
        host_key = gateway_pins.parse_host_key(b["hostKey"])
    except (ServiceError, ValueError, KeyError, AssertionError, gateway_pins.PinError) as exc:
        raise AgentError("binding-invalid", sanitize(f"the agent binding is unusable ({exc})", 600)) from None
    if m.sha256 != b["manifestSHA256"]:
        raise AgentError("binding-invalid", "the manifest changed since `agent bind`; bind again after review")
    if b["ownerSID"] != api.current_sid():
        raise AgentError("binding-invalid", "the binding belongs to another user")
    if revalidate:
        try:
            ep.check_trust(m, file_sha256=win.file_sha256)
            if win.file_sha256(b["helper"]) != b["helperSHA256"]:
                raise ServiceError("the helper changed since `agent bind`")
            win.check_digest(b["helperSHA256"])
            show = common.check_enrollment(b["helper"], b["configDir"], runner)
            if ep.check_binding(m, show, b["ownerSID"], qualification=False).line != host_key.line:
                raise ServiceError("the enrolled host key changed since `agent bind`")
            wep.check_authority(m, api)
        except ServiceError as exc:
            raise AgentError("binding-invalid", sanitize(str(exc), 600)) from None
    return b, m, host_key


# --- state of the link (the guardian's state lives in its protocol files) ----------------


def _link_state() -> Optional[dict]:
    data = _read_private(_path("link.json"))
    if not data:
        return None
    try:
        state = json.loads(data.decode("utf-8"))
        return state if isinstance(state, dict) else None
    except ValueError:
        return None


def _link_status(b: dict, api) -> dict:
    from pocketshell.gateway import service_windows as win

    state = _link_state()
    out = {"state": "stopped", "pid": None, "creationFILETIME": None, "helperSHA256": b["helperSHA256"],
           "note": "the gateway connection itself is not observable locally; this is the exact link process"}
    if not state:
        return out
    pid, birth = state.get("pid"), state.get("creationFILETIME")
    if type(pid) is int and isinstance(birth, str) and api.process_birth(pid) == birth \
            and win._same_path(api.process_image(pid), b["helper"]):
        out.update(state="running", pid=pid, creationFILETIME=birth)
    return out


# --- status ------------------------------------------------------------------------------


def _endpoint_status(m, host_key, api, runner, session: int) -> dict:
    from pocketshell.gateway import service_windows_endpoint as wep

    ready = wep.readiness(m, host_key, api, runner, mode=MODE, session=session)
    out = {
        "state": "ready" if ready["ok"] else ("stopped" if not ready.get("generation") or
                                               "CLOSED" in " ".join(ready["problems"]) else "not-ready"),
        "generation": ready.get("generation"),
        "daemon": {"pid": ready.get("pid"), "creationFILETIME": ready.get("birth")},
        "guardian": {"pid": ready.get("guardianPID"), "identity": ready.get("guardianIdentity")},
        "privateDesktop": ready.get("privateDesktop"),
        "context": {"session": ready.get("session"), "station": ready.get("station")},
        "hostKey": {"proven": bool(ready["ok"]), "fingerprint": host_key.fingerprint,
                    "detail": ready.get("hostKey")},
        "problems": ready["problems"],
    }
    if not ready["ok"] and ready.get("pid") and api.process_birth(ready["pid"]) is None \
            and not api.listener_pids(m.port):
        out["state"] = "stopped"
    return out


def _document(operation_id, *, state: str, binding=None, owner=None, endpoint=None, outbound=None,
              error: Optional[AgentError] = None) -> dict:
    return {
        "version": API_VERSION,
        "operationId": operation_id,
        "mode": MODE,
        "state": state,
        "owner": owner,
        "binding": None if binding is None else {
            k: binding[k] for k in ("manifest", "manifestSHA256", "deviceId", "port", "configDir")},
        "endpoint": endpoint,
        "outbound": outbound,
        "error": None if error is None else {"code": error.code, "message": sanitize(str(error), 600)},
    }


def _owner(api) -> dict:
    return {"sid": api.current_sid(), "session": api.current_session()}


def _collect(b, m, host_key, api, runner) -> tuple:
    owner = _owner(api)
    endpoint = _endpoint_status(m, host_key, api, runner, owner["session"])
    outbound = _link_status(b, api)
    if endpoint["state"] == "ready" and outbound["state"] == "running":
        state, code = "ready", EXIT_READY
    elif endpoint["state"] == "stopped" and outbound["state"] == "stopped":
        state, code = "stopped", EXIT_STOPPED
    else:
        state, code = "starting" if endpoint["state"] != "ready" else "failed", EXIT_NOT_READY
        if endpoint["state"] == "ready":
            state = "failed"  # endpoint up, link down
    return owner, endpoint, outbound, state, code


def _guarded(operation_id, fn):
    if sys.platform != "win32":
        err = AgentError("unsupported-platform",
                         "the ordinary-user agent is Windows-only; Linux uses `gateway service` (systemd --user)")
        return _document(operation_id, state="unavailable", error=err), EXIT_ERROR
    try:
        with _OperationLock():
            return fn()
    except AgentError as exc:
        return _document(operation_id, state="unavailable" if exc.code in ("not-bound", "binding-invalid", "busy")
                         else "failed", error=exc), EXIT_ERROR
    except ServiceError as exc:
        return _document(operation_id, state="failed", error=AgentError("error", str(exc))), EXIT_ERROR


def status(*, api, runner, operation_id=None) -> tuple:
    def run():
        b, m, host_key = load_binding(api=api, runner=runner, revalidate=False)
        owner, endpoint, outbound, state, code = _collect(b, m, host_key, api, runner)
        return _document(operation_id, state=state, binding=b, owner=owner, endpoint=endpoint,
                         outbound=outbound), code
    return _guarded(operation_id, run)


def bind_command(manifest_path, config_dir, helper, *, api, runner, operation_id=None) -> tuple:
    def run():
        b = bind(manifest_path, config_dir, helper, api=api, runner=runner)
        return _document(operation_id, state="stopped", binding=b, owner=_owner(api)), EXIT_READY
    return _guarded(operation_id, run)


def start(*, api, runner, timeout: float = DEFAULT_START_TIMEOUT, operation_id=None) -> tuple:
    from pocketshell.gateway import service_windows_endpoint as wep

    def run():
        b, m, host_key = load_binding(api=api, runner=runner, revalidate=True)
        owner = _owner(api)
        deadline = time.monotonic() + timeout
        endpoint = _endpoint_status(m, host_key, api, runner, owner["session"])
        if endpoint["state"] != "ready":
            previous = endpoint.get("generation")
            if api.listener_pids(m.port):
                raise AgentError("port-busy", f"127.0.0.1:{m.port} is served by another process; not starting")
            api.spawn_hidden([m.python, *ep.BOOTSTRAP_FLAGS, m.guardian, "--manifest", m.path],
                             m.root, dict(m.environment))
            while True:
                ready = wep.readiness(m, host_key, api, runner, not_generation=previous,
                                      mode=MODE, session=owner["session"])
                if ready["ok"] or time.monotonic() >= deadline:
                    break
                time.sleep(wep.POLL_SECONDS)
        link = _link_status(b, api)
        if link["state"] != "running":
            pid, birth = api.spawn_hidden([b["helper"], "run", "--config-dir", b["configDir"]],
                                          ntpath.dirname(b["helper"]), None)
            _write_private(_path("link.json"), json.dumps(
                {"pid": pid, "creationFILETIME": birth, "helper": b["helper"], "session": owner["session"]}).encode())
            settle = min(LINK_SETTLE_SECONDS, max(0.0, deadline - time.monotonic()))
            if settle and sys.platform == "win32" and os.name == "nt":
                time.sleep(settle)
        owner, endpoint, outbound, state, code = _collect(b, m, host_key, api, runner)
        doc = _document(operation_id, state=state, binding=b, owner=owner, endpoint=endpoint, outbound=outbound)
        if code != EXIT_READY:
            doc["state"] = "starting" if endpoint["state"] != "ready" else "failed"
            doc["error"] = {"code": "start-deadline",
                            "message": f"not ready within {timeout:g}s: "
                                       + "; ".join(endpoint["problems"] or [f"outbound {outbound['state']}"])}
            return doc, EXIT_START_DEADLINE
        return doc, EXIT_READY
    return _guarded(operation_id, run)


def stop(*, api, runner, timeout: float = DEFAULT_STOP_TIMEOUT, operation_id=None) -> tuple:
    from pocketshell.gateway import service_windows_endpoint as wep

    def run():
        b, m, host_key = load_binding(api=api, runner=runner, revalidate=False)
        owner = _owner(api)
        errors = []

        def guardian_running() -> bool:
            try:
                data = wep.read_private(api, ep.current_path(m), m)
                if data is None:
                    return False
                cur = ep.parse_current(data, m)
                ready = ep.parse_ready(wep.read_private(api, cur.ready, m) or b"{}", m, mode=MODE,
                                       session=owner["session"])
            except ServiceError:
                return False
            return api.process_birth(ready.guardian_pid) is not None

        old = wep.STOP_CONFIRM_SECONDS
        wep.STOP_CONFIRM_SECONDS = min(old, timeout)
        try:
            note = wep._stop_current_generation(m, "agent", runner, api, is_running=guardian_running,
                                                mode=MODE, session=owner["session"])
            if "NOT accepted" in note:
                errors.append(note)
        except ServiceError as exc:
            errors.append(str(exc).replace("the task is left registered and DISABLED, ", "")
                          .replace("; the task is left registered and DISABLED", ""))
        finally:
            wep.STOP_CONFIRM_SECONDS = old
        state = _link_state()
        if state and type(state.get("pid")) is int and isinstance(state.get("creationFILETIME"), str):
            if api.terminate_exact(state["pid"], state["creationFILETIME"], b["helper"]):
                pass  # the exact recorded link process, now gone
            _delete(_path("link.json"))
        owner, endpoint, outbound, state_name, code = _collect(b, m, host_key, api, runner)
        doc = _document(operation_id, state="stopped", binding=b, owner=owner, endpoint=endpoint, outbound=outbound)
        if errors or endpoint["state"] == "ready" or outbound["state"] == "running":
            doc["state"] = "failed"
            doc["error"] = {"code": "stop-failed", "message": sanitize("; ".join(errors) or "still running", 600)}
            return doc, EXIT_ERROR
        return doc, EXIT_READY
    return _guarded(operation_id, run)
