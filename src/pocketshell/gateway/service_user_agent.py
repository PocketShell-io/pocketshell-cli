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
    def __init__(self, code: str, message: str, recovery: Optional[dict] = None):
        super().__init__(message)
        self.code = code
        self.recovery = recovery


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


# --- spawning ------------------------------------------------------------------------------

LAUNCH_KEYS = ("inJob", "callerJobKillOnClose", "brokeAway", "elevated", "session")


def _spawn(api, argv, cwd, env) -> dict:
    """Hidden direct spawn; the child's job membership is MEASURED, never
    assumed (see WindowsApi.spawn_hidden): a child that could not break away
    from a KILL_ON_JOB_CLOSE caller job is refused."""
    from pocketshell.gateway import service_windows as win

    try:
        meta = api.spawn_hidden(argv, cwd, env)
    except win.CallerJobError as exc:
        raise AgentError("caller-job", str(exc)) from None
    if meta.get("elevated") is not False:
        raise AgentError("error", "the spawned child token is elevated or unknown; refusing")
    return meta


MALFORMED = {"malformed": True}  # sentinel: a record exists but names no verifiable identity
RECOVERY_RE = re.compile(r"^recovery-(guardian|link)-([0-9]{1,10})\.json$")


def _read_record(name: str):
    """None (no record), a well-formed identity dict, or MALFORMED. An
    unusable record cannot prove absence: it is never treated as 'none'."""
    data = _read_private(_path(name))
    if data is None:
        return None
    try:
        meta = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return MALFORMED
    if not isinstance(meta, dict) or type(meta.get("pid")) is not int or meta["pid"] <= 0 \
            or not isinstance(meta.get("creationFILETIME"), str) or not meta["creationFILETIME"].isdigit():
        return MALFORMED
    return meta


def _guardian_launch():
    """The exact launch identity of the guardian this CLI started (custody,
    independent of CURRENT/READY): None, a dict, or MALFORMED."""
    return _read_record("guardian.json")


def _recovery_records(stem: str) -> list:
    """[(name, record)] of validated private recovery-<stem>-<pid>.json files
    (written when a primary custody record could not be). Each is custody."""
    try:
        names = sorted(os.listdir(agent_dir()))
    except FileNotFoundError:
        return []
    out = []
    for name in names:
        match = RECOVERY_RE.match(name)
        if match and match.group(1) == stem:
            meta = _read_record(name)
            if meta is not MALFORMED and meta is not None and meta.get("pid") != int(match.group(2)):
                meta = MALFORMED
            if meta is not None:
                out.append((name, meta))
    return out


ALIVE, GONE, UNKNOWN = "alive", "gone", "unknown"


def _identity_state(meta, image, api) -> str:
    """alive / gone / unknown for a recorded exact identity. GONE only when
    PROVEN: the pid is absent (or exited), or it now has a DIFFERENT birth
    (pid reused). Any query failure (access denied, image unreadable, ...) is
    UNKNOWN and never releases custody."""
    from pocketshell.gateway import service_windows as win

    if meta is None:
        return GONE  # no record at all
    if meta is MALFORMED or type(meta.get("pid")) is not int or not isinstance(meta.get("creationFILETIME"), str):
        return UNKNOWN  # an unusable record cannot prove absence
    try:
        ident = api.process_identity(meta["pid"])
    except Exception:  # noqa: BLE001 - unverifiable
        return UNKNOWN
    if ident.get("state") == "absent":
        return GONE
    if ident.get("state") != "present" or not isinstance(ident.get("birth"), str):
        return UNKNOWN
    if ident["birth"] != meta["creationFILETIME"]:
        return GONE  # proven pid reuse
    if not isinstance(ident.get("image"), str) or not win._same_path(ident["image"], image):
        return UNKNOWN  # same birth but the image cannot be confirmed
    return ALIVE


def _launch_alive(meta, image, api) -> bool:
    return _identity_state(meta, image, api) == ALIVE


def _record_launch(name, meta, image, api) -> None:
    """Persist custody. If that fails, end the exact child; if ending it is
    not PROVEN, keep a recovery identity (alternate private file + the JSON
    error) and fail honestly."""
    try:
        _write_private(_path(name), json.dumps(meta).encode())
        return
    except Exception as exc:  # noqa: BLE001
        cause = exc
    try:
        api.terminate_exact(meta["pid"], meta["creationFILETIME"], image)
    except Exception:  # noqa: BLE001 - judged by the re-read below
        pass
    if _identity_state(meta, image, api) == GONE:
        raise AgentError("launch-unrecorded", f"cannot record the launch of {meta['pid']} ({cause}); "
                         "the child was ended (proven absent)") from None
    recovery = {"pid": meta["pid"], "creationFILETIME": meta["creationFILETIME"], "image": image,
                "record": name}
    where = "the recovery identity is only in this error"
    try:
        stem = name.rsplit(".", 1)[0]
        _write_private(_path(f"recovery-{stem}-{meta['pid']}.json"), json.dumps(recovery).encode())
        where = f"recovery-{stem}-{meta['pid']}.json keeps the identity"
    except Exception:  # noqa: BLE001
        pass
    raise AgentError("launch-unrecorded", f"cannot record the launch of {meta['pid']} ({cause}) and could not "
                     f"prove it ended; it may still be running; {where}", recovery=recovery) from None


def _release_custody(name, meta, image, api, errors, what) -> None:
    """End the exact recorded process and re-read its identity: PROVEN gone
    (absent / pid reused) => release the record; alive or unverifiable =>
    keep it and fail."""
    if meta is None:
        return
    if meta is MALFORMED:
        errors.append(f"the {what} custody record {name} is malformed; it cannot prove absence and is retained")
        return
    try:
        state = _identity_state(meta, image, api)
        if state == GONE:
            _delete(_path(name))
            return
        if state == ALIVE:
            api.terminate_exact(meta["pid"], meta["creationFILETIME"], image)
        state = _identity_state(meta, image, api)
    except Exception:  # noqa: BLE001 - unverifiable
        state = UNKNOWN
    if state == GONE:
        _delete(_path(name))
        return
    detail = "is still running" if state == ALIVE else "cannot be verified (it may still be running)"
    errors.append(f"the {what} process {meta['pid']} (birth {meta['creationFILETIME']}) {detail}; "
                  "its identity is retained for a retry")


def _launch(meta) -> Optional[dict]:
    return None if not meta else {k: meta.get(k) for k in LAUNCH_KEYS}


# --- state of the link (the guardian's state lives in its protocol files) ----------------


def _link_state():
    return _read_record("link.json")


def _link_status(b: dict, api) -> dict:
    """running / stopped / unknown from the exact recorded identity
    (tri-state process_identity): unknown, malformed or recovery custody is
    never 'stopped'."""
    state = _link_state()
    out = {"state": "stopped", "pid": None, "creationFILETIME": None, "helperSHA256": b["helperSHA256"],
           "note": "the gateway connection itself is not observable locally; this is the exact link process",
           "problems": []}
    if state is MALFORMED:
        out["state"] = "unknown"
        out["problems"].append("the link custody record link.json is malformed")
    elif state:
        out["launch"] = _launch(state)
        verdict = _identity_state(state, b["helper"], api)
        if verdict == ALIVE:
            out.update(state="running", pid=state["pid"], creationFILETIME=state["creationFILETIME"])
        elif verdict == UNKNOWN:
            out.update(state="unknown", pid=state["pid"], creationFILETIME=state["creationFILETIME"])
            out["problems"].append(f"the link process {state['pid']} cannot be verified (it may still be running)")
    for name, meta in _recovery_records("link"):
        if meta is MALFORMED or _identity_state(meta, b["helper"], api) != GONE:
            out["problems"].append(f"recovery custody {name} names a link process that is not proven gone")
            if out["state"] == "stopped":
                out["state"] = "unknown"
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
        "launch": None,
    }
    meta = _guardian_launch()
    out["launch"] = None if meta is MALFORMED else _launch(meta)
    out["guardianLaunch"] = None if not meta or meta is MALFORMED else {
        "pid": meta.get("pid"), "creationFILETIME": meta.get("creationFILETIME"),
        "running": {ALIVE: True, GONE: False}.get(_identity_state(meta, m.python, api))}
    if not ready["ok"] and ready.get("pid") and not api.listener_pids(m.port):
        try:
            daemon_absent = api.process_identity(ready["pid"]).get("state") == "absent"
        except Exception:  # noqa: BLE001 - unverifiable is not absent
            daemon_absent = False
        if daemon_absent:
            out["state"] = "stopped"
    custody = []
    if meta is MALFORMED:
        custody.append("the guardian custody record guardian.json is malformed; it cannot prove absence")
    for name, rec in _recovery_records("guardian"):
        if rec is MALFORMED or _identity_state(rec, m.python, api) != GONE:
            pid = "?" if rec is MALFORMED else rec["pid"]
            custody.append(f"recovery custody {name} names guardian process {pid}, not proven gone")
    out["custodyProblems"] = custody
    if custody:
        out["problems"] = [*out["problems"], *custody]
        if out["state"] == "stopped":
            out["state"] = "not-ready"
    if out["state"] == "stopped" and out["guardianLaunch"] and out["guardianLaunch"]["running"] is not False:
        # never infer "no runtime" from an absent CURRENT/READY: our launched
        # guardian is alive
        out["state"] = "not-ready"
        out["problems"] = [*out["problems"], f"the launched guardian {meta['pid']} is "
                                            + ("running" if out["guardianLaunch"]["running"] else "unverifiable")
                                            + " without a current READY"]
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
        "error": None if error is None else {"code": error.code, "message": sanitize(str(error), 600),
                                             **({"recovery": error.recovery}
                                                if getattr(error, "recovery", None) else {})},
    }


def _owner(api) -> dict:
    return {"sid": api.current_sid(), "session": api.current_session()}


def _collect(b, m, host_key, api, runner) -> tuple:
    owner = _owner(api)
    endpoint = _endpoint_status(m, host_key, api, runner, owner["session"])
    outbound = _link_status(b, api)
    custody = endpoint.get("custodyProblems") or outbound["state"] == "unknown" or outbound.get("problems")
    if custody:
        state, code = "failed", EXIT_NOT_READY  # unverifiable / recovery custody: never ready, never stopped
    elif endpoint["state"] == "ready" and outbound["state"] == "running":
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


def win_same(a, b) -> bool:
    from pocketshell.gateway import service_windows as win

    return isinstance(a, str) and win._same_path(a, b)


def _custody_gate(b, m, api) -> None:
    """Refuse to spawn anything while any custody is unverifiable (malformed
    record, access/query failure) or a recovery record names a process that
    is not proven gone. Proven-gone recovery records are released."""
    for name, meta, image, what in (("guardian.json", _guardian_launch(), m.python, "launched guardian"),
                                    ("link.json", _link_state(), b["helper"], "link")):
        if meta is MALFORMED:
            raise AgentError("custody-unverifiable", f"the {what} custody record {name} is malformed; it cannot "
                             "prove absence; not starting (run stop, or repair the record)")
        if meta is not None and _identity_state(meta, image, api) == UNKNOWN:
            raise AgentError("custody-unverifiable", f"the {what} process {meta['pid']} cannot be verified (it "
                             "may still be running); not starting a second one; retry or stop")
    for stem, image in (("guardian", m.python), ("link", b["helper"])):
        for name, meta in _recovery_records(stem):
            if meta is not MALFORMED and _identity_state(meta, image, api) == GONE:
                _delete(_path(name))
                continue
            pid = "?" if meta is MALFORMED else meta["pid"]
            raise AgentError("custody-recovery", f"recovery custody {name} names {stem} process {pid}, which is "
                             "not proven gone; run stop first")


def start(*, api, runner, timeout: float = DEFAULT_START_TIMEOUT, operation_id=None) -> tuple:
    from pocketshell.gateway import service_windows_endpoint as wep

    def run():
        b, m, host_key = load_binding(api=api, runner=runner, revalidate=True)
        owner = _owner(api)
        deadline = time.monotonic() + timeout
        _custody_gate(b, m, api)  # before ANY spawn
        endpoint = _endpoint_status(m, host_key, api, runner, owner["session"])
        if endpoint["state"] != "ready":
            previous = endpoint.get("generation")
            if api.listener_pids(m.port):
                raise AgentError("port-busy", f"127.0.0.1:{m.port} is served by another process; not starting")
            if _identity_state(_guardian_launch(), m.python, api) != ALIVE:
                launch = _spawn(api, [m.python, *ep.BOOTSTRAP_FLAGS, m.guardian, "--manifest", m.path],
                                m.root, dict(m.environment))
                _record_launch("guardian.json", launch, m.python, api)  # custody BEFORE any wait
            while True:
                ready = wep.readiness(m, host_key, api, runner, not_generation=previous,
                                      mode=MODE, session=owner["session"])
                if ready["ok"] or time.monotonic() >= deadline:
                    break
                time.sleep(wep.POLL_SECONDS)
        link = _link_status(b, api)
        if link["state"] != "running":
            launch = _spawn(api, [b["helper"], "run", "--config-dir", b["configDir"]],
                            ntpath.dirname(b["helper"]), None)
            _record_launch("link.json", {**launch, "helper": b["helper"]}, b["helper"], api)
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
        # the guardian WE launched: consumed even without CURRENT/READY (a
        # start that timed out before READY must not orphan it)
        _release_custody("guardian.json", _guardian_launch(), m.python, api, errors, "launched guardian")
        _release_custody("link.json", _link_state(), b["helper"], api, errors, "link")
        for stem, image in (("guardian", m.python), ("link", b["helper"])):
            for name, meta in _recovery_records(stem):
                if meta is not MALFORMED and not win_same(meta.get("image"), image):
                    meta = MALFORMED  # a recovery identity must name the expected image
                _release_custody(name, meta, image, api, errors, f"{stem} (recovery)")
        served = api.listener_pids(m.port)
        if served:
            errors.append(f"127.0.0.1:{m.port} is still served by {sanitize(str(served), 200)}")
        owner, endpoint, outbound, state_name, code = _collect(b, m, host_key, api, runner)
        doc = _document(operation_id, state="stopped", binding=b, owner=owner, endpoint=endpoint, outbound=outbound)
        if errors or endpoint["state"] == "ready" or outbound["state"] == "running":
            doc["state"] = "failed"
            doc["error"] = {"code": "stop-failed", "message": sanitize("; ".join(errors) or "still running", 600)}
            return doc, EXIT_ERROR
        return doc, EXIT_READY
    return _guarded(operation_id, run)


# --- ordinary-v2 producer (agreement v3 §10, PROPOSED) ------------------------------------


def install_command(*, user_data, catalog, staged, dry_run, api, runner, operation_id=None, paths=None,
                    folders=None) -> tuple:
    """`gateway agent install`: copy the catalogued closure and write the
    public-only authority receipt. Never starts, enrolls, or reads secrets."""
    from pocketshell import __version__
    from pocketshell.gateway import service_agent_install as inst

    def doc(ok, receipt=None, error=None):
        return {"version": API_VERSION, "operationId": operation_id, "action": "install", "ok": ok,
                "dryRun": bool(dry_run), "receipt": receipt,
                "error": None if error is None else {"code": error.code, "message": sanitize(str(error), 600)}}

    if sys.platform != "win32":
        return doc(False, error=AgentError("unsupported-platform", "the ordinary-v2 runtime is Windows-only")), \
            EXIT_ERROR
    try:
        with _OperationLock():
            b, _m, host_key = load_binding(api=api, runner=runner, revalidate=True)
            show = common.parse_show(common.check_enrollment(b["helper"], b["configDir"], runner))
            public = {**b, "hostKeyFingerprint": host_key.fingerprint}
            receipt = inst.install_runtime(
                user_data=user_data, catalog_path=catalog, staged=staged, binding=public,
                server=show.get("server", ""), owner_sid=api.current_sid(),
                paths=paths or inst.NativePaths(api), folders=folders or inst.known_folders(),
                cli_version=__version__, dry_run=dry_run)
    except (AgentError, inst.InstallError) as exc:
        return doc(False, error=exc), EXIT_USAGE if getattr(exc, "code", "") == "usage" else EXIT_ERROR
    except Exception as exc:  # noqa: BLE001 - a refusal, never a traceback
        return doc(False, error=AgentError("error", str(exc) or type(exc).__name__)), EXIT_ERROR
    return doc(True, receipt), EXIT_READY


def verify_paths_command(*, owner_sid, files, anchored, directories, inventories, max_bytes, api,
                         paths=None) -> tuple:
    """`gateway agent verify-paths`: the trusted native path verifier."""
    from pocketshell.gateway import service_agent_install as inst

    if sys.platform != "win32":
        return {"version": inst.VERIFY_VERSION, "ownerSid": owner_sid, "ok": False, "results": [],
                "problem": "Windows-only"}, EXIT_ERROR
    if not 0 <= max_bytes <= inst.MAX_DOC:
        return {"version": inst.VERIFY_VERSION, "ownerSid": owner_sid, "ok": False, "results": [],
                "problem": "--max-bytes must be in [0, 1048576]"}, EXIT_USAGE
    try:
        current = api.current_sid()
    except Exception:  # noqa: BLE001
        current = None
    return inst.verify_paths(owner_sid=owner_sid, files=files, anchored=anchored, directories=directories,
                             inventories=inventories, max_bytes=max_bytes, paths=paths or inst.NativePaths(api),
                             current_sid=current)
