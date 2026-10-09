"""Windows endpoint task for the FINAL guardian ABI.

Task ``\\PocketShell\\GatewayEndpoint`` (``GatewayEndpointQ<instance>`` for an
isolated qualification) runs, directly (no shell):

    <manifest python> -I -S -B <pinned guardian.py> --manifest <manifest>
    [--check-only]      (Phase A qualification only)

as the current SID (S4U, LeastPrivilege, session 0), working directory = the
manifest root. Before anything is registered the service binds the
interpreter, guardian.py / native_api.py / policy.py, the manifest and every
runtime pin by hash (reviewed lists + disk), mirrors the guardian's
config_guard, and checks the same protected-ancestor / final-file mutation
authority the guardian checks (path_authority) — so no unprotected bytes are
ever executed by the task.

Readiness: task Running and its contract intact; CURRENT.json (owned by the
manifest owner) -> a ``generation-<uuidhex>`` child of the state base and its
READY.json (owned by the owner, bound to the manifest digest and port, the
guardian source digest); no CLOSED.json there; the held daemon pid alive with
exactly the READY creation FILETIME; the guardian pid alive running the
manifest interpreter; the daemon the only listener; and a real SSH key
exchange proving the ENROLLED host key.

Stop: disable the task, STOP.json with the exact held identity into the
CURRENT generation, wait for CLOSED.json with accepted/requestedOwnedJobStop/
activeAtClose 0/no cleanupErrors and the daemon gone, then delete. Never
/End, never a kill.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Optional

from pocketshell.gateway import service_endpoint as ep
from pocketshell.gateway import service_hostkey as hostkey
from pocketshell.gateway import service_windows as win
from pocketshell.gateway.service_common import NotStartedError, ServiceError, decode, sanitize

ENDPOINT_CONFIRM_SECONDS = 90.0
STOP_CONFIRM_SECONDS = 45.0
POLL_SECONDS = 1.0
_KEY_IN_DESCRIPTION = re.compile(r"Enrolled host key: (\S+ \S+)\.")


@dataclass
class EndpointPlan:
    manifest: ep.GuardianManifest
    leaf: str
    spec: "win.TaskSpec"
    xml: str
    host_key: object  # pins.HostKey
    qualification: bool
    check_only: bool = False
    problems: list = field(default_factory=list)

    @property
    def name(self) -> str:
        return win.TASK_FOLDER + self.leaf


def action_argv(m: ep.GuardianManifest, check_only: bool = False) -> tuple:
    """Everything after the interpreter: the root-approved bootstrap."""
    argv = (*ep.BOOTSTRAP_FLAGS, m.guardian, "--manifest", m.path)
    return argv + ("--check-only",) if check_only else argv


def endpoint_spec(m: ep.GuardianManifest, leaf: str, host_key, qualification: bool,
                  check_only: bool = False) -> "win.TaskSpec":
    argv = action_argv(m, check_only)
    kind = ("CHECK-ONLY qualification" if check_only else "QUALIFICATION") if qualification \
        else "private loopback SSH endpoint"
    return win.TaskSpec(
        leaf=leaf,
        command=m.python,
        argv=argv,
        arguments=" ".join(a if a.startswith("-") else win.quote_arg(a) for a in argv),
        working_directory=m.root,
        boot_delay=ep.ENDPOINT_BOOT_DELAY,
        description=(
            f"PocketShell {kind} guardian on 127.0.0.1:{m.port}: hidden, session 0, runs "
            f"as the enrolling user. Manifest sha256 {m.sha256}. "
            f"Enrolled host key: {host_key.line}. {win.MANAGED_MARKER}."
        ),
    )


def read_bounded(path: str, limit: int) -> Optional[bytes]:
    try:
        with open(path, "rb") as handle:
            data = handle.read(limit + 1)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ServiceError(f"cannot read {sanitize(path)}: {sanitize(exc.strerror or '')}") from None
    if len(data) > limit:
        raise ServiceError(f"{sanitize(path)} is larger than {limit} bytes")
    return data


def load_manifest(path: str) -> ep.GuardianManifest:
    data = read_bounded(path, ep.MAX_MANIFEST_BYTES)
    if data is None:
        raise ServiceError(f"the endpoint manifest {sanitize(path)} does not exist")
    return ep.parse_manifest(data, path)


def check_authority(m: ep.GuardianManifest, api) -> None:
    """The guardian's own path_authority set, before anything executes."""
    for path, role, directory, protected, servicing in ep.authority_plan(m):
        api.path_authority(path, m.owner_sid, role=role, directory=directory,
                           protected=protected, servicing=servicing)


def plan_endpoint(manifest_path: str, show: str, user_sid: str, *, instance: Optional[str],
                  start: bool, api, runner, logon_type: str, check_only: bool = False) -> EndpointPlan:
    if check_only and instance is None:
        raise ServiceError("--check-only is the Phase A qualification preflight: use it with --endpoint-only --instance")
    leaf = ep.leaf_for(instance)
    qualification = instance is not None
    m = load_manifest(manifest_path)
    ep.check_trust(m, file_sha256=win.file_sha256)
    config = read_bounded(m.config, ep.MAX_MANIFEST_BYTES)
    if config is None:
        raise ServiceError(f"the endpoint config {sanitize(m.config)} does not exist")
    try:
        ep.config_guard(config.decode("utf-8"), m)
    except UnicodeDecodeError:
        raise ServiceError("endpoint config: not UTF-8") from None
    host_key = ep.check_binding(m, show, user_sid, qualification=qualification)
    check_authority(m, api)
    spec = endpoint_spec(m, leaf, host_key, qualification, check_only)
    xml = win.build_spec_xml(
        spec, user_sid, logon_type=logon_type, enabled=start,
        triggers=not check_only,
        execution_time_limit=ep.CHECK_ONLY_TIME_LIMIT if check_only else "PT0S",
    )
    if win.query_task_xml(runner, leaf) is not None:
        raise ServiceError(
            f"the scheduled task {win.TASK_FOLDER + leaf} already exists. Endpoint replacement "
            "goes through the guardian STOP protocol: run `pocketshell gateway service "
            "uninstall` first"
        )
    if not check_only and api.listener_pids(m.port):
        raise ServiceError(
            f"127.0.0.1:{m.port} is already served by another process (e.g. the currently held "
            "endpoint). Have its owner stop it through its own controlled-stop mechanism first; "
            "this command never stops it."
        )
    return EndpointPlan(m, leaf, spec, xml, host_key, qualification, check_only)


def _owned(api, path: str, m: ep.GuardianManifest, what: str, problems: list) -> bool:
    owner = api.owner_sid(path)
    if owner != m.owner_sid:
        problems.append(f"{what} is owned by {owner}, not {m.owner_sid}")
        return False
    return True


def readiness(m: ep.GuardianManifest, host_key, api, runner, *, not_generation: Optional[str] = None) -> dict:
    out = {"ok": False, "problems": [], "generation": None, "pid": None, "birth": None,
           "guardianPID": None, "hostKey": None}
    problems = out["problems"]
    data = read_bounded(ep.current_path(m), ep.MAX_PROTOCOL_BYTES)
    if data is None:
        problems.append("no CURRENT.json yet (guardian not READY)")
        return out
    if not _owned(api, ep.current_path(m), m, "CURRENT.json", problems):
        return out
    try:
        cur = ep.parse_current(data, m)
    except ServiceError as exc:
        problems.append(str(exc))
        return out
    out["generation"] = cur.generation
    if not_generation is not None and cur.generation.casefold() == not_generation.casefold():
        problems.append("CURRENT.json still names the generation from before this start (stale)")
        return out
    ready_data = read_bounded(cur.ready, ep.MAX_PROTOCOL_BYTES)
    if ready_data is None:
        problems.append("READY.json of the current generation is missing")
        return out
    if not _owned(api, cur.ready, m, "READY.json", problems):
        return out
    try:
        ready = ep.parse_ready(ready_data, m)
    except ServiceError as exc:
        problems.append(str(exc))
        return out
    out.update(pid=ready.pid, birth=ready.birth, guardianPID=ready.guardian_pid)
    if read_bounded(cur.file("CLOSED.json"), ep.MAX_PROTOCOL_BYTES) is not None:
        problems.append("the current generation is CLOSED (stale CURRENT is not proof of running)")
        return out
    if api.process_birth(ready.pid) != ready.birth:
        problems.append(f"the held daemon pid {ready.pid} with birth {ready.birth} is not alive")
    if api.process_birth(ready.guardian_pid) is None or not win._same_path(
        api.process_image(ready.guardian_pid), m.python
    ):
        problems.append(f"the guardian pid {ready.guardian_pid} is not alive running the manifest interpreter")
    listeners = api.listener_pids(m.port)
    if listeners != [("127.0.0.1", ready.pid)]:
        problems.append(f"127.0.0.1:{m.port} listeners {listeners} are not exactly the held daemon {ready.pid}")
    if problems:
        return out
    ok, detail = hostkey.verify_host_key(m.port, host_key, runner=runner)
    out["hostKey"] = detail
    if not ok:
        problems.append(detail)
        return out
    out["ok"] = True
    return out


def _previous_generation(m: ep.GuardianManifest) -> Optional[str]:
    data = read_bounded(ep.current_path(m), ep.MAX_PROTOCOL_BYTES)
    if data is None:
        return None
    try:
        return ep.parse_current(data, m).generation
    except ServiceError:
        return None


def start_and_confirm(plan: EndpointPlan, runner, api) -> dict:
    previous = None if plan.check_only else _previous_generation(plan.manifest)
    result = runner(win.schtasks("/Run", "/TN", plan.name))
    if result.returncode != 0:
        raise NotStartedError(
            f"{plan.name} is registered but NOT started: /Run failed (exit {result.returncode}): "
            f"{sanitize(decode(result.stderr or result.stdout), 400)}"
        )
    deadline = time.monotonic() + ENDPOINT_CONFIRM_SECONDS
    last = {"problems": ["not checked"]}
    state, seen_running = "Unknown", False
    while True:
        info = win.query_task(runner, plan.leaf)
        state = info.state if info else "absent"
        if plan.check_only:
            seen_running = seen_running or state == "Running"
            if state not in ("Running", "Queued") and info is not None and info.last_result != 267011:
                # 267011 = SCHED_S_TASK_HAS_NOT_RUN
                if info.last_result == 0:
                    return {"ok": True, "problems": [], "checkOnly": True,
                            "detail": f"{plan.name}: check-only preflight exited 0 (no generation, no daemon)"}
                raise NotStartedError(
                    f"{plan.name}: check-only preflight exited {info.last_result}; nothing was started"
                )
        elif state == "Running":
            last = readiness(plan.manifest, plan.host_key, api, runner, not_generation=previous)
            if last["ok"]:
                return last
        if time.monotonic() >= deadline:
            break
        time.sleep(POLL_SECONDS)
    raise NotStartedError(
        f"{plan.name} is registered but NOT ready after {ENDPOINT_CONFIRM_SECONDS:g}s "
        f"(task {state}; {'; '.join(last['problems'])})"
    )


def _set_enabled(leaf: str, enabled: bool, runner) -> None:
    if not re.fullmatch(r"[A-Za-z0-9]+", leaf):
        raise ServiceError("unexpected task name")
    script = (
        "$ErrorActionPreference='Stop';"
        "try{$s=New-Object -ComObject Schedule.Service;$s.Connect();"
        f"$t=$s.GetFolder('{win.TASK_FOLDER.rstrip(chr(92))}').GetTask('{leaf}');"
        f"$t.Enabled=${'true' if enabled else 'false'};'ok'"
        "}catch{$e=$_.Exception;while($e.InnerException){$e=$e.InnerException};"
        "'error 0x{0:X8} {1}' -f $e.HResult,$e.Message}"
    )
    result = runner(win._powershell(script))
    text = decode(result.stdout).strip()
    if result.returncode != 0 or text != "ok":
        raise ServiceError(
            f"could not {'enable' if enabled else 'disable'} {win.TASK_FOLDER + leaf}: "
            f"{sanitize(text or decode(result.stderr), 300)}"
        )


def _manifest_from_fields(fields: dict) -> Optional[str]:
    args = win.parse_arguments(fields.get("arguments") or "")
    if args[:3] == list(ep.BOOTSTRAP_FLAGS) and len(args) in (6, 7) and args[4] == "--manifest":
        return args[5]
    return None


def _wait_not_running(leaf: str, runner, seconds: float) -> str:
    deadline = time.monotonic() + seconds
    while True:
        info = win.query_task(runner, leaf)
        state = info.state if info else "absent"
        if state != "Running" or time.monotonic() >= deadline:
            return state
        time.sleep(POLL_SECONDS)


def stop_and_remove(leaf: str, *, force: bool, runner, api) -> Optional[str]:
    """Disable -> STOP protocol -> delete. None when the task is absent."""
    name = win.TASK_FOLDER + leaf
    registered = win.query_task_xml(runner, leaf)
    if registered is None:
        return None
    try:
        fields = win.parse_task_xml(registered)
    except ServiceError:
        fields = {"description": "", "arguments": ""}
    if win.MANAGED_MARKER not in fields["description"] and not force:
        raise ServiceError(
            f"{name} was not written by `pocketshell gateway service install`; "
            "refusing to stop or delete a task this command does not own (pass --force)"
        )
    _set_enabled(leaf, False, runner)  # no watchdog / RestartOnFailure restart from here on
    notes = []
    manifest_path = _manifest_from_fields(fields)
    m = None
    if manifest_path:
        try:
            m = load_manifest(manifest_path)
        except ServiceError as exc:
            notes.append(f"manifest unreadable ({exc})")
    if m is not None:
        notes.append(_stop_current_generation(m, leaf, runner, api))
    state = _wait_not_running(leaf, runner, 20)
    if state == "Running":
        raise ServiceError(
            f"{name} is still Running without an accepted guardian stop "
            f"({'; '.join(n for n in notes if n)}). The task is left registered and DISABLED; "
            "nothing was killed. Stop it through the guardian's STOP protocol, then uninstall again."
        )
    result = runner(win.schtasks("/Delete", "/TN", name, "/F"))
    if result.returncode != 0:
        raise win._fail(result, f"deleting {name}", win.ELEVATION_HINT)
    try:
        still = win.query_task(runner, leaf) is not None
    except ServiceError as exc:
        raise ServiceError(f"deleted {name} but could not verify its removal: {exc}") from None
    if still:
        raise ServiceError(f"{name} still exists after deletion")
    return "; ".join(n for n in notes if n)


def _stop_current_generation(m: ep.GuardianManifest, leaf: str, runner, api) -> str:
    deadline = time.monotonic() + 30
    data = read_bounded(ep.current_path(m), ep.MAX_PROTOCOL_BYTES)
    while data is None:
        info = win.query_task(runner, leaf)
        if not info or info.state != "Running" or time.monotonic() >= deadline:
            return "no CURRENT.json: no READY generation to stop"
        time.sleep(POLL_SECONDS)
        data = read_bounded(ep.current_path(m), ep.MAX_PROTOCOL_BYTES)
    if api.owner_sid(ep.current_path(m)) != m.owner_sid:
        raise ServiceError("CURRENT.json is not owned by the manifest owner; not acting on it")
    cur = ep.parse_current(data, m)
    closed_path = cur.file("CLOSED.json")
    if read_bounded(closed_path, ep.MAX_PROTOCOL_BYTES) is not None:
        return f"generation {cur.generation} already CLOSED"
    ready_data = read_bounded(cur.ready, ep.MAX_PROTOCOL_BYTES)
    if ready_data is None:
        raise ServiceError("CURRENT.json names a generation without READY.json; not acting on it")
    if api.owner_sid(cur.ready) != m.owner_sid:
        raise ServiceError("READY.json is not owned by the manifest owner; not acting on it")
    ready = ep.parse_ready(ready_data, m)
    if api.process_birth(ready.pid) == ready.birth:
        stop_path = cur.file("STOP.json")
        if read_bounded(stop_path, ep.MAX_STOP_BYTES) is None:
            api.write_owned_file(stop_path, ep.stop_request(ready), m.owner_sid)
    deadline = time.monotonic() + STOP_CONFIRM_SECONDS
    closed = read_bounded(closed_path, ep.MAX_PROTOCOL_BYTES)
    while closed is None and time.monotonic() < deadline:
        time.sleep(POLL_SECONDS)
        closed = read_bounded(closed_path, ep.MAX_PROTOCOL_BYTES)
    if closed is None:
        raise ServiceError(
            f"the guardian did not write CLOSED.json for {cur.generation} within "
            f"{STOP_CONFIRM_SECONDS:g}s; the task is left DISABLED, nothing was killed"
        )
    accepted, detail = ep.closed_accepted(closed)
    if api.process_birth(ready.pid) == ready.birth:
        raise ServiceError(
            f"CLOSED.json was written but the held daemon {ready.pid} (birth {ready.birth}) is still "
            "alive; the task is left DISABLED"
        )
    if api.listener_pids(m.port):
        raise ServiceError(f"127.0.0.1:{m.port} is still listening after the guardian closed")
    if not accepted:
        return f"generation {cur.generation} CLOSED without acceptance ({detail})"
    return f"generation {cur.generation} stopped by the guardian (CLOSED accepted)"


def endpoint_status(leaf: str, runner, api, user_sid: Optional[str] = None) -> Optional[dict]:
    info = win.query_task(runner, leaf)
    if info is None:
        return None
    out = {"task": win.TASK_FOLDER + leaf, "state": info.state, "lastResult": info.last_result,
           "managed": False, "running": False, "contract": [], "readiness": None}
    try:
        fields = win.parse_task_xml(info.xml)
    except ServiceError as exc:
        out["contract"] = [str(exc)]
        return out
    out["managed"] = win.MANAGED_MARKER in fields["description"]
    out["command"] = fields["command"]
    out["arguments"] = win.parse_arguments(fields["arguments"] or "")
    out["logon_type"] = fields["logon_type"]
    out["run_level"] = fields["run_level"]
    manifest_path = _manifest_from_fields(fields)
    key_match = _KEY_IN_DESCRIPTION.search(fields["description"])
    if not manifest_path or not key_match:
        out["contract"] = ["the task does not run the -I -S -B guardian bootstrap with a manifest "
                           "and an enrolled host key"]
        return out
    from pocketshell.gateway import pins as gateway_pins

    try:
        m = load_manifest(manifest_path)
        host_key = gateway_pins.parse_host_key(key_match.group(1))
    except (ServiceError, gateway_pins.PinError) as exc:
        out["contract"] = [str(exc)]
        return out
    out.update(manifest=m.path, manifestSHA256=m.sha256, port=m.port)
    check_only = out["arguments"][-1:] == ["--check-only"]
    spec = endpoint_spec(m, leaf, host_key, leaf != ep.ENDPOINT_LEAF, check_only)
    sid = user_sid or api.current_sid()
    out["contract"] = win.spec_readback_problems(fields, spec, sid, win.DEFAULT_LOGON_TYPE, api)
    if m.sha256 not in ep.ALLOWED_ENDPOINT_MANIFEST_SHA256:
        out["contract"].append("the manifest is no longer a reviewed manifest")
    if m.source_digests() not in ep.ALLOWED_GUARDIAN_SOURCES:
        out["contract"].append("the pinned guardian sources are no longer a reviewed triple")
    out["processes"] = win._matching(api, m.python)
    if check_only:
        out["checkOnly"] = True
        out["running"] = False
        return out
    ready = readiness(m, host_key, api, runner)
    out["readiness"] = ready
    out["running"] = info.state == "Running" and not out["contract"] and ready["ok"]
    return out
