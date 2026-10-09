"""Windows endpoint task: the guardian launched by Task Scheduler.

Task ``\\PocketShell\\GatewayEndpoint`` (or ``GatewayEndpointQ<instance>`` for
an isolated qualification) runs ``<manifest python> <pinned guardian.py>
--manifest <manifest>`` directly: current SID, S4U, LeastPrivilege, session 0,
working directory = the manifest root, boot +10 s, 5-minute IgnoreNew watchdog.

Readiness (install confirmation and ``status``) requires ALL of:
the task's own state Running; CURRENT.json of a generation bound to this
manifest (digest, port) and owned by the manifest owner; READY.json of that
generation naming the same held daemon; no CLOSED.json; the daemon PID alive
with exactly the recorded creation FILETIME (and the guardian likewise); the
loopback listener owned by exactly that daemon; and a real SSH key exchange
proving the ENROLLED host key.

Stop (``uninstall``) never kills: the task is disabled first (so neither the
watchdog nor RestartOnFailure restarts it), then STOP.json carries the exact
held identity to the guardian, which stops its own Job and writes CLOSED.json.
Only after an accepted close (or a confirmed not-running guardian) is the task
deleted. Otherwise it stays registered and DISABLED, and the error says why.
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
    problems: list = field(default_factory=list)

    @property
    def name(self) -> str:
        return win.TASK_FOLDER + self.leaf


def endpoint_spec(m: ep.GuardianManifest, leaf: str, host_key, qualification: bool) -> "win.TaskSpec":
    kind = "QUALIFICATION endpoint" if qualification else "private loopback SSH endpoint"
    return win.TaskSpec(
        leaf=leaf,
        command=m.python,
        argv=(m.guardian, "--manifest", m.path),
        arguments=" ".join(win.quote_arg(a) for a in (m.guardian, "--manifest", m.path)),
        working_directory=m.root,
        boot_delay=ep.ENDPOINT_BOOT_DELAY,
        description=(
            f"PocketShell {kind} guardian on 127.0.0.1:{m.port}: hidden, session 0, runs "
            f"as the enrolling user. Manifest sha256 {m.sha256}. "
            f"Enrolled host key: {host_key.line}. {win.MANAGED_MARKER}."
        ),
    )


def read_bounded(path: str, limit: int) -> Optional[bytes]:
    """File bytes, or None when it does not exist. Larger than ``limit``
    is an error (never read unbounded)."""
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


def plan_endpoint(
    manifest_path: str,
    show: str,
    user_sid: str,
    *,
    instance: Optional[str],
    start: bool,
    api,
    runner,
    logon_type: str,
) -> EndpointPlan:
    leaf = ep.leaf_for(instance)
    qualification = instance is not None
    m = load_manifest(manifest_path)
    ep.check_trust(m, file_sha256=win.file_sha256)
    host_key = ep.check_binding(m, show, user_sid, qualification=qualification)
    for path in (m.root, m.state, m.path, m.config):
        owner = api.owner_sid(path)
        if owner != m.owner_sid:
            raise ServiceError(
                f"{sanitize(path)} is owned by {sanitize(owner)}, not by the manifest owner "
                f"{m.owner_sid}; the guardian would refuse it"
            )
    spec = endpoint_spec(m, leaf, host_key, qualification)
    xml = win.build_spec_xml(spec, user_sid, logon_type=logon_type, enabled=start)
    if win.query_task_xml(runner, leaf) is not None:
        raise ServiceError(
            f"the scheduled task {win.TASK_FOLDER + leaf} already exists. Endpoint replacement "
            "goes through the guardian STOP protocol: run `pocketshell gateway service "
            "uninstall` first"
        )
    if api.listener_pids(m.port):
        raise ServiceError(
            f"127.0.0.1:{m.port} is already served by another process (e.g. the currently held "
            "endpoint). Have its owner stop it through its own controlled-stop mechanism first; "
            "this command never stops it."
        )
    return EndpointPlan(m, leaf, spec, xml, host_key, qualification)


def readiness(m: ep.GuardianManifest, host_key, api, runner, *, not_generation: Optional[str] = None) -> dict:
    """Every readiness fact; ``ok`` only when all hold (task state is separate)."""
    out = {"ok": False, "problems": [], "generation": None, "pid": None, "birth": None,
           "guardianPID": None, "hostKey": None}
    problems = out["problems"]
    current_file = ep.current_path(m)
    data = read_bounded(current_file, ep.MAX_PROTOCOL_BYTES)
    if data is None:
        problems.append("no CURRENT.json yet (guardian not READY)")
        return out
    owner = api.owner_sid(current_file)
    if owner != m.owner_sid:
        problems.append(f"CURRENT.json is owned by {owner}, not {m.owner_sid}")
        return out
    try:
        cur = ep.parse_current(data, m)
    except ServiceError as exc:
        problems.append(str(exc))
        return out
    out.update(generation=cur.generation, pid=cur.pid, birth=cur.birth, guardianPID=cur.guardian_pid)
    if not_generation is not None and cur.generation == not_generation:
        problems.append("CURRENT.json still names the previous generation")
        return out
    ready = read_bounded(ep.generation_file(m, cur.generation, "READY.json"), ep.MAX_PROTOCOL_BYTES)
    if ready is None:
        problems.append("READY.json of the current generation is missing")
        return out
    try:
        ep.check_ready(ready, cur)
    except ServiceError as exc:
        problems.append(str(exc))
        return out
    if read_bounded(ep.generation_file(m, cur.generation, "CLOSED.json"), ep.MAX_PROTOCOL_BYTES) is not None:
        problems.append("the current generation is CLOSED")
        return out
    if api.process_birth(cur.pid) != cur.birth:
        problems.append(f"the held daemon pid {cur.pid} with birth {cur.birth} is not alive")
    if api.process_birth(cur.guardian_pid) != cur.guardian_birth:
        problems.append(f"the guardian pid {cur.guardian_pid} with its recorded birth is not alive")
    listeners = api.listener_pids(m.port)
    if listeners != [("127.0.0.1", cur.pid)]:
        problems.append(
            f"127.0.0.1:{m.port} listeners {listeners} are not exactly the held daemon {cur.pid}"
        )
    if problems:
        return out
    ok, detail = hostkey.verify_host_key(m.port, host_key, runner=runner)
    out["hostKey"] = detail
    if not ok:
        problems.append(detail)
        return out
    out["ok"] = True
    return out


def start_and_confirm(plan: EndpointPlan, runner, api) -> dict:
    """/Run, then wait for the task Running AND full readiness of a NEW generation."""
    previous = None
    data = read_bounded(ep.current_path(plan.manifest), ep.MAX_PROTOCOL_BYTES)
    if data is not None:
        try:
            previous = ep.parse_current(data, plan.manifest).generation
        except ServiceError:
            previous = None
    result = runner(win.schtasks("/Run", "/TN", plan.name))
    if result.returncode != 0:
        raise NotStartedError(
            f"{plan.name} is registered but NOT started: /Run failed (exit {result.returncode}): "
            f"{sanitize(decode(result.stderr or result.stdout), 400)}"
        )
    deadline = time.monotonic() + ENDPOINT_CONFIRM_SECONDS
    last = {"problems": ["not checked"]}
    state = "Unknown"
    while True:
        info = win.query_task(runner, plan.leaf)
        state = info.state if info else "absent"
        if state == "Running":
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
    script = (
        "$ErrorActionPreference='Stop';"
        "try{$s=New-Object -ComObject Schedule.Service;$s.Connect();"
        f"$t=$s.GetFolder('{win.TASK_FOLDER.rstrip(chr(92))}').GetTask('{leaf}');"
        f"$t.Enabled=${'true' if enabled else 'false'};'ok'"
        "}catch{$e=$_.Exception;while($e.InnerException){$e=$e.InnerException};"
        "'error 0x{0:X8} {1}' -f $e.HResult,$e.Message}"
    )
    if not re.fullmatch(r"[A-Za-z0-9]+", leaf):
        raise ServiceError("unexpected task name")
    result = runner(win._powershell(script))
    text = decode(result.stdout).strip()
    if result.returncode != 0 or text != "ok":
        raise ServiceError(
            f"could not {'enable' if enabled else 'disable'} {win.TASK_FOLDER + leaf}: "
            f"{sanitize(text or decode(result.stderr), 300)}"
        )


def _manifest_from_fields(fields: dict) -> Optional[str]:
    args = win.parse_arguments(fields.get("arguments") or "")
    if len(args) == 3 and args[1] == "--manifest":
        return args[2]
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
    """STOP.json with the exact held identity; wait for an accepted CLOSED.json."""
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
    closed_path = ep.generation_file(m, cur.generation, "CLOSED.json")
    if read_bounded(closed_path, ep.MAX_PROTOCOL_BYTES) is not None:
        return f"generation {cur.generation} already CLOSED"
    if api.process_birth(cur.pid) == cur.birth:
        stop_path = ep.generation_file(m, cur.generation, "STOP.json")
        if read_bounded(stop_path, ep.MAX_STOP_BYTES) is None:
            api.write_owned_file(stop_path, ep.stop_request(cur), m.owner_sid)
    deadline = time.monotonic() + STOP_CONFIRM_SECONDS
    closed = read_bounded(closed_path, ep.MAX_PROTOCOL_BYTES)
    while closed is None and time.monotonic() < deadline:
        time.sleep(POLL_SECONDS)
        closed = read_bounded(closed_path, ep.MAX_PROTOCOL_BYTES)
    if closed is None:
        raise ServiceError(
            f"the guardian did not write CLOSED.json for generation {cur.generation} within "
            f"{STOP_CONFIRM_SECONDS:g}s; the task is left DISABLED, nothing was killed"
        )
    result = ep.parse_closed(closed, cur)
    if api.process_birth(cur.pid) == cur.birth:
        raise ServiceError(
            f"CLOSED.json was written but the held daemon {cur.pid} (birth {cur.birth}) is still "
            "alive; the task is left DISABLED"
        )
    if api.listener_pids(m.port):
        raise ServiceError(f"127.0.0.1:{m.port} is still listening after the guardian closed")
    if result.get("accepted") is not True:
        return (
            f"generation {cur.generation} CLOSED without acceptance "
            f"({sanitize(str(result.get('failure') or result.get('cleanupErrors')), 200)})"
        )
    return f"generation {cur.generation} stopped by the guardian (CLOSED accepted)"


def endpoint_status(leaf: str, runner, api, user_sid: Optional[str] = None) -> Optional[dict]:
    info = win.query_task(runner, leaf)
    if info is None:
        return None
    out = {"task": win.TASK_FOLDER + leaf, "state": info.state, "managed": False,
           "running": False, "contract": [], "readiness": None}
    try:
        fields = win.parse_task_xml(info.xml)
    except ServiceError as exc:
        out["contract"] = [str(exc)]
        return out
    out["managed"] = win.MANAGED_MARKER in fields["description"]
    out["command"] = fields["command"]
    out["logon_type"] = fields["logon_type"]
    out["run_level"] = fields["run_level"]
    manifest_path = _manifest_from_fields(fields)
    key_match = _KEY_IN_DESCRIPTION.search(fields["description"])
    if not manifest_path or not key_match:
        out["contract"] = ["the task does not name a manifest and an enrolled host key"]
        return out
    from pocketshell.gateway import pins as gateway_pins

    try:
        m = load_manifest(manifest_path)
        host_key = gateway_pins.parse_host_key(key_match.group(1))
    except (ServiceError, gateway_pins.PinError) as exc:
        out["contract"] = [str(exc)]
        return out
    out["manifest"] = m.path
    out["manifestSHA256"] = m.sha256
    out["port"] = m.port
    qualification = leaf != ep.ENDPOINT_LEAF
    spec = endpoint_spec(m, leaf, host_key, qualification)
    sid = user_sid or api.current_sid()
    out["contract"] = win.spec_readback_problems(fields, spec, sid, win.DEFAULT_LOGON_TYPE, api)
    if m.sha256 not in ep.ALLOWED_ENDPOINT_MANIFEST_SHA256:
        out["contract"].append("the manifest is no longer a reviewed manifest")
    out["processes"] = win._matching(api, m.python)
    ready = readiness(m, host_key, api, runner)
    out["readiness"] = ready
    out["running"] = info.state == "Running" and not out["contract"] and ready["ok"]
    return out
