"""Private loopback SSH endpoint: the productized guardian's interface.

``gateway service install --with-endpoint MANIFEST`` gives the enrolled
loopback sshd its own durable owner: a managed task that launches the
protected Python interpreter running the endpoint's ``guardian.py --manifest
<protected absolute manifest>`` DIRECTLY (no shell, no cmd.exe), as the
current user (S4U, session 0, LeastPrivilege).

The guardian (maintained by the Windows endpoint author, not this CLI) owns
the daemon: it validates its own token/session, creates a private desktop on
its non-visible window station, starts the daemon NO_WINDOW + suspended +
Job-before-resume, and holds the exact daemon PID + decimal creation FILETIME
as its stop authority. This module only speaks the agreed file protocol
(endpoint-guardian-api-agreement.md, schema 1):

    <state>/.lock                            exclusive, held by the live guardian
    <state>/CURRENT.json                     written by the guardian, atomically,
                                             only after its owned daemon is READY
    <state>/generations/<generation>/READY.json   guardian
    <state>/generations/<generation>/STOP.json    THIS CLI (stop request)
    <state>/generations/<generation>/CLOSED.json  guardian (final result)

Status and stop always go CURRENT.json -> generation -> READY.json, check the
manifest binding and the exact held daemon PID + birth string, and stop only
through STOP.json — never by a numeric kill.

The manifest is the guardian's own closed schema (``version`` 1). Trust is
two reviewed source constants, both EMPTY until reviewed: the per-host
manifest file digest and the guardian source digest.
"""

from __future__ import annotations

import hashlib
import json
import ntpath
import re
from dataclasses import dataclass, field
from typing import Callable, Optional

from pocketshell.gateway.service_common import ServiceError, has_control_chars, parse_show, sanitize

ENDPOINT_LEAF = "GatewayEndpoint"
ENDPOINT_BOOT_DELAY = "PT10S"  # the link keeps PT30S (soft ordering only)
MAX_MANIFEST_BYTES = 64 * 1024
MAX_PROTOCOL_BYTES = 64 * 1024
MAX_STOP_BYTES = 4096
GUARDIAN_SCRIPT = "guardian.py"
INSTANCE_RE = re.compile(r"[A-Za-z0-9]{1,32}")
GENERATION_RE = re.compile(r"[0-9a-f]{32}")
FILETIME_RE = re.compile(r"[1-9][0-9]{0,19}")

# Reviewed per-host guardian manifests (sha256 of the manifest FILE) and
# reviewed guardian sources (sha256 of guardian.py). Adding one is a reviewed
# source change, never a flag or environment variable. EMPTY until the
# productized guardian and the laptop manifest have been reviewed.
ALLOWED_ENDPOINT_MANIFEST_SHA256: frozenset = frozenset()
ALLOWED_GUARDIAN_SOURCE_SHA256: frozenset = frozenset()

# The guardian's closed manifest schema (policy.validate_manifest, version 1).
MANIFEST_KEYS = frozenset(
    {"version", "ownerSID", "root", "state", "config", "port", "daemon", "python", "pins", "environment"}
)
ENVIRONMENT_KEYS = frozenset(
    {"SystemRoot", "WINDIR", "SystemDrive", "ProgramData", "USERPROFILE", "HOME", "TEMP", "TMP"}
)
_OWNER_SID = re.compile(r"S-1-5-21-\d+-\d+-\d+-\d+")
_HEX64 = re.compile(r"[a-f0-9]{64}")


def leaf_for(instance: Optional[str]) -> str:
    """Task leaf: GatewayEndpoint, or GatewayEndpointQ<instance> for an
    isolated qualification task (never the production name)."""
    if instance is None:
        return ENDPOINT_LEAF
    if not INSTANCE_RE.fullmatch(instance):
        raise ServiceError("--instance must be 1-32 letters/digits")
    return ENDPOINT_LEAF + "Q" + instance


@dataclass(frozen=True)
class GuardianManifest:
    path: str
    sha256: str
    owner_sid: str
    root: str
    state: str
    config: str
    port: int
    daemon: str
    python: str
    guardian: str
    pins: dict = field(hash=False)
    environment: dict = field(hash=False)


def _fail(message: str) -> ServiceError:
    return ServiceError(f"endpoint manifest: {message}")


def _absolute(value, what: str) -> str:
    """policy.absolute: a local drive path, no traversal/device/ADS/quotes."""
    if not isinstance(value, str) or not re.match(r"^[A-Za-z]:[\\/]", value) or any(
        ch in value for ch in ("\x00", "\r", "\n", '"')
    ):
        raise _fail(f"{what} must be an absolute local drive path")
    if value.startswith(("\\\\", "//")) or any(
        part in ("..", ".") for part in re.split(r"[\\/]", value)[1:]
    ):
        raise _fail(f"{what}: traversal or device path refused")
    if ":" in value[2:]:
        raise _fail(f"{what}: alternate data stream refused")
    if has_control_chars(value) or "%" in value:
        raise _fail(f"{what} contains a control character or '%'")
    return ntpath.normpath(value)


def _below(value, root: str, what: str) -> str:
    value = _absolute(value, what)
    if ntpath.commonpath([value.casefold(), root.casefold()]) != root.casefold() or (
        value.casefold() == root.casefold()
    ):
        raise _fail(f"{what} escapes the protected root")
    return value


def parse_manifest(data: bytes, manifest_path: str) -> GuardianManifest:
    """The guardian's closed schema, checked exactly as the guardian does,
    plus the service convention: exactly one pinned ``guardian.py``."""
    if len(data) > MAX_MANIFEST_BYTES:
        raise _fail("larger than 64 KiB")
    try:
        m = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise _fail("not UTF-8 JSON") from None
    if not isinstance(m, dict) or set(m) != MANIFEST_KEYS or m.get("version") != 1:
        raise _fail("the closed guardian schema (version 1, exactly its ten keys) is required")
    if not isinstance(m["ownerSID"], str) or not _OWNER_SID.fullmatch(m["ownerSID"]):
        raise _fail("ownerSID must be an own-account SID (S-1-5-21-…)")
    root = _absolute(m["root"], "root")
    state = _below(m["state"], root, "state")
    config = _below(m["config"], root, "config")
    daemon = _below(m["daemon"], root, "daemon")
    python = _absolute(m["python"], "python")
    _below(manifest_path, root, "the manifest itself")
    if type(m["port"]) is not int or not 1024 <= m["port"] <= 65535:
        raise _fail("port must be an unprivileged integer 1024-65535")
    pins = m["pins"]
    if not isinstance(pins, dict) or not pins:
        raise _fail("pins (the exact file closure) are required")
    normalized: dict = {}
    for path, digest in pins.items():
        key = _absolute(path, "pinned path")
        if key.casefold() in {k.casefold() for k in normalized} or not isinstance(digest, str) or not _HEX64.fullmatch(digest):
            raise _fail("pins must be unique paths with lowercase sha256")
        normalized[key] = digest
    folded = {k.casefold(): k for k in normalized}
    for required in (daemon, python, config):
        if required.casefold() not in folded:
            raise _fail(f"startup file {sanitize(required)} lacks a pin")
    guardians = [k for k in normalized if ntpath.basename(k).casefold() == GUARDIAN_SCRIPT]
    if len(guardians) != 1:
        raise _fail(f"exactly one pinned {GUARDIAN_SCRIPT} is required (the task launches it)")
    env = m["environment"]
    if not isinstance(env, dict) or set(env) != ENVIRONMENT_KEYS or any(
        not isinstance(v, str) or any(c in v for c in "\x00\r\n") for v in env.values()
    ):
        raise _fail("the closed fixed environment (exactly its eight keys) is required")
    if (
        env["SystemDrive"] != "C:"
        or env["SystemRoot"].casefold() != "c:/windows"
        or env["WINDIR"].casefold() != "c:/windows"
        or env["ProgramData"].casefold() != "c:/programdata"
    ):
        raise _fail("the qualified system paths are required")
    _below(env["TEMP"], state, "TEMP")
    _below(env["TMP"], state, "TMP")
    _absolute(env["USERPROFILE"], "USERPROFILE")
    _absolute(env["HOME"], "HOME")
    return GuardianManifest(
        path=_absolute(manifest_path, "manifest path"),
        sha256=hashlib.sha256(data).hexdigest(),
        owner_sid=m["ownerSID"],
        root=root,
        state=state,
        config=config,
        port=m["port"],
        daemon=daemon,
        python=python,
        guardian=guardians[0],
        pins=normalized,
        environment=dict(env),
    )


def check_trust(m: GuardianManifest, *, file_sha256: Callable[[str], str]) -> None:
    """Reviewed manifest digest, reviewed guardian source, every pin on disk."""
    if m.sha256 not in ALLOWED_ENDPOINT_MANIFEST_SHA256:
        raise ServiceError(
            f"endpoint manifest sha256 {m.sha256[:12]}… is not a reviewed manifest "
            "(ALLOWED_ENDPOINT_MANIFEST_SHA256)"
        )
    if m.pins[m.guardian] not in ALLOWED_GUARDIAN_SOURCE_SHA256:
        raise ServiceError(
            f"the pinned {GUARDIAN_SCRIPT} is not a reviewed guardian source "
            "(ALLOWED_GUARDIAN_SOURCE_SHA256)"
        )
    for path, digest in m.pins.items():
        if file_sha256(path) != digest:
            raise ServiceError(f"pinned endpoint file {sanitize(path)} does not match the manifest")


def check_binding(m: GuardianManifest, show_text: str, user_sid: str, *, qualification: bool):
    """The endpoint must serve THIS enrolled device as THIS user.

    Returns the enrolled pinned host key (the readiness check later compares
    the key the running daemon actually proves against it). The production
    endpoint must also listen on the enrolled ``local ssh`` port; an isolated
    qualification instance runs on its own port (e.g. 22025) instead.
    """
    from pocketshell.gateway import pins as gateway_pins

    if m.owner_sid != user_sid:
        raise ServiceError(
            f"the manifest's ownerSID {m.owner_sid} is not your SID {user_sid}; run as the enrolling user"
        )
    fields = parse_show(show_text)
    try:
        key = gateway_pins.parse_host_key(fields.get("pinned ssh host key", ""))
    except gateway_pins.PinError:
        raise ServiceError("the enrollment has no usable pinned host key to verify the endpoint against") from None
    local = (fields.get("local ssh") or "").split()
    expected = f"127.0.0.1:{m.port}"
    if not qualification and (not local or local[0] != expected):
        raise ServiceError(
            f"the endpoint port {expected} is not the enrolled local ssh "
            f"{sanitize(local[0] if local else '(none)', 80)}; it would not serve this device"
        )
    if qualification and local and local[0] == expected:
        raise ServiceError(
            f"a qualification instance must not use the enrolled production port {expected}"
        )
    return key


# --- protocol files ---------------------------------------------------------------


def _json_object(data: bytes, what: str) -> dict:
    if len(data) > MAX_PROTOCOL_BYTES:
        raise ServiceError(f"{what} is larger than {MAX_PROTOCOL_BYTES} bytes")
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ServiceError(f"{what} is not UTF-8 JSON") from None
    if not isinstance(value, dict):
        raise ServiceError(f"{what} is not a JSON object")
    return value


def current_path(m: GuardianManifest) -> str:
    return ntpath.join(m.state, "CURRENT.json")


def generation_file(m: GuardianManifest, generation: str, name: str) -> str:
    if not GENERATION_RE.fullmatch(generation):
        raise ServiceError("invalid generation id")
    return ntpath.join(m.state, "generations", generation, name)


@dataclass(frozen=True)
class Current:
    generation: str
    pid: int
    birth: str
    guardian_pid: int
    guardian_birth: str
    port: int
    manifest_sha256: str


def parse_current(data: bytes, m: GuardianManifest) -> Current:
    """CURRENT.json, bound to this manifest (digest and port)."""
    c = _json_object(data, "CURRENT.json")
    if c.get("schema") != 1:
        raise ServiceError("CURRENT.json: schema 1 required")
    generation = c.get("generation")
    if not isinstance(generation, str) or not GENERATION_RE.fullmatch(generation):
        raise ServiceError("CURRENT.json: generation must be 32 lowercase hex")
    for name in ("pid", "guardianPID", "port"):
        if type(c.get(name)) is not int or c[name] <= 0:
            raise ServiceError(f"CURRENT.json: {name} must be a positive integer")
    for name in ("creationFILETIME", "guardianCreationFILETIME"):
        if not isinstance(c.get(name), str) or not FILETIME_RE.fullmatch(c[name]):
            raise ServiceError(f"CURRENT.json: {name} must be a decimal FILETIME string")
    if c.get("manifestSHA256") != m.sha256:
        raise ServiceError("CURRENT.json belongs to a different manifest")
    if c["port"] != m.port:
        raise ServiceError("CURRENT.json port differs from the manifest")
    return Current(
        generation, c["pid"], c["creationFILETIME"], c["guardianPID"],
        c["guardianCreationFILETIME"], c["port"], c["manifestSHA256"],
    )


def check_ready(data: bytes, current: Current) -> None:
    """READY.json of the CURRENT generation must name the same held daemon."""
    r = _json_object(data, "READY.json")
    expected = {
        "generation": current.generation,
        "pid": current.pid,
        "creationFILETIME": current.birth,
        "guardianPID": current.guardian_pid,
        "manifestSHA256": current.manifest_sha256,
        "port": current.port,
    }
    for name, value in expected.items():
        if r.get(name) != value:
            raise ServiceError(f"READY.json {name} does not match CURRENT.json")


def stop_request(current: Current) -> bytes:
    """The exact STOP.json body (policy.validate_stop: these four keys only)."""
    body = {
        "pid": current.pid,
        "creationFILETIME": current.birth,
        "manifestSHA256": current.manifest_sha256,
        "stopOwnedJob": True,
    }
    data = json.dumps(body, sort_keys=True).encode("utf-8")
    assert len(data) <= MAX_STOP_BYTES
    return data


def parse_closed(data: bytes, current: Current) -> dict:
    closed = _json_object(data, "CLOSED.json")
    if closed.get("generation", current.generation) != current.generation:
        raise ServiceError("CLOSED.json belongs to another generation")
    return closed
