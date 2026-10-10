"""Private loopback SSH endpoint: the FINAL guardian ABI (portable rules).

Authoritative interface: the guardian author's INTERFACE.md (packet
windows-durable-native-guardian-74a0-api, sha 8d6711ae… final-packet) with
the 6cf7ae85 successor (guardian 6cf7ae85 / policy e92bbe02 / native_api
cab601e2; servicing-hardlink role for System32 cmd.exe/conhost.exe):

* task action (built in service_windows_endpoint):
  ``<qualified python.exe> -I -S -B <protected guardian.py> --manifest
  <protected manifest>``; the Phase A qualification adds ``--check-only``;
* manifest version 1 with EXACTLY ownerSID, root, state, config, port,
  daemon, python, pins, environment, configBindings — validated here with
  the same rules as the guardian's ``policy.validate_manifest``;
* ``state`` is a stable generation BASE: ``INSTANCE.lock``,
  ``generation-<uuidhex>\\{READY,STOP,CLOSED}.json`` (retained), and
  ``CURRENT.json`` = ``{version:1, generation:<abs>, ready:<abs>,
  manifestSHA256}`` published atomically only after READY; all metadata
  comes from the referenced READY.json;
* STOP.json = exactly ``{pid, creationFILETIME, manifestSHA256,
  stopOwnedJob:true}`` in that exact generation; CLOSED.json accepted only
  with ``accepted``, ``requestedOwnedJobStop``, ``activeAtClose == 0`` and
  empty ``cleanupErrors``.

Trust before execution: the reviewed per-host manifest digest, the reviewed
(guardian.py, native_api.py, policy.py) source triple, every pin re-hashed on
disk, and protected-ancestor/final-file authority checked by the Windows
backend. Both reviewed lists are EMPTY until the artifacts are reviewed.
"""

from __future__ import annotations

import hashlib
import json
import ntpath
import re
import shlex
from dataclasses import dataclass, field
from typing import Callable, Optional

from pocketshell.gateway.service_common import ServiceError, parse_show, sanitize

ENDPOINT_LEAF = "GatewayEndpoint"
ENDPOINT_BOOT_DELAY = "PT10S"  # the link keeps PT30S (soft ordering only)
CHECK_ONLY_TIME_LIMIT = "PT5M"
BOOTSTRAP_FLAGS = ("-I", "-S", "-B")  # isolated, no site, no bytecode writes
MAX_MANIFEST_BYTES = 64 * 1024
MAX_PROTOCOL_BYTES = 64 * 1024
MAX_STOP_BYTES = 4096
SOURCE_NAMES = ("guardian.py", "native_api.py", "policy.py")
INSTANCE_RE = re.compile(r"[A-Za-z0-9]{1,32}")
GENERATION_DIR_RE = re.compile(r"generation-[0-9a-f]{32}")
FILETIME_RE = re.compile(r"[1-9][0-9]{0,19}")
SERVICING_IMAGES = ("c:\\windows\\system32\\cmd.exe", "c:\\windows\\system32\\conhost.exe")

# Reviewed per-host guardian manifests (sha256 of the manifest FILE) and
# reviewed guardian source triples (guardian.py, native_api.py, policy.py).
# Adding one is a reviewed source change, never a flag or environment
# variable. EMPTY until the productized guardian and the manifests have been
# reviewed (final candidate: 6cf7ae85…, cab601e2…, e92bbe02…).
ALLOWED_ENDPOINT_MANIFEST_SHA256: frozenset = frozenset()
# Setup ABI v3 (Option B): the ONE generic reviewed trio, compiled once. Per-host
# manifests are trusted only through the installed authority record
# (check_trust_authority), never by a compiled per-manifest digest.
ALLOWED_GUARDIAN_SOURCES: frozenset = frozenset({(
    "6cf7ae85ad21b23496e7187da7e3bb4f171adef5f63edd2fd01f6ce6435bd047",
    "cab601e27e9814ee8c4e3cd72e0dfd55fd2808682d302655725885b4a4812231",
    "e92bbe02c497c959702b35cfd2d4444a073eafe6e17d5e3872449c3bd4f6b1ce",
)})

MANIFEST_KEYS = frozenset(
    {"version", "ownerSID", "root", "state", "config", "port", "daemon", "python", "pins",
     "environment", "configBindings"}
)
ENVIRONMENT_KEYS = frozenset(
    {"SystemRoot", "WINDIR", "SystemDrive", "ProgramData", "USERPROFILE", "HOME", "TEMP", "TMP"}
)
BINDING_KEYS = frozenset(
    {"hostKey", "authorizedKeys", "pidFile", "allowUser", "sftp", "backendConfig",
     "backendExecutable", "backendDLL", "setEnv"}
)
SETENV_KEYS = frozenset(
    {"APLEXER_CONFIG", "APLEXER_RUNTIME_DIR", "APLEXER_STATE_DIR", "APLEXER_RUN_IN_PLACE",
     "APLEXER_SHELL", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME",
     "BASH_ENV", "ENV", "ZDOTDIR"}
)
SETENV_DIRECTORIES = ("APLEXER_RUNTIME_DIR", "APLEXER_STATE_DIR", "XDG_CONFIG_HOME",
                      "XDG_STATE_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME")
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


def is_servicing_image(path: str) -> bool:
    return ntpath.normpath(path).casefold() in SERVICING_IMAGES


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
    native_api: str
    policy: str
    pins: dict = field(hash=False)
    environment: dict = field(hash=False)
    config_bindings: dict = field(hash=False)
    raw_bindings: dict = field(hash=False, default_factory=dict)

    @property
    def sources(self) -> tuple:
        return (self.guardian, self.native_api, self.policy)

    def source_digests(self) -> tuple:
        return tuple(self.pins[p] for p in self.sources)


def _fail(message: str) -> ServiceError:
    return ServiceError(f"endpoint manifest: {message}")


def _absolute(value, what: str) -> str:
    """policy.absolute."""
    if not isinstance(value, str) or not re.match(r"^[A-Za-z]:[\\/]", value) or any(
        ch in value for ch in ("\x00", "\r", "\n", '"')
    ):
        raise _fail(f"{what} must be an absolute local drive path")
    if value.startswith(("\\\\", "//")) or any(part in ("..", ".") for part in re.split(r"[\\/]", value)[1:]):
        raise _fail(f"{what}: traversal or device path refused")
    if ":" in value[2:]:
        raise _fail(f"{what}: alternate data stream refused")
    return ntpath.normpath(value)


def _below(value, root: str, what: str) -> str:
    """policy.below."""
    value, root = _absolute(value, what), _absolute(root, "root")
    if ntpath.commonpath([value.casefold(), root.casefold()]) != root.casefold() or value.casefold() == root.casefold():
        raise _fail(f"{what} escapes the protected root")
    return value


def parse_manifest(data: bytes, manifest_path: str) -> GuardianManifest:
    """The final closed schema, checked as policy.validate_manifest does,
    plus require_source_pins and the guardian's own containment of the
    manifest and its three sources below root (path layout: the three
    sources sit together, HERE = the guardian's directory)."""
    if len(data) > MAX_MANIFEST_BYTES:
        raise _fail("larger than 64 KiB")
    try:
        m = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise _fail("not UTF-8 JSON") from None
    if not isinstance(m, dict) or set(m) != MANIFEST_KEYS or m.get("version") != 1:
        raise _fail("the closed guardian schema (version 1 plus its ten keys incl. configBindings) is required")
    if not isinstance(m["ownerSID"], str) or not _OWNER_SID.fullmatch(m["ownerSID"]):
        raise _fail("ownerSID must be an own-account SID (S-1-5-21-…)")
    root = _absolute(m["root"], "root")
    state = _below(m["state"], root, "state")
    config = _below(m["config"], root, "config")
    daemon = _below(m["daemon"], root, "daemon")
    python = _absolute(m["python"], "python")
    path = _below(manifest_path, root, "the manifest itself")
    if type(m["port"]) is not int or not 1024 <= m["port"] <= 65535:
        raise _fail("port must be an unprivileged integer 1024-65535")
    pins = m["pins"]
    if not isinstance(pins, dict) or not pins:
        raise _fail("pins (the exact file closure) are required")
    normalized: dict = {}
    for p, digest in pins.items():
        key = _absolute(p, "pinned path")
        if key.casefold() in {k.casefold() for k in normalized} or not isinstance(digest, str) or not _HEX64.fullmatch(digest):
            raise _fail("pins must be unique paths with lowercase sha256")
        normalized[key] = digest
    folded = {k.casefold(): k for k in normalized}

    def pinned(p: str, what: str) -> str:
        if p.casefold() not in folded:
            raise _fail(what)
        return folded[p.casefold()]

    for required in (daemon, python, config):
        pinned(required, f"startup file {sanitize(required)} lacks a pin")
    b = m["configBindings"]
    if not isinstance(b, dict) or set(b) != BINDING_KEYS:
        raise _fail("closed config binding roles are required")
    bindings = {}
    for name in ("hostKey", "authorizedKeys", "pidFile", "sftp", "backendConfig", "backendExecutable", "backendDLL"):
        bindings[name] = _absolute(b[name], f"configBindings.{name}")
    _below(b["pidFile"], state, "configBindings.pidFile")
    for name in ("sftp", "backendConfig", "backendExecutable", "backendDLL"):
        pinned(bindings[name], f"config runtime role lacks a pin ({name})")
    if not isinstance(b["allowUser"], str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", b["allowUser"]):
        raise _fail("one explicit username (allowUser) is required")
    bindings["allowUser"] = b["allowUser"]
    env_b = b["setEnv"]
    if (
        not isinstance(env_b, dict) or set(env_b) != SETENV_KEYS
        or env_b.get("APLEXER_CONFIG") != b["backendConfig"]
        or env_b.get("APLEXER_RUN_IN_PLACE") != "1"
        or any(env_b.get(k) != "" for k in ("APLEXER_SHELL", "BASH_ENV", "ENV", "ZDOTDIR"))
    ):
        raise _fail("the closed incoming backend environment (setEnv) is required")
    for key, value in env_b.items():
        if not isinstance(value, str) or any(c in value for c in "\x00\r\n"):
            raise _fail("invalid backend environment value")
        if key not in ("APLEXER_RUN_IN_PLACE", "APLEXER_SHELL", "BASH_ENV", "ENV", "ZDOTDIR"):
            _absolute(value, f"setEnv.{key}")
    bindings["setEnv"] = dict(env_b)
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
    # require_source_pins: guardian.py, native_api.py, policy.py pinned,
    # together (the guardian imports its siblings from HERE) and below root.
    guardians = [k for k in normalized if ntpath.basename(k).casefold() == "guardian.py"]
    if len(guardians) != 1:
        raise _fail("the guardian/native_api/policy source closure needs exactly one pinned guardian.py")
    here = ntpath.dirname(guardians[0])
    sources = []
    for name in SOURCE_NAMES:
        candidate = ntpath.join(here, name)
        if candidate.casefold() not in folded:
            raise _fail(f"the guardian/native_api/policy source closure lacks {name} next to guardian.py")
        sources.append(_below(folded[candidate.casefold()], root, f"source {name}"))
    return GuardianManifest(
        path=path,
        sha256=hashlib.sha256(data).hexdigest(),
        owner_sid=m["ownerSID"],
        root=root, state=state, config=config, port=m["port"], daemon=daemon, python=python,
        guardian=sources[0], native_api=sources[1], policy=sources[2],
        pins=normalized, environment=dict(env), config_bindings=bindings,
        raw_bindings=json.loads(json.dumps(b)),
    )


def config_guard(text: str, m: GuardianManifest) -> None:
    """policy.config_guard: closed loopback key-only config bound to the roles."""
    bindings = m.config_bindings
    keys: dict = {}
    allowed = {"port", "listenaddress", "hostkey", "pidfile", "authorizedkeysfile", "authenticationmethods",
               "pubkeyauthentication", "passwordauthentication", "kbdinteractiveauthentication",
               "permitemptypasswords", "allowusers", "disableforwarding", "permittty", "loglevel",
               "subsystem", "setenv"}
    for line in text.splitlines():
        try:
            tokens = shlex.split(line, comments=True)
        except ValueError:
            raise ServiceError("endpoint config: unparseable line") from None
        if not tokens:
            continue
        key = tokens[0].lower()
        if key not in allowed:
            raise ServiceError(f"endpoint config: Undeclared config directive refused ({sanitize(tokens[0], 40)})")
        keys.setdefault(key, []).append(tokens[1:])
    expected = {"port": [[str(m.port)]], "listenaddress": [["127.0.0.1"]], "authenticationmethods": [["publickey"]],
                "pubkeyauthentication": [["yes"]], "passwordauthentication": [["no"]],
                "kbdinteractiveauthentication": [["no"]], "permitemptypasswords": [["no"]],
                "disableforwarding": [["yes"]], "permittty": [["yes"]], "allowusers": [[bindings["allowUser"]]]}
    if any(keys.get(k) != v for k, v in expected.items()):
        raise ServiceError("endpoint config: Closed loopback key-only config required")
    for directive, role in (("hostkey", "hostKey"), ("authorizedkeysfile", "authorizedKeys"), ("pidfile", "pidFile")):
        rows = keys.get(directive)
        if not rows or len(rows) != 1 or len(rows[0]) != 1 or (
            _absolute(rows[0][0], directive).casefold() != bindings[role].casefold()
        ):
            raise ServiceError("endpoint config: Config path role mismatch")
    if keys.get("subsystem") != [["sftp", m.raw_bindings["sftp"]]]:  # exact, as the guardian compares
        raise ServiceError("endpoint config: Pinned private SFTP binding required")
    if len(keys.get("setenv", [])) != 1:
        raise ServiceError("endpoint config: One closed SetEnv declaration required")
    env = {}
    for item in keys["setenv"][0]:
        name, sep, value = item.partition("=")
        if not sep or name in env:
            raise ServiceError("endpoint config: Duplicate/invalid SetEnv")
        env[name] = value
    if env != bindings["setEnv"]:
        raise ServiceError("endpoint config: Backend environment binding mismatch")
    if len(keys.get("loglevel", [])) > 1:
        raise ServiceError("endpoint config: Duplicate log directive refused")


def check_trust(m: GuardianManifest, *, file_sha256: Callable[[str], str]) -> None:
    """Reviewed manifest digest, reviewed source triple, every pin on disk."""
    if m.sha256 not in ALLOWED_ENDPOINT_MANIFEST_SHA256:
        raise ServiceError(
            f"endpoint manifest sha256 {m.sha256[:12]}… is not a reviewed manifest "
            "(ALLOWED_ENDPOINT_MANIFEST_SHA256)"
        )
    if m.source_digests() not in ALLOWED_GUARDIAN_SOURCES:
        raise ServiceError(
            "the pinned guardian.py/native_api.py/policy.py are not a reviewed guardian/native_api/policy "
            "source triple (ALLOWED_GUARDIAN_SOURCES)"
        )
    for path, digest in m.pins.items():
        if file_sha256(path) != digest:
            raise ServiceError(f"pinned endpoint file {sanitize(path)} does not match the manifest")


SYSTEM_REFERENCE_NAMES = ("cmd.exe", "conhost.exe")


def system_references(refs, system_root) -> dict:
    """§16.13 endpoint.systemReferences: EXACTLY [{role:"system-reference",
    name, path, sha256}] for cmd.exe then conhost.exe, each path the plain
    <measured SystemRoot>\\System32\\<name> spelling (no 8.3, \\\\?\\, SysWOW64,
    other directory) and a guardian servicing image. Returns casefolded
    path -> sha256."""
    if not isinstance(system_root, str) or not isinstance(refs, list) or len(refs) != len(SYSTEM_REFERENCE_NAMES):
        raise ServiceError("the authority's systemReferences are not exactly cmd.exe and conhost.exe")
    out = {}
    for ref, name in zip(refs, SYSTEM_REFERENCE_NAMES):
        want = ntpath.join(system_root, "System32", name)
        if not isinstance(ref, dict) or set(ref) != {"role", "name", "path", "sha256"} \
                or ref["role"] != "system-reference" or ref["name"] != name \
                or not isinstance(ref["path"], str) or ref["path"].casefold() != want.casefold() \
                or any(c in ref["path"] for c in "/~?") or not is_servicing_image(ref["path"]) \
                or not isinstance(ref["sha256"], str) or not _HEX64.fullmatch(ref["sha256"]):
            raise ServiceError(f"the authority's system reference for {name} is not the exact measured "
                               "<SystemRoot>\\System32 image")
        out[ntpath.normcase(ref["path"])] = ref["sha256"]
    return out


def check_trust_authority(m: GuardianManifest, receipt, *, file_sha256: Callable[[str], str],
                          release_pins: Optional[dict] = None) -> None:
    """Setup ABI v3 trust: the installed authority (receipt v3) records THIS
    manifest. The fixed managed-runtime layout, the generic reviewed trio,
    every pin re-hashed on disk, and (``release_pins``: casefolded release
    path -> catalog sha256) every release pin equal to its catalog row.
    No structural-only acceptance and no compiled per-host digest."""
    e = receipt.get("endpoint") if isinstance(receipt, dict) and receipt.get("version") == 3 else None
    if not isinstance(e, dict) or set(e) != {"root", "manifest", "manifestSHA256", "config", "state",
                                             "systemReferences"}:
        raise ServiceError("no installed authority (receipt v3) records an endpoint manifest; run `agent install`")
    if m.sha256 != e["manifestSHA256"]:
        raise ServiceError(f"endpoint manifest sha256 {m.sha256[:12]}… is not the one recorded by the installed "
                           "authority")
    root = e["root"]
    if not isinstance(root, str) or ntpath.basename(ntpath.normpath(root)).casefold() != "managed-runtime":
        raise ServiceError("the authority's endpoint root is not managed-runtime")
    fixed = {"manifest": ntpath.join(root, "endpoint", "endpoint-manifest.json"),
             "config": ntpath.join(root, "endpoint", "sshd.conf"), "state": ntpath.join(root, "endpoint", "state")}
    actual = {"manifest": m.path, "config": m.config, "state": m.state}
    for key, want in fixed.items():
        if not isinstance(e[key], str) or ntpath.normcase(ntpath.normpath(e[key])) != ntpath.normcase(want) \
                or ntpath.normcase(actual[key]) != ntpath.normcase(want):
            raise ServiceError(f"the endpoint {key} is not the authority's fixed {key} below managed-runtime")
    if ntpath.normcase(m.root) != ntpath.normcase(ntpath.normpath(root)):
        raise ServiceError("the manifest root is not the authority's managed-runtime root")
    binding = receipt.get("binding") or {}
    if not isinstance(binding, dict) or binding.get("manifestSHA256") != e["manifestSHA256"] \
            or not isinstance(binding.get("manifest"), str) \
            or ntpath.normcase(ntpath.normpath(binding["manifest"])) != ntpath.normcase(fixed["manifest"]):
        raise ServiceError("the authority binding does not name its endpoint manifest")
    if m.source_digests() not in ALLOWED_GUARDIAN_SOURCES:
        raise ServiceError("the pinned guardian.py/native_api.py/policy.py are not the reviewed generic guardian "
                           "source trio (ALLOWED_GUARDIAN_SOURCES)")
    # ALL guardian-required pins: every pin lives below managed-runtime or is
    # a System32 servicing role; both servicing roles, the config and the
    # backend config are pinned; with the catalog rows, the WHOLE release
    # closure is pinned at its catalog digest (no missing startup member).
    base = ntpath.normcase(ntpath.normpath(root)) + "\\"
    keys = {ntpath.normcase(p) for p in m.pins}
    refs = system_references(e["systemReferences"], (receipt.get("environment") or {}).get("SystemRoot"))
    outside = {ntpath.normcase(p): h for p, h in m.pins.items() if not ntpath.normcase(p).startswith(base)}
    for path in outside:
        if path not in refs:
            raise ServiceError(f"pinned file {sanitize(path)} is outside managed-runtime and not a recorded "
                               "system reference")
    roles = {"daemon": m.daemon, "python": m.python, "config": m.config,
             **{k: m.config_bindings[k] for k in ("sftp", "backendExecutable", "backendDLL", "backendConfig")}}
    for role, path in roles.items():
        if not ntpath.normcase(path).startswith(base):
            raise ServiceError(f"the {role} role must live below managed-runtime (a system reference serves only "
                               "the guardian's servicing role)")
    for path, digest in refs.items():
        if outside.get(path) != digest:
            raise ServiceError(f"the manifest lacks the recorded system reference pin {sanitize(path)}")
    for need in (m.config, m.config_bindings["backendConfig"]):
        if ntpath.normcase(need) not in keys:
            raise ServiceError(f"the manifest lacks a pin for {sanitize(need)}")
    if release_pins is not None:
        release = ntpath.normcase(ntpath.join(ntpath.normpath(root), "releases")) + "\\"
        missing = sorted(k for k in release_pins if k not in keys)
        if missing:
            raise ServiceError(f"the manifest lacks catalog closure pins ({len(missing)} missing, e.g. "
                               f"{sanitize(missing[0])})")
        for path, digest in m.pins.items():
            key = ntpath.normcase(path)
            if key.startswith(release) and release_pins.get(key) != digest:
                raise ServiceError(f"pinned release file {sanitize(path)} does not match its catalog row")
    for path, digest in m.pins.items():
        if file_sha256(path) != digest:
            raise ServiceError(f"pinned endpoint file {sanitize(path)} does not match the manifest")


def check_binding(m: GuardianManifest, show_text: str, user_sid: str, *, qualification: bool):
    """Same user, the enrolled device's port (production) and pinned host key."""
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
        raise ServiceError(f"a qualification instance must not use the enrolled production port {expected}")
    return key


def authority_plan(m: GuardianManifest) -> list:
    """Every (path, role, directory, protected, servicing) the guardian itself
    checks with path_authority (6cf7ae85 main()), so the service refuses the
    same foreign ancestor/final-file mutation authority BEFORE execution."""
    plan = [
        (m.root, "private", True, True, False),
        (m.state, "private", True, False, False),
        (m.path, "private", False, False, False),
        (m.guardian, "private", False, False, False),
        (m.native_api, "private", False, False, False),
        (m.policy, "private", False, False, False),
        (m.config, "private", False, False, False),
    ]
    for p in m.pins:
        if p.casefold() in {s.casefold() for s in (m.guardian, m.native_api, m.policy, m.config)}:
            continue
        plan.append((p, "file", False, False, is_servicing_image(p)))
    b = m.config_bindings
    for key in ("hostKey", "authorizedKeys", "backendConfig"):
        plan.append((b[key], "private", False, False, False))
    for key in ("sftp", "backendExecutable", "backendDLL"):
        plan.append((b[key], "file", False, False, False))
    for key in SETENV_DIRECTORIES:
        plan.append((ntpath.normpath(b["setEnv"][key]), "private", True, False, False))
    for key in ("TEMP", "TMP"):
        plan.append((ntpath.normpath(m.environment[key]), "private", True, False, False))
    seen, unique = set(), []
    for row in plan:
        if (row[0].casefold(), row[1]) not in seen:
            seen.add((row[0].casefold(), row[1]))
            unique.append(row)
    return unique


# --- protocol files (generation base) -------------------------------------------------


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


@dataclass(frozen=True)
class Current:
    generation: str  # absolute generation directory
    ready: str  # absolute READY.json
    manifest_sha256: str

    def file(self, name: str) -> str:
        return ntpath.join(self.generation, name)


def parse_current(data: bytes, m: GuardianManifest) -> Current:
    """CURRENT.json = exactly {version:1, generation, ready, manifestSHA256};
    generation must be a direct ``generation-<32 hex>`` child of the state
    base and ready exactly its READY.json; bound to this manifest."""
    c = _json_object(data, "CURRENT.json")
    if set(c) != {"version", "generation", "ready", "manifestSHA256"} or c.get("version") != 1:
        raise ServiceError("CURRENT.json: exactly {version:1, generation, ready, manifestSHA256} required")
    try:
        generation = _absolute(c["generation"], "CURRENT.generation")
        ready = _absolute(c["ready"], "CURRENT.ready")
    except ServiceError as exc:
        raise ServiceError(f"CURRENT.json: {exc}") from None
    if ntpath.dirname(generation).casefold() != m.state.casefold() or not GENERATION_DIR_RE.fullmatch(
        ntpath.basename(generation)
    ):
        raise ServiceError("CURRENT.json: generation is not a generation-<uuidhex> child of the state base")
    if ready.casefold() != ntpath.join(generation, "READY.json").casefold():
        raise ServiceError("CURRENT.json: ready is not that generation's READY.json")
    if c["manifestSHA256"] != m.sha256:
        raise ServiceError("CURRENT.json belongs to a different manifest")
    return Current(generation, ready, c["manifestSHA256"])


def desktop_acl_ok(acl, owner_sid: str) -> bool:
    """native_api.verify_desktop_acl's result schema, exactly (cab601e2): the
    guardian returns it only after checking owner, PROTECTED DACL, exactly
    three type-0 flags-0 ACEs with GENERIC_ALL/0xF01FF masks for exactly
    {SYSTEM, Administrators, owner}. (The masks are verified by the guardian
    but not published; see the agreement.)"""
    return (
        isinstance(acl, dict)
        and set(acl) == {"ownerSID", "protectedDACL", "allowTrustees", "ACECount"}
        and acl["ownerSID"] == owner_sid
        and acl["protectedDACL"] is True
        and acl["allowTrustees"] == sorted([owner_sid, "S-1-5-18", "S-1-5-32-544"])
        and type(acl["ACECount"]) is int and acl["ACECount"] == 3
    )


CLOSED_IDENTITY = ("pid", "creationFILETIME", "manifestSHA256", "privateDesktop", "guardianPID",
                   "sourceSHA256", "desktopACL")


def closed_identity_problems(data: bytes, ready: "Ready") -> list:
    """CLOSED.json serializes the SAME retained result dictionary as READY,
    so it must carry exactly the generation's held identity: daemon pid,
    decimal creationFILETIME string, manifestSHA256, privateDesktop,
    guardianPID, sourceSHA256 and desktopACL (types included)."""
    closed = _json_object(data, "CLOSED.json")
    # strict schema/types first (1 is not True, 3.0 is not 3), then exact equality
    if not desktop_acl_ok(closed.get("desktopACL"), ready.desktop_acl.get("ownerSID")):
        return ["CLOSED.json desktopACL is not the guardian's exact desktopACL schema (strict types)"]
    expected = {"pid": ready.pid, "creationFILETIME": ready.birth, "manifestSHA256": ready.manifest_sha256,
                "privateDesktop": ready.private_desktop, "guardianPID": ready.guardian_pid,
                "sourceSHA256": ready.source_sha256, "desktopACL": ready.desktop_acl}
    wrong = [k for k in CLOSED_IDENTITY if closed.get(k) != expected[k]
             or type(closed.get(k)) is not type(expected[k])]
    return [f"CLOSED.json {', '.join(wrong)} does not match the READY identity"] if wrong else []


GUARDIAN_IDENTITY = "pid+image only (READY carries no guardian birth); diagnostic, not stop authority"
STOP_AUTHORITY = "held daemon pid + creationFILETIME"


@dataclass(frozen=True)
class Ready:
    pid: int
    birth: str
    guardian_pid: int
    port: int
    manifest_sha256: str
    source_sha256: str
    station: str
    private_desktop: str
    desktop_acl: dict = field(default_factory=dict, hash=False, compare=False)
    mode: str = "s4u-session0"
    session: int = 0


MODE_S4U = "s4u-session0"
MODE_ACTIVE_CONSOLE = "active-console"


def parse_ready(data: bytes, m: GuardianManifest, *, mode: str = MODE_S4U,
                session: Optional[int] = None) -> Ready:
    """READY.json as the 6cf7ae85 guardian publishes it, with every fact the
    production (S4U) readiness depends on REQUIRED:

    held daemon pid (int, not bool) + decimal STRING creationFILETIME,
    guardianPID, manifestSHA256 and port of this manifest, sourceSHA256 of the
    pinned guardian.py (mandatory), heldProcessHandle and ownedJob true, and
    the context the guardian validated: ownerSID = manifest owner, session 0,
    a NON-visible station other than WinSta0, the private desktop created on
    that station, and its checked desktop ACL. The guardian's interactive
    (active console WinSta0/Default) branch is a qualification fallback, never
    readiness of the scheduled task.
    """
    r = _json_object(data, "READY.json")

    def require(ok: bool, what: str) -> None:
        if not ok:
            raise ServiceError(f"READY.json: {what}")

    require(type(r.get("pid")) is int and r["pid"] > 0, "pid must be a positive integer")
    require(type(r.get("guardianPID")) is int and r["guardianPID"] > 0, "guardianPID must be a positive integer")
    require(isinstance(r.get("creationFILETIME"), str) and bool(FILETIME_RE.fullmatch(r["creationFILETIME"])),
            "creationFILETIME must be a decimal STRING")
    require(r.get("manifestSHA256") == m.sha256, "belongs to a different manifest")
    require(type(r.get("port")) is int and r["port"] == m.port, "port differs from the manifest")
    require(r.get("sourceSHA256") == m.pins[m.guardian], "sourceSHA256 is missing or not the pinned guardian.py")
    require(r.get("heldProcessHandle") is True, "heldProcessHandle is not true")
    require(r.get("ownedJob") is True, "ownedJob is not true")
    c = r.get("context")
    require(isinstance(c, dict), "context is missing")
    require(c.get("ownerSID") == m.owner_sid, "context.ownerSID is not the manifest owner")
    station = c.get("station")
    if mode == MODE_S4U:
        require(type(c.get("session")) is int and c["session"] == 0, "context.session is not 0 (not the S4U task)")
        require(c.get("stationVisible") is False, "context.stationVisible is not false")
        require(isinstance(station, str) and bool(station) and not any(x in station for x in "\\/\x00\r\n")
                and station.casefold() != "winsta0", "context.station is not an actual non-WinSta0 station")
    elif mode == MODE_ACTIVE_CONSOLE:
        # The ordinary-user mode: the guardian's validated interactive branch,
        # captured AT LAUNCH (own SID, the caller's session, the active console
        # session, the visible WinSta0 station, thread desktop Default). The
        # CURRENT input desktop is never consulted: locking switches it to
        # Winlogon and the endpoint stays online.
        require(type(session) is int and session > 0, "the caller's session is unknown")
        require(type(c.get("session")) is int and c["session"] == session and c["session"] != 0,
                "context.session is not the caller's (non-zero) session")
        require(type(c.get("activeConsoleSession")) is int and c["activeConsoleSession"] == c["session"],
                "context.session was not the active console session at launch")
        require(station == "WinSta0", "context.station is not WinSta0")
        require(c.get("stationVisible") is True, "context.stationVisible is not true (visible WinSta0)")
        require(c.get("desktop") == "Default", "context.desktop at launch is not Default")
    else:
        raise ServiceError(f"unknown readiness mode {mode!r}")
    desktop = r.get("privateDesktop")
    require(isinstance(desktop, str) and desktop.startswith(station + "\\")
            and bool(re.fullmatch(r"PocketShellPrivate_[0-9a-f]{32}", desktop[len(station) + 1:])),
            "privateDesktop is not <station>\\PocketShellPrivate_<uuid hex> on the guardian's own station")
    require(desktop_acl_ok(r.get("desktopACL"), m.owner_sid),
            "desktopACL is not the guardian's checked private-desktop ACL "
            "{ownerSID: manifest owner, protectedDACL: true, allowTrustees: sorted [own, SYSTEM, "
            "Administrators], ACECount: 3}")
    return Ready(r["pid"], r["creationFILETIME"], r["guardianPID"], r["port"], r["manifestSHA256"],
                 r["sourceSHA256"], station, desktop, dict(r["desktopACL"]), mode, c["session"])


def stop_request(ready: Ready) -> bytes:
    """The exact STOP.json body (policy.validate_stop: these four keys only)."""
    body = {
        "pid": ready.pid,
        "creationFILETIME": ready.birth,
        "manifestSHA256": ready.manifest_sha256,
        "stopOwnedJob": True,
    }
    data = json.dumps(body, sort_keys=True).encode("utf-8")
    assert len(data) <= MAX_STOP_BYTES
    return data


def closed_accepted(data: bytes) -> tuple:
    # (accepted, detail); the caller also verifies identity and listener absence
    """(accepted, detail) from CLOSED.json: accepted AND requestedOwnedJobStop
    AND activeAtClose == 0 AND no cleanupErrors."""
    closed = _json_object(data, "CLOSED.json")
    ok = (
        closed.get("accepted") is True
        and closed.get("requestedOwnedJobStop") is True
        and closed.get("activeAtClose") == 0
        and closed.get("cleanupErrors") == []
    )
    detail = closed.get("failure") or closed.get("cleanupErrors") or {
        k: closed.get(k) for k in ("accepted", "requestedOwnedJobStop", "activeAtClose")
    }
    return ok, sanitize(str(detail), 300)
