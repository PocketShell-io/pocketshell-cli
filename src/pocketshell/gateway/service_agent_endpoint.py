"""Setup ABI v3 (Option B): the generic per-host endpoint, generated at install.

Frozen contract: generic-per-host-manifest-design/setup-abi-v3.md revision B
(f41c5f01…), bilaterally ACKed with the Fleet consumer. The release ships the
endpoint binaries as catalog v3 roles (sshd, sftp, backend-shell, backend-dll
plus modules), so one build serves every ordinary user. Everything host-specific
is MEASURED here and recorded once:

* port, device, server and the pinned host-key line come from the catalog
  helper's ``show``;
* allowUser is the native token account;
* the host-key and authorized_keys files are referenced by path. They are
  measured by metadata only (owner-only, single link, no reparse) and are NEVER
  opened for read.

The generated sshd.conf, aplexer.toml and endpoint-manifest.json (guardian
6cf7ae85 schema) live in ``<userData>\\managed-runtime\\endpoint``. The receipt
v3 ``endpoint`` block records the manifest's sha256. Trust at bind and start is
anchored on that record (service_endpoint.check_trust_authority), never on a
compiled per-host digest.
"""

from __future__ import annotations

import hashlib
import json
import ntpath
import re
import time

from pocketshell.gateway import pins as gateway_pins
from pocketshell.gateway.service_agent_install import (
    DEVICE_RE, ENDPOINT_ROLES, SERVER_RE, SID_RE, VERIFIER, InstallError, _abs, _copy_release, _same,
    _verify_staged, parse_catalog, role_file,
)
from pocketshell.gateway.service_common import ServiceError, parse_show, sanitize

RECEIPT_VERSION = 3
INPUTS_VERSION = 1
MAX_INPUTS = 64 * 1024
ENDPOINT_DIR = "endpoint"
MANIFEST_NAME = "endpoint-manifest.json"
CONFIG_NAME = "sshd.conf"
BACKEND_CONFIG_NAME = "aplexer.toml"
ACCOUNT_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
# characters that would need quoting in sshd_config / shlex (never generated)
_UNQUOTABLE = re.compile(r"[\s\"'#\\$`=,]")
BACKEND_DIRS = {"APLEXER_RUNTIME_DIR": "runtime", "APLEXER_STATE_DIR": "state", "XDG_CONFIG_HOME": "xdg-config",
                "XDG_STATE_HOME": "xdg-state", "XDG_DATA_HOME": "xdg-data", "XDG_CACHE_HOME": "xdg-cache"}


def layout(user_data: str, release: str) -> dict:
    """The fixed generated paths (agreed: manifest.root = managed-runtime)."""
    root = ntpath.join(user_data, "managed-runtime")
    ep = ntpath.join(root, ENDPOINT_DIR)
    state = ntpath.join(ep, "state")
    return {"root": root, "release": ntpath.join(root, "releases", release), "tmp": ntpath.join(root, "tmp"),
            "endpoint": ep, "manifest": ntpath.join(ep, MANIFEST_NAME), "config": ntpath.join(ep, CONFIG_NAME),
            "backendConfig": ntpath.join(ep, BACKEND_CONFIG_NAME), "state": state,
            "stateTmp": ntpath.join(state, "tmp"), "pidFile": ntpath.join(state, "sshd.pid"),
            "backend": ntpath.join(ep, "backend")}


def parse_endpoint_inputs(data: bytes) -> dict:
    """The PUBLIC inputs: exactly {version:1, hostKey, authorizedKeys} (paths only)."""
    bad = InstallError("endpoint-inputs", "endpoint inputs must be exactly {version:1, hostKey, authorizedKeys} "
                       "with plain drive-absolute paths")
    if not isinstance(data, (bytes, bytearray)) or len(data) > MAX_INPUTS:
        raise bad
    try:
        d = json.loads(bytes(data).decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise bad from None
    if not isinstance(d, dict) or set(d) != {"version", "hostKey", "authorizedKeys"} \
            or d["version"] != INPUTS_VERSION or type(d["version"]) is not int:
        raise bad
    for key in ("hostKey", "authorizedKeys"):
        if not _abs(d[key]):
            raise bad
    if _same(d["hostKey"], d["authorizedKeys"]):
        raise bad
    return {"hostKey": ntpath.normpath(d["hostKey"]), "authorizedKeys": ntpath.normpath(d["authorizedKeys"])}


def _fw(path: str) -> str:
    """The generated (unquoted, shlex/sshd-literal) form: forward slashes."""
    value = ntpath.normpath(path).replace("\\", "/")
    if _UNQUOTABLE.search(value.replace("/", "")[2:]) or not value.isascii():
        raise InstallError("endpoint-layout", f"{sanitize(path, 200)} contains characters the generated sshd "
                           "config cannot carry unquoted (whitespace, quotes, $, =, ',', non-ASCII)")
    return value


def _measured_show(show_text: str) -> dict:
    fields = parse_show(show_text or "")
    server, device = fields.get("server") or "", fields.get("device id") or ""
    local = (fields.get("local ssh") or "").split()
    m = re.fullmatch(r"127\.0\.0\.1:([0-9]{4,5})", local[0]) if local else None
    try:
        key = gateway_pins.parse_host_key(fields.get("pinned ssh host key", ""))
    except gateway_pins.PinError:
        key = None
    if not SERVER_RE.match(server) or not DEVICE_RE.match(device) or not m or key is None \
            or not 1024 <= int(m.group(1)) <= 65535:
        raise InstallError("binding-mismatch", "the catalog helper's show does not report an enrolled device "
                           "(public wss server, device id, loopback local ssh port, pinned ssh host key)")
    return {"server": server, "deviceId": device, "port": int(m.group(1)), "hostKeyFingerprint": key.fingerprint}


def _system_environment(folders: dict) -> dict:
    sd, sr, pd = folders.get("SystemDrive"), folders.get("SystemRoot") or "", folders.get("ProgramData") or ""
    if sd != "C:" or ntpath.normcase(ntpath.normpath(sr)) != "c:\\windows" \
            or ntpath.normcase(ntpath.normpath(pd)) != "c:\\programdata":
        raise InstallError("environment", "the reviewed guardian requires SystemDrive C:, SystemRoot C:\\Windows "
                           "and ProgramData C:\\ProgramData")
    for key in ("USERPROFILE", "LOCALAPPDATA"):
        if not _abs(folders.get(key)):
            raise InstallError("environment", f"{key} is not a plain drive-absolute path")
    return folders


def generate(*, lay: dict, catalog: dict, owner_sid: str, account: str, port: int, inputs: dict,
             folders: dict) -> dict:
    """The exact generated bytes {config, backendConfig, manifest} (pure)."""
    rel = lay["release"]

    def role(name):
        return ntpath.join(rel, *role_file(catalog, name)["path"].split("/"))

    backend_dirs = {k: _fw(ntpath.join(lay["backend"], v)) for k, v in BACKEND_DIRS.items()}
    set_env = {"APLEXER_CONFIG": _fw(lay["backendConfig"]), "APLEXER_RUN_IN_PLACE": "1", "APLEXER_SHELL": "",
               "BASH_ENV": "", "ENV": "", "ZDOTDIR": "", **backend_dirs}
    bindings = {"hostKey": _fw(inputs["hostKey"]), "authorizedKeys": _fw(inputs["authorizedKeys"]),
                "pidFile": _fw(lay["pidFile"]), "allowUser": account, "sftp": _fw(role("sftp")),
                "backendConfig": _fw(lay["backendConfig"]), "backendExecutable": _fw(role("backend-shell")),
                "backendDLL": _fw(role("backend-dll")), "setEnv": set_env}
    config = "\n".join([
        "# generated by pocketshell gateway agent install (setup ABI v3); do not edit",
        f"Port {port}", "ListenAddress 127.0.0.1", f"HostKey {bindings['hostKey']}",
        f"AuthorizedKeysFile {bindings['authorizedKeys']}", f"PidFile {bindings['pidFile']}",
        "AuthenticationMethods publickey", "PubkeyAuthentication yes", "PasswordAuthentication no",
        "KbdInteractiveAuthentication no", "PermitEmptyPasswords no", f"AllowUsers {account}",
        "DisableForwarding yes", "PermitTTY yes", f"Subsystem sftp {bindings['sftp']}",
        "SetEnv " + " ".join(f"{k}={v}" for k, v in sorted(set_env.items())), "",
    ]).encode("ascii")
    backend = ("# generated by pocketshell gateway agent install (setup ABI v3); do not edit\n"
               "[engines.shell]\n"
               f"command = {json.dumps([bindings['backendExecutable'], '--noprofile', '--norc', '-i'])}\n"
               'env_unset = ["BASH_ENV", "ENV", "ZDOTDIR"]\n').encode("ascii")
    pins = {}
    for f in catalog["files"]:
        if f["path"].startswith("endpoint/") or f["role"] in ("interpreter", "guardian", "native-api", "policy"):
            pins[ntpath.join(rel, *f["path"].split("/"))] = f["sha256"]
    pins[lay["config"]] = hashlib.sha256(config).hexdigest()
    pins[lay["backendConfig"]] = hashlib.sha256(backend).hexdigest()
    manifest = {
        "version": 1, "ownerSID": owner_sid, "root": lay["root"], "state": lay["state"], "config": lay["config"],
        "port": port, "daemon": role("sshd"), "python": role("interpreter"), "pins": pins,
        "environment": {"SystemRoot": "C:/Windows", "WINDIR": "C:/Windows", "SystemDrive": "C:",
                        "ProgramData": "C:/ProgramData", "USERPROFILE": folders["USERPROFILE"],
                        "HOME": folders["USERPROFILE"], "TEMP": lay["stateTmp"], "TMP": lay["stateTmp"]},
        "configBindings": bindings,
    }
    return {"config": config, "backendConfig": backend,
            "manifest": json.dumps(manifest, indent=1, sort_keys=True).encode("utf-8")}


def local_account(owner_sid: str) -> str:
    """The token account's sshd AllowUsers name: a LOCAL account (its domain is
    this computer), lower-cased as Win32-OpenSSH matches it. Measured from the
    SID by LookupAccountSidW, never from the environment."""
    import ctypes as c
    from ctypes import wintypes as w

    adv = c.WinDLL("advapi32", use_last_error=True)
    k = c.WinDLL("kernel32", use_last_error=True)
    sid = c.c_void_p()
    if not adv.ConvertStringSidToSidW(w.LPCWSTR(owner_sid), c.byref(sid)):
        raise c.WinError(c.get_last_error())
    try:
        name, domain = c.create_unicode_buffer(257), c.create_unicode_buffer(257)
        n, d, use = w.DWORD(257), w.DWORD(257), w.DWORD()
        if not adv.LookupAccountSidW(None, sid, name, c.byref(n), domain, c.byref(d), c.byref(use)):
            raise c.WinError(c.get_last_error())
    finally:
        k.LocalFree(sid)
    computer, size = c.create_unicode_buffer(257), w.DWORD(257)
    if not k.GetComputerNameW(computer, c.byref(size)):
        raise c.WinError(c.get_last_error())
    if use.value != 1 or domain.value.casefold() != computer.value.casefold():
        raise InstallError("environment", "the ordinary endpoint serves a LOCAL account only (the token's "
                           "account domain is not this computer)")
    return name.value.lower()


def install_endpoint_runtime(*, user_data: str, catalog_path: str, staged: str, config_dir: str,
                             endpoint_inputs: bytes, owner_sid: str, account: str, show_text: str,
                             helper_sha256: str, paths, folders: dict, cli_version: str, dry_run: bool = False,
                             now=None) -> dict:
    """Install FIRST (no prior bind). Verify, copy, measure, generate, and
    commit authority.json (receipt v3) last. ``show_text`` is the CATALOG
    helper's ``show --config-dir <config_dir>`` (the caller runs it)."""
    from pocketshell.gateway import service_endpoint as ep

    for name, value in (("--user-data", user_data), ("--catalog", catalog_path), ("--staged", staged),
                        ("--config-dir", config_dir)):
        if not _abs(value):
            raise InstallError("usage", f"{name} must be an absolute local path")
    if not SID_RE.match(owner_sid or ""):
        raise InstallError("binding-mismatch", "not an own-account SID")
    if not ACCOUNT_RE.match(account or ""):
        raise InstallError("environment", "the account name cannot be an sshd AllowUsers entry")
    inputs = parse_endpoint_inputs(endpoint_inputs)
    try:
        cat = paths.file(catalog_path, owner_sid, private=False, max_bytes=64 * 1024,
                         root=ntpath.dirname(catalog_path))
    except Exception as exc:  # noqa: BLE001
        raise InstallError("catalog-invalid", f"cannot read the catalog: {sanitize(str(exc), 300)}") from None
    if cat["bytes"] is None:
        raise InstallError("catalog-invalid", "the catalog is larger than 64 KiB")
    catalog = parse_catalog(cat["bytes"])
    if catalog["version"] != 3:
        raise InstallError("catalog-invalid", "setup ABI v3 needs a catalog v3 (endpoint roles)")
    if catalog["lineage"]["cliVersion"] != cli_version:
        raise InstallError("catalog-mismatch", f"this CLI is {cli_version}; the catalog is release "
                           f"{catalog['lineage']['cliVersion']}")
    if helper_sha256 != role_file(catalog, "helper")["sha256"]:
        raise InstallError("binding-mismatch", "the show output must come from this catalog's own helper")
    folders = _system_environment(folders)
    measured = _measured_show(show_text)

    # existing enrollment + the key files: measured, never read, never re-ACLed
    try:
        if not _same(paths.directory(config_dir, owner_sid, private_root=config_dir), config_dir):
            raise ServiceError("not the requested directory")
    except Exception as exc:  # noqa: BLE001
        raise InstallError("binding-mismatch", f"the enrolled config dir is not an owner-only protected private "
                           f"root ({sanitize(str(exc), 200)}); the installer never changes its ACL") from None
    for label in ("hostKey", "authorizedKeys"):
        target = inputs[label]
        try:
            paths.metadata(target, owner_sid)
        except Exception as exc:  # noqa: BLE001
            raise InstallError("endpoint-inputs", f"{label} {sanitize(target, 200)} is not an owner-protected "
                               f"single-link regular file ({sanitize(str(exc), 200)}); it is never read or "
                               "re-ACLed") from None

    blobs, want = _verify_staged(staged, catalog, owner_sid, paths)
    for role in ENDPOINT_ROLES:
        role_file(catalog, role)
    lay = layout(user_data, catalog["release"])
    generated = generate(lay=lay, catalog=catalog, owner_sid=owner_sid, account=account, port=measured["port"],
                         inputs=inputs, folders=folders)
    if len(generated["manifest"]) > ep.MAX_MANIFEST_BYTES:
        raise InstallError("endpoint-layout", "the generated manifest exceeds the guardian's 64 KiB bound")
    m = ep.parse_manifest(generated["manifest"], lay["manifest"])  # the guardian's own schema rules
    ep.config_guard(generated["config"].decode("ascii"), m)
    manifest_sha = hashlib.sha256(generated["manifest"]).hexdigest()
    env = {k: folders[k] for k in ("SystemDrive", "SystemRoot", "ProgramData", "USERPROFILE", "LOCALAPPDATA")}
    env.update(TEMP=lay["tmp"], TMP=lay["tmp"])
    receipt = {
        "version": RECEIPT_VERSION, "release": catalog["release"], "catalogSHA256": cat["sha256"],
        "ownerSid": owner_sid,
        "binding": {"deviceId": measured["deviceId"], "manifest": lay["manifest"], "manifestSHA256": manifest_sha,
                    "configDir": ntpath.normpath(config_dir), "port": measured["port"],
                    "hostKeyFingerprint": measured["hostKeyFingerprint"], "server": measured["server"]},
        "environment": env,
        "location": {"root": lay["root"], "ownerSid": owner_sid, "protectedDACL": True,
                     "allowTrustees": [owner_sid], "reparseFree": True, "verifier": VERIFIER},
        "installer": {"cliVersion": cli_version, "cliCommit": catalog["source"],
                      "installedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))},
        "endpoint": {"root": lay["root"], "manifest": lay["manifest"], "manifestSHA256": manifest_sha,
                     "config": lay["config"], "state": lay["state"]},
    }
    if dry_run:
        return receipt

    _copy_release(lay["root"], lay["release"], lay["tmp"], blobs, want, catalog, owner_sid, paths)
    for folder in (lay["endpoint"], lay["state"], lay["stateTmp"], lay["backend"],
                   *(ntpath.join(lay["backend"], v) for v in BACKEND_DIRS.values())):
        paths.mkdir(folder)
    for key in ("config", "backendConfig", "manifest"):
        paths.write(lay[key], generated[key])
    for key in ("config", "backendConfig", "manifest"):
        got = paths.file(lay[key], owner_sid, private=True, max_bytes=0, private_root=lay["root"])
        if got["sha256"] != hashlib.sha256(generated[key]).hexdigest():
            raise InstallError("install-failed", f"the generated {key} did not land intact")
    for folder in (lay["endpoint"], lay["state"], lay["stateTmp"],
                   *(ntpath.join(lay["backend"], v) for v in BACKEND_DIRS.values())):
        if not _same(paths.directory(folder, owner_sid, private_root=lay["root"]), folder):
            raise InstallError("install-failed", f"{folder} is not the protected directory")
    paths.write(ntpath.join(lay["root"], "authority.json"), json.dumps(receipt, indent=1).encode("utf-8"))
    return receipt
