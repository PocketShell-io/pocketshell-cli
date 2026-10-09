"""ordinary-v2 producer: the installed-runtime authority (agreement v3, §10).

``gateway agent verify-paths`` is the trusted native path verifier the Desktop
consumer calls instead of shelling out to ACL tools. ``gateway agent install``
copies a catalogued release closure into ``<userData>\\managed-runtime`` with
the private (protected, owner-only, reparse-free) shape and writes the
public-only receipt ``authority.json``. Neither starts, enrolls, nor reads a
credential. PROPOSED schema: the JSON-v1 agent wire API is unchanged.
"""

from __future__ import annotations

import base64
import hashlib
import json
import ntpath
import re
import sys
import time
from typing import Optional

from pocketshell.gateway.service_common import ServiceError, sanitize

CATALOG_VERSION = 2
RECEIPT_VERSION = 2
VERIFY_VERSION = 1
API_NAME = "ordinary-v2"
PLATFORM = "win32-x64"
VERIFIER = "pocketshell gateway agent verify-paths"
GUARDIAN_ABI = "6cf7ae85"
SINGLE_ROLES = ("cli", "interpreter", "guardian", "native-api", "policy", "helper")
ROLES = (*SINGLE_ROLES, "module")
MAX_DOC = 1024 * 1024
MAX_FILE = 256 * 1024 * 1024
MAX_FILES = 4096
ENV_KEYS = ("SystemDrive", "SystemRoot", "ProgramData", "USERPROFILE", "LOCALAPPDATA", "TEMP", "TMP")

SHA_RE = re.compile(r"^[a-f0-9]{64}$")
COMMIT_RE = re.compile(r"^[a-f0-9]{40}$")
RELEASE_RE = re.compile(r"^[A-Za-z0-9_-]{1,80}$")
REL_RE = re.compile(r"^[A-Za-z0-9_.\-]+(/[A-Za-z0-9_.\-]+)*$")
SID_RE = re.compile(r"^S-1-5-21-[0-9]+(-[0-9]+){3}$")
DEVICE_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
SERVER_RE = re.compile(r"^wss://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+([.+-][A-Za-z0-9.]+)?$")


class InstallError(ServiceError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _exact(obj, keys) -> bool:
    return isinstance(obj, dict) and sorted(obj) == sorted(keys)


def _abs(path) -> bool:
    return isinstance(path, str) and re.match(r"^[A-Za-z]:[\\/]", path) is not None and "\0" not in path \
        and ":" not in path[2:] and not any(p in ("..", ".") or p.endswith((".", " "))
                                            for p in re.split(r"[\\/]", path[3:]) if p)


def _same(a: str, b: str) -> bool:
    return ntpath.normcase(ntpath.normpath(a)) == ntpath.normcase(ntpath.normpath(b))


# --- catalog v2 ------------------------------------------------------------------------


def parse_catalog(data: bytes) -> dict:
    """Validate catalog v2 (schema + cross-field rules); return it."""
    if len(data) > MAX_DOC:
        raise InstallError("catalog-invalid", "the catalog is larger than 1 MiB")
    try:
        c = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise InstallError("catalog-invalid", "the catalog is not UTF-8 JSON") from None
    bad = lambda why: InstallError("catalog-invalid", f"catalog: {why}")  # noqa: E731
    if not _exact(c, ["version", "release", "source", "platform", "api", "lineage", "files"]):
        raise bad("keys must be exactly version, release, source, platform, api, lineage, files")
    if c["version"] != CATALOG_VERSION or c["platform"] != PLATFORM or c["api"] != API_NAME:
        raise bad(f"version/platform/api must be {CATALOG_VERSION}/{PLATFORM}/{API_NAME}")
    if not isinstance(c["release"], str) or not RELEASE_RE.match(c["release"]):
        raise bad("release")
    if not isinstance(c["source"], str) or not COMMIT_RE.match(c["source"]):
        raise bad("source must be a 40-hex commit")
    lin = c["lineage"]
    if not _exact(lin, ["cliVersion", "cliCommit", "agentApi", "guardian", "nativeApi", "policy", "interpreter",
                        "helper", "lockSHA256"]):
        raise bad("lineage keys")
    if not isinstance(lin["cliVersion"], str) or not VERSION_RE.match(lin["cliVersion"]) \
            or lin["cliCommit"] != c["source"] or lin["agentApi"] != 1:
        raise bad("lineage cliVersion/cliCommit/agentApi")
    if not _exact(lin["guardian"], ["abi", "sourceSHA256"]) or lin["guardian"]["abi"] != GUARDIAN_ABI \
            or not _exact(lin["nativeApi"], ["sourceSHA256"]) \
            or not _exact(lin["policy"], ["version", "sourceSHA256"]) \
            or type(lin["policy"]["version"]) is not int or lin["policy"]["version"] < 1 \
            or not _exact(lin["interpreter"], ["distribution", "version", "sha256"]) \
            or lin["interpreter"]["distribution"] != "python-build-standalone" \
            or not re.match(r"^3\.[0-9]+\.[0-9]+$", str(lin["interpreter"]["version"])) \
            or not _exact(lin["helper"], ["version", "sha256"]) \
            or not isinstance(lin["helper"]["version"], str) or not 0 < len(lin["helper"]["version"]) <= 64 \
            or not isinstance(lin["lockSHA256"], str) or not SHA_RE.match(lin["lockSHA256"]):
        raise bad("lineage pins")
    files = c["files"]
    if not isinstance(files, list) or not 7 <= len(files) <= MAX_FILES:
        raise bad("files must list 7..4096 entries")
    seen, roles = set(), {}
    for f in files:
        if not _exact(f, ["path", "sha256", "role"]) or not isinstance(f["path"], str) \
                or not REL_RE.match(f["path"]) or any(p in (".", "..") or p.endswith(".")
                                                      for p in f["path"].split("/")) \
                or not isinstance(f["sha256"], str) or not SHA_RE.match(f["sha256"]) or f["role"] not in ROLES:
            raise bad(f"file entry {sanitize(str(f), 120)}")
        key = f["path"].lower()
        if key in seen:
            raise bad(f"case-colliding path {f['path']}")
        seen.add(key)
        if f["role"] != "module" and f["role"] in roles:
            raise bad(f"more than one {f['role']}")
        roles.setdefault(f["role"], f)
    for role in ROLES:
        if role not in roles:
            raise bad(f"no {role} file")
    pins = {"guardian": lin["guardian"]["sourceSHA256"], "native-api": lin["nativeApi"]["sourceSHA256"],
            "policy": lin["policy"]["sourceSHA256"], "interpreter": lin["interpreter"]["sha256"],
            "helper": lin["helper"]["sha256"]}
    for role, sha in pins.items():
        if roles[role]["sha256"] != sha:
            raise bad(f"lineage {role} pin does not match its file entry")
    return c


def role_file(catalog: dict, role: str) -> dict:
    return next(f for f in catalog["files"] if f["role"] == role)


# --- native verifier (Windows) -----------------------------------------------------------


class NativePaths:
    """Handle-based checks built on the private store (windows_security) and
    the guardian-mirrored ancestor authority (WindowsApi._check_acl)."""

    def __init__(self, api):
        self.api = api

    def _ancestors(self, path: str, owner_sid: str) -> None:
        import pathlib

        for parent in reversed(pathlib.PureWindowsPath(path).parents):
            self.api._check_acl(str(parent), owner_sid, "ancestor")

    @staticmethod
    def _pinned(path, *, private_leaf: bool):
        """Open every directory component of ``path`` by handle (list access,
        no delete sharing: pinned against rename/replace while held), refuse
        reparse points, and require the private shape on ``path`` itself when
        ``private_leaf``. Returns the handles (caller closes)."""
        from pathlib import Path

        from pocketshell import windows_security as ws

        handles, current = [], Path(path.anchor)
        try:
            for part in (None, *path.parts[1:]):
                if part is not None:
                    current /= part
                handle = ws._open(current, directory=True, access=0x20081)
                handles.append(handle)
                ws._check(handle, directory=True, private=private_leaf and current == path)
            return handles
        except BaseException:
            for handle in reversed(handles):
                ws.CloseHandle(handle)
            raise

    @staticmethod
    def _close(handles) -> None:
        from pocketshell import windows_security as ws

        for handle in reversed(handles):
            ws.CloseHandle(handle)

    @staticmethod
    def _final(handle) -> Optional[str]:
        import ctypes as c
        from ctypes import wintypes as w

        k = c.WinDLL("kernel32", use_last_error=True)
        k.GetFinalPathNameByHandleW.argtypes = [w.HANDLE, w.LPWSTR, w.DWORD, w.DWORD]
        buf = c.create_unicode_buffer(32768)
        n = k.GetFinalPathNameByHandleW(handle, buf, 32768, 0)
        if not n or n >= 32768:
            return None
        value = buf.value
        return value[4:] if value.startswith("\\\\?\\") else value

    def file(self, path: str, owner_sid: str, *, private: bool, max_bytes: int) -> dict:
        import os
        from pathlib import Path

        from pocketshell import windows_security as ws

        p = ws._path(Path(path))
        self._ancestors(str(p), owner_sid)
        pinned = self._pinned(p.parent, private_leaf=private)
        try:
            handle = ws._open(p)
            try:
                ws._check(handle, directory=False, private=private)
                canonical = self._final(handle)
                import msvcrt

                fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
                handle = None  # the fd owns the SAME checked handle
                digest, size, head = hashlib.sha256(), 0, bytearray()
                with os.fdopen(fd, "rb") as stream:
                    while True:
                        chunk = stream.read(1 << 20)
                        if not chunk:
                            break
                        size += len(chunk)
                        if size > MAX_FILE:
                            raise ServiceError("file larger than 256 MiB")
                        digest.update(chunk)
                        if len(head) <= max_bytes:
                            head.extend(chunk)
            finally:
                if handle is not None:
                    ws.CloseHandle(handle)
        finally:
            self._close(pinned)
        return {"canonicalPath": canonical, "size": size, "sha256": digest.hexdigest(),
                "bytes": bytes(head) if size <= max_bytes else None}

    def directory(self, path: str, owner_sid: str) -> str:
        from pathlib import Path

        from pocketshell import windows_security as ws

        p = ws._path(Path(path))
        self._ancestors(str(p), owner_sid)
        pinned = self._pinned(p, private_leaf=True)
        try:
            return self._final(pinned[-1]) or str(p)
        finally:
            self._close(pinned)

    def inventory(self, path: str, owner_sid: str, *, private: bool = True) -> list:
        """Every regular file under a directory, by handle; any reparse entry
        refuses, and with ``private`` any non-private object refuses."""
        import os
        from pathlib import Path

        from pocketshell import windows_security as ws

        root = ws._path(Path(path))
        self._ancestors(str(root), owner_sid)
        out = []
        pinned = self._pinned(root, private_leaf=private)
        try:
            stack = [root]
            while stack:
                folder = stack.pop()
                with os.scandir(folder) as entries:
                    for entry in entries:
                        full = Path(entry.path)
                        attrs = entry.stat(follow_symlinks=False).st_file_attributes
                        if attrs & 0x400:
                            raise ServiceError(f"{sanitize(str(full))} is a reparse point")
                        directory = bool(attrs & 0x10)
                        handle = ws._open(full, directory=directory, access=0x20081 if directory else 0x80020000)
                        try:
                            ws._check(handle, directory=directory, private=private)
                        finally:
                            ws.CloseHandle(handle)
                        if directory:
                            stack.append(full)
                        else:
                            out.append(full.relative_to(root).as_posix())
        finally:
            self._close(pinned)
        if len(out) > MAX_FILES:
            raise ServiceError("more than 4096 files")
        return sorted(out)

    def write(self, path: str, data: bytes) -> None:
        from pathlib import Path

        from pocketshell import windows_security as ws

        ws.write_private(Path(path), data)

    def mkdir(self, path: str) -> None:
        from pathlib import Path

        from pocketshell import windows_security as ws

        with ws._directory(Path(path), create=True):
            pass


def known_folders() -> dict:
    """Measured native bindings (never inherited caller environment)."""
    import ctypes as c
    from ctypes import wintypes as w

    class GUID(c.Structure):
        _fields_ = [("a", w.DWORD), ("b", w.WORD), ("c", w.WORD), ("d", c.c_ubyte * 8)]

    def guid(text):
        h = text.replace("-", "")
        return GUID(int(h[0:8], 16), int(h[8:12], 16), int(h[12:16], 16),
                    (c.c_ubyte * 8)(*bytes.fromhex(h[16:])))

    shell = c.WinDLL("shell32")
    ole = c.WinDLL("ole32")
    shell.SHGetKnownFolderPath.argtypes = [c.POINTER(GUID), w.DWORD, w.HANDLE, c.POINTER(c.c_wchar_p)]
    ole.CoTaskMemFree.argtypes = [c.c_void_p]

    def folder(text):
        out = c.c_wchar_p()
        if shell.SHGetKnownFolderPath(c.byref(guid(text)), 0, None, c.byref(out)) != 0:
            raise ServiceError("cannot resolve a known folder")
        try:
            return out.value
        finally:
            ole.CoTaskMemFree(c.cast(out, c.c_void_p))

    k = c.WinDLL("kernel32")
    buf = c.create_unicode_buffer(260)
    k.GetSystemWindowsDirectoryW(buf, 260)
    return {"SystemRoot": buf.value, "SystemDrive": buf.value[:2],
            "ProgramData": folder("62AB5D82-FDC1-4DC3-A9DD-070D1D495D97"),
            "USERPROFILE": folder("5E6C858F-0E22-4760-9AFE-EA3317B67173"),
            "LOCALAPPDATA": folder("F1B32785-6FBA-4FCF-9D55-7B8E7F157091")}


# --- verify-paths -------------------------------------------------------------------------


def verify_paths(*, owner_sid: str, files=(), anchored=(), directories=(), inventories=(), max_bytes=MAX_DOC,
                 paths, current_sid: str) -> tuple:
    """(reply, exit code): 0 all ok, 1 refusal."""
    results = []
    if not SID_RE.match(owner_sid or "") or owner_sid != current_sid:
        return {"version": VERIFY_VERSION, "ownerSid": owner_sid, "ok": False, "results": [],
                "problem": "--owner-sid is not the measured current user"}, 1
    for path, private in [*((p, True) for p in files), *((p, False) for p in anchored)]:
        item = {"kind": "file", "path": path, "canonicalPath": None, "ok": False, "size": None, "sha256": None,
                "bytesBase64": None, "problem": None}
        try:
            if not _abs(path):
                raise ServiceError("not an absolute local path")
            got = paths.file(path, owner_sid, private=private, max_bytes=max_bytes)
            if not got["canonicalPath"] or not _same(got["canonicalPath"], path):
                raise ServiceError("the opened object is not the requested path")
            item.update(canonicalPath=got["canonicalPath"], size=got["size"], sha256=got["sha256"], ok=True,
                        bytesBase64=None if got["bytes"] is None else base64.b64encode(got["bytes"]).decode())
        except Exception as exc:  # noqa: BLE001 - every failure is a refusal
            item["problem"] = sanitize(str(exc) or type(exc).__name__, 600)
        results.append(item)
    for path in directories:
        item = {"kind": "directory", "path": path, "canonicalPath": None, "ok": False, "problem": None}
        try:
            if not _abs(path):
                raise ServiceError("not an absolute local path")
            canonical = paths.directory(path, owner_sid)
            if not _same(canonical, path):
                raise ServiceError("the opened directory is not the requested path")
            item.update(canonicalPath=canonical, ok=True)
        except Exception as exc:  # noqa: BLE001
            item["problem"] = sanitize(str(exc) or type(exc).__name__, 600)
        results.append(item)
    for path in inventories:
        item = {"kind": "inventory", "path": path, "ok": False, "files": [], "problem": None}
        try:
            if not _abs(path):
                raise ServiceError("not an absolute local path")
            item.update(files=paths.inventory(path, owner_sid), ok=True)
        except Exception as exc:  # noqa: BLE001
            item["problem"] = sanitize(str(exc) or type(exc).__name__, 600)
        results.append(item)
    ok = bool(results) and all(r["ok"] for r in results)
    return {"version": VERIFY_VERSION, "ownerSid": owner_sid, "ok": ok, "results": results}, 0 if ok else 1


# --- install -------------------------------------------------------------------------------


def install_runtime(*, user_data: str, catalog_path: str, staged: str, binding: dict, server: str,
                    owner_sid: str, paths, folders: dict, cli_version: str, dry_run: bool = False,
                    now=None) -> dict:
    """Verify, copy and record. ``binding`` is the EXISTING agent binding
    (already re-validated by the caller). Returns the receipt."""
    for name, value in (("--user-data", user_data), ("--catalog", catalog_path), ("--staged", staged)):
        if not _abs(value):
            raise InstallError("usage", f"{name} must be an absolute local path")
    try:
        cat = paths.file(catalog_path, owner_sid, private=False, max_bytes=MAX_DOC)
    except Exception as exc:  # noqa: BLE001
        raise InstallError("catalog-invalid", f"cannot read the catalog: {sanitize(str(exc), 300)}") from None
    if cat["bytes"] is None:
        raise InstallError("catalog-invalid", "the catalog is larger than 1 MiB")
    catalog = parse_catalog(cat["bytes"])
    if catalog["lineage"]["cliVersion"] != cli_version:
        raise InstallError("catalog-mismatch", f"this CLI is {cli_version}; the catalog is release "
                           f"{catalog['lineage']['cliVersion']} (install with that release's own CLI)")
    if binding["helperSHA256"] != role_file(catalog, "helper")["sha256"]:
        raise InstallError("binding-mismatch", "the bound helper is not this release's helper; run `agent bind` "
                           "with the release's pocketshell-link first")
    if not SID_RE.match(owner_sid) or binding["ownerSID"] != owner_sid:
        raise InstallError("binding-mismatch", "the binding belongs to another user")
    if not SERVER_RE.match(server or ""):
        raise InstallError("binding-mismatch", "the enrolled helper reports no public wss:// server")
    if not DEVICE_RE.match(binding.get("deviceId") or ""):
        raise InstallError("binding-mismatch", "the binding has no usable device id")

    # 1) the staged closure, exactly
    try:
        staged_files = paths.inventory(staged, owner_sid, private=False)
    except Exception as exc:  # noqa: BLE001
        raise InstallError("staged-invalid", f"the staged release cannot be enumerated safely: "
                           f"{sanitize(str(exc), 300)}") from None
    want = {f["path"].lower(): f for f in catalog["files"]}
    if sorted(p.lower() for p in staged_files) != sorted(want):
        extra = sorted(set(p.lower() for p in staged_files) - set(want))[:5]
        missing = sorted(set(want) - set(p.lower() for p in staged_files))[:5]
        raise InstallError("staged-invalid", f"the staged closure differs from the catalog (extra {extra}, "
                           f"missing {missing})")
    blobs = {}
    for rel in staged_files:
        # staged bytes are anchored by the catalog digest (no ACL requirement)
        got = paths.file(ntpath.join(staged, *rel.split("/")), owner_sid, private=False, max_bytes=MAX_FILE)
        if got["sha256"] != want[rel.lower()]["sha256"] or got["bytes"] is None:
            raise InstallError("staged-invalid", f"{rel} does not match its catalog sha256")
        blobs[want[rel.lower()]["path"]] = got["bytes"]

    root = ntpath.join(user_data, "managed-runtime")
    release_dir = ntpath.join(root, "releases", catalog["release"])
    tmp = ntpath.join(root, "tmp")
    env = {k: folders[k] for k in ("SystemDrive", "SystemRoot", "ProgramData", "USERPROFILE", "LOCALAPPDATA")}
    env.update(TEMP=tmp, TMP=tmp)
    receipt = {
        "version": RECEIPT_VERSION,
        "release": catalog["release"],
        "catalogSHA256": cat["sha256"],
        "ownerSid": owner_sid,
        "binding": {"deviceId": binding["deviceId"], "manifest": binding["manifest"],
                    "manifestSHA256": binding["manifestSHA256"], "configDir": binding["configDir"],
                    "port": binding["port"], "hostKeyFingerprint": binding["hostKeyFingerprint"],
                    "server": server},
        "environment": env,
        "location": {"root": root, "ownerSid": owner_sid, "protectedDACL": True, "allowTrustees": [owner_sid],
                     "reparseFree": True, "verifier": VERIFIER},
        "installer": {"cliVersion": cli_version, "cliCommit": catalog["source"],
                      "installedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))},
    }
    if dry_run:
        return receipt

    # 2) copy with the private shape; an existing release dir must be exactly this closure
    for folder in (root, ntpath.join(root, "releases"), release_dir, tmp):
        paths.mkdir(folder)
    present = paths.inventory(release_dir, owner_sid)
    stray = sorted(set(p.lower() for p in present) - set(want))
    if stray:
        raise InstallError("release-dirty", f"{release_dir} holds files outside the catalog: {stray[:5]}")
    for rel, data in sorted(blobs.items()):
        target = ntpath.join(release_dir, *rel.split("/"))
        parent = ntpath.dirname(target)
        if not _same(parent, release_dir):
            paths.mkdir(parent)
        paths.write(target, data)

    # 3) re-measure what is installed (handle-based), then the receipt
    if sorted(p.lower() for p in paths.inventory(release_dir, owner_sid)) != sorted(want):
        raise InstallError("install-failed", "the installed closure differs from the catalog")
    for f in catalog["files"]:
        got = paths.file(ntpath.join(release_dir, *f["path"].split("/")), owner_sid, private=True, max_bytes=0)
        if got["sha256"] != f["sha256"]:
            raise InstallError("install-failed", f"installed {f['path']} does not match its catalog sha256")
    for folder in (root, tmp, release_dir):
        if not _same(paths.directory(folder, owner_sid), folder):
            raise InstallError("install-failed", f"{folder} is not the protected directory")
    paths.write(ntpath.join(root, "authority.json"), json.dumps(receipt, indent=1).encode("utf-8"))
    return receipt


def platform_ok() -> bool:
    return sys.platform == "win32"
