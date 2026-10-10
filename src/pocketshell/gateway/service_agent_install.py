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
CATALOG_VERSIONS = (2, 3)           # v3 adds the endpoint roles + lineage (setup ABI v3)
RECEIPT_VERSION = 2
ENDPOINT_ROLES = ("sshd", "sftp", "backend-shell", "backend-dll")
VERIFY_VERSION = 2
API_NAME = "ordinary-v2"
PLATFORM = "win32-x64"
VERIFIER = "pocketshell gateway agent verify-paths"
GUARDIAN_ABI = "6cf7ae85"           # catalog v2
GUARDIAN3_ABI = "e862645d"          # catalog v3: the successor with the agreed 8 MiB manifest bound (§16.14)
SINGLE_ROLES = ("cli", "interpreter", "guardian", "native-api", "policy", "helper")
ROLES = (*SINGLE_ROLES, "module")
MAX_DOC = 1024 * 1024              # catalog v2 (unchanged)
MAX_FILE = 256 * 1024 * 1024
MAX_FILES = 4096                   # catalog v2 (unchanged)
# §16.14 agreed full-closure bounds (catalog v3; Fleet d3d3b455; native verifier;
# successor guardian): measured whole closure ~9 777 rows / 1.61 MB catalog.
CATALOG3_MAX_FILES = 16384
CATALOG3_MAX_BYTES = 8 << 20
ENV_KEYS = ("SystemDrive", "SystemRoot", "ProgramData", "USERPROFILE", "LOCALAPPDATA", "TEMP", "TMP")

SHA_RE = re.compile(r"^[a-f0-9]{64}$")
COMMIT_RE = re.compile(r"^[a-f0-9]{40}$")
RELEASE_RE = re.compile(r"^[A-Za-z0-9_-]{1,80}$")
# Shared with the schema (ordinary-v2-authority.schema.json $defs absPath/relPath):
# drive-absolute only (no UNC / \\?\ / device namespace), no ADS colon after the
# drive, no '.'/'..' or empty components, no device names, no trailing dot/space
# aliases, no wildcards or control characters.
ABS_RE = re.compile('^(?!.*[\\\\/]\\.{1,2}(?:[\\\\/]|$))(?!.*[\\\\/](?:[Cc][Oo][Nn]|[Pp][Rr][Nn]|[Aa][Uu][Xx]|[Nn][Uu][Ll]|[Cc][Oo][Mm][1-9]|[Ll][Pp][Tt][1-9])(?:\\.[^\\\\/]*)?(?:[\\\\/]|$))(?!.*[. ](?:[\\\\/]|$))(?!.*[\\\\/]{2})[A-Za-z]:[\\\\/][^:*?\\"<>|\\u0000-\\u001f]+$')
REL_RE = re.compile('^(?!(?:.*/)?\\.{1,2}(?:/|$))(?!(?:.*/)?(?:[Cc][Oo][Nn]|[Pp][Rr][Nn]|[Aa][Uu][Xx]|[Nn][Uu][Ll]|[Cc][Oo][Mm][1-9]|[Ll][Pp][Tt][1-9])(?:\\.[^/]*)?(?:/|$))(?!.*\\.(?:/|$))[A-Za-z0-9_.\\-]+(?:/[A-Za-z0-9_.\\-]+)*$')
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
    return isinstance(path, str) and len(path) <= 4096 and ABS_RE.match(path) is not None


def _same(a: str, b: str) -> bool:
    return ntpath.normcase(ntpath.normpath(a)) == ntpath.normcase(ntpath.normpath(b))


# --- catalog v2 ------------------------------------------------------------------------


def parse_catalog(data: bytes) -> dict:
    """Validate catalog v2 (schema + cross-field rules); return it."""
    if len(data) > CATALOG3_MAX_BYTES:
        raise InstallError("catalog-invalid", "the catalog is larger than 8 MiB")
    try:
        c = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise InstallError("catalog-invalid", "the catalog is not UTF-8 JSON") from None
    bad = lambda why: InstallError("catalog-invalid", f"catalog: {why}")  # noqa: E731
    if not _exact(c, ["version", "release", "source", "platform", "api", "lineage", "files"]):
        raise bad("keys must be exactly version, release, source, platform, api, lineage, files")
    if c["version"] not in CATALOG_VERSIONS or c["platform"] != PLATFORM or c["api"] != API_NAME:
        raise bad(f"version/platform/api must be {CATALOG_VERSIONS}/{PLATFORM}/{API_NAME}")
    v3 = c["version"] == 3
    if not v3 and len(data) > MAX_DOC:
        raise InstallError("catalog-invalid", "the catalog v2 is larger than 1 MiB")
    max_files = CATALOG3_MAX_FILES if v3 else MAX_FILES
    roles_allowed = (*SINGLE_ROLES, *ENDPOINT_ROLES, "module") if v3 else ROLES
    if not isinstance(c["release"], str) or not RELEASE_RE.match(c["release"]):
        raise bad("release")
    if not isinstance(c["source"], str) or not COMMIT_RE.match(c["source"]):
        raise bad("source must be a 40-hex commit")
    lin = c["lineage"]
    if not _exact(lin, ["cliVersion", "cliCommit", "agentApi", "guardian", "nativeApi", "policy", "interpreter",
                        "helper", "lockSHA256", *(["endpoint"] if v3 else [])]):
        raise bad("lineage keys")
    if not isinstance(lin["cliVersion"], str) or not VERSION_RE.match(lin["cliVersion"]) \
            or lin["cliCommit"] != c["source"] or lin["agentApi"] != 1:
        raise bad("lineage cliVersion/cliCommit/agentApi")
    if not _exact(lin["guardian"], ["abi", "sourceSHA256"]) \
            or lin["guardian"]["abi"] != (GUARDIAN3_ABI if v3 else GUARDIAN_ABI) \
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
    if not isinstance(files, list) or not 7 <= len(files) <= max_files:
        raise bad(f"files must list 7..{max_files} entries")
    seen, roles = set(), {}
    for f in files:
        if not _exact(f, ["path", "sha256", "role"]) or not isinstance(f["path"], str) \
                or len(f["path"]) > 1024 or not REL_RE.match(f["path"]) \
                or not isinstance(f["sha256"], str) or not SHA_RE.match(f["sha256"]) or f["role"] not in roles_allowed:
            raise bad(f"file entry {sanitize(str(f), 120)}")
        key = f["path"].lower()
        if key in seen:
            raise bad(f"case-colliding path {f['path']}")
        seen.add(key)
        if f["role"] != "module" and f["role"] in roles:
            raise bad(f"more than one {f['role']}")
        roles.setdefault(f["role"], f)
    for role in roles_allowed:
        if role not in roles:
            raise bad(f"no {role} file")
    pins = {"guardian": lin["guardian"]["sourceSHA256"], "native-api": lin["nativeApi"]["sourceSHA256"],
            "policy": lin["policy"]["sourceSHA256"], "interpreter": lin["interpreter"]["sha256"],
            "helper": lin["helper"]["sha256"]}
    if v3:
        e = lin["endpoint"]
        if not _exact(e, ["openssh", "sftp", "backendShell"]) \
                or not _exact(e["openssh"], ["version", "sourceCommit", "buildReceiptSHA256"]) \
                or not isinstance(e["openssh"]["version"], str) or not 0 < len(e["openssh"]["version"]) <= 64 \
                or not COMMIT_RE.match(str(e["openssh"]["sourceCommit"])) \
                or not SHA_RE.match(str(e["openssh"]["buildReceiptSHA256"])) \
                or not _exact(e["sftp"], ["version", "sha256"]) or not isinstance(e["sftp"]["version"], str) \
                or not _exact(e["backendShell"], ["distribution", "version", "sha256"]) \
                or not isinstance(e["backendShell"]["distribution"], str) \
                or not isinstance(e["backendShell"]["version"], str):
            raise bad("lineage endpoint")
        pins.update({"sftp": e["sftp"]["sha256"], "backend-shell": e["backendShell"]["sha256"]})
        for f in files:
            if f["role"] in ENDPOINT_ROLES and not f["path"].startswith("endpoint/"):
                raise bad(f"endpoint role {f['role']} must live under endpoint/")
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

    def _ancestors(self, path: str, owner_sid: str, root=None) -> None:
        """No-foreign-mutation authority on the parents of ``path`` — only from
        the declared request ``root`` down (diagnostic 7a, as the native
        verifier's aclRole). Directories above the root are still opened by
        handle, reparse-refused and held by _pinned; their ACLs belong to the
        user's profile. ``root`` None (legacy callers) checks every parent."""
        import pathlib

        for parent in reversed(pathlib.PureWindowsPath(path).parents):
            if root is None or _under(str(parent), str(root)):
                self.api._check_acl(str(parent), owner_sid, "ancestor")

    @staticmethod
    def _pinned(path, *, private_leaf: bool, private_root=None):
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
                inside = private_root is not None and _under(str(current), str(private_root))
                ws._check(handle, directory=True, private=inside or (private_leaf and current == path))
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

    def file(self, path: str, owner_sid: str, *, private: bool, max_bytes: int, private_root=None, root=None) -> dict:
        import os
        from pathlib import Path

        from pocketshell import windows_security as ws

        p = ws._path(Path(path))
        self._ancestors(str(p), owner_sid, root=root or private_root)
        pinned = self._pinned(p.parent, private_leaf=private, private_root=private_root if private else None)
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

    def system_reference(self, path: str, owner_sid: str) -> dict:
        """§16.13: exactly <GetSystemWindowsDirectory>\\System32\\{cmd,conhost}.exe,
        the guardian's servicing path_authority, canonical final path, digest."""
        import ctypes as c

        buf = c.create_unicode_buffer(261)
        if not c.WinDLL("kernel32", use_last_error=True).GetSystemWindowsDirectoryW(buf, 261):
            raise ServiceError("cannot measure the system directory")
        system32 = buf.value.rstrip("\\") + "\\System32"
        head, _sep, name = path.rpartition("\\")
        if "/" in path or "~" in path or name.lower() not in SYSTEM_REFERENCES or head.casefold() != system32.casefold():
            raise ServiceError("not an allowed canonical system reference")
        self.api.path_authority(path, owner_sid, role="file", servicing=True)
        from pocketshell.gateway import service_windows as win

        return {"canonicalPath": path, "size": None, "sha256": win.file_sha256(path)}

    def metadata(self, path: str, owner_sid: str) -> dict:
        """Setup ABI v3 key files: owner-only, protected, single-link, reparse-free
        regular file whose parent is a private root. Opened with
        FILE_READ_ATTRIBUTES|READ_CONTROL only (0x20080): no data access, so
        the contents are never read (no share-mode check applies either)."""
        from pathlib import Path

        from pocketshell import windows_security as ws

        p = ws._path(Path(path))
        self._ancestors(str(p), owner_sid, root=str(p.parent))
        pinned = self._pinned(p.parent, private_leaf=True, private_root=p.parent)
        try:
            handle = ws._open(p, access=0x20080)
            try:
                ws._check(handle, directory=False, private=True)
                canonical = self._final(handle)
            finally:
                ws.CloseHandle(handle)
        finally:
            self._close(pinned)
        if not canonical or not _same(canonical, str(p)):
            raise ServiceError("the opened object is not the requested path")
        return {"canonicalPath": canonical}

    def directory(self, path: str, owner_sid: str, private_root=None, root=None) -> str:
        from pathlib import Path

        from pocketshell import windows_security as ws

        p = ws._path(Path(path))
        self._ancestors(str(p), owner_sid, root=root or private_root)
        pinned = self._pinned(p, private_leaf=True, private_root=private_root)
        try:
            return self._final(pinned[-1]) or str(p)
        finally:
            self._close(pinned)

    def directory_anchored(self, path: str, owner_sid: str, root=None) -> str:
        """A resources directory: reparse-free by handle, ancestors without
        foreign mutation authority; no owner-only requirement."""
        from pathlib import Path

        from pocketshell import windows_security as ws

        p = ws._path(Path(path))
        self._ancestors(str(p), owner_sid, root=root)
        pinned = self._pinned(p, private_leaf=False)
        try:
            return self._final(pinned[-1]) or str(p)
        finally:
            self._close(pinned)

    def inventory(self, path: str, owner_sid: str, *, private: bool = True, private_root=None, root=None,
                  max_files: int = MAX_FILES) -> list:
        """Every regular file under a directory, by handle; any reparse entry
        refuses, and with ``private`` any non-private object refuses. More than
        ``max_files`` (catalog v2: 4 096; v3/native: the agreed 16 384) refuses
        the whole inventory (never sliced)."""
        root_bound = root
        import os
        from pathlib import Path

        from pocketshell import windows_security as ws

        root = ws._path(Path(path))
        self._ancestors(str(root), owner_sid, root=root_bound or private_root)
        out = []
        pinned = self._pinned(root, private_leaf=private, private_root=private_root if private else None)
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
                            if len(out) > max_files:
                                raise ServiceError(f"more than {max_files} files")
        finally:
            self._close(pinned)
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


OPERATION_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
VERIFY_KINDS = ("document", "binary", "directory", "inventory", "system-reference")
SYSTEM_REFERENCES = ("cmd.exe", "conhost.exe")  # agreement §16.13 (guardian 6cf servicing roles)
MAX_REQUESTS = 32768              # §16.14 (native verifier maxRequests)
MAX_DOCUMENT = 8 << 20            # bytes returned per document (native maxDocument)
MAX_REPLY = 32 << 20              # the verifier's own channel (native maxReply)


def _under(path: str, root: str) -> bool:
    p, r = ntpath.normcase(ntpath.normpath(path)), ntpath.normcase(ntpath.normpath(root))
    return p == r or p.startswith(r.rstrip("\\") + "\\")


def verify_paths(*, owner_sid: str, operation_id: str, private_roots=(), resources_roots=(), requests=(),
                 paths, current_sid: str) -> tuple:
    """Verifier protocol v2 (agreement v3.1 §11.4): (reply, exit code) with
    0 = every request verified, 1 = refusal, 2 = malformed request.

    Each request is (kind, path). A path must lie in exactly one declared
    root: under a PRIVATE root it must have the owner-only protected shape;
    under a RESOURCES root (the Desktop install) it is read reparse-free by
    handle and anchored by digest only. ``document`` returns bounded bytes
    (.json, <= 8 MiB); ``binary`` returns size + sha256 only (never bytes).
    Results correspond 1:1, in order, to the requests (``index``)."""
    def reply(ok, results, problem=None):
        doc = {"version": VERIFY_VERSION, "operationId": operation_id, "ownerSid": owner_sid, "ok": ok,
               "results": results}
        if problem:
            doc["problem"] = problem
        return doc

    if not isinstance(operation_id, str) or not OPERATION_RE.match(operation_id):
        return reply(False, [], "--operation-id is required ([A-Za-z0-9._-]{1,64})"), 2
    if not SID_RE.match(owner_sid or "") or owner_sid != current_sid:
        return reply(False, [], "--owner-sid is not the measured current user"), 1
    roots = [(r, True) for r in private_roots] + [(r, False) for r in resources_roots]
    if not roots or any(not _abs(r) for r, _ in roots):
        return reply(False, [], "at least one drive-absolute --private-root/--resources-root is required"), 2
    for i, (r1, _p1) in enumerate(roots):
        for r2, _p2 in roots[i + 1:]:
            if _under(r1, r2) or _under(r2, r1):
                return reply(False, [], "declared roots must not overlap"), 2
    if not requests or len(requests) > MAX_REQUESTS:
        return reply(False, [], f"1..{MAX_REQUESTS} requests are required"), 2
    seen = set()
    for kind, path in requests:
        key = (kind, ntpath.normcase(ntpath.normpath(path)) if isinstance(path, str) else path)
        if kind not in VERIFY_KINDS or key in seen:
            return reply(False, [], "unknown or duplicate request"), 2
        seen.add(key)
    results = []
    for index, (kind, path) in enumerate(requests):
        item = {"index": index, "kind": kind, "path": path, "root": None, "ok": False, "canonicalPath": None,
                "size": None, "sha256": None, "bytesBase64": None, "files": None, "problem": None}
        try:
            if not _abs(path):
                raise ServiceError("not a plain drive-absolute path")
            if kind == "system-reference":
                if any(_under(path, r) for r, _p in roots):
                    raise ServiceError("a system-reference is never inside a declared root")
                got = paths.system_reference(path, owner_sid)
                item.update(canonicalPath=got["canonicalPath"], size=got["size"], sha256=got["sha256"], ok=True)
                results.append(item)
                continue
            owners = [(r, private) for r, private in roots if _under(path, r)]
            if len(owners) != 1:
                raise ServiceError("the path is not inside exactly one declared root")
            root, private = owners[0]
            item["root"] = root
            if kind in ("document", "binary"):
                if kind == "document" and not path.lower().endswith(".json"):
                    raise ServiceError("only .json documents return bytes; use binary")
                got = paths.file(path, owner_sid, private=private,
                                 max_bytes=MAX_DOCUMENT if kind == "document" else 0,
                                 private_root=root if private else None, root=root)
                if not got["canonicalPath"] or not _same(got["canonicalPath"], path):
                    raise ServiceError("the opened object is not the requested path")
                if kind == "document" and got["bytes"] is None:
                    raise ServiceError("document larger than 8 MiB")
                item.update(canonicalPath=got["canonicalPath"], size=got["size"], sha256=got["sha256"],
                            bytesBase64=base64.b64encode(got["bytes"]).decode() if kind == "document" else None)
            elif kind == "directory":
                canonical = paths.directory(path, owner_sid, private_root=root) if private \
                    else paths.directory_anchored(path, owner_sid, root=root)
                if not _same(canonical, path):
                    raise ServiceError("the opened directory is not the requested path")
                item["canonicalPath"] = canonical
            else:
                item["files"] = paths.inventory(path, owner_sid, private=private, max_files=CATALOG3_MAX_FILES,
                                                private_root=root if private else None, root=root)
            item["ok"] = True
        except Exception as exc:  # noqa: BLE001 - every failure is a refusal of that request
            item["problem"] = sanitize(str(exc) or type(exc).__name__, 600)
        results.append(item)
    ok = all(r["ok"] for r in results)
    doc = reply(ok, results)
    if len(json.dumps(doc)) > MAX_REPLY:
        return reply(False, [], "the reply would exceed 32 MiB"), 1
    return doc, 0 if ok else 1


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
        cat = paths.file(catalog_path, owner_sid, private=False, max_bytes=MAX_DOC, root=ntpath.dirname(catalog_path))
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
    if not _abs(binding.get("manifest")) or not _abs(binding.get("configDir")):
        raise InstallError("binding-mismatch", "the binding manifest/configDir is not a plain drive-absolute path")
    for key, value in folders.items():
        if key == "SystemDrive" and not re.match(r"^[A-Za-z]:$", value or ""):
            raise InstallError("environment", "SystemDrive is not a drive")
        if key != "SystemDrive" and not _abs(value):
            raise InstallError("environment", f"{key} is not a plain drive-absolute path")

    # 0) the EXISTING enrollment and guardian roots are private roots too (agreement
    #    §16): measured, never re-ACLed or moved by the installer
    for label, folder in (("the enrolled config dir", binding["configDir"]),
                          ("the guardian manifest's directory", ntpath.dirname(binding["manifest"]))):
        try:
            if not _same(paths.directory(folder, owner_sid, private_root=folder), folder):
                raise ServiceError("not the requested directory")
        except Exception as exc:  # noqa: BLE001
            raise InstallError("binding-mismatch", f"{label} {folder} is not an owner-only protected private root "
                               f"({sanitize(str(exc), 200)}); the installer never changes its ACL") from None
    try:
        manifest = paths.file(binding["manifest"], owner_sid, private=True, max_bytes=0,
                              private_root=ntpath.dirname(binding["manifest"]))
    except Exception as exc:  # noqa: BLE001
        raise InstallError("binding-mismatch", f"the guardian manifest cannot be measured privately "
                           f"({sanitize(str(exc), 200)})") from None
    if manifest["sha256"] != binding["manifestSHA256"]:
        raise InstallError("binding-mismatch", "the guardian manifest is not the bound one; bind again after review")

    blobs, want = _verify_staged(staged, catalog, owner_sid, paths)

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

    _copy_release(root, release_dir, tmp, blobs, want, catalog, owner_sid, paths)
    paths.write(ntpath.join(root, "authority.json"), json.dumps(receipt, indent=1).encode("utf-8"))
    return receipt


def _bound(catalog) -> int:
    """The inventory bound of this catalog's version (§16.14; v2 unchanged)."""
    return CATALOG3_MAX_FILES if catalog["version"] == 3 else MAX_FILES


def _verify_staged(staged, catalog, owner_sid, paths):
    """1) the staged closure, exactly (set + per-file sha256 by handle)."""
    try:
        staged_files = paths.inventory(staged, owner_sid, private=False, root=staged, max_files=_bound(catalog))
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
        got = paths.file(ntpath.join(staged, *rel.split("/")), owner_sid, private=False, max_bytes=MAX_FILE,
                         root=staged)
        if got["sha256"] != want[rel.lower()]["sha256"] or got["bytes"] is None:
            raise InstallError("staged-invalid", f"{rel} does not match its catalog sha256")
        blobs[want[rel.lower()]["path"]] = got["bytes"]
    return blobs, want


def _copy_release(root, release_dir, tmp, blobs, want, catalog, owner_sid, paths):
    """2) copy with the private shape; 3) re-measure by handle."""
    for folder in (root, ntpath.join(root, "releases"), release_dir, tmp):
        paths.mkdir(folder)
    present = paths.inventory(release_dir, owner_sid, private_root=root, max_files=_bound(catalog))
    stray = sorted(set(p.lower() for p in present) - set(want))
    if stray:
        raise InstallError("release-dirty", f"{release_dir} holds files outside the catalog: {stray[:5]}")
    for rel, data in sorted(blobs.items()):
        target = ntpath.join(release_dir, *rel.split("/"))
        parent = ntpath.dirname(target)
        if not _same(parent, release_dir):
            paths.mkdir(parent)
        paths.write(target, data)
    if sorted(p.lower() for p in paths.inventory(release_dir, owner_sid, private_root=root,
                                                 max_files=_bound(catalog))) != sorted(want):
        raise InstallError("install-failed", "the installed closure differs from the catalog")
    for f in catalog["files"]:
        got = paths.file(ntpath.join(release_dir, *f["path"].split("/")), owner_sid, private=True, max_bytes=0,
                         private_root=root)
        if got["sha256"] != f["sha256"]:
            raise InstallError("install-failed", f"installed {f['path']} does not match its catalog sha256")
    for folder in (root, tmp, release_dir):
        if not _same(paths.directory(folder, owner_sid, private_root=root), folder):
            raise InstallError("install-failed", f"{folder} is not the protected directory")


def platform_ok() -> bool:
    return sys.platform == "win32"
