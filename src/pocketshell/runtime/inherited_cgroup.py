"""Verify an existing kernel memory boundary; never infer one from config.

The inherited mode is for a read-only cgroup-v2 domain (e.g. an unprivileged
container) with a hard RAM limit at least as strict as the requested cap and
zero swap. All processes share that stronger bound; it is not an additional
per-session scope. Invalid evidence fails closed before launch.
"""
from __future__ import annotations

import ctypes
import os
import re
import shutil
import stat
import sys
from dataclasses import dataclass
from pathlib import PurePosixPath

from pocketshell.runtime.memcap import MemCapError

CGROUP2_MAGIC = 0x63677270
PROC_MAGIC = 0x9FA0
MAX_METADATA_BYTES = 1024 * 1024


def _error(reason: str):
    return MemCapError("Cannot enforce session memory cap: " + reason + "; no uncapped session was started.")


def _path(value: str) -> PurePosixPath:
    if not value.startswith("/") or any(ord(c) < 32 for c in value) \
            or (value != "/" and any(p in ("", ".", "..") for p in value[1:].split("/"))):
        raise _error("unsafe cgroup path")
    return PurePosixPath(value)


def membership(text: str) -> PurePosixPath:
    found = []
    for line in text.splitlines():
        fields = line.split(":", 2)
        if len(fields) != 3 or not fields[0].isdigit():
            raise _error("malformed proc cgroup membership")
        if fields[0] == "0" and fields[1] == "":
            found.append(_path(fields[2]))
    if len(found) != 1:
        raise _error("ambiguous or missing cgroup-v2 membership")
    return found[0]


def _unescape(value: str):
    escapes = {"040": " ", "011": "\t", "012": "\n", "134": "\\"}
    if re.search(r"\\(?!040|011|012|134)", value):
        raise _error("unsupported mountinfo escape")
    return re.sub(r"\\(040|011|012|134)", lambda m: escapes[m[1]], value)


@dataclass(frozen=True)
class CgroupMount:
    mount_id: int
    root: PurePosixPath
    path: PurePosixPath
    relative: PurePosixPath


def cgroup_mount(text: str, current: PurePosixPath) -> CgroupMount:
    candidates = []
    for line in text.splitlines():
        left, sep, right = line.partition(" - ")
        fields, fs = left.split(), right.split()
        if not sep or len(fields) < 6 or len(fs) != 3:
            raise _error("malformed mountinfo")
        if fs[0] != "cgroup2":
            continue
        if not fields[0].isdigit() or int(fields[0]) <= 0:
            raise _error("invalid cgroup mount ID")
        root, path = _path(_unescape(fields[3])), _path(_unescape(fields[4]))
        if current != root and root not in current.parents:
            continue
        if "ro" not in fields[5].split(",") or "rw" in fields[5].split(","):
            raise _error("the current cgroup2 mount is writable")
        candidates.append(CgroupMount(int(fields[0]), root, path, current.relative_to(root)))
    if len(candidates) != 1:
        raise _error("ambiguous or missing cgroup2 mount")
    return candidates[0]


def hard_limit(text: str, *, zero_allowed=False) -> int:
    if not re.fullmatch(r"(?:0|[1-9][0-9]{0,19})\n?", text):
        raise _error("memory limit is missing, unbounded or malformed")
    value = int(text)
    if value > 2**63 - 1 or (value == 0 and not zero_allowed):
        raise _error("memory limit is not a positive finite bound")
    return value


@dataclass(frozen=True)
class InheritedBound:
    requested_bytes: int
    memory_max_bytes: int
    membership: str
    mount_id: int
    device: int
    inode: int

    def public(self):
        return {"mode": "inherited_cgroup", "requested_bytes": self.requested_bytes,
                "memory_max_bytes": self.memory_max_bytes, "swap_max_bytes": 0,
                "shared": True}


class Kernel:
    """Only real procfs/cgroup2 FDs; neither environment nor user paths supply proof."""
    @staticmethod
    def _magic(fd):
        libc = ctypes.CDLL(None, use_errno=True)
        function = libc.fstatfs
        function.argtypes = [ctypes.c_int, ctypes.c_void_p]
        function.restype = ctypes.c_int
        # The leading f_type field is a native signed long on Linux; leave
        # ample room for libc's complete architecture-specific statfs struct.
        buffer = ctypes.create_string_buffer(512)
        if function(fd, buffer) != 0:
            raise OSError(ctypes.get_errno(), "fstatfs failed")
        return ctypes.c_long.from_buffer(buffer).value

    def _read(self, path, magic, *, directory_fd=None, mount_id=None):
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd)
        try:
            if self._magic(fd) != magic or not stat.S_ISREG(os.fstat(fd).st_mode):
                raise _error("kernel proof file is not on its expected filesystem")
            if mount_id is not None and self._mount_id(fd) != mount_id:
                raise _error("cgroup proof file was overmounted")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(MAX_METADATA_BYTES + 1)
            if len(raw) > MAX_METADATA_BYTES:
                raise _error("kernel metadata is too large")
            return raw.decode("utf-8", errors="strict")
        finally:
            os.close(fd)

    def proc(self, path):
        return self._read(path, PROC_MAGIC)

    def _mount_id(self, fd):
        text = self.proc(f"/proc/self/fdinfo/{fd}")
        found = re.findall(r"^mnt_id:\s*([0-9]+)$", text, re.MULTILINE)
        if len(found) != 1:
            raise _error("kernel FD mount identity is ambiguous")
        return int(found[0])

    def limits(self, mount):
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            for component in (*mount.path.parts[1:], *mount.relative.parts):
                next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                os.close(fd)
                fd = next_fd
            if self._magic(fd) != CGROUP2_MAGIC or self._mount_id(fd) != mount.mount_id:
                raise _error("cgroup directory identity does not match mountinfo")
            identity = os.fstat(fd)
            values = [self._read(name, CGROUP2_MAGIC, directory_fd=fd, mount_id=mount.mount_id)
                      for name in ("cgroup.type", "memory.max", "memory.swap.max")]
            return (*values, identity.st_dev, identity.st_ino)
        finally:
            os.close(fd)


def discover(requested: int, *, kernel=None) -> InheritedBound:
    if type(requested) is not int or requested <= 0:
        raise _error("the requested bound is not a positive integer")
    kernel = kernel or Kernel()
    try:
        before = kernel.proc("/proc/self/cgroup")
        mounts = kernel.proc("/proc/self/mountinfo")
        current = membership(before)
        mount = cgroup_mount(mounts, current)
        kind, ram, swap, device, inode = kernel.limits(mount)
        if kind != "domain\n":
            raise _error("the current cgroup is not a domain")
        limit, swap_limit = hard_limit(ram), hard_limit(swap, zero_allowed=True)
        if limit > requested or swap_limit != 0:
            raise _error("the inherited RAM/swap bounds are weaker than requested")
        if os.environ.get("APLEXER_LAUNCH_SYSTEM_SCOPE"):
            raise _error("a system-scope escape override conflicts with inherited containment")
        if before != kernel.proc("/proc/self/cgroup") or mounts != kernel.proc("/proc/self/mountinfo"):
            raise _error("cgroup membership or mount identity changed during verification")
        return InheritedBound(requested, limit, str(current), mount.mount_id, device, inode)
    except (OSError, UnicodeError, ValueError) as exc:
        raise _error("kernel cgroup metadata could not be verified") from exc


def dedicated_scope_available():
    if shutil.which("systemd-run") is None:
        return False
    # No user-manager IPC: starting a transient user scope cannot work.
    # These are kernel-visible standard sockets, never an environment proof.
    for name in (f"/run/user/{os.getuid()}/bus", f"/run/user/{os.getuid()}/systemd/private"):
        try:
            if stat.S_ISSOCK(os.stat(name, follow_symlinks=False).st_mode):
                return True
        except OSError:
            continue
    return False


def plan(requested: int | None) -> InheritedBound | None:
    if requested is None or sys.platform != "linux" or dedicated_scope_available():
        return None
    return discover(requested)


def revalidate(proof: InheritedBound):
    if discover(proof.requested_bytes) != proof:
        raise _error("the inherited memory boundary changed before launch")
