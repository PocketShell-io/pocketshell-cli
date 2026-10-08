"""Windows private-file storage using owner/DACL and pinned native handles.

No chmod emulation: every new object receives a protected, owner-only DACL
at creation. Existing objects must have that same effective security shape.
Every directory component is opened without delete sharing and checked on
its handle for reparse points; those handles remain live for the operation.
The leaf is opened with OPEN_REPARSE_POINT, checked by handle before reading,
and no write/delete sharing. Junctions, symlinks, foreign owners, null or
unprotected DACLs and unfamiliar ACE types fail closed. Privileged Windows
administrators can override security, like root on Unix.
"""
from __future__ import annotations

import ctypes as c
from ctypes import wintypes as w
from contextlib import contextmanager
import os
from pathlib import Path
import secrets

k = c.WinDLL("kernel32", use_last_error=True)
a = c.WinDLL("advapi32", use_last_error=True)
P = c.c_void_p


def _bind(lib, name, args, result):
    fn = getattr(lib, name)
    fn.argtypes, fn.restype = args, result
    return fn


CloseHandle = _bind(k, "CloseHandle", [w.HANDLE], w.BOOL)
LocalFree = _bind(k, "LocalFree", [P], P)
CreateFile = _bind(k, "CreateFileW", [w.LPCWSTR, w.DWORD, w.DWORD, P, w.DWORD, w.DWORD, w.HANDLE], w.HANDLE)
CreateDirectory = _bind(k, "CreateDirectoryW", [w.LPCWSTR, P], w.BOOL)
MoveFile = _bind(k, "MoveFileExW", [w.LPCWSTR, w.LPCWSTR, w.DWORD], w.BOOL)
GetInfo = _bind(k, "GetFileInformationByHandle", [w.HANDLE, P], w.BOOL)
SetInfo = _bind(k, "SetFileInformationByHandle", [w.HANDLE, c.c_int, P, w.DWORD], w.BOOL)
GetCurrentProcess = _bind(k, "GetCurrentProcess", [], w.HANDLE)
OpenToken = _bind(a, "OpenProcessToken", [w.HANDLE, w.DWORD, c.POINTER(w.HANDLE)], w.BOOL)
GetTokenInfo = _bind(a, "GetTokenInformation", [w.HANDLE, c.c_int, P, w.DWORD, c.POINTER(w.DWORD)], w.BOOL)
SidString = _bind(a, "ConvertSidToStringSidW", [P, c.POINTER(P)], w.BOOL)
StringSD = _bind(a, "ConvertStringSecurityDescriptorToSecurityDescriptorW", [w.LPCWSTR, w.DWORD, c.POINTER(P), P], w.BOOL)
GetSecurity = _bind(a, "GetSecurityInfo", [w.HANDLE, c.c_int, w.DWORD, c.POINTER(P), P, c.POINTER(P), P, c.POINTER(P)], w.DWORD)
GetControl = _bind(a, "GetSecurityDescriptorControl", [P, c.POINTER(w.WORD), c.POINTER(w.DWORD)], w.BOOL)
GetAce = _bind(a, "GetAce", [P, w.DWORD, c.POINTER(P)], w.BOOL)


class PrivateFileError(OSError):
    """A native private-storage invariant failed; contains no file contents."""


class _SA(c.Structure):
    _fields_ = [("length", w.DWORD), ("descriptor", P), ("inherit", w.BOOL)]


class _Info(c.Structure):
    _fields_ = [("attributes", w.DWORD), ("created", w.FILETIME),
                ("accessed", w.FILETIME), ("written", w.FILETIME),
                ("volume", w.DWORD), ("size_high", w.DWORD), ("size_low", w.DWORD),
                ("links", w.DWORD), ("index_high", w.DWORD), ("index_low", w.DWORD)]


class _ACL(c.Structure):
    _fields_ = [("revision", w.BYTE), ("reserved", w.BYTE), ("size", w.WORD),
                ("count", w.WORD), ("reserved2", w.WORD)]


class _ACE(c.Structure):
    _fields_ = [("type", w.BYTE), ("flags", w.BYTE), ("size", w.WORD),
                ("mask", w.DWORD), ("sid_start", w.DWORD)]


def _ok(result):
    if not result:
        raise c.WinError(c.get_last_error())
    return result


def _sid_text(ptr):
    out = P()
    _ok(SidString(ptr, c.byref(out)))
    try:
        return c.wstring_at(out)
    finally:
        LocalFree(out)


def _current_sid():
    token = w.HANDLE()
    _ok(OpenToken(GetCurrentProcess(), 8, c.byref(token)))  # TOKEN_QUERY
    try:
        size = w.DWORD()
        GetTokenInfo(token, 1, None, 0, c.byref(size))  # TokenUser
        buf = c.create_string_buffer(size.value)
        _ok(GetTokenInfo(token, 1, buf, size.value, c.byref(size)))
        return _sid_text(c.cast(buf, c.POINTER(P))[0])
    finally:
        CloseHandle(token)


@contextmanager
def _security():
    sid = _current_sid()
    sd = P()
    # Set owner explicitly; inheritable owner-only ACEs protect new children.
    _ok(StringSD(f"O:{sid}D:P(A;OICI;FA;;;{sid})", 1, c.byref(sd), None))
    sa = _SA(c.sizeof(_SA), sd, False)
    try:
        yield c.byref(sa)
    finally:
        LocalFree(sd)


def _check(handle, *, directory, private):
    info = _Info()
    _ok(GetInfo(handle, c.byref(info)))
    if info.attributes & 0x400 or bool(info.attributes & 0x10) != directory:
        raise PrivateFileError("refusing reparse point or unexpected file type")
    if not directory and info.links != 1:
        raise PrivateFileError("refusing multiply-linked private file")
    if not private:
        return
    owner, dacl, sd = P(), P(), P()
    error = GetSecurity(handle, 1, 5, c.byref(owner), None, c.byref(dacl), None, c.byref(sd))
    if error:
        raise c.WinError(error)
    try:
        current = _current_sid()
        if not owner or _sid_text(owner) != current or not dacl:
            raise PrivateFileError("private storage must be owned by you with a non-null DACL")
        control, revision = w.WORD(), w.DWORD()
        _ok(GetControl(sd, c.byref(control), c.byref(revision)))
        if not control.value & 0x1000:  # SE_DACL_PROTECTED
            raise PrivateFileError("private storage DACL must disable inheritance")
        acl = c.cast(dacl, c.POINTER(_ACL)).contents
        owner_access = False
        for index in range(acl.count):
            ptr = P()
            _ok(GetAce(dacl, index, c.byref(ptr)))
            ace = c.cast(ptr, c.POINTER(_ACE)).contents
            # Accept only ordinary current-user allow ACEs, never object/callback
            # ACEs or an Everyone/Users/group grant (even a read-only one).
            if ace.type != 0 or ace.flags & 8 or _sid_text(ptr.value + _ACE.sid_start.offset) != current:
                raise PrivateFileError("private storage DACL grants access outside your account")
            owner_access |= (ace.mask & 0x1F01FF) == 0x1F01FF
        if not owner_access:
            raise PrivateFileError("private storage requires current-user full control")
    finally:
        LocalFree(sd)


def _open(path, *, directory=False, access=0x80020000, create=False, security=None):
    # Generic read + READ_CONTROL by default; never grant delete sharing.
    handle = CreateFile(str(path), access, 3 if directory else 1, security,
                        1 if create else 3, 0x00200000 | (0x02000000 if directory else 0), None)
    if handle == w.HANDLE(-1).value:
        raise c.WinError(c.get_last_error())
    return handle


def _path(path):
    path = Path(os.path.abspath(path))
    # Disallow alternate streams, UNC/device paths, and reserved namespace forms.
    if not path.drive or len(path.drive) != 2 or path.drive[1] != ":":
        raise PrivateFileError("private storage must use a local drive path")
    for part in path.parts[1:]:
        if ":" in part or part.rstrip(" .") != part or part.upper().split(".")[0] in {
            "CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
            *(f"LPT{i}" for i in range(1, 10)),
        }:
            raise PrivateFileError("unsafe private storage path component")
    return path


@contextmanager
def _directory(path, *, create=False):
    path = _path(path)
    handles = []
    current = Path(path.anchor)
    try:
        for part in (None, *path.parts[1:]):
            if part is not None:
                current /= part
            if create and part is not None:
                with _security() as sa:
                    if not CreateDirectory(str(current), sa) and c.get_last_error() != 183:
                        raise c.WinError(c.get_last_error())
            # READ_CONTROL/READ_ATTRIBUTES alone are metadata-only accesses:
            # Windows does not enforce the intended delete-sharing exclusion
            # for those handles. FILE_LIST_DIRECTORY makes this a real read
            # access, so omitting FILE_SHARE_DELETE pins rename/delete too.
            handle = _open(current, directory=True, access=0x20081)
            handles.append(handle)
            _check(handle, directory=True, private=current == path)
        yield path
    finally:
        for handle in reversed(handles):
            CloseHandle(handle)


def read_private(path: Path, maximum: int) -> bytes:
    import msvcrt
    path = _path(path)
    with _directory(path.parent):
        handle = _open(path)
        try:
            _check(handle, directory=False, private=True)
            fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
            handle = None  # fd owns the same checked handle; no reopen-by-name
            with os.fdopen(fd, "rb") as stream:
                data = stream.read(maximum + 1)
            if len(data) > maximum:
                raise PrivateFileError("private file exceeds size limit")
            return data
        finally:
            if handle is not None:
                CloseHandle(handle)


def write_private(path: Path, payload: bytes) -> None:
    import msvcrt
    path = _path(path)
    with _directory(path.parent, create=True):
        try:
            read_private(path, max(len(payload), 1 << 20))  # refuse unsafe existing leaf
        except FileNotFoundError:
            pass
        tmp = path.with_name(f".{path.name}.{secrets.token_hex(12)}.tmp")
        try:
            with _security() as sa:
                handle = _open(tmp, access=0x40020000, create=True, security=sa)
            try:
                _check(handle, directory=False, private=True)
                fd = msvcrt.open_osfhandle(handle, os.O_WRONLY | os.O_BINARY)
                handle = None
                with os.fdopen(fd, "wb") as stream:
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
            finally:
                if handle is not None:
                    CloseHandle(handle)
            _ok(MoveFile(str(tmp), str(path), 1 | 8))  # REPLACE_EXISTING | WRITE_THROUGH
        finally:
            if tmp.exists():
                os.unlink(tmp)  # private pinned directory, only a generated temp name


def delete_private(path: Path) -> bool:
    path = _path(path)
    try:
        with _directory(path.parent):
            handle = _open(path, access=0x30080)  # DELETE | READ_CONTROL | READ_ATTRIBUTES
            try:
                _check(handle, directory=False, private=True)
                disposition = w.BOOL(True)
                _ok(SetInfo(handle, 4, c.byref(disposition), c.sizeof(disposition)))
            finally:
                CloseHandle(handle)
        return True
    except FileNotFoundError:
        return False
