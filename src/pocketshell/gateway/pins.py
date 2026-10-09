"""Client-side host-key pins for gateway SSH: the ONLY source of host trust.

A pin is one OpenSSH known_hosts line

    pocketshell-gateway.<id lower-cased>-<sha256(id)[:12]> <keytype> <base64-blob> <device-id>

in ``${XDG_CONFIG_HOME:-~/.config}/pocketshell/gateway_known_hosts``
(directory 0700, file 0600, written atomically). The trailing field is the
known_hosts *comment* (ignored by OpenSSH) and records the exact device id;
the name must equal :func:`host_key_alias` of that id. `gateway ssh` hands
the file to OpenSSH as its only known_hosts (``UserKnownHostsFile``) with
``HostKeyAlias=<that name>`` and ``StrictHostKeyChecking=yes``.

OpenSSH compares known_hosts names case-insensitively, so ``Home-Lab`` and
``home-lab`` must never share a name: the hash of the exact id keeps their
aliases distinct, and on top of that two pinned ids that differ only in
case are refused outright (on write and on read).

Migration: files written before the hashed alias hold three-field lines
``pocketshell-gateway.<device-id> <keytype> <base64>``. They are still
accepted (same strict validation); `gateway ssh` verifies against the alias
that is actually in the file, and the next `pin`/`unpin` rewrites every
line in the current format.

The key comes out of band — `pocketshell gateway show --host-key` run on
the host itself — and never from the gateway (the gateway's
``ready.ssh_host_key`` and the device listing are advisory and untrusted).

Because OpenSSH would honor *any* known_hosts syntax in this file
(``@cert-authority`` / ``@revoked`` markers, wildcard host patterns, hashed
names, extra fields), every line is validated strictly on write AND on
every read: the file must consist solely of lines this module produces.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import stat
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from pocketshell.gateway.endpoint import (
    DEVICE_ID_RE,
    HOST_KEY_ALIAS_PREFIX,
    EndpointError,
    host_key_alias,
    validate_device_id,
)

PIN_FILE_NAME = "gateway_known_hosts"
MAX_PIN_FILE_BYTES = 1 << 20
MAX_KEY_BLOB_BYTES = 8192
MIN_RSA_BITS = 2048

_ECDSA_CURVES = {
    "ecdsa-sha2-nistp256": ("nistp256", 65),
    "ecdsa-sha2-nistp384": ("nistp384", 97),
    "ecdsa-sha2-nistp521": ("nistp521", 133),
}
KEY_TYPES = ("ssh-ed25519", *_ECDSA_CURVES, "ssh-rsa")
_KEY_TYPE_LABEL = {
    "ssh-ed25519": "ED25519",
    "ecdsa-sha2-nistp256": "ECDSA",
    "ecdsa-sha2-nistp384": "ECDSA",
    "ecdsa-sha2-nistp521": "ECDSA",
    "ssh-rsa": "RSA",
}
_B64_RE = re.compile(r"\A[A-Za-z0-9+/]+={0,2}\Z")


class PinError(Exception):
    """A pin that is malformed, missing, or a pin file that is unsafe.

    The message is safe to print (no raw untrusted bytes)."""


@dataclass(frozen=True)
class HostKey:
    key_type: str
    blob_b64: str

    @property
    def line(self) -> str:
        return f"{self.key_type} {self.blob_b64}"

    @property
    def fingerprint(self) -> str:
        return fingerprint_of_blob(base64.b64decode(self.blob_b64))

    @property
    def label(self) -> str:
        return _KEY_TYPE_LABEL[self.key_type]


def fingerprint_of_blob(blob: bytes) -> str:
    """OpenSSH ``SHA256:`` fingerprint (unpadded base64) of a key blob."""
    digest = hashlib.sha256(blob).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


# --- SSH wire-format parsing ------------------------------------------------


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def string(self) -> bytes:
        if len(self.data) - self.pos < 4:
            raise PinError("truncated key blob")
        (n,) = struct.unpack(">I", self.data[self.pos : self.pos + 4])
        self.pos += 4
        if n > len(self.data) - self.pos:
            raise PinError("truncated key blob")
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def mpint_positive(self) -> int:
        raw = self.string()
        if not raw:
            raise PinError("malformed RSA key (empty integer)")
        if raw[0] & 0x80:
            raise PinError("malformed RSA key (negative integer)")
        if len(raw) > 1 and raw[0] == 0 and not raw[1] & 0x80:
            raise PinError("malformed RSA key (non-minimal integer)")
        return int.from_bytes(raw, "big")

    def done(self) -> None:
        if self.pos != len(self.data):
            raise PinError("trailing bytes after the key blob")


def _check_blob(key_type: str, blob: bytes) -> None:
    r = _Reader(blob)
    try:
        inner_type = r.string().decode("ascii")
    except UnicodeDecodeError as exc:
        raise PinError("key blob type is not ASCII") from exc
    if inner_type != key_type:
        raise PinError(
            f"key blob is of type {ascii(inner_type)[:40]}, not the stated {key_type}"
        )
    if key_type == "ssh-ed25519":
        if len(r.string()) != 32:
            raise PinError("malformed ssh-ed25519 key (public key must be 32 bytes)")
    elif key_type in _ECDSA_CURVES:
        curve, point_len = _ECDSA_CURVES[key_type]
        if r.string() != curve.encode():
            raise PinError(f"malformed {key_type} key (curve is not {curve})")
        point = r.string()
        if len(point) != point_len or point[0] != 0x04:
            raise PinError(f"malformed {key_type} key (bad public point)")
    else:  # ssh-rsa
        e = r.mpint_positive()
        n = r.mpint_positive()
        if e < 3 or e % 2 == 0:
            raise PinError("malformed ssh-rsa key (bad public exponent)")
        if n.bit_length() < MIN_RSA_BITS:
            raise PinError(
                f"ssh-rsa host key is {n.bit_length()} bits; at least "
                f"{MIN_RSA_BITS} are required"
            )
    r.done()


def parse_host_key(text: str) -> HostKey:
    """Validate a ``<keytype> <base64>`` host-key line.

    Exactly two space-separated fields; printable ASCII only (so no
    newline can smuggle a second known_hosts line and no marker such as
    ``@cert-authority``/``@revoked`` can appear); a supported key type;
    canonical base64 that decodes to a well-formed key blob of the stated
    type with nothing trailing. A trailing comment is refused rather than
    silently dropped: pin exactly what `gateway show --host-key` prints.
    """
    if not isinstance(text, str):
        raise PinError("host key must be text")
    stripped = text.strip(" ")
    if not stripped:
        raise PinError("host key line is empty")
    if any(not (0x20 <= ord(c) <= 0x7E) for c in stripped):
        raise PinError(
            "host key line contains a newline, tab, control or non-ASCII "
            "character; paste exactly one '<keytype> <base64>' line"
        )
    fields = stripped.split(" ")
    if len(fields) != 2 or not all(fields):
        raise PinError(
            "host key line must be exactly '<keytype> <base64>' separated by "
            "one space (no options, markers, host names or comments)"
        )
    key_type, b64 = fields
    if key_type not in KEY_TYPES:
        raise PinError(
            f"unsupported host key type {ascii(key_type)[:40]}; expected one "
            f"of {', '.join(KEY_TYPES)}"
        )
    if not _B64_RE.match(b64) or len(b64) % 4:
        raise PinError("host key blob is not valid base64")
    try:
        blob = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise PinError("host key blob is not valid base64") from exc
    if base64.b64encode(blob).decode("ascii") != b64:
        raise PinError("host key blob is not canonical base64")
    if len(blob) > MAX_KEY_BLOB_BYTES:
        raise PinError("host key blob is too large")
    _check_blob(key_type, blob)
    return HostKey(key_type=key_type, blob_b64=b64)


# --- the pin file -----------------------------------------------------------


def config_dir() -> Path:
    """``${XDG_CONFIG_HOME:-~/.config}/pocketshell`` (a relative
    XDG_CONFIG_HOME is ignored, as the XDG spec requires)."""
    xdg = os.environ.get("XDG_CONFIG_HOME", "")
    base = Path(xdg) if xdg and os.path.isabs(xdg) else Path.home() / ".config"
    return base / "pocketshell"


def pin_file_path() -> Path:
    return config_dir() / PIN_FILE_NAME


def _check_owned_private(path: Path, st: os.stat_result, what: str) -> None:
    if st.st_uid != os.getuid():
        raise PinError(f"{what} {path} is not owned by you; refusing to trust it")
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise PinError(
            f"{what} {path} is writable by group/others; fix with "
            f"`chmod go-w {path}` and re-check its contents"
        )


@dataclass(frozen=True)
class PinEntry:
    """One validated pin: the exact device id, its key, and the known_hosts
    name it is stored under (the current alias, or a legacy one)."""

    device_id: str
    key: HostKey
    alias: str

    @property
    def legacy(self) -> bool:
        return self.alias != host_key_alias(self.device_id)


def _not_a_pin(path: Path, lineno: int) -> PinError:
    return PinError(
        f"{path}:{lineno} is not a pocketshell gateway pin; this file "
        "must only be edited with `pocketshell gateway pin/unpin`"
    )


def _parse_pin_line(line: str, lineno: int, path: Path) -> PinEntry:
    fields = line.split(" ")
    if len(fields) not in (3, 4) or not fields[0].startswith(HOST_KEY_ALIAS_PREFIX):
        raise _not_a_pin(path, lineno)
    alias = fields[0]
    if len(fields) == 4:
        device_id = fields[3]
        if not DEVICE_ID_RE.match(device_id):
            raise PinError(f"{path}:{lineno} has an invalid device id")
        if alias != host_key_alias(device_id):
            raise _not_a_pin(path, lineno)
    else:  # legacy: pocketshell-gateway.<device-id> <keytype> <base64>
        device_id = alias[len(HOST_KEY_ALIAS_PREFIX) :]
        if not DEVICE_ID_RE.match(device_id):
            raise PinError(f"{path}:{lineno} has an invalid device id")
    try:
        key = parse_host_key(" ".join(fields[1:3]))
    except PinError as exc:
        raise PinError(f"{path}:{lineno}: {exc}") from None
    return PinEntry(device_id=device_id, key=key, alias=alias)


def _case_collision(device_id: str, existing) -> Optional[str]:
    folded = device_id.lower()
    for other in existing:
        if other != device_id and other.lower() == folded:
            return other
    return None


def load_pin_entries(path: Optional[Path] = None) -> dict[str, PinEntry]:
    """Read and strictly validate the whole pin file (see :func:`load_pins`)."""
    path = path or pin_file_path()
    if os.name == "nt":
        from pocketshell.windows_security import read_private
        try:
            data = read_private(path, MAX_PIN_FILE_BYTES)
        except FileNotFoundError:
            return {}
        except OSError:
            raise PinError("Windows pin storage has an unsafe owner/DACL/reparse point or is inaccessible") from None
    else:
        # The containing directory must be ours and not group/world-writable:
        # otherwise someone else could swap the file between this check and
        # OpenSSH reading it by name (and only `pin` would have tightened it).
        try:
            dfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        except FileNotFoundError:
            return {}
        except OSError as exc:
            raise PinError(f"cannot open pin directory {path.parent}: {exc.strerror}") from None
        try:
            _check_owned_private(path.parent, os.fstat(dfd), "pin directory")
            try:
                fd = os.open(
                    path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dfd
                )
            except FileNotFoundError:
                return {}
            except OSError as exc:
                raise PinError(f"cannot open pin file {path}: {exc.strerror}") from None
        finally:
            os.close(dfd)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise PinError(f"pin file {path} is not a regular file")
            _check_owned_private(path, st, "pin file")
            data = os.read(fd, MAX_PIN_FILE_BYTES + 1)
        finally:
            os.close(fd)
    if len(data) > MAX_PIN_FILE_BYTES:
        raise PinError(f"pin file {path} is too large")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise PinError(f"pin file {path} contains non-ASCII bytes") from None
    if text and not text.endswith("\n"):
        raise PinError(f"pin file {path} is truncated (no final newline)")
    entries: dict[str, PinEntry] = {}
    for lineno, line in enumerate(text.split("\n")[:-1], start=1):
        entry = _parse_pin_line(line, lineno, path)
        if entry.device_id in entries:
            raise PinError(f"{path}:{lineno} pins device {entry.device_id} twice")
        other = _case_collision(entry.device_id, entries)
        if other is not None:
            raise PinError(
                f"{path}:{lineno} pins device {entry.device_id}, which differs from "
                f"pinned device {other} only in letter case; OpenSSH would not "
                "tell them apart. Remove one with `pocketshell gateway unpin`."
            )
        entries[entry.device_id] = entry
    return entries


def load_pins(path: Optional[Path] = None) -> dict[str, HostKey]:
    """Read and strictly validate the whole pin file.

    Missing file → no pins. Any foreign line (a ``@cert-authority`` /
    ``@revoked`` marker, a wildcard or hashed host, a comment that is not
    the line's own device id, a second key for one device, two ids that
    differ only in case) makes the whole file untrusted and raises,
    because OpenSSH would honor it when the file is used as known_hosts.
    """
    return {device_id: e.key for device_id, e in load_pin_entries(path).items()}


def _ensure_private_dir(directory: Path) -> None:
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = os.lstat(directory)
    if not stat.S_ISDIR(st.st_mode):
        raise PinError(f"{directory} is not a directory")
    _check_owned_private(directory, st, "config directory")


def _write_pins(pins: dict[str, HostKey], path: Path) -> None:
    directory = path.parent
    if os.name != "nt":
        _ensure_private_dir(directory)
    # Always the current format: legacy lines are migrated on every write.
    body = "".join(
        f"{host_key_alias(device_id)} {key.line} {device_id}\n"
        for device_id, key in sorted(pins.items())
    ).encode("ascii")
    if os.name == "nt":
        from pocketshell.windows_security import write_private
        try:
            write_private(path, body)
        except OSError:
            raise PinError("Cannot safely save Windows pins; check the private directory DACL and reparse points") from None
        return
    tmp = directory / f".{PIN_FILE_NAME}.{os.getpid()}.{os.urandom(4).hex()}.tmp"
    fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC, 0o600)
    try:
        try:
            view = memoryview(body)
            while view:
                view = view[os.write(fd, view) :]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise
    dir_fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def add_pin(
    device_id: str, key: HostKey, *, replace: bool = False, path: Optional[Path] = None
) -> bool:
    """Pin ``key`` for ``device_id``. Returns False if it was already pinned.

    A *different* key already pinned for the device is refused unless
    ``replace`` — silently swapping a pin is exactly what an attacker
    would want.
    """
    try:
        validate_device_id(device_id)
    except EndpointError as exc:
        raise PinError(str(exc)) from None
    path = path or pin_file_path()
    entries = load_pin_entries(path)
    pins = {i: e.key for i, e in entries.items()}
    other = _case_collision(device_id, pins)
    if other is not None:
        raise PinError(
            f"device {device_id} differs from the already pinned device {other} "
            "only in letter case; OpenSSH would not tell them apart. Unpin "
            f"{other} first if it is really the same host."
        )
    current = pins.get(device_id)
    if current == key and not any(e.legacy for e in entries.values()):
        return False
    if current == key:
        _write_pins(pins, path)  # migrate legacy lines; the pin itself is unchanged
        return False
    if current is not None and not replace:
        raise PinError(
            f"device {device_id} already has a different pinned host key "
            f"({current.fingerprint}). If the host was really re-keyed, "
            "verify the new key on the host and re-run with --replace."
        )
    pins[device_id] = key
    _write_pins(pins, path)
    return True


def remove_pin(device_id: str, *, path: Optional[Path] = None) -> HostKey:
    """Remove and return the pin for ``device_id``; raises if none."""
    try:
        validate_device_id(device_id)
    except EndpointError as exc:
        raise PinError(str(exc)) from None
    path = path or pin_file_path()
    pins = load_pins(path)
    key = pins.pop(device_id, None)
    if key is None:
        raise PinError(f"no host key is pinned for device {device_id}")
    _write_pins(pins, path)
    return key


def require_pin(device_id: str, *, path: Optional[Path] = None) -> HostKey:
    """The pinned key for ``device_id`` (validating the whole file)."""
    return require_pin_entry(device_id, path=path).key


def require_pin_entry(device_id: str, *, path: Optional[Path] = None) -> PinEntry:
    """The pin for ``device_id`` with the alias actually in the file."""
    path = path or pin_file_path()
    entry = load_pin_entries(path).get(device_id)
    if entry is None:
        raise PinError(
            f"no host key is pinned for device {device_id}. On the host, run\n"
            "    pocketshell gateway show --host-key\n"
            "then here run\n"
            f"    pocketshell gateway pin {device_id}\n"
            "and paste that one key line when prompted. The gateway's "
            "advertised key is never trusted."
        )
    return entry
