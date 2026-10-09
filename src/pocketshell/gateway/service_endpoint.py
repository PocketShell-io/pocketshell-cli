"""Private loopback SSH endpoint for ``gateway service install --with-endpoint``.

The outbound link task alone is not a usable Windows host: every gateway
stream is bridged to the enrolled loopback sshd. When that sshd is a private
endpoint (e.g. a pinned MSYS build supervised by its own guardian), it needs a
durable owner of its own. This module describes it as a reviewed **endpoint
manifest** and turns it into a second managed task,
``\\PocketShell\\GatewayEndpoint``, with the same rules as the link task: the
current user's SID, S4U, LeastPrivilege, session 0, one direct Exec of the
guardian (no shell, no cmd.exe), boot trigger + 5-minute IgnoreNew watchdog.

What is launched belongs to the endpoint maintainer (the manifest); how it is
launched belongs to this CLI. Nothing here builds, copies, edits or stops the
endpoint's own files, keys, config or processes.

Manifest (JSON, UTF-8, at most 64 KiB), schema 1::

    {
      "schema": 1,
      "name": "quiet-sshd-v26a",
      "guardian": {
        "command": "C:\\\\...\\\\guardian.exe",
        "sha256": "<64 hex>",
        "arguments": ["...", "..."],
        "working_directory": "C:\\\\..."
      },
      "pinned_files": [{"path": "C:\\\\...\\\\sshd.exe", "sha256": "<64 hex>"}],
      "listen": "127.0.0.1:22024",
      "host_key_fingerprint": "SHA256:..."
    }

Trust: the sha256 of the manifest FILE must be on the reviewed
:data:`ALLOWED_ENDPOINT_MANIFEST_SHA256` list (a source constant, initially
empty: no endpoint is trusted until its manifest is reviewed). That binds the
guardian digest, its argv, its working directory, every pinned file and the
endpoint identity; each declared digest is then re-checked against the files
on disk. ``listen`` must equal the enrolled ``local ssh`` and
``host_key_fingerprint`` the enrolled pinned host key (both from the helper's
own ``show``), so the endpoint task can only serve the device it belongs to.
"""

from __future__ import annotations

import hashlib
import json
import re
import socket
from dataclasses import dataclass
from typing import Callable

from pocketshell.gateway.service_common import ServiceError, has_control_chars, parse_show, sanitize

ENDPOINT_LEAF = "GatewayEndpoint"
ENDPOINT_BOOT_DELAY = "PT10S"  # the link task keeps PT30S: soft ordering only
MAX_MANIFEST_BYTES = 64 * 1024
MAX_ARGUMENTS = 32
MAX_PINNED_FILES = 64
BANNER_TIMEOUT_SECONDS = 3.0

# Reviewed endpoint manifests (sha256 of the manifest file). Adding one is a
# reviewed source change, never a flag or environment variable. EMPTY until
# the endpoint maintainer's manifest for quiet-sshd-v26a has been reviewed.
ALLOWED_ENDPOINT_MANIFEST_SHA256: frozenset = frozenset()

_HEX64 = re.compile(r"[0-9a-f]{64}")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
_FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}")
_TOP_KEYS = {"schema", "name", "guardian", "pinned_files", "listen", "host_key_fingerprint"}
_GUARDIAN_KEYS = {"command", "sha256", "arguments", "working_directory"}


@dataclass(frozen=True)
class EndpointManifest:
    name: str
    command: str
    command_sha256: str
    arguments: tuple
    working_directory: str
    pinned_files: tuple  # ((path, sha256), ...)
    listen_host: str
    listen_port: int
    host_key_fingerprint: str
    manifest_sha256: str

    @property
    def listen(self) -> str:
        return f"{self.listen_host}:{self.listen_port}"


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ServiceError(f"endpoint manifest: {message}")


def parse_manifest(data: bytes, *, validate_path: Callable[[str, str], str]) -> EndpointManifest:
    """Strictly parse a manifest (structure only; trust is checked separately)."""
    _require(len(data) <= MAX_MANIFEST_BYTES, "larger than 64 KiB")
    try:
        doc = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ServiceError("endpoint manifest: not UTF-8 JSON") from None
    _require(isinstance(doc, dict), "not a JSON object")
    unknown = set(doc) - _TOP_KEYS
    _require(not unknown, f"unknown key(s) {sorted(unknown)}")
    _require(doc.get("schema") == 1, "schema must be 1")
    name = doc.get("name")
    _require(isinstance(name, str) and bool(_NAME.fullmatch(name)), "name must match [A-Za-z0-9._-]{1,64}")

    guardian = doc.get("guardian")
    _require(isinstance(guardian, dict), "guardian must be an object")
    unknown = set(guardian) - _GUARDIAN_KEYS
    _require(not unknown, f"unknown guardian key(s) {sorted(unknown)}")
    command = guardian.get("command")
    _require(isinstance(command, str), "guardian.command must be a string")
    command = validate_path(command, "endpoint guardian command")
    _require(command.lower().endswith(".exe"), "guardian.command must be an absolute .exe")
    digest = guardian.get("sha256")
    _require(isinstance(digest, str) and bool(_HEX64.fullmatch(digest)), "guardian.sha256 must be 64 lowercase hex")
    arguments = guardian.get("arguments", [])
    _require(isinstance(arguments, list) and len(arguments) <= MAX_ARGUMENTS,
             f"guardian.arguments must be a list of at most {MAX_ARGUMENTS} strings")
    for arg in arguments:
        _require(isinstance(arg, str), "guardian.arguments must be strings")
        _require(not has_control_chars(arg) and '"' not in arg and "%" not in arg,
                 "a guardian argument contains a double quote, '%' or a control character")
    cwd = guardian.get("working_directory")
    _require(isinstance(cwd, str), "guardian.working_directory must be a string")
    cwd = validate_path(cwd, "endpoint working directory")

    pinned = doc.get("pinned_files", [])
    _require(isinstance(pinned, list) and len(pinned) <= MAX_PINNED_FILES,
             f"pinned_files must be a list of at most {MAX_PINNED_FILES} entries")
    pins = []
    for entry in pinned:
        _require(isinstance(entry, dict) and set(entry) == {"path", "sha256"},
                 "each pinned file is exactly {path, sha256}")
        _require(isinstance(entry["path"], str), "pinned path must be a string")
        _require(isinstance(entry["sha256"], str) and bool(_HEX64.fullmatch(entry["sha256"])),
                 "pinned sha256 must be 64 lowercase hex")
        pins.append((validate_path(entry["path"], "pinned endpoint file"), entry["sha256"]))

    listen = doc.get("listen")
    _require(isinstance(listen, str), "listen must be a string")
    host, _, port = listen.rpartition(":")
    _require(host == "127.0.0.1", "listen must be 127.0.0.1:<port> (loopback IPv4 only)")
    _require(port.isdigit() and 1 <= int(port) <= 65535 and str(int(port)) == port, "listen port is invalid")
    fingerprint = doc.get("host_key_fingerprint")
    _require(isinstance(fingerprint, str) and bool(_FINGERPRINT.fullmatch(fingerprint)),
             "host_key_fingerprint must be an OpenSSH SHA256:... fingerprint")
    return EndpointManifest(
        name=name,
        command=command,
        command_sha256=digest,
        arguments=tuple(arguments),
        working_directory=cwd,
        pinned_files=tuple(pins),
        listen_host=host,
        listen_port=int(port),
        host_key_fingerprint=fingerprint,
        manifest_sha256=hashlib.sha256(data).hexdigest(),
    )


def check_trust(manifest: EndpointManifest, *, file_sha256: Callable[[str], str]) -> None:
    """Reviewed manifest digest, then every declared digest against the disk."""
    if manifest.manifest_sha256 not in ALLOWED_ENDPOINT_MANIFEST_SHA256:
        raise ServiceError(
            f"endpoint manifest sha256 {manifest.manifest_sha256[:12]}… is not a reviewed "
            "endpoint manifest (ALLOWED_ENDPOINT_MANIFEST_SHA256)"
        )
    if file_sha256(manifest.command) != manifest.command_sha256:
        raise ServiceError("the endpoint guardian's sha256 does not match its manifest")
    for path, digest in manifest.pinned_files:
        if file_sha256(path) != digest:
            raise ServiceError(f"pinned endpoint file {sanitize(path)} does not match its manifest digest")


def check_binding(manifest: EndpointManifest, show_text: str) -> None:
    """The endpoint must be the enrolled local sshd: same address, same host key."""
    from pocketshell.gateway import pins as gateway_pins

    fields = parse_show(show_text)
    local = (fields.get("local ssh") or "").split()
    if not local or local[0] != manifest.listen:
        raise ServiceError(
            f"the endpoint listens on {manifest.listen} but the enrolled local ssh is "
            f"{sanitize(local[0] if local else '(none)', 80)}; it would not serve this device"
        )
    try:
        key = gateway_pins.parse_host_key(fields.get("pinned ssh host key", ""))
    except gateway_pins.PinError:
        raise ServiceError("the enrollment has no usable pinned host key to bind the endpoint to") from None
    if key.fingerprint != manifest.host_key_fingerprint:
        raise ServiceError(
            f"the endpoint host key {manifest.host_key_fingerprint} is not the enrolled "
            f"pinned host key {key.fingerprint}"
        )


def endpoint_arguments(manifest: EndpointManifest, quote: Callable[[str], str]) -> str:
    return " ".join(quote(arg) for arg in manifest.arguments)


def port_in_use(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=1.0):
            return True
    except OSError:
        return False


def probe_banner(host: str, port: int) -> tuple:
    """(ok, detail): connect, read the SSH identification line, close.

    Read-only: no key exchange, no authentication.
    """
    try:
        with socket.create_connection((host, port), timeout=BANNER_TIMEOUT_SECONDS) as conn:
            conn.settimeout(BANNER_TIMEOUT_SECONDS)
            data = b""
            while b"\n" not in data and len(data) < 256:
                chunk = conn.recv(256 - len(data))
                if not chunk:
                    break
                data += chunk
    except OSError as exc:
        return False, f"no SSH banner on {host}:{port} ({sanitize(exc.strerror or type(exc).__name__, 80)})"
    line = data.split(b"\n", 1)[0].rstrip(b"\r")
    if line.startswith(b"SSH-2.0-"):
        return True, sanitize(line.decode("ascii", "replace"), 120)
    return False, f"{host}:{port} did not answer with an SSH-2.0 banner"
