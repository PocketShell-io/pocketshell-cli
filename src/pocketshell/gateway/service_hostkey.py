"""Exact host-key readiness for the loopback endpoint.

An SSH-2.0 banner proves nothing about WHICH server answers. Readiness
instead performs a real SSH key exchange with the OpenSSH client against
``127.0.0.1:<port>``, with strict host-key checking against a throw-away
known_hosts that holds ONLY the enrolled pinned host key. The client verifies
the server's signature over the exchange hash, so only a daemon holding the
enrolled host PRIVATE key passes. No authentication is attempted (every
method off, a non-existent probe user): the expected outcome of a matching
key is the client's own "Permission denied", of a different key "Host key
verification failed" / "REMOTE HOST IDENTIFICATION HAS CHANGED".
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from typing import Callable, Optional

from pocketshell.gateway.service_common import ChildResult, ServiceError, decode, run_child, sanitize

PROBE_USER = "pocketshell-hostkey-probe"
_MISMATCH = (
    "host key verification failed",
    "remote host identification has changed",
    "no matching host key type",
)
_ACCEPTED = ("permission denied",)


def find_ssh() -> str:
    if sys.platform == "win32":
        from pocketshell.gateway import winssh

        try:
            return winssh.find_windows_ssh()
        except winssh.WindowsSshError as exc:
            raise ServiceError(str(exc)) from None
    found = shutil.which("ssh")
    if not found:
        raise ServiceError("the OpenSSH client `ssh` is needed to verify the endpoint host key")
    return found


def _option_path(path: str) -> str:
    if sys.platform == "win32":
        from pocketshell.gateway import winssh

        return winssh.ssh_option_path(path, "known_hosts")
    if any(ch.isspace() or ch in "'#\"" for ch in path):
        raise ServiceError("temporary known_hosts path is not usable by ssh")
    return path


def _algorithms(key_type: str) -> str:
    if key_type == "ssh-rsa":
        return "rsa-sha2-512,rsa-sha2-256"
    return key_type


def probe_argv(ssh: str, port: int, known_hosts: str, key_type: str) -> list:
    known = _option_path(known_hosts)
    return [
        ssh, "-F", "none",
        "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={known}",
        "-o", f"GlobalKnownHostsFile={known}",
        "-o", f"HostKeyAlgorithms={_algorithms(key_type)}",
        "-o", "PubkeyAuthentication=no",
        "-o", "PasswordAuthentication=no",
        "-o", "KbdInteractiveAuthentication=no",
        "-o", "GSSAPIAuthentication=no",
        "-o", "HostbasedAuthentication=no",
        "-o", "ConnectTimeout=5",
        "-o", "ConnectionAttempts=1",
        "-o", "LogLevel=ERROR",
        "-p", str(port), "-l", PROBE_USER, "127.0.0.1", "exit",
    ]


def verify_host_key(
    port: int,
    host_key,
    *,
    ssh: Optional[str] = None,
    runner: Optional[Callable[..., ChildResult]] = None,
) -> tuple:
    """(ok, detail): does 127.0.0.1:<port> prove possession of ``host_key``
    (a pins.HostKey)? Never raises for a mismatch; raises ServiceError only
    when the probe itself cannot run."""
    runner = runner or run_child
    ssh = ssh or find_ssh()
    tmpdir = tempfile.mkdtemp(prefix="pshk-")
    try:
        known = os.path.join(tmpdir, "known_hosts")
        with open(known, "w", encoding="ascii", newline="\n") as handle:
            handle.write(f"[127.0.0.1]:{port} {host_key.line}\n")
        result = runner(probe_argv(ssh, port, known, host_key.key_type), timeout=20)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    text = decode(result.stderr + result.stdout)
    low = text.lower()
    if any(marker in low for marker in _MISMATCH):
        return False, f"127.0.0.1:{port} does NOT prove the enrolled host key {host_key.fingerprint}"
    if result.returncode == 255 and any(marker in low for marker in _ACCEPTED):
        return True, f"127.0.0.1:{port} proved the enrolled host key {host_key.fingerprint}"
    return False, (
        f"could not verify the host key on 127.0.0.1:{port} (ssh exit {result.returncode}: "
        f"{sanitize(text, 200) or 'no output'})"
    )
