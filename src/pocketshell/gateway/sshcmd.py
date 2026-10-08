"""`pocketshell gateway ssh`: exec OpenSSH through the gateway, hardened.

OpenSSH does the SSH: user authentication, encryption, and — the point of
the design — host-key verification against the client's own pin file. The
gateway is just the ProxyCommand transport (:mod:`pocketshell.gateway.proxy`)
and is never trusted with the session.

The ssh argv is fully explicit:

- ``-F none``: the user's ``~/.ssh/config`` (``Host *`` with
  ``ForwardAgent``, ``ProxyJump``, ``LocalCommand``, ``ControlMaster`` …)
  is not read at all;
- every hardening ``-o`` comes FIRST (for ssh the first value of an option
  wins), and user arguments are limited to an allowlist (no ``-o``, no
  ``-F``/``-J``/``-W``/``-A``/``-X``/``-R`` …);
- the destination follows ``--`` so nothing after it is parsed as an
  option;
- ``ProxyCommand`` is built from validated, ``shlex.quote``-d elements with
  ``%`` doubled (ssh's token expansion) and ssh runs it with
  ``SHELL=/bin/sh``; the interpreter is started with ``-P`` so a
  ``pocketshell``/``click`` module in the current directory cannot be
  imported in its place;
- file paths handed to ssh (pin file, identity) are refused if they
  contain whitespace, ``%``, ``$``, ``~``, quotes or backslashes (ssh
  expands ``%``-tokens, ``${ENV}`` and ``~`` in them).
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Sequence

from pocketshell.gateway.endpoint import (
    GatewayEndpoint,
    host_key_alias,
    legacy_host_key_alias,
    validate_device_id,
)


class SshArgsError(ValueError):
    """Refused ssh invocation. Message is safe to print."""


# Options that must hold for every gateway session. Order matters only for
# IgnoreUnknown, which must precede the option it excuses (older OpenSSH
# without EnableEscapeCommandline, < 9.2, where the escape command line is
# unconditionally available — there it is simply not disabled).
HARDENING_OPTIONS: tuple[str, ...] = (
    "IgnoreUnknown=EnableEscapeCommandline",
    "EnableEscapeCommandline=no",
    "StrictHostKeyChecking=yes",
    "GlobalKnownHostsFile=/dev/null",
    "CheckHostIP=no",
    "UpdateHostKeys=no",
    "VerifyHostKeyDNS=no",
    "ForwardAgent=no",
    "ForwardX11=no",
    "ForwardX11Trusted=no",
    "PermitLocalCommand=no",
    "ControlMaster=no",
    "ControlPath=none",
    "ControlPersist=no",
    "ProxyUseFdpass=no",
    "Tunnel=no",
    "CanonicalizeHostname=no",
    "PubkeyAuthentication=yes",
    "PasswordAuthentication=no",
    "KbdInteractiveAuthentication=no",
    "GSSAPIAuthentication=no",
    "HostbasedAuthentication=no",
    "PreferredAuthentications=publickey",
    "IdentitiesOnly=yes",
    "Compression=no",
    "ExitOnForwardFailure=yes",
)

_UNSAFE_PATH_RE = re.compile(r"[\s%$~'\"\\`]|[^\x21-\x7e]")
_USER_RE = re.compile(r"\A[A-Za-z0-9_][A-Za-z0-9._@-]{0,63}\Z")
_FORWARD_SPEC_RE = re.compile(r"\A[A-Za-z0-9_.:/\[\]*-]{1,255}\Z")
_NO_ARG_FLAGS = frozenset("NTtvq")
_FORWARD_FLAGS = frozenset("LD")
_REFUSAL_HINT = (
    "allowed ssh arguments after `--` are -L SPEC, -D SPEC, -N, -T, -t, "
    "-v, -q, then an optional remote command"
)


def _check_path(path: str, what: str) -> str:
    if not os.path.isabs(path):
        raise SshArgsError(f"{what} path must be absolute")
    if _UNSAFE_PATH_RE.search(path):
        raise SshArgsError(
            f"{what} path {ascii(path)[:120]} contains whitespace, '%', '$', "
            "'~', quotes, backslashes or non-ASCII characters, which OpenSSH "
            "would expand or split; move it (or set XDG_CONFIG_HOME) to a "
            "plain path"
        )
    return path


def _check_proxy_element(value: str) -> str:
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in value) or "\\" in value:
        raise SshArgsError(
            f"refusing to put {ascii(value)[:120]} in a ProxyCommand "
            "(control characters or backslash)"
        )
    return value


def proxy_command(
    device_id: str,
    endpoint: GatewayEndpoint,
    *,
    python: Optional[str] = None,
    insecure_dev: bool = False,
) -> str:
    """The ProxyCommand string: quoted argv, ``%`` escaped for ssh."""
    python = sys.executable if python is None else python
    if not python or not os.path.isabs(python):
        raise SshArgsError("cannot locate an absolute Python interpreter path")
    argv = [python, "-P", "-m", "pocketshell", "gateway", "proxy", validate_device_id(device_id)]
    if not endpoint.is_production or endpoint.ws_base != "wss://gateway.pocketshell.io":
        argv += ["--server", endpoint.ws_base]
    if not endpoint.is_production:
        argv += ["--trust-gateway", endpoint.host]
    if insecure_dev:
        argv.append("--insecure-dev")
    return " ".join(shlex.quote(_check_proxy_element(a)).replace("%", "%%") for a in argv)


@dataclass
class ExtraArgs:
    flags: list[str] = field(default_factory=list)
    command: list[str] = field(default_factory=list)
    has_forwards: bool = False


def parse_extra_args(extra: Sequence[str]) -> ExtraArgs:
    """Split user-supplied ssh arguments into allowlisted flags + command.

    Flags come first: ``-L SPEC`` / ``-D SPEC`` (attached or separate),
    and bundles of ``-N -T -t -v -q``. An optional ``--`` ends the flags;
    the first non-flag word starts the remote command, which is passed to
    ssh verbatim after the destination (it runs in the REMOTE shell, as
    with plain ssh). Everything else — ``-o`` overrides in particular — is
    refused.
    """
    out = ExtraArgs()
    items = list(extra)
    i = 0
    while i < len(items):
        arg = items[i]
        if arg == "--":
            out.command = items[i + 1 :]
            return out
        if not arg.startswith("-") or arg == "-":
            out.command = items[i:]
            return out
        letter = arg[1:2]
        if letter in _FORWARD_FLAGS:
            spec = arg[2:]
            if not spec:
                i += 1
                if i >= len(items):
                    raise SshArgsError(f"{arg} needs a forwarding spec")
                spec = items[i]
            if spec.startswith("-") or not _FORWARD_SPEC_RE.match(spec):
                raise SshArgsError(f"invalid forwarding spec {ascii(spec)[:80]}")
            out.flags += [f"-{letter}", spec]
            out.has_forwards = True
        elif len(arg) > 1 and all(c in _NO_ARG_FLAGS for c in arg[1:]):
            out.flags.append(arg)
        else:
            raise SshArgsError(f"ssh argument {ascii(arg)[:40]} is not allowed; {_REFUSAL_HINT}")
        i += 1
    return out


def build_ssh_argv(
    *,
    ssh: str,
    device_id: str,
    endpoint: GatewayEndpoint,
    pin_file: Path,
    user: Optional[str] = None,
    identity: Optional[str] = None,
    extra: Sequence[str] = (),
    insecure_dev: bool = False,
    python: Optional[str] = None,
    alias: Optional[str] = None,
) -> list[str]:
    """The complete, hardened ssh argv (argv[0] is the ssh path).

    ``alias`` is the known_hosts name the pin is stored under
    (:attr:`pocketshell.gateway.pins.PinEntry.alias`); it must be this
    device's current or legacy alias. Default: the current one.
    """
    current = host_key_alias(device_id)
    if alias is None:
        alias = current
    elif alias not in (current, legacy_host_key_alias(device_id)):
        raise SshArgsError(f"host key alias does not belong to device {device_id}")
    if not os.path.isabs(ssh):
        raise SshArgsError("ssh path must be absolute")
    pin_path = _check_path(str(pin_file), "pin file")
    parsed = parse_extra_args(extra)
    argv = [ssh, "-F", "none"]
    for opt in HARDENING_OPTIONS:
        argv += ["-o", opt]
    if not parsed.has_forwards:
        argv += ["-o", "ClearAllForwardings=yes"]
    argv += [
        "-o", f"UserKnownHostsFile={pin_path}",
        "-o", f"HostKeyAlias={alias}",
        "-o", "ProxyCommand="
        + proxy_command(device_id, endpoint, python=python, insecure_dev=insecure_dev),
    ]
    if user is not None:
        if not _USER_RE.match(user):
            raise SshArgsError(f"invalid login name {ascii(user)[:80]}")
        argv += ["-l", user]
    if identity is not None:
        ident = _check_path(os.path.abspath(identity), "identity file")
        if not os.path.isfile(ident):
            raise SshArgsError(f"identity file {ident} does not exist")
        argv += ["-i", ident]
    argv += parsed.flags
    argv += ["--", alias, *parsed.command]
    return argv


def find_ssh() -> str:
    found = shutil.which("ssh")
    if not found:
        raise SshArgsError("OpenSSH client `ssh` was not found on PATH")
    return os.path.abspath(found)


def ssh_environment(base: Optional[dict] = None) -> dict:
    """ssh's environment: ProxyCommand always runs under /bin/sh."""
    env = dict(os.environ if base is None else base)
    env["SHELL"] = "/bin/sh"
    return env
