"""Gateway endpoint rules shared by the host wrappers and the client side.

One place for: the production gateway host set (used by the host-side
``--dev-broker-issuer`` refusal and by the client-side ``--insecure-dev``
rules), the device-id grammar the gateway enforces, and the client's
``--server`` resolution (``wss://`` only, plain ``ws://`` only with
``--insecure-dev`` against a loopback/docker lab host).

The host-side wrappers forward ``--server`` to the Go helper verbatim (the
helper owns its own validation). The CLIENT commands (``gateway devices``,
``gateway proxy``, ``gateway ssh``) dial the gateway from Python and send a
broker JWT to it, so they resolve the URL here, strictly.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit

# The built-in production gateway (DefaultServerURL in the Go hostagent).
DEFAULT_SERVER = "wss://gateway.pocketshell.io"

# Both names the production deployment serves (`gateway.pocketshell.io` and
# its legacy `relay.pocketshell.io` alias — DefaultServerURL/LegacyServerURL
# in the Go hostagent), compared DNS-style (case-insensitive, trailing FQDN
# dot ignored) so `gateway.pocketshell.io.` or `RELAY.POCKETSHELL.IO:8080`
# cannot slip past an exact-string check.
PRODUCTION_GATEWAY_HOSTS = frozenset(
    {"gateway.pocketshell.io", "relay.pocketshell.io"}
)

# identity.ValidDeviceID in the gateway (deviceIDPattern). Validated before
# a device id reaches a URL path, a known_hosts alias, or a ProxyCommand.
DEVICE_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{2,63}\Z")

# The known_hosts name a pinned host key is stored under, and the
# HostKeyAlias `gateway ssh` verifies against.
HOST_KEY_ALIAS_PREFIX = "pocketshell-gateway."


class EndpointError(ValueError):
    """A ``--server`` or device id the client refuses. Message is safe to print."""


def canonical_host(server: str) -> str:
    """Canonical (lowercase, no trailing dot) host of a server URL.

    Raises :class:`EndpointError` for a URL urllib cannot parse at all
    (unbalanced brackets, malformed IPv6 literal).
    """
    try:
        host = urlsplit(server).hostname
    except ValueError as exc:
        raise EndpointError(f"--server {server!r} is not a valid URL ({exc})") from exc
    return (host or "").strip().lower().rstrip(".")


def is_production_host(host: str) -> bool:
    return host.strip().lower().rstrip(".") in PRODUCTION_GATEWAY_HOSTS


def validate_device_id(device_id: str) -> str:
    """Return ``device_id`` unchanged if it matches the gateway grammar."""
    if not isinstance(device_id, str) or not DEVICE_ID_RE.match(device_id):
        raise EndpointError(
            f"invalid device id {ascii(device_id)[:80]}: expected 3-64 "
            "characters, letters/digits first, then letters, digits, "
            "'.', '_', ':' or '-'"
        )
    return device_id


def host_key_alias(device_id: str) -> str:
    return HOST_KEY_ALIAS_PREFIX + validate_device_id(device_id)


def _is_dev_host(host: str) -> bool:
    """Hosts plain ``ws://`` may target under ``--insecure-dev``.

    Loopback only — IP literals in 127.0.0.0/8 or ::1, ``localhost`` and
    ``*.localhost`` — plus single-label names (docker-compose service names
    such as ``gateway``), which never resolve through public DNS. The
    broker JWT the client sends is a real, replayable credential, so it
    never crosses a routed network in cleartext.
    """
    if not host or is_production_host(host):
        return False
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        pass
    if host == "localhost" or host.endswith(".localhost"):
        return True
    return "." not in host and re.fullmatch(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?", host) is not None


@dataclass(frozen=True)
class GatewayEndpoint:
    """A resolved gateway: WebSocket base, HTTPS API base, and host."""

    ws_base: str  # e.g. wss://gateway.pocketshell.io (no trailing slash)
    http_base: str  # e.g. https://gateway.pocketshell.io
    host: str  # canonical host, for messages
    is_default: bool  # True when this is the built-in production gateway

    def client_ssh_url(self, device_id: str) -> str:
        return f"{self.ws_base}/api/v1/hosts/{validate_device_id(device_id)}/ssh"

    def devices_url(self) -> str:
        return f"{self.http_base}/identity/v1/devices"


_FORBIDDEN_URL_CHARS = re.compile(r"[\x00-\x20\x7f-\x9f\\'\"`$!]")


def resolve_endpoint(server: Optional[str], insecure_dev: bool) -> GatewayEndpoint:
    """Resolve the client's ``--server`` strictly.

    - absent → the production default ``wss://gateway.pocketshell.io``;
    - ``wss://`` / ``https://`` → TLS (certificate verification is never
      optional);
    - ``ws://`` / ``http://`` → only with ``--insecure-dev`` AND a
      loopback/docker lab host (see :func:`_is_dev_host`), never a
      production host;
    - no credentials, query, fragment or path (the gateway routes are
      absolute), no whitespace, quotes, backslashes or ``$``/backtick (the
      URL is later embedded in an ssh ProxyCommand).
    """
    if server is None:
        server = DEFAULT_SERVER
    if not server.strip():
        raise EndpointError("--server must not be blank")
    if _FORBIDDEN_URL_CHARS.search(server):
        raise EndpointError(
            "--server contains whitespace, control, quote, backslash or "
            "shell characters"
        )
    try:
        parts = urlsplit(server)
        port = parts.port
    except ValueError as exc:
        raise EndpointError(f"--server {server!r} is not a valid URL ({exc})") from exc
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise EndpointError(f"--server {server!r} has no host")
    if parts.username is not None or parts.password is not None:
        raise EndpointError("--server must not contain credentials")
    if parts.query or parts.fragment or parts.path not in ("", "/"):
        raise EndpointError(
            "--server must be a bare origin like wss://gateway.example "
            "(no path, query or fragment)"
        )
    if scheme in ("wss", "https"):
        secure = True
    elif scheme in ("ws", "http"):
        secure = False
        if not insecure_dev:
            raise EndpointError(
                "plain ws:// / http:// gateway URLs require --insecure-dev "
                "(local development only)"
            )
        if not _is_dev_host(host):
            raise EndpointError(
                f"--insecure-dev only allows plain ws:// to a loopback or "
                f"single-label docker host, not {host!r}: the broker token "
                "must never cross a network in cleartext"
            )
    else:
        raise EndpointError(
            f"--server scheme {parts.scheme!r} is not supported (use wss://)"
        )
    netloc_host = f"[{host}]" if ":" in host else host
    netloc = netloc_host if port is None else f"{netloc_host}:{port}"
    ws_base = f"{'wss' if secure else 'ws'}://{netloc}"
    http_base = f"{'https' if secure else 'http'}://{netloc}"
    is_default = secure and host == "gateway.pocketshell.io" and port in (None, 443)
    return GatewayEndpoint(ws_base=ws_base, http_base=http_base, host=host, is_default=is_default)
