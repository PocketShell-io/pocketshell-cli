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


_DNS_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_DNS_NAME_RE = re.compile(rf"\A{_DNS_LABEL}(?:\.{_DNS_LABEL})*\Z")


def normalize_host(host: str) -> str:
    """Strict canonical host: an IP literal, or an IDNA-encoded DNS name of
    ``[a-z0-9.-]`` labels. Raises :class:`EndpointError` otherwise."""
    host = host.strip().rstrip(".").lower()
    if not host:
        raise EndpointError("gateway host is empty")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if not host.isascii():
        try:
            host = host.encode("idna").decode("ascii").lower()
        except UnicodeError:
            raise EndpointError("gateway host is not a valid internationalized name") from None
    if len(host) > 253 or not _DNS_NAME_RE.match(host):
        raise EndpointError(
            f"gateway host {ascii(host)[:80]} is not a valid DNS name or IP literal"
        )
    return host


def _dev_host_status(host: str) -> Optional[str]:
    """Whether plain ``ws://`` may target ``host`` under ``--insecure-dev``.

    Returns ``None`` if refused, ``""`` if allowed silently (a loopback IP
    literal or ``localhost``), or a warning string for a single-label
    docker-compose service name (``gateway``), which never resolves
    through public DNS but does cross the docker bridge network. The
    broker JWT the client sends is a real, replayable credential, so it
    never crosses a routed network in cleartext.
    """
    if is_production_host(host):
        return None
    try:
        return "" if ipaddress.ip_address(host).is_loopback else None
    except ValueError:
        pass
    if host == "localhost":
        return ""
    if "." not in host:
        return (
            f"warning: sending a gateway token in CLEARTEXT to docker host "
            f"{host!r} (--insecure-dev)"
        )
    return None


@dataclass(frozen=True)
class GatewayEndpoint:
    """A resolved gateway: WebSocket base, HTTPS API base, and host."""

    ws_base: str  # e.g. wss://gateway.pocketshell.io (no trailing slash)
    http_base: str  # e.g. https://gateway.pocketshell.io
    host: str  # canonical host
    is_production: bool  # one of PRODUCTION_GATEWAY_HOSTS, over TLS
    warning: str = ""  # one-line notice for stderr, if any

    def client_ssh_url(self, device_id: str) -> str:
        return f"{self.ws_base}/api/v1/hosts/{validate_device_id(device_id)}/ssh"

    def devices_url(self) -> str:
        return f"{self.http_base}/identity/v1/devices"


# Whitespace/controls, quotes, backslash, `%` (also IPv6 zone ids), and
# every shell metacharacter: the URL is later embedded in a ProxyCommand.
_FORBIDDEN_URL_CHARS = re.compile(r"[\x00-\x20\x7f-\x9f\\'\"`$!%;|&<>(){}*?#^~,]")


def resolve_endpoint(
    server: Optional[str], insecure_dev: bool, trust_gateway: Optional[str] = None
) -> GatewayEndpoint:
    """Resolve the client's ``--server`` strictly.

    - absent → the production default ``wss://gateway.pocketshell.io``;
    - ``wss://`` / ``https://`` → TLS (certificate verification is never
      optional);
    - ``ws://`` / ``http://`` → only with ``--insecure-dev`` AND a loopback
      literal / ``localhost`` (or, with a warning, a single-label docker
      host), never a production host;
    - any NON-production host additionally needs ``--trust-gateway HOST``
      naming exactly that host: the client sends it a real broker JWT,
      which a hostile server could replay against the production gateway;
    - strict host grammar (IP literal or IDNA DNS name), no credentials,
      query, fragment or path, no whitespace, quotes, ``%``, backslash or
      shell metacharacters.
    """
    if server is None:
        server = DEFAULT_SERVER
    if not server.strip():
        raise EndpointError("--server must not be blank")
    if _FORBIDDEN_URL_CHARS.search(server):
        raise EndpointError(
            "--server contains whitespace, control, quote, '%', '?', '#', "
            "backslash or shell characters"
        )
    try:
        parts = urlsplit(server)
        port = parts.port
    except ValueError as exc:
        raise EndpointError(f"--server {server!r} is not a valid URL ({exc})") from exc
    scheme = parts.scheme.lower()
    if not parts.hostname:
        raise EndpointError(f"--server {server!r} has no host")
    host = normalize_host(parts.hostname)
    if parts.username is not None or parts.password is not None:
        raise EndpointError("--server must not contain credentials")
    if parts.query or parts.fragment or parts.path not in ("", "/"):
        raise EndpointError(
            "--server must be a bare origin like wss://gateway.example "
            "(no path, query or fragment)"
        )
    warning = ""
    if scheme in ("wss", "https"):
        secure = True
    elif scheme in ("ws", "http"):
        secure = False
        if not insecure_dev:
            raise EndpointError(
                "plain ws:// / http:// gateway URLs require --insecure-dev "
                "(local development only)"
            )
        status = _dev_host_status(host)
        if status is None:
            raise EndpointError(
                f"--insecure-dev only allows plain ws:// to a loopback "
                f"address, localhost or a single-label docker host, not "
                f"{host!r}: the broker token must never cross a network in "
                "cleartext"
            )
        warning = status
    else:
        raise EndpointError(
            f"--server scheme {parts.scheme!r} is not supported (use wss://)"
        )
    is_production = secure and is_production_host(host)
    if not is_production:
        trusted = None
        if trust_gateway is not None:
            try:
                trusted = normalize_host(trust_gateway)
            except EndpointError:
                trusted = None
        if trusted != host:
            raise EndpointError(
                f"{host!r} is not the PocketShell production gateway. The "
                "client sends it a real gateway token, which a hostile server "
                "could replay; confirm you trust it with "
                f"--trust-gateway {host}"
            )
    netloc_host = f"[{host}]" if ":" in host else host
    netloc = netloc_host if port is None else f"{netloc_host}:{port}"
    ws_base = f"{'wss' if secure else 'ws'}://{netloc}"
    http_base = f"{'https' if secure else 'http'}://{netloc}"
    return GatewayEndpoint(
        ws_base=ws_base,
        http_base=http_base,
        host=host,
        is_production=is_production,
        warning=warning,
    )
