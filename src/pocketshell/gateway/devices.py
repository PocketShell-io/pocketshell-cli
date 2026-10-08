"""`pocketshell gateway devices`: list the account's enrolled hosts.

``GET <gateway https base>/identity/v1/devices`` with the broker JWT as a
Bearer header (never in the URL). Everything in the answer is untrusted
display data: ids are re-validated, the advertised SSH host key is shown
only as an *advertised* fingerprint and never becomes a pin.
"""

from __future__ import annotations

import http.client
import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional

from pocketshell.gateway.endpoint import DEVICE_ID_RE, GatewayEndpoint
from pocketshell.gateway.pins import HostKey, PinError, parse_host_key
from pocketshell.gateway.tokens import TokenProvider, obtain_token, sanitize_remote_text
from pocketshell.tokentls import token_opener

HTTP_TIMEOUT_SECONDS = 15.0
MAX_RESPONSE_BYTES = 1 << 20
MAX_DEVICES = 1000


class DevicesError(Exception):
    """Listing failed. Message is safe to print."""


@dataclass(frozen=True)
class DeviceInfo:
    id: str  # raw from the gateway; display via display_id
    id_valid: bool
    revoked: bool
    advertised_key: Optional[HostKey]

    @property
    def display_id(self) -> str:
        return self.id if self.id_valid else sanitize_remote_text(self.id, 64)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: urllib would re-send the Authorization
    header to wherever the gateway points it."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def _opener() -> urllib.request.OpenerDirector:
    # No environment proxy, no SSL_CERT_FILE/SSL_CERT_DIR: see
    # pocketshell.tokentls.
    return token_opener(_NoRedirect())


def _strict_pairs(pairs):
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise ValueError("duplicate key")
        seen[key] = value
    return seen


def _reject_constant(_token):
    raise ValueError("non-JSON constant")


def parse_devices(body: bytes) -> list[DeviceInfo]:
    try:
        doc = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_strict_pairs,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise DevicesError("gateway returned a malformed device list") from None
    devices = doc.get("devices") if isinstance(doc, dict) else None
    if not isinstance(devices, list):
        raise DevicesError("gateway returned a malformed device list")
    if len(devices) > MAX_DEVICES:
        raise DevicesError("gateway returned too many devices")
    out = []
    for item in devices:
        if not isinstance(item, dict):
            raise DevicesError("gateway returned a malformed device entry")
        for name, kind in (
            ("id", str),
            ("account_id", str),
            ("public_key", str),
            ("ssh_host_key", str),
            ("revoked", bool),
        ):
            if not isinstance(item.get(name), kind):
                raise DevicesError(
                    f"gateway returned a device entry with a missing or "
                    f"mistyped {name!r}"
                )
        try:
            advertised = parse_host_key(item["ssh_host_key"]) if item["ssh_host_key"] else None
        except PinError:
            advertised = None
        out.append(
            DeviceInfo(
                id=item["id"],
                id_valid=bool(DEVICE_ID_RE.match(item["id"])),
                revoked=item["revoked"],
                advertised_key=advertised,
            )
        )
    return out


def fetch_devices(
    endpoint: GatewayEndpoint,
    token_provider: TokenProvider,
    *,
    opener: Optional[urllib.request.OpenerDirector] = None,
    timeout: float = HTTP_TIMEOUT_SECONDS,
) -> list[DeviceInfo]:
    """Fetch and strictly parse the device list (raises DevicesError /
    GatewayTokenError)."""
    token = obtain_token(token_provider)
    request = urllib.request.Request(
        endpoint.devices_url(),
        method="GET",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "User-Agent": "pocketshell-cli",
        },
    )
    try:
        with (opener or _opener()).open(request, timeout=timeout) as resp:
            status = resp.status
            body = resp.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        exc.close()
        reason = {
            401: "the gateway rejected the token (try `pocketshell login` again)",
            403: "the gateway refused the request",
            404: "this gateway does not serve the device listing",
            429: "the gateway is rate limiting requests; retry later",
        }.get(exc.code)
        if 300 <= exc.code < 400:
            reason = "the gateway answered with a redirect, which is not followed"
        raise DevicesError(reason or f"the gateway answered HTTP {exc.code}") from None
    except (urllib.error.URLError, OSError) as exc:
        detail = getattr(exc, "reason", exc)
        raise DevicesError(
            f"cannot reach {endpoint.http_base}: {sanitize_remote_text(str(detail))}"
        ) from None
    except (http.client.HTTPException, ValueError):
        # e.g. BadStatusLine / IncompleteRead / LineTooLong: their messages
        # quote raw gateway bytes (possibly terminal escapes) — never echo.
        raise DevicesError("malformed HTTP response from the gateway") from None
    if status != 200:
        raise DevicesError(f"the gateway answered HTTP {status}")
    if len(body) > MAX_RESPONSE_BYTES:
        raise DevicesError("gateway device list is too large")
    return parse_devices(body)
