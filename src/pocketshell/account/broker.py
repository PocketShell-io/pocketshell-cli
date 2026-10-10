"""Minimal HTTPS client for the PocketShell broker's device-flow/CLI endpoints.

stdlib ``urllib`` only. Hardening relative to a bare ``urlopen``:

* TLS verification always on, against the platform's compiled-in trust
  store only (:func:`pocketshell.tokentls.token_ssl_context`:
  ``SSL_CERT_FILE``/``SSL_CERT_DIR`` are ignored); the base URL went through
  :func:`pocketshell.account.config.validate_broker_url`.
* Environment proxies (``HTTPS_PROXY``, ``http_proxy`` …) are ignored: the
  session token goes straight to the broker.
* Redirects are refused: urllib would replay the ``Authorization`` header to
  whatever ``Location`` says, including an ``http://`` downgrade.
* Every request has a timeout; response bodies are capped at 64 KiB.
* Responses are strict JSON objects and every field we use is type-checked.
* Tokens travel only in the ``Authorization`` header or the JSON body —
  never in a URL — and no exception message ever includes a token, the
  device code, or raw response text.
"""

from __future__ import annotations

import base64
import http.client
import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from pocketshell import __version__
from pocketshell.account.credentials import SESSION_TOKEN_RE
from pocketshell.account.errors import (
    AccountError,
    BrokerRateLimited,
    BrokerUnavailable,
    GatewayToken,
    NotLoggedIn,
)
from pocketshell.account.jsonutil import StrictJSONError, loads_strict
from pocketshell.account.sanitize import clean_text
from pocketshell.tokentls import token_opener

MAX_BODY_BYTES = 64 * 1024
DEFAULT_TIMEOUT = 15.0

_ERROR_CODE_RE = re.compile(r"^[a-z0-9_]{1,64}$")
_DEVICE_CODE_RE = re.compile(r"^[A-Za-z0-9_-]{16,512}$")
_JWT_SEGMENT = r"[A-Za-z0-9_-]+"
_JWT_RE = re.compile(rf"^{_JWT_SEGMENT}\.{_JWT_SEGMENT}\.{_JWT_SEGMENT}$")
_MAX_JWT_LEN = 8192
# The broker mints gateway JWTs for <= 300 s. Allow a little clock skew
# between this machine and the broker when checking `expires_at`.
_GATEWAY_TOKEN_MAX_TTL = 300
_CLOCK_SKEW = 300

_LOGIN_HINT = "run `pocketshell login`"
_RATE_LIMITED = (
    "The PocketShell broker is rate limiting requests from this network "
    "(HTTP 429); try again shortly."
)


def _raise_if_rate_limited(resp: "Response") -> None:
    """429 on a session-bearing endpoint is transient and says nothing about
    the session: never NotLoggedIn (which would invite deleting it)."""
    if resp.status == 429:
        raise BrokerRateLimited(_RATE_LIMITED)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None  # urllib then raises HTTPError(3xx) instead of following


def _build_opener() -> urllib.request.OpenerDirector:
    return token_opener(_NoRedirect())


@dataclass(frozen=True)
class Response:
    status: int
    data: dict | None = field(default=None)

    @property
    def error(self) -> str | None:
        """The OAuth-style ``error`` code if it is a plain identifier."""
        if isinstance(self.data, dict):
            code = self.data.get("error")
            if isinstance(code, str) and _ERROR_CODE_RE.match(code):
                return code
        return None


def _read_capped(stream) -> bytes:
    if stream is None:
        return b""
    body = stream.read(MAX_BODY_BYTES + 1)
    if len(body) > MAX_BODY_BYTES:
        raise AccountError("The broker response was too large; refusing to parse it.")
    return body


def request(
    base_url: str,
    method: str,
    path: str,
    *,
    body: dict | None = None,
    bearer: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> Response:
    """Send one request. ``body=None`` on POST sends an empty body.

    Returns the status and the parsed JSON object (``None`` for an empty or,
    on an error status, unparseable body). Raises :class:`BrokerUnavailable`
    for transport failures and :class:`AccountError` for a malformed success.
    """
    headers = {"Accept": "application/json", "User-Agent": f"pocketshell/{__version__}"}
    data: bytes | None = None
    if method == "POST":
        data = b""
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
    if bearer is not None:
        headers["Authorization"] = f"Bearer {bearer}"
    req = urllib.request.Request(base_url + path, data=data, headers=headers, method=method)
    try:
        resp = _build_opener().open(req, timeout=timeout)
    except urllib.error.HTTPError as exc:
        try:
            raw = _read_capped(exc)
        finally:
            exc.close()
        return Response(exc.code, _parse(raw, exc.code))
    except urllib.error.URLError as exc:
        reason = exc.reason
        if isinstance(reason, ssl.SSLError):
            raise BrokerUnavailable(
                "TLS verification with the PocketShell broker failed."
            ) from None
        raise BrokerUnavailable(
            f"Could not reach the PocketShell broker ({clean_text(str(reason), max_len=120)})."
        ) from None
    except (TimeoutError, socket.timeout):
        raise BrokerUnavailable("The PocketShell broker did not respond in time.") from None
    except (OSError, http.client.HTTPException) as exc:
        raise BrokerUnavailable(
            f"Could not reach the PocketShell broker ({type(exc).__name__})."
        ) from None
    try:
        try:
            raw = _read_capped(resp)
        except (OSError, http.client.HTTPException):
            raise BrokerUnavailable("The PocketShell broker connection failed.") from None
        status = resp.status
    finally:
        resp.close()
    return Response(status, _parse(raw, status))


def _parse(raw: bytes, status: int) -> dict | None:
    if not raw.strip():
        return None
    try:
        value = loads_strict(raw)
    except StrictJSONError:
        value = None
    if isinstance(value, dict):
        return value
    if status >= 400:
        return None
    raise AccountError(f"The broker returned a malformed response (HTTP {status}).")


def describe_failure(resp: Response, what: str) -> str:
    code = resp.error
    suffix = f", {code}" if code else ""
    return f"{what} failed (HTTP {resp.status}{suffix})."


# -- field validation --------------------------------------------------------


def _malformed(what: str, key: str) -> AccountError:
    return AccountError(f"The broker returned a malformed {what} response (field {key!r}).")


def req_str(data: dict | None, key: str, what: str, *, max_len: int = 512) -> str:
    value = (data or {}).get(key)
    if not isinstance(value, str) or not value or len(value) > max_len:
        raise _malformed(what, key)
    return value


def req_int(data: dict | None, key: str, what: str, *, lo: int, hi: int) -> int:
    value = (data or {}).get(key)
    if not isinstance(value, int) or isinstance(value, bool) or not lo <= value <= hi:
        raise _malformed(what, key)
    return value


# -- endpoints ---------------------------------------------------------------


@dataclass(frozen=True)
class DeviceStart:
    device_code: str = field(repr=False)
    user_code: str
    verification_uri: object  # validated by the caller (must be https)
    verification_uri_complete: object
    expires_in: int
    interval: int


def start_device(base_url: str, label: str) -> DeviceStart:
    resp = request(base_url, "POST", "/auth/device/start", body={"label": label})
    if resp.status == 429:
        raise AccountError(
            "Too many login attempts from this network; wait a few minutes and try again."
        )
    if resp.status != 200:
        raise AccountError(describe_failure(resp, "Starting the login"))
    what = "device-start"
    device_code = req_str(resp.data, "device_code", what)
    if not _DEVICE_CODE_RE.match(device_code):
        raise _malformed(what, "device_code")
    data = resp.data or {}
    interval = data.get("interval", 5)
    if not isinstance(interval, int) or isinstance(interval, bool) or not 0 <= interval <= 300:
        raise _malformed(what, "interval")
    return DeviceStart(
        device_code=device_code,
        user_code=req_str(resp.data, "user_code", what, max_len=64),
        verification_uri=data.get("verification_uri"),
        verification_uri_complete=data.get("verification_uri_complete"),
        expires_in=req_int(resp.data, "expires_in", what, lo=1, hi=3600),
        interval=max(interval, 1),
    )


def poll_device(base_url: str, device_code: str, timeout: float = DEFAULT_TIMEOUT) -> Response:
    return request(base_url, "POST", "/auth/device/token", body={"device_code": device_code}, timeout=timeout)


@dataclass(frozen=True)
class DeviceToken:
    access_token: str = field(repr=False)
    token_id: str
    expires_at: int
    email: str


def parse_device_token(data: dict | None) -> DeviceToken:
    what = "device-token"
    token = req_str(data, "access_token", what, max_len=256)
    if not SESSION_TOKEN_RE.match(token):
        raise _malformed(what, "access_token")
    token_type = (data or {}).get("token_type", "Bearer")
    if not isinstance(token_type, str) or token_type.lower() != "bearer":
        raise _malformed(what, "token_type")
    return DeviceToken(
        access_token=token,
        token_id=req_str(data, "token_id", what, max_len=256),
        expires_at=req_int(data, "expires_at", what, lo=1, hi=2**40),
        email=req_str(data, "email", what, max_len=320),
    )


@dataclass(frozen=True)
class SessionInfo:
    email: str
    token_id: str
    label: str
    created_at: object
    expires_at: int


def get_session(base_url: str, access_token: str, *, timeout: float = DEFAULT_TIMEOUT) -> SessionInfo:
    resp = request(base_url, "GET", "/cli/session", bearer=access_token, timeout=timeout)
    _raise_if_rate_limited(resp)
    if resp.status == 401:
        raise NotLoggedIn(f"Your PocketShell login is no longer valid; {_LOGIN_HINT}.")
    if resp.status != 200:
        raise AccountError(describe_failure(resp, "Checking the session"))
    what = "session"
    data = resp.data or {}
    label = data.get("label", "")
    if not isinstance(label, str) or len(label) > 512:
        raise _malformed(what, "label")
    return SessionInfo(
        email=req_str(resp.data, "email", what, max_len=320),
        token_id=req_str(resp.data, "token_id", what, max_len=256),
        label=label,
        created_at=data.get("created_at"),
        expires_at=req_int(resp.data, "expires_at", what, lo=1, hi=2**40),
    )


def logout(base_url: str, access_token: str) -> bool:
    """Revoke the session server-side. True on 2xx (or 401: already gone).

    Raises :class:`BrokerRateLimited` on 429: the session was NOT revoked.
    """
    resp = request(base_url, "POST", "/cli/logout", bearer=access_token, timeout=10)
    _raise_if_rate_limited(resp)
    return 200 <= resp.status < 300 or resp.status == 401


def _looks_like_jwt(token: str) -> bool:
    if len(token) > _MAX_JWT_LEN or not _JWT_RE.match(token):
        return False
    header = token.split(".", 1)[0]
    try:
        decoded = base64.urlsafe_b64decode(header + "=" * (-len(header) % 4))
        value = loads_strict(decoded)
    except (ValueError, StrictJSONError):
        return False
    return isinstance(value, dict) and isinstance(value.get("alg"), str)


def mint_gateway_token(
    base_url: str, access_token: str, *, now: float | None = None
) -> GatewayToken:
    resp = request(base_url, "POST", "/cli/gateway/token", bearer=access_token)
    _raise_if_rate_limited(resp)
    if resp.status == 401:
        raise NotLoggedIn(f"Your PocketShell login is no longer valid; {_LOGIN_HINT}.")
    if resp.status == 403:
        raise AccountError(
            "The broker refused a gateway token for this account (HTTP 403); "
            "check that the account is allowed to use the gateway."
        )
    if resp.status != 200:
        raise AccountError(describe_failure(resp, "Getting a gateway token"))
    what = "gateway-token"
    token = req_str(resp.data, "token", what, max_len=_MAX_JWT_LEN)
    if not _looks_like_jwt(token):
        raise _malformed(what, "token")
    token_type = (resp.data or {}).get("token_type", "Bearer")
    if not isinstance(token_type, str) or token_type.lower() != "bearer":
        raise _malformed(what, "token_type")
    expires_at = req_int(resp.data, "expires_at", what, lo=1, hi=2**40)
    current = time.time() if now is None else now
    if not current - _CLOCK_SKEW < expires_at <= current + _GATEWAY_TOKEN_MAX_TTL + _CLOCK_SKEW:
        raise AccountError(
            "The broker returned a gateway token with an implausible expiry; "
            "check this machine's clock."
        )
    return GatewayToken(token=token, expires_at=expires_at)
