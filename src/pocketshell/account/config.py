"""Broker base-URL resolution and validation.

The CLI session token is sent to whatever this resolves to, so the rules are
strict: ``https`` only, no userinfo/query/fragment. Plain ``http`` is allowed
solely for local development and tests, behind
``POCKETSHELL_BROKER_INSECURE_DEV=1`` AND a loopback host — there is no way to
send a token over cleartext to a remote machine.
"""

from __future__ import annotations

import ipaddress
import os
from urllib.parse import urlsplit, urlunsplit

from pocketshell.account.errors import AccountError
from pocketshell.account.sanitize import clean_text

DEFAULT_BROKER_URL = "https://a7sota2qic.execute-api.eu-west-1.amazonaws.com"
ENV_BROKER_URL = "POCKETSHELL_BROKER_URL"
ENV_INSECURE_DEV = "POCKETSHELL_BROKER_INSECURE_DEV"


def insecure_dev_enabled() -> bool:
    return os.environ.get(ENV_INSECURE_DEV, "") == "1"


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def validate_broker_url(raw: str) -> str:
    """Return the normalized broker base URL or raise :class:`AccountError`.

    Normalization: lower-cased scheme/host, trailing ``/`` removed, so two
    spellings of one broker compare equal.
    """
    shown = clean_text(raw, max_len=120)
    if not isinstance(raw, str) or not raw.strip():
        raise AccountError("broker URL is empty")
    value = raw.strip()
    if len(value) > 2048 or any(not (0x21 <= ord(ch) <= 0x7E) for ch in value):
        raise AccountError(f"broker URL {shown!r} contains invalid characters")
    try:
        parts = urlsplit(value)
        host = parts.hostname
        port = parts.port
    except ValueError:
        raise AccountError(f"broker URL {shown!r} is not a valid URL") from None
    if not host:
        raise AccountError(f"broker URL {shown!r} has no host")
    if "@" in parts.netloc:
        raise AccountError(f"broker URL {shown!r} must not contain credentials")
    if parts.query or parts.fragment or value.endswith(("?", "#")):
        raise AccountError(f"broker URL {shown!r} must not have a query or fragment")
    scheme = parts.scheme.lower()
    if scheme == "http":
        if not (insecure_dev_enabled() and _is_loopback(host)):
            raise AccountError(
                f"broker URL {shown!r} must use https "
                f"(plain http is only allowed for a loopback host with {ENV_INSECURE_DEV}=1)"
            )
    elif scheme != "https":
        raise AccountError(f"broker URL {shown!r} must use https")
    netloc = f"[{host}]" if ":" in host else host
    if port is not None:
        netloc = f"{netloc}:{port}"
    return urlunsplit((scheme, netloc, parts.path.rstrip("/"), "", ""))


def resolve_broker_url() -> str:
    """``$POCKETSHELL_BROKER_URL`` if set, else the production broker."""
    return validate_broker_url(os.environ.get(ENV_BROKER_URL) or DEFAULT_BROKER_URL)


def normalize_or_none(raw: str) -> str | None:
    """Normalized URL, or ``None`` if it is not acceptable under the current policy."""
    try:
        return validate_broker_url(raw)
    except AccountError:
        return None


def session_broker_url(stored: str, requested: str | None = None) -> str:
    """The ONLY URL an existing session token may be sent to: the stored one.

    The session token is a 30-day credential bound to the broker that issued
    it at login. ``$POCKETSHELL_BROKER_URL`` (easy to set by accident, or by a
    hostile ``.envrc``) is ignored for an existing session; if it — or an
    explicit ``requested`` URL — names a different broker, this refuses with
    :class:`NotLoggedIn` instead of choosing either one.
    """
    from pocketshell.account.errors import NotLoggedIn

    target = normalize_or_none(stored)
    if target is None:
        raise NotLoggedIn(
            "The broker URL stored with your login is not allowed by the current "
            "settings; run `pocketshell login`."
        )
    if requested is None:
        requested = os.environ.get(ENV_BROKER_URL) or None
        source = ENV_BROKER_URL
    else:
        source = "the requested broker URL"
    if requested is not None and normalize_or_none(requested) != target:
        raise NotLoggedIn(
            f"{source} ({clean_text(requested, max_len=120)}) differs from the broker you "
            f"logged in to ({clean_text(target, max_len=120)}); refusing to send your "
            f"session to it. Unset it, or run `pocketshell login --force` for that broker."
        )
    return target
