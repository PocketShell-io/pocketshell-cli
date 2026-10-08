"""Broker-JWT acquisition for the client commands, and remote-text hygiene.

The account layer (:mod:`pocketshell.account`, ``pocketshell login``) mints
the short-lived broker JWT the gateway admits clients with. It is imported
lazily so the gateway commands work (and can be tested) without it, and
every command takes an injectable ``token_provider`` instead of calling it
directly.

The token is never printed, logged, put in argv, a URL, or the environment.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Callable, Protocol


class TokenLike(Protocol):
    token: str
    expires_at: int


TokenProvider = Callable[[], TokenLike]

MAX_TOKEN_CHARS = 16384
_TOKEN_RE = re.compile(r"\A[\x21-\x7e]+\Z")

LOGIN_HINT = (
    "run `pocketshell login` on this machine first (device sign-in), "
    "then retry"
)


class GatewayTokenError(Exception):
    """Could not obtain a usable broker token. Message is safe to print."""


class NotLoggedInError(GatewayTokenError):
    """No usable `pocketshell login` session on this machine."""


def default_token_provider() -> TokenLike:
    """Mint a broker JWT through the logged-in `pocketshell login` session."""
    try:
        from pocketshell.account import mint_gateway_token
    except ImportError:
        raise NotLoggedInError(
            "this pocketshell build has no `pocketshell login` support yet; "
            "upgrade pocketshell"
        ) from None
    return mint_gateway_token()


def obtain_token(provider: TokenProvider) -> str:
    """Call ``provider`` and return the validated token string.

    Account-layer errors become :class:`GatewayTokenError` /
    :class:`NotLoggedInError` with a sanitized message; anything else
    propagates (a bug, not a user condition).
    """
    try:
        from pocketshell.account import AccountError, NotLoggedIn
    except ImportError:
        AccountError = NotLoggedIn = ()  # type: ignore[assignment,misc]
    try:
        minted = provider()
    except GatewayTokenError:
        raise
    except NotLoggedIn as exc:  # type: ignore[misc]
        detail = sanitize_remote_text(str(exc))
        raise NotLoggedInError(
            f"not logged in{': ' + detail if detail else ''}; {LOGIN_HINT}"
        ) from None
    except AccountError as exc:  # type: ignore[misc]
        raise GatewayTokenError(
            f"could not get a gateway token: {sanitize_remote_text(str(exc))}"
        ) from None
    token = getattr(minted, "token", None)
    if (
        not isinstance(token, str)
        or len(token) > MAX_TOKEN_CHARS
        or not _TOKEN_RE.match(token)
    ):
        raise GatewayTokenError("the account layer returned a malformed gateway token")
    return token


# --- remote text --------------------------------------------------------------

# ESC-introduced sequences: CSI (ESC [ … final), OSC (ESC ] … BEL / ST),
# DCS/SOS/PM/APC strings (ESC P|X|^|_ … ST), and two-byte escapes.
_ANSI_RE = re.compile(
    r"\x1b(?:\[[0-?]*[ -/]*[@-~]"
    r"|\][^\x07\x1b]*(?:\x07|\x1b\\)?"
    r"|[PX^_][^\x1b]*(?:\x1b\\)?"
    r"|[ -/]*[0-~])"
)
REMOTE_TEXT_LIMIT = 200


def sanitize_remote_text(text: object, limit: int = REMOTE_TEXT_LIMIT) -> str:
    """Make server-provided text safe to print on a terminal.

    Removes ANSI/VT escape sequences, then every character in Unicode
    categories C* (controls incl. C1/CSI, format chars such as bidi
    overrides and zero-width joiners, surrogates, private use,
    unassigned) and line/paragraph separators, collapses whitespace and
    caps the length.
    """
    if not isinstance(text, str):
        return ""
    text = _ANSI_RE.sub("", text)
    kept = []
    for ch in text:
        if ch in "\t\n\r\v\f":
            kept.append(" ")
            continue
        cat = unicodedata.category(ch)
        if cat[0] == "C" or cat in ("Zl", "Zp"):
            continue
        kept.append(" " if cat == "Zs" else ch)
    out = " ".join("".join(kept).split())
    if len(out) > limit:
        out = out[: max(0, limit - 1)] + "…"
    return out
