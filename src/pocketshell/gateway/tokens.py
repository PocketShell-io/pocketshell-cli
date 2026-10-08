"""Broker-JWT acquisition for the client commands, and remote-text hygiene.

The account layer (:mod:`pocketshell.account`, ``pocketshell login``) mints
the short-lived broker JWT the gateway admits clients with. It is imported
lazily so the gateway commands work (and can be tested) without it, and
every command takes an injectable ``token_provider`` instead of calling it
directly.

The token is never printed, logged, put in argv, a URL, or the environment.
"""

from __future__ import annotations

import contextlib
import re
import unicodedata
from typing import Callable, Iterator, Protocol


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


_NO_ACCOUNT_SUPPORT = (
    "this pocketshell build has no `pocketshell login` support yet; "
    "upgrade pocketshell"
)


# Account-layer messages are local, already-cleaned advice (they embed
# broker URLs and what to run next); re-sanitize them but do not cut them
# to the short cap meant for text from the gateway.
ACCOUNT_TEXT_LIMIT = 1000


class GatewayTokenError(Exception):
    """Could not obtain a usable broker token. Message is safe to print."""


class NotLoggedInError(GatewayTokenError):
    """No usable `pocketshell login` session on this machine."""


def default_token_provider() -> TokenLike:
    """Mint a broker JWT through the logged-in `pocketshell login` session."""
    try:
        from pocketshell.account import mint_gateway_token
    except ImportError:
        raise NotLoggedInError(_NO_ACCOUNT_SUPPORT) from None
    return mint_gateway_token()


def _not_logged_in(detail: str) -> NotLoggedInError:
    # The account layer's own message usually already says what to run;
    # do not repeat the hint after it.
    if "pocketshell login" in detail:
        return NotLoggedInError(detail)
    return NotLoggedInError(f"not logged in{': ' + detail if detail else ''}; {LOGIN_HINT}")


@contextlib.contextmanager
def _account_errors(what: str) -> Iterator[None]:
    """Map account-layer exceptions to :class:`GatewayTokenError` /
    :class:`NotLoggedInError` with a sanitized message."""
    try:
        from pocketshell.account import AccountError, NotLoggedIn
    except ImportError:
        AccountError = NotLoggedIn = ()  # type: ignore[assignment,misc]
    try:
        yield
    except GatewayTokenError:
        raise
    except NotLoggedIn as exc:  # type: ignore[misc]
        detail = sanitize_remote_text(str(exc), ACCOUNT_TEXT_LIMIT)
        raise _not_logged_in(detail) from None
    except AccountError as exc:  # type: ignore[misc]
        detail = sanitize_remote_text(str(exc), ACCOUNT_TEXT_LIMIT)
        raise GatewayTokenError(f"{what}: {detail}") from None


def require_login() -> None:
    """Fail fast, without network I/O, when there is no usable login session.

    For commands that hand the actual minting to a child process (``gateway
    ssh`` → ssh → ``gateway proxy``), where the child's exit status would
    be lost behind ssh's own 255.
    """
    with _account_errors("cannot use your `pocketshell login` session"):
        try:
            from pocketshell.account import require_login as account_require_login
        except ImportError:
            raise NotLoggedInError(_NO_ACCOUNT_SUPPORT) from None
        account_require_login()


def obtain_token(provider: TokenProvider) -> str:
    """Call ``provider`` and return the validated token string.

    Account-layer errors become :class:`GatewayTokenError` /
    :class:`NotLoggedInError` with a sanitized message; anything else
    propagates (a bug, not a user condition).
    """
    with _account_errors("could not get a gateway token"):
        minted = provider()
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
