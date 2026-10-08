"""PocketShell account: device-flow login and short-lived gateway tokens.

``pocketshell login`` pairs this machine with a PocketShell account through
the broker's OAuth-style device flow and stores a CLI session token in
``${XDG_CONFIG_HOME:-~/.config}/pocketshell/credentials.json`` (0600 in a
0700 directory). Other commands never see that token: they call
:func:`mint_gateway_token` for a broker JWT that lives at most five minutes.

Public API (consumed by the gateway connect commands; keep stable)::

    AccountError, NotLoggedIn, GatewayToken, mint_gateway_token, broker_url,
    require_login
"""

from __future__ import annotations

from pocketshell.account.config import resolve_broker_url, session_broker_url
from pocketshell.account.errors import AccountError, GatewayToken, NotLoggedIn

__all__ = [
    "AccountError",
    "GatewayToken",
    "NotLoggedIn",
    "broker_url",
    "mint_gateway_token",
    "require_login",
]


def broker_url() -> str:
    """The resolved broker base URL (``$POCKETSHELL_BROKER_URL`` or production).

    Raises :class:`AccountError` when the override is not an acceptable URL.
    """
    return resolve_broker_url()


def mint_gateway_token(*, broker_url: str | None = None) -> GatewayToken:
    """Exchange the stored CLI session for a short-lived broker JWT.

    The session token is sent ONLY to the broker URL stored at login.
    ``broker_url`` (or ``$POCKETSHELL_BROKER_URL`` when it is omitted) is
    checked against it and must name the same broker; a mismatch raises
    :class:`NotLoggedIn` without sending anything. Raises
    :class:`NotLoggedIn` when there is no usable session (missing, unsafe,
    expired, or rejected by the broker with 401) and :class:`AccountError`
    for every other failure. The returned token is a bearer credential:
    never print, log, or put it in argv/env.
    """
    from pocketshell.account import broker, credentials

    creds = credentials.require_session()
    target = session_broker_url(creds.broker_url, broker_url)
    return broker.mint_gateway_token(target, creds.access_token)


def require_login(*, broker_url: str | None = None) -> None:
    """Check, locally and without any network I/O, that a session is usable.

    Raises :class:`NotLoggedIn` exactly when :func:`mint_gateway_token`
    would refuse before contacting the broker: no credentials file, an
    unsafe or expired one, or ``broker_url`` / ``$POCKETSHELL_BROKER_URL``
    naming a different broker than the stored one. A session revoked on
    the broker side is only detected by minting.
    """
    from pocketshell.account import credentials

    creds = credentials.require_session()
    session_broker_url(creds.broker_url, broker_url)
