"""PocketShell account: device-flow login and short-lived gateway tokens.

``pocketshell login`` pairs this machine with a PocketShell account through
the broker's OAuth-style device flow and stores a CLI session token in
``${XDG_CONFIG_HOME:-~/.config}/pocketshell/credentials.json`` (0600 in a
0700 directory). Other commands never see that token: they call
:func:`mint_gateway_token` for a broker JWT that lives at most five minutes.

Public API (consumed by the gateway connect commands; keep stable)::

    AccountError, NotLoggedIn, GatewayToken, mint_gateway_token, broker_url
"""

from __future__ import annotations

from pocketshell.account.config import (
    normalize_or_none,
    resolve_broker_url,
    validate_broker_url,
)
from pocketshell.account.errors import AccountError, GatewayToken, NotLoggedIn

__all__ = [
    "AccountError",
    "GatewayToken",
    "NotLoggedIn",
    "broker_url",
    "mint_gateway_token",
]


def broker_url() -> str:
    """The resolved broker base URL (``$POCKETSHELL_BROKER_URL`` or production).

    Raises :class:`AccountError` when the override is not an acceptable URL.
    """
    return resolve_broker_url()


def mint_gateway_token(*, broker_url: str | None = None) -> GatewayToken:
    """Exchange the stored CLI session for a short-lived broker JWT.

    ``broker_url`` defaults to :func:`broker_url`. The session token is only
    ever sent to the broker that issued it: if the target differs from the
    broker recorded at login, this raises :class:`NotLoggedIn` instead of
    sending it. Raises :class:`NotLoggedIn` when there is no usable session
    (missing, unsafe, expired, or rejected by the broker with 401) and
    :class:`AccountError` for every other failure. The returned token is a
    bearer credential: never print, log, or put it in argv/env.
    """
    from pocketshell.account import broker, credentials

    target = validate_broker_url(broker_url) if broker_url is not None else resolve_broker_url()
    creds = credentials.require_session()
    if normalize_or_none(creds.broker_url) != target:
        raise NotLoggedIn(
            "You are logged in to a different PocketShell broker than the one "
            "requested; run `pocketshell login` for this broker."
        )
    return broker.mint_gateway_token(target, creds.access_token)

