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

from pocketshell.account.config import resolve_broker_url
from pocketshell.account.errors import AccountError, GatewayToken, NotLoggedIn

__all__ = [
    "AccountError",
    "GatewayToken",
    "NotLoggedIn",
    "broker_url",
]


def broker_url() -> str:
    """The resolved broker base URL (``$POCKETSHELL_BROKER_URL`` or production).

    Raises :class:`AccountError` when the override is not an acceptable URL.
    """
    return resolve_broker_url()
