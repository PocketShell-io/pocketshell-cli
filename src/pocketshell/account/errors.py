"""Exception and value types for the PocketShell account (device-login) module.

Every message carried by these exceptions is safe to print: it never contains
a CLI session token, a device code, a broker JWT, or raw server text. Callers
(``pocketshell login`` and the gateway connect commands) print ``str(exc)``
verbatim.
"""

from __future__ import annotations

from dataclasses import dataclass

from pocketshell.account.sanitize import clean_text


class AccountError(Exception):
    """A login/account failure whose message is safe to show to the user.

    The message is passed through :func:`clean_text` on construction, so even
    a message that embeds a path or a server-derived fragment can never carry
    terminal control/escape or invisible format characters to whoever
    prints ``str(exc)``.
    """

    def __init__(self, message: object = "") -> None:
        super().__init__(clean_text(str(message), max_len=2000))


class NotLoggedIn(AccountError):
    """There is no usable CLI session: run ``pocketshell login``."""


class CredentialsUnsafe(NotLoggedIn):
    """A credentials file exists but is refused (symlink, wrong owner, mode).

    Treated exactly like "not logged in" by every consumer; the subclass only
    lets ``logout``/``login`` explain what they are replacing.
    """


class BrokerUnavailable(AccountError):
    """The broker could not be reached (DNS, TCP, TLS, timeout).

    Transient by nature: the device-flow poller retries it a bounded number
    of times; everything else surfaces it as a plain :class:`AccountError`.
    """


@dataclass(frozen=True)
class GatewayToken:
    """A short-lived broker JWT for the PocketShell gateway.

    ``token`` is a bearer credential: it is never printed, logged, or put in
    argv/env. ``repr``/``str`` redact it so an accidental ``print(tok)`` or a
    traceback local-variable dump cannot leak it.
    """

    token: str  # broker JWT, never printed/logged
    expires_at: int  # unix seconds

    def __repr__(self) -> str:
        return f"GatewayToken(token='<redacted>', expires_at={self.expires_at})"

    __str__ = __repr__
