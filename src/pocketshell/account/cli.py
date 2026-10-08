"""``pocketshell login`` / ``logout`` / ``whoami``.

Exit codes: 0 success, 1 failure / not logged in, 130 cancelled (Ctrl+C).
Errors go to stderr as ``error: <message>``; messages never contain tokens.
"""

from __future__ import annotations

import functools
import json
import time

import click

from pocketshell.account import broker, credentials, device
from pocketshell.account.config import SESSIONS_URL, resolve_broker_url, session_broker_url
from pocketshell.account.errors import AccountError, CredentialsUnsafe, NotLoggedIn
from pocketshell.account.sanitize import clean_text


def _fail(message: str, code: int = 1) -> None:
    click.echo(f"error: {clean_text(message, max_len=2000)}", err=True)
    raise click.exceptions.Exit(code)


def _guarded(func):
    """No tracebacks: an unexpected exception becomes a one-line error.

    Only the exception TYPE is shown — its text could contain anything,
    including server-provided bytes.
    """

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except (click.exceptions.Exit, click.ClickException, click.Abort):
            raise
        except KeyboardInterrupt:
            click.echo("\nCancelled.", err=True)
            raise click.exceptions.Exit(130) from None
        except Exception as exc:  # noqa: BLE001
            _fail(f"unexpected internal error ({type(exc).__name__}).")

    return wrapper


def _when(epoch: int) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(epoch))
    except (OverflowError, OSError, ValueError):
        return str(epoch)


@click.command(
    "login",
    context_settings={"help_option_names": ["-h", "--help"]},
    help=(
        "Log this machine in to your PocketShell account (device flow).\n\n"
        "Prints a short code and a URL; approve the code in the browser while "
        "signed in to PocketShell. The CLI session is stored in "
        "${XDG_CONFIG_HOME:-~/.config}/pocketshell/credentials.json (mode 0600). "
        "An existing login is never replaced silently: pass --force to replace it "
        "(the old session is then revoked)."
    ),
)
@click.option(
    "--label",
    metavar="TEXT",
    help="Name for this session shown on the approval page (default: user@hostname).",
)
@click.option("--no-open", is_flag=True, help="Do not try to open a web browser.")
@click.option("--force", is_flag=True, help="Replace an existing, still-valid login.")
@_guarded
def login_command(label: str | None, no_open: bool, force: bool) -> None:
    try:
        base = resolve_broker_url()
        label = device.validate_label(label) if label is not None else device.default_label()
        previous = None
        try:
            previous = credentials.load()
        except CredentialsUnsafe as exc:
            click.echo(f"warning: {clean_text(str(exc), max_len=2000)} It will be replaced.", err=True)
        except NotLoggedIn:
            pass
        if previous is not None and not previous.expired() and not force:
            _fail(
                f"Already logged in as {clean_text(previous.email)}. Run `pocketshell logout` "
                "first, or `pocketshell login --force` to replace this login."
            )
        creds = device.login(base, label=label, open_browser=not no_open, echo=click.echo)
        if previous is not None and previous.access_token != creds.access_token:
            # The new login may target another broker; the old token still
            # only ever goes to the broker stored with it.
            _revoke_quietly(previous)
        click.echo(f"Logged in as {clean_text(creds.email)}.")
    except KeyboardInterrupt:
        click.echo("\nLogin cancelled.", err=True)
        raise click.exceptions.Exit(130) from None
    except AccountError as exc:
        _fail(str(exc))


def _revoke_quietly(creds: credentials.Credentials) -> str | None:
    """Revoke at the STORED broker. ``None`` on success, else why not."""
    if creds.expired():
        return None
    try:
        target = session_broker_url(creds.broker_url)
        if broker.logout(target, creds.access_token):
            return None
        return "the broker did not confirm the revocation"
    except AccountError as exc:
        return str(exc)


@click.command(
    "logout",
    context_settings={"help_option_names": ["-h", "--help"]},
    help=(
        "Revoke this machine's PocketShell CLI session (best effort) and delete "
        "the stored credentials."
    ),
)
@_guarded
def logout_command() -> None:
    try:
        try:
            creds = credentials.load(allow_shared_mode=True)
        except CredentialsUnsafe:
            credentials.delete()
            click.echo(
                "Removed an unsafe credentials file without contacting the broker.", err=True
            )
            return
        except NotLoggedIn:
            if credentials.exists():
                credentials.delete()
                click.echo("Removed an unreadable credentials file.", err=True)
            else:
                click.echo("Not logged in.")
            return
        problem = _revoke_quietly(creds)
        credentials.delete()
    except KeyboardInterrupt:
        raise click.exceptions.Exit(130) from None
    except AccountError as exc:
        _fail(str(exc))
    click.echo("Logged out.")
    if problem is not None:
        click.echo(
            f"warning: could not revoke the session on the broker ({problem}); "
            f"it stays valid until {_when(creds.expires_at)}.",
            err=True,
        )


@click.command(
    "whoami",
    context_settings={"help_option_names": ["-h", "--help"]},
    help="Show which PocketShell account this machine is logged in to.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON.")
@_guarded
def whoami_command(as_json: bool) -> None:
    try:
        creds = credentials.require_session()
    except NotLoggedIn as exc:
        _not_logged_in(exc, as_json)
        return
    email, label, expires_at = creds.email, creds.label, creds.expires_at
    verified = False
    warnings: list[str] = []
    try:
        target = session_broker_url(creds.broker_url)
    except NotLoggedIn as exc:
        # Never send the session anywhere but its own broker; show local info.
        warnings.append(f"not verified: {exc}")
    else:
        try:
            info = broker.get_session(target, creds.access_token, timeout=10)
        except NotLoggedIn as exc:
            _not_logged_in(exc, as_json)
            return
        except AccountError as exc:
            warnings.append(f"could not verify the session with the broker: {exc}")
        else:
            verified = True
            email, label, expires_at = info.email, info.label, info.expires_at
    if as_json:
        click.echo(
            json.dumps(
                {
                    "logged_in": True,
                    "verified": verified,
                    "email": clean_text(email, max_len=320),
                    "label": clean_text(label),
                    "token_id": clean_text(creds.token_id),
                    "broker_url": creds.broker_url,
                    "expires_at": expires_at,
                },
                sort_keys=True,
            )
        )
    else:
        click.echo(f"Logged in as {clean_text(email, max_len=320)}")
        click.echo(f"  label:    {clean_text(label)}")
        click.echo(f"  broker:   {clean_text(creds.broker_url)}")
        click.echo(f"  expires:  {_when(expires_at)}")
        click.echo(f"  verified: {'yes' if verified else 'no'}")
        click.echo(f"Review or revoke sessions at {SESSIONS_URL}")
    for warning in warnings:
        click.echo(f"warning: {clean_text(warning, max_len=2000)}", err=True)


def _not_logged_in(exc: NotLoggedIn, as_json: bool) -> None:
    if as_json:
        click.echo(json.dumps({"logged_in": False}))
    click.echo(f"error: {clean_text(str(exc), max_len=2000)}", err=True)
    raise click.exceptions.Exit(1)
