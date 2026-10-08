"""OAuth-style device-authorization login against the PocketShell broker.

1. ``POST /auth/device/start`` with a human label (``user@hostname``).
2. Show the user code and the https verification URL (sanitized), and
   optionally open ``verification_uri_complete`` in a browser.
3. Poll ``POST /auth/device/token`` every ``interval`` seconds; ``slow_down``
   (or HTTP 429) adds 5 s; ``access_denied`` / ``expired_token`` stop.
4. Confirm the new token with ``GET /cli/session`` and store it.

The device code is a bearer secret for the pairing: it goes only into JSON
request bodies and is never printed. If anything fails or the user hits
Ctrl+C after a session token was issued but before it was saved, the token
is revoked best-effort so no orphaned session lingers.
"""

from __future__ import annotations

import getpass
import socket
import time
import webbrowser
from typing import Callable

from pocketshell.account import broker
from pocketshell.account.credentials import Credentials, save
from pocketshell.account.errors import AccountError, BrokerUnavailable
from pocketshell.account.sanitize import clean_text, https_url

MAX_LABEL = 80
SLOW_DOWN_STEP = 5
MAX_INTERVAL = 60
MAX_TRANSIENT_FAILURES = 5

_AGAIN = "Run `pocketshell login` again."


def default_label() -> str:
    try:
        user = getpass.getuser()
    except Exception:  # noqa: BLE001 - no passwd entry / no env: fall back
        user = "user"
    label = clean_text(f"{user}@{socket.gethostname()}", max_len=MAX_LABEL)
    return label or "pocketshell-cli"


def validate_label(label: str) -> str:
    cleaned = clean_text(label, max_len=10_000)
    if not cleaned or cleaned != label.strip() or len(cleaned) > MAX_LABEL:
        raise AccountError(
            f"--label must be 1-{MAX_LABEL} printable characters without control characters."
        )
    return cleaned


def login(
    base_url: str,
    *,
    label: str,
    open_browser: bool = True,
    echo: Callable[[str], None] = print,
    sleep: Callable[[float], None] | None = None,
    monotonic: Callable[[], float] | None = None,
    browser_open: Callable[[str], object] | None = None,
) -> Credentials:
    """Run the device flow and save the resulting session. Returns it."""
    sleep = sleep or time.sleep
    monotonic = monotonic or time.monotonic
    browser_open = browser_open or webbrowser.open
    start = broker.start_device(base_url, label)
    verification_uri = https_url(start.verification_uri)
    if verification_uri is None:
        raise AccountError("The broker returned an invalid (non-https) verification URL.")
    complete_uri = https_url(start.verification_uri_complete)
    user_code = clean_text(start.user_code, max_len=32)
    if not user_code:
        raise AccountError("The broker returned an empty user code.")

    echo(f"To log in, open:  {verification_uri}")
    echo(f"and enter code:   {user_code}")
    echo("Check that the code shown in the browser matches before approving.")
    if open_browser and complete_uri is not None:
        try:
            browser_open(complete_uri)
        except Exception:  # noqa: BLE001 - a browser is a convenience only
            pass
    echo("Waiting for approval (Ctrl+C to cancel)...")

    token = _poll(base_url, start, sleep=sleep, monotonic=monotonic)
    try:
        session = broker.get_session(base_url, token.access_token)
        if session.token_id != token.token_id:
            raise AccountError("The broker's session check did not match the issued token.")
        creds = Credentials(
            broker_url=base_url,
            access_token=token.access_token,
            token_id=session.token_id,
            email=clean_text(session.email, max_len=320),
            expires_at=session.expires_at,
            label=clean_text(session.label, max_len=MAX_LABEL) or label,
        )
        save(creds)
    except BaseException:
        _revoke_quietly(base_url, token.access_token)
        raise
    return creds


def _poll(base_url, start, *, sleep, monotonic) -> broker.DeviceToken:
    deadline = monotonic() + start.expires_in
    interval = min(start.interval, MAX_INTERVAL)
    failures = 0
    while True:
        if monotonic() + interval > deadline:
            raise AccountError(f"The login code expired before it was approved. {_AGAIN}")
        sleep(interval)
        try:
            resp = broker.poll_device(base_url, start.device_code)
        except BrokerUnavailable as exc:
            failures += 1
            if failures >= MAX_TRANSIENT_FAILURES:
                raise AccountError(f"{exc} {_AGAIN}") from None
            continue
        if resp.status == 200:
            return broker.parse_device_token(resp.data)
        if resp.status >= 500:
            failures += 1
            if failures >= MAX_TRANSIENT_FAILURES:
                raise AccountError(broker.describe_failure(resp, "Waiting for approval"))
            continue
        failures = 0
        code = resp.error
        if resp.status == 429 or code == "slow_down":
            interval = min(interval + SLOW_DOWN_STEP, MAX_INTERVAL)
            continue
        if resp.status == 400 and code == "authorization_pending":
            continue
        if code == "access_denied":
            raise AccountError(f"The login request was denied in the browser. {_AGAIN}")
        if code == "expired_token":
            raise AccountError(f"The login code expired before it was approved. {_AGAIN}")
        raise AccountError(broker.describe_failure(resp, "Waiting for approval"))


def _revoke_quietly(base_url: str, access_token: str) -> None:
    try:
        broker.logout(base_url, access_token)
    except Exception:  # noqa: BLE001 - best effort
        pass
