"""First-use bridge roles (agreement §16.17, revision E).

The native bridge stays TERMINAL-ONLY: no in-flight stdout and no stdin after
authorize. So the Desktop drives first use through short held roles, each
returning ONE terminal JSON document:

* ``login-start``: starts the supported device flow (POST /auth/device/start)
  and returns ONLY public fields (user code, trusted verification URL, expiry,
  interval). The secret device code is stored owner-private as
  ``<agent dir>/login-<OP>.json``, bound to that operation id, and is never
  printed or logged.
* ``login-complete --login OP``: polls (POST /auth/device/token) for at most
  ``--timeout`` seconds (1..120). It can be invoked again. On approval it
  checks GET /cli/session and stores the session exactly as ``pocketshell
  login`` does. It returns approved | pending | denied | expired, with no token.
* ``enroll``: the supported helper enrollment against the GENERATED host key
  (service_user_agent.enroll_command).

The account session file and the agent directory follow the closed launch
environment: ``%USERPROFILE%\\.config\\pocketshell`` (no XDG_CONFIG_HOME is set
by the bridge).
"""

from __future__ import annotations

import json
import re
import time

from pocketshell.account import broker, credentials
from pocketshell.account import config as web_origin_mod
from pocketshell.account.device import USER_CODE_RE, default_label, validate_label
from pocketshell.account.errors import AccountError, BrokerUnavailable, NotLoggedIn

API_VERSION = 1
OPERATION_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
MAX_COMPLETE_TIMEOUT = 120
SLOW_DOWN_STEP = 5
MAX_INTERVAL = 60
EXIT_OK, EXIT_ERROR, EXIT_USAGE, EXIT_PENDING = 0, 1, 2, 3

_now = time.time
_sleep = time.sleep


def _agent():
    from pocketshell.gateway import service_user_agent as agent

    return agent


def _read_private(path):
    return _agent()._read_private(path)


def pending_path(operation_id: str) -> str:
    return _agent()._path(f"login-{operation_id}.json")


def _doc(action, operation_id, *, ok, state=None, error=None, **extra):
    return {"version": API_VERSION, "operationId": operation_id, "action": action, "ok": ok, "state": state,
            **extra, "error": None if error is None else {"code": error[0], "message": error[1][:600]}}


def _trusted(value, origin):
    from pocketshell.account.config import same_origin
    from pocketshell.account.sanitize import https_url

    url = https_url(value)
    return url if url is not None and same_origin(url, origin) else None


def login_start(*, operation_id: str, label=None) -> tuple:
    """Start the device flow; public fields only."""
    action = "login-start"
    if not OPERATION_RE.match(operation_id or ""):
        return _doc(action, operation_id, ok=False, error=("usage", "--operation-id is required")), EXIT_USAGE
    try:
        label = validate_label(label) if label is not None else default_label()
        if _read_private(pending_path(operation_id)) is not None:
            return _doc(action, operation_id, ok=False, error=(
                "login-exists", "this operation id already started a login; use a new one")), EXIT_ERROR
        try:
            current = credentials.load()
            if not current.expired():
                return _doc(action, operation_id, ok=True, state="already-logged-in", login=None), EXIT_OK
        except (NotLoggedIn, AccountError):
            pass
        base = web_origin_mod.resolve_broker_url()
        start = broker.start_device(base, label)
        if not isinstance(start.user_code, str) or USER_CODE_RE.fullmatch(start.user_code) is None:
            return _doc(action, operation_id, ok=False, error=("broker-malformed", "malformed user code")), \
                EXIT_ERROR
        origin = web_origin_mod.web_origin()
        uri = _trusted(start.verification_uri, origin) or f"{origin}/device"
        complete = _trusted(start.verification_uri_complete, origin)
        if _trusted(start.verification_uri, origin) is None or complete != f"{uri}?code={start.user_code}":
            complete = None
        interval = min(max(int(start.interval), 1), MAX_INTERVAL)
        expires_at = int(_now()) + int(start.expires_in)
        record = {"version": 1, "operationId": operation_id, "brokerUrl": base, "label": label,
                  "deviceCode": start.device_code, "userCode": start.user_code, "interval": interval,
                  "expiresAt": expires_at}
        _agent()._write_private(pending_path(operation_id), json.dumps(record).encode("utf-8"))
    except AccountError as exc:
        return _doc(action, operation_id, ok=False, error=("login-failed", str(exc))), EXIT_ERROR
    return _doc(action, operation_id, ok=True, state="pending",
                login={"userCode": start.user_code, "verificationUri": uri, "verificationUriComplete": complete,
                       "expiresAt": expires_at, "interval": interval}), EXIT_OK


def login_complete(*, operation_id: str, login: str, timeout: float = 60) -> tuple:
    """Bounded poll of a started login (re-invocable)."""
    action = "login-complete"
    extra = {"login": login}
    if not OPERATION_RE.match(operation_id or "") or not OPERATION_RE.match(login or "") \
            or not isinstance(timeout, (int, float)) or not 1 <= timeout <= MAX_COMPLETE_TIMEOUT:
        return _doc(action, operation_id, ok=False, error=(
            "usage", f"--operation-id, --login and --timeout 1..{MAX_COMPLETE_TIMEOUT} are required"),
            **extra), EXIT_USAGE
    path = pending_path(login)
    data = _read_private(path)
    try:
        record = json.loads(data.decode("utf-8")) if data is not None else None
        assert record is None or (isinstance(record, dict) and record.get("operationId") == login)
    except (ValueError, UnicodeDecodeError, AssertionError):
        record = None
    if record is None:
        return _doc(action, operation_id, ok=False, error=(
            "login-unknown", "no started login for this --login operation id"), **extra), EXIT_ERROR

    def finish(state, code, message):
        _agent()._delete(path)
        return _doc(action, operation_id, ok=False, state=state, error=(code, message), **extra), EXIT_ERROR

    deadline = min(_now() + timeout, record["expiresAt"])
    interval = record["interval"]
    failures = 0
    while True:
        if _now() >= record["expiresAt"]:
            return finish("expired", "login-expired", "the login code expired before it was approved")
        if _now() + interval > deadline:
            if record["interval"] != interval:
                record["interval"] = interval
                _agent()._write_private(path, json.dumps(record).encode("utf-8"))
            return _doc(action, operation_id, ok=True, state="pending", **extra), EXIT_PENDING
        _sleep(interval)
        try:
            resp = broker.poll_device(record["brokerUrl"], record["deviceCode"])
        except BrokerUnavailable:
            failures += 1
            if failures >= 5:
                return _doc(action, operation_id, ok=True, state="pending", **extra), EXIT_PENDING
            continue
        if resp.status == 200:
            break
        error = resp.error
        if resp.status == 429 or error == "slow_down":
            interval = min(interval + SLOW_DOWN_STEP, MAX_INTERVAL)
        elif error == "access_denied":
            return finish("denied", "login-denied", "the login request was denied in the browser")
        elif error == "expired_token":
            return finish("expired", "login-expired", "the login code expired before it was approved")
        elif not (resp.status == 400 and error == "authorization_pending") and resp.status < 500:
            return finish("failed", "login-failed", broker.describe_failure(resp, "Waiting for approval"))
    try:
        token = broker.parse_device_token(resp.data)
        session = broker.get_session(record["brokerUrl"], token.access_token)
        if session.token_id != token.token_id:
            raise AccountError("the broker's session check did not match the issued token")
        from pocketshell.account.sanitize import clean_text

        creds = credentials.Credentials(broker_url=record["brokerUrl"], access_token=token.access_token,
                                        token_id=session.token_id, email=clean_text(session.email, max_len=320),
                                        expires_at=session.expires_at,
                                        label=clean_text(session.label, max_len=80) or record["label"])
        credentials.save(creds)
    except AccountError as exc:
        try:
            broker.logout(record["brokerUrl"], token.access_token)  # no orphaned session
        except Exception:  # noqa: BLE001 - best effort
            pass
        return finish("failed", "login-failed", str(exc))
    _agent()._delete(path)
    return _doc(action, operation_id, ok=True, state="approved", account={"email": creds.email}, **extra), EXIT_OK
