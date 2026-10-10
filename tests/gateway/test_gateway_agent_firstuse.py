"""First-use bridge roles (agreement §16.17): every role is a SHORT held role
that returns ONE terminal JSON document (the native bridge stays
terminal-only, no in-flight stdout, no post-authorize stdin).

login-start -> public code; login-complete -> bounded poll; enroll -> the
supported helper enrollment against the GENERATED host key; authorize-key
--public-key-file with recorded consent. No secret ever reaches an output."""

from __future__ import annotations

import json

import pytest

from pocketshell.account import broker
from pocketshell.gateway import service_agent_firstuse as fu

DEVICE_CODE = "dc_" + "S" * 40
TOKEN = "psc_" + "T" * 43


class Clock:
    def __init__(self):
        self.t = 1_800_000_000.0

    def now(self):
        return self.t

    def sleep(self, s):
        self.t += s


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "profile"))
    clock = Clock()
    monkeypatch.setattr(fu, "_now", clock.now)
    monkeypatch.setattr(fu, "_sleep", clock.sleep)
    monkeypatch.setattr(fu.web_origin_mod, "web_origin", lambda: "https://app.pocketshell.io")
    start = broker.DeviceStart(device_code=DEVICE_CODE, user_code="BCDF-GH23",
                               verification_uri="https://app.pocketshell.io/device",
                               verification_uri_complete="https://app.pocketshell.io/device?code=BCDF-GH23",
                               expires_in=600, interval=5)
    monkeypatch.setattr(broker, "start_device", lambda base, label: start)
    state = {"answers": [], "saved": [], "polled": []}

    def poll(base, code):
        state["polled"].append(code)
        status, body = state["answers"].pop(0) if state["answers"] else (400, {"error": "authorization_pending"})
        return broker.Response(status=status, data=body)

    monkeypatch.setattr(broker, "poll_device", poll)
    monkeypatch.setattr(broker, "get_session", lambda base, tok: broker.SessionInfo(
        email="me@example.com", token_id="tid-1", label="l", created_at=None, expires_at=1_900_000_000))
    monkeypatch.setattr(fu.credentials, "save", lambda c: state["saved"].append(c))
    monkeypatch.setattr(fu.credentials, "load", lambda **kw: (_ for _ in ()).throw(fu.NotLoggedIn("no")))
    return state


def _no_secret(doc):
    text = json.dumps(doc)
    assert DEVICE_CODE not in text and TOKEN not in text and "access_token" not in text


def test_login_start_returns_only_public_fields_and_stores_the_device_code_privately(env):
    doc, code = fu.login_start(operation_id="op-start", label="me@host")
    assert code == 0 and doc["state"] == "pending" and doc["action"] == "login-start"
    assert doc["login"] == {"userCode": "BCDF-GH23", "verificationUri": "https://app.pocketshell.io/device",
                            "verificationUriComplete": "https://app.pocketshell.io/device?code=BCDF-GH23",
                            "expiresAt": 1_800_000_600, "interval": 5}
    _no_secret(doc)
    stored = json.loads(fu._read_private(fu.pending_path("op-start")))
    assert stored["deviceCode"] == DEVICE_CODE and stored["operationId"] == "op-start"


def test_login_complete_approved_saves_the_session_and_returns_no_token(env):
    fu.login_start(operation_id="op-start", label="me@host")
    env["answers"] = [(400, {"error": "authorization_pending"}),
                      (200, {"access_token": TOKEN, "token_id": "tid-1", "expires_at": 1_900_000_000,
                             "email": "me@example.com"})]
    doc, code = fu.login_complete(operation_id="op-done", login="op-start", timeout=60)
    assert code == 0 and doc["state"] == "approved" and doc["account"] == {"email": "me@example.com"}
    _no_secret(doc)
    assert env["saved"] and env["saved"][0].access_token == TOKEN
    assert fu._read_private(fu.pending_path("op-start")) is None  # consumed


def test_login_complete_is_bounded_and_re_invocable(env):
    fu.login_start(operation_id="op-start", label="me@host")
    doc, code = fu.login_complete(operation_id="op-1", login="op-start", timeout=12)
    assert code == 3 and doc["state"] == "pending" and len(env["polled"]) <= 3
    _no_secret(doc)
    env["answers"] = [(200, {"access_token": TOKEN, "token_id": "tid-1", "expires_at": 1_900_000_000,
                             "email": "me@example.com"})]
    doc, code = fu.login_complete(operation_id="op-2", login="op-start", timeout=12)
    assert code == 0 and doc["state"] == "approved"


@pytest.mark.parametrize("answer,state", [((400, {"error": "access_denied"}), "denied"),
                                          ((400, {"error": "expired_token"}), "expired")])
def test_login_complete_denied_and_expired_are_terminal(env, answer, state):
    fu.login_start(operation_id="op-start", label="me@host")
    env["answers"] = [answer]
    doc, code = fu.login_complete(operation_id="op-x", login="op-start", timeout=30)
    assert code == 1 and doc["state"] == state and doc["error"]["code"] == f"login-{state}"
    assert fu._read_private(fu.pending_path("op-start")) is None and not env["saved"]


def test_login_complete_after_the_local_expiry_never_polls(env, monkeypatch):
    fu.login_start(operation_id="op-start", label="me@host")
    fu._sleep(601)
    doc, code = fu.login_complete(operation_id="op-x", login="op-start", timeout=30)
    assert code == 1 and doc["state"] == "expired" and not env["polled"]


def test_wrong_operation_correlation_is_refused(env):
    fu.login_start(operation_id="op-start", label="me@host")
    doc, code = fu.login_complete(operation_id="op-x", login="op-other", timeout=5)
    assert code == 1 and doc["error"]["code"] == "login-unknown" and not env["polled"]
    doc, code = fu.login_complete(operation_id="op-x", login="../op-start", timeout=5)
    assert code == 2 and doc["error"]["code"] == "usage"
    doc, code = fu.login_start(operation_id="op-start", label="me@host")  # an operation id is never reused
    assert code == 1 and doc["error"]["code"] == "login-exists"


@pytest.mark.parametrize("timeout", [0, 121, -1])
def test_login_complete_deadline_is_bounded(env, timeout):
    fu.login_start(operation_id="op-start", label="me@host")
    doc, code = fu.login_complete(operation_id="op-x", login="op-start", timeout=timeout)
    assert code == 2 and doc["error"]["code"] == "usage"


def test_login_start_with_a_valid_session_needs_no_new_login(env, monkeypatch):
    class Creds:
        email = "me@example.com"

        def expired(self):
            return False

    monkeypatch.setattr(fu.credentials, "load", lambda **kw: Creds())
    doc, code = fu.login_start(operation_id="op-start", label="me@host")
    assert code == 0 and doc["state"] == "already-logged-in" and doc["login"] is None


def test_login_start_refuses_an_untrusted_verification_origin(env, monkeypatch):
    bad = broker.DeviceStart(device_code=DEVICE_CODE, user_code="BCDF-GH23",
                             verification_uri="https://evil.example/device",
                             verification_uri_complete="https://evil.example/device?code=BCDF-GH23",
                             expires_in=600, interval=5)
    monkeypatch.setattr(broker, "start_device", lambda base, label: bad)
    doc, code = fu.login_start(operation_id="op-start", label="me@host")
    assert doc["login"]["verificationUri"] == "https://app.pocketshell.io/device"
    assert doc["login"]["verificationUriComplete"] is None
    _no_secret(doc)
