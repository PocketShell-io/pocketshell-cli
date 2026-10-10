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

    def poll(base, code, timeout=None):
        state["polled"].append(code)
        status, body = state["answers"].pop(0) if state["answers"] else (400, {"error": "authorization_pending"})
        return broker.Response(status=status, data=body)

    monkeypatch.setattr(broker, "poll_device", poll)
    monkeypatch.setattr(broker, "get_session", lambda base, tok, timeout=None: broker.SessionInfo(
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
                            "expiresAt": 1_800_000_600, "interval": 5}  # exactly these (Fleet)
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
    _no_secret(doc)


# --- review 28a64d4f: every failure class is ONE correlated public terminal document -------


def _clean(doc, capsys):
    out = capsys.readouterr()
    for text in (json.dumps(doc), out.out, out.err):
        assert DEVICE_CODE not in text and TOKEN not in text and "deviceCode" not in text


def test_complete_with_an_unreadable_private_record(env, monkeypatch, capsys):
    fu.login_start(operation_id="op-start", label="me@host")

    def boom(path, *a, **k):
        raise PermissionError(13, "Access is denied", path)

    monkeypatch.setattr(fu, "_read_private", boom)
    doc, code = fu.login_complete(operation_id="op-x", login="op-start", timeout=10)
    assert code == 1 and doc["error"]["code"] == "state-unreadable" and doc["login"] == "op-start"
    _clean(doc, capsys)


def test_complete_with_a_corrupt_private_record(env, capsys):
    fu.login_start(operation_id="op-start", label="me@host")
    fu._agent()._write_private(fu.pending_path("op-start"), b"{not json" + DEVICE_CODE.encode())
    doc, code = fu.login_complete(operation_id="op-x", login="op-start", timeout=10)
    assert code == 1 and doc["error"]["code"] == "state-unreadable"
    _clean(doc, capsys)


def test_complete_when_the_pending_record_cannot_be_deleted(env, monkeypatch, capsys):
    fu.login_start(operation_id="op-start", label="me@host")
    env["answers"] = [(400, {"error": "access_denied"})]

    def no_delete(path):
        raise PermissionError(13, "Access is denied", path)

    monkeypatch.setattr(fu._agent(), "_delete", no_delete)
    doc, code = fu.login_complete(operation_id="op-x", login="op-start", timeout=30)
    assert code == 1 and doc["state"] == "denied" and doc["error"]["code"] == "state-cleanup-failed"
    _clean(doc, capsys)


def test_complete_with_a_malformed_broker_token(env, capsys):
    fu.login_start(operation_id="op-start", label="me@host")
    env["answers"] = [(200, {"access_token": "not-a-token", "token_id": "t"})]
    doc, code = fu.login_complete(operation_id="op-x", login="op-start", timeout=30)
    assert code == 1 and doc["state"] == "failed" and doc["error"]["code"] == "broker-malformed"
    _clean(doc, capsys)


def test_start_when_the_private_record_cannot_be_written(env, monkeypatch, capsys):
    def no_write(path, data):
        raise PermissionError(13, "Access is denied", path)

    monkeypatch.setattr(fu._agent(), "_write_private", no_write)
    doc, code = fu.login_start(operation_id="op-start", label="me@host")
    assert code == 1 and doc["error"]["code"] == "state-write-failed" and doc["login"] is None
    _clean(doc, capsys)


def test_complete_wall_time_is_bounded_by_the_documented_budget(env, monkeypatch):
    """--timeout bounds the WHOLE operation: polls + per-request HTTP time; the
    final session check adds at most fu.SESSION_CHECK_TIMEOUT."""
    fu.login_start(operation_id="op-start", label="me@host")
    seen = []

    def slow_poll(base, code, timeout=None):
        seen.append(timeout)
        fu._sleep(timeout)  # every request uses its whole allowance
        return broker.Response(status=400, data={"error": "authorization_pending"})

    monkeypatch.setattr(broker, "poll_device", slow_poll)
    t0 = fu._now()
    doc, code = fu.login_complete(operation_id="op-x", login="op-start", timeout=20)
    assert code == 3 and fu._now() - t0 <= 20 and all(t and t <= 15 for t in seen)
