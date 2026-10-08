"""Device-flow login against the fake broker."""

from __future__ import annotations

import json
import os
import stat

import pytest

from pocketshell.account import AccountError
from pocketshell.account import credentials as store
from pocketshell.account import device

SESSION_TOKEN = "psc_" + "S" * 43
DEVICE_CODE = "psdc_" + "D" * 43


class Clock:
    """Fake monotonic clock advanced by the fake sleep."""

    def __init__(self) -> None:
        self.now = 1000.0
        self.sleeps: list[float] = []

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def _run(fake_broker, clock=None, **kw):
    clock = clock or Clock()
    lines: list[str] = []
    opened: list[str] = []
    kw.setdefault("label", "me@laptop")
    creds = device.login(
        fake_broker.url,
        echo=lines.append,
        sleep=clock.sleep,
        monotonic=clock.monotonic,
        browser_open=opened.append,
        **kw,
    )
    return creds, "\n".join(lines), opened, clock


def test_full_flow_saves_credentials(fake_broker) -> None:
    creds, out, opened, clock = _run(fake_broker)
    assert creds.email == "me@example.com"
    assert creds.access_token == SESSION_TOKEN
    assert creds.broker_url == fake_broker.url
    assert clock.sleeps == [5, 5]
    assert "https://app.pocketshell.io/device" in out
    assert "BCDF-GHJK" in out
    assert opened == ["https://app.pocketshell.io/device?code=BCDF-GHJK"]
    # secrets never printed
    assert SESSION_TOKEN not in out and DEVICE_CODE not in out
    # request shapes
    paths = [r["path"] for r in fake_broker.requests]
    assert paths == [
        "/auth/device/start",
        "/auth/device/token",
        "/auth/device/token",
        "/cli/session",
    ]
    assert json.loads(fake_broker.requests[0]["body"]) == {"label": "me@laptop"}
    assert json.loads(fake_broker.requests[1]["body"]) == {"device_code": DEVICE_CODE}
    # stored safely
    path = store.credentials_path()
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert store.load() == creds


def test_no_open_skips_browser(fake_broker) -> None:
    _, _, opened, _ = _run(fake_broker, open_browser=False)
    assert opened == []


def test_slow_down_adds_five_seconds(fake_broker) -> None:
    fake_broker.token_script.clear()
    fake_broker.token_script.extend(
        [
            (400, {"error": "authorization_pending"}),
            (400, {"error": "slow_down"}),
            (400, {"error": "authorization_pending"}),
            (429, {"error": "too_many_requests"}),
            (200, None),
        ]
    )
    _, _, _, clock = _run(fake_broker)
    assert clock.sleeps == [5, 5, 10, 10, 15]


def test_access_denied_stops_with_clear_message(fake_broker) -> None:
    fake_broker.token_script.clear()
    fake_broker.token_script.append((400, {"error": "access_denied"}))
    with pytest.raises(AccountError, match="denied"):
        _run(fake_broker)
    assert not store.exists()


def test_expired_token_stops_with_clear_message(fake_broker) -> None:
    fake_broker.token_script.clear()
    fake_broker.token_script.append((400, {"error": "expired_token"}))
    with pytest.raises(AccountError, match="expired"):
        _run(fake_broker)
    assert not store.exists()


def test_local_deadline_stops_polling(fake_broker) -> None:
    fake_broker.start_response["expires_in"] = 12
    fake_broker.token_script.clear()
    fake_broker.token_script.extend([(400, {"error": "authorization_pending"})] * 10)
    with pytest.raises(AccountError, match="expired"):
        _run(fake_broker)
    assert len(fake_broker.requests_to("/auth/device/token")) == 2


def test_unknown_error_stops(fake_broker) -> None:
    fake_broker.token_script.clear()
    fake_broker.token_script.append((400, {"error": "invalid_request"}))
    with pytest.raises(AccountError, match="invalid_request"):
        _run(fake_broker)


def test_transient_5xx_is_retried_then_gives_up(fake_broker) -> None:
    fake_broker.token_script.clear()
    fake_broker.token_script.extend([(503, None), (200, None)])
    creds, *_ = _run(fake_broker)
    assert creds.email == "me@example.com"
    fake_broker.token_script.clear()
    fake_broker.token_script.extend([(503, None)] * 6)
    with pytest.raises(AccountError, match="HTTP 503"):
        _run(fake_broker)


def test_server_strings_are_sanitized_before_printing(fake_broker) -> None:
    fake_broker.start_response["user_code"] = "\x1b]0;pwned\x07BCDF-\x1b[2JGHJK‮"
    _, out, _, _ = _run(fake_broker)
    assert "\x1b" not in out and "\x07" not in out and "‮" not in out
    assert "BCDF-[2JGHJK" in out


def test_non_https_verification_uri_is_refused(fake_broker) -> None:
    fake_broker.start_response["verification_uri"] = "http://app.pocketshell.io/device"
    with pytest.raises(AccountError, match="non-https"):
        _run(fake_broker)
    assert fake_broker.requests_to("/auth/device/token") == []


@pytest.mark.parametrize(
    "bad",
    [
        "http://evil.example/device",
        "javascript:alert(1)",
        "https://app.pocketshell.io/\x1b[2Jdevice",
        None,
    ],
)
def test_unsafe_complete_uri_is_never_opened(fake_broker, bad) -> None:
    fake_broker.start_response["verification_uri_complete"] = bad
    _, out, opened, _ = _run(fake_broker)
    assert opened == []
    assert "\x1b" not in out


@pytest.mark.parametrize(
    "field, value",
    [
        ("device_code", 12),
        ("device_code", "has space"),
        ("expires_in", "600"),
        ("expires_in", 0),
        ("interval", -1),
        ("interval", True),
        ("user_code", ""),
    ],
)
def test_malformed_start_response_is_refused(fake_broker, field, value) -> None:
    fake_broker.start_response[field] = value
    with pytest.raises(AccountError):
        _run(fake_broker)


def test_malformed_access_token_is_refused_and_not_echoed(fake_broker) -> None:
    fake_broker.access_token = "psc_\x1b[2J" + "x" * 40
    with pytest.raises(AccountError) as info:
        _run(fake_broker)
    assert "x" * 40 not in str(info.value)
    assert not store.exists()


def test_session_mismatch_revokes_issued_token(fake_broker) -> None:
    original = fake_broker.session_body

    def other_session():
        body = original()
        body["token_id"] = "tok_other"
        return body

    fake_broker.session_body = other_session
    with pytest.raises(AccountError, match="did not match"):
        _run(fake_broker)
    assert fake_broker.logged_out is True
    assert not store.exists()


def test_ctrl_c_during_polling_propagates_and_saves_nothing(fake_broker) -> None:
    clock = Clock()

    def interrupting_sleep(seconds):
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        device.login(
            fake_broker.url,
            label="me@laptop",
            echo=lambda _l: None,
            sleep=interrupting_sleep,
            monotonic=clock.monotonic,
            browser_open=lambda _u: None,
        )
    assert not store.exists()


def test_ctrl_c_after_token_issued_revokes_it(fake_broker, monkeypatch) -> None:
    def interrupted_save(_creds):
        raise KeyboardInterrupt

    monkeypatch.setattr(device, "save", interrupted_save)
    with pytest.raises(KeyboardInterrupt):
        _run(fake_broker)
    assert fake_broker.logged_out is True


def test_default_label_is_user_at_host(monkeypatch) -> None:
    monkeypatch.setattr(device.getpass, "getuser", lambda: "alice\x1b[2J")
    monkeypatch.setattr(device.socket, "gethostname", lambda: "box")
    assert device.default_label() == "alice[2J@box"


@pytest.mark.parametrize("bad", ["", "   ", "a\x1bb", "x" * 81, "tab\there"])
def test_validate_label_rejects_bad_labels(bad) -> None:
    with pytest.raises(AccountError):
        device.validate_label(bad)


def test_validate_label_accepts_unicode() -> None:
    assert device.validate_label("Алексей@laptop") == "Алексей@laptop"
