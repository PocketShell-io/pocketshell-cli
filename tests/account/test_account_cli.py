"""`pocketshell login` / `logout` / `whoami` end to end against the fake broker."""

from __future__ import annotations

import json
import os
import time

import pytest
from click.testing import CliRunner

from pocketshell.account import credentials as store
from pocketshell.account import device
from pocketshell.cli import cli

SESSION_TOKEN = "psc_" + "S" * 43
OLD_TOKEN = "psc_" + "O" * 43
DEVICE_CODE = "psdc_" + "D" * 43


@pytest.fixture
def opened(monkeypatch):
    urls: list[str] = []
    monkeypatch.setattr(device.time, "sleep", lambda _s: None)
    monkeypatch.setattr(device.webbrowser, "open", urls.append)
    return urls


def _invoke(*args):
    return CliRunner().invoke(cli, list(args))


def _assert_no_secrets(result) -> None:
    for secret in (SESSION_TOKEN, OLD_TOKEN, DEVICE_CODE):
        assert secret not in result.output
        assert secret not in (result.stderr or "")


def _save(fake_broker, token=SESSION_TOKEN, **over) -> None:
    values = dict(
        broker_url=fake_broker.url,
        access_token=token,
        token_id="tok_123",
        email="me@example.com",
        expires_at=int(time.time()) + 3600,
        label="me@laptop",
    )
    values.update(over)
    store.save(store.Credentials(**values))


def test_commands_are_registered() -> None:
    result = _invoke("--help")
    for name in ("login", "logout", "whoami"):
        assert name in result.output


def test_login_full_flow(fake_broker, opened) -> None:
    result = _invoke("login", "--label", "ci@runner")
    assert result.exit_code == 0, result.output
    assert "https://app.pocketshell.io/device" in result.stdout
    assert "BCDF-GHJK" in result.stdout
    assert "Logged in as me@example.com." in result.stdout
    assert opened == ["https://app.pocketshell.io/device?code=BCDF-GHJK"]
    assert json.loads(fake_broker.requests[0]["body"]) == {"label": "ci@runner"}
    assert store.load().access_token == SESSION_TOKEN
    _assert_no_secrets(result)


def test_login_no_open(fake_broker, opened) -> None:
    result = _invoke("login", "--no-open")
    assert result.exit_code == 0, result.output
    assert opened == []


def test_login_refuses_to_replace_without_force(fake_broker, opened) -> None:
    _save(fake_broker, token=OLD_TOKEN)
    result = _invoke("login")
    assert result.exit_code == 1
    assert "Already logged in as me@example.com" in result.stderr
    assert "--force" in result.stderr
    assert fake_broker.requests == []
    assert store.load().access_token == OLD_TOKEN


def test_login_force_replaces_and_revokes_old_session(fake_broker, opened) -> None:
    _save(fake_broker, token=OLD_TOKEN)
    result = _invoke("login", "--force")
    assert result.exit_code == 0, result.output
    assert store.load().access_token == SESSION_TOKEN
    [revoke] = fake_broker.requests_to("/cli/logout")
    assert revoke["headers"]["Authorization"] == f"Bearer {OLD_TOKEN}"
    _assert_no_secrets(result)


def test_login_over_expired_session_needs_no_force(fake_broker, opened) -> None:
    _save(fake_broker, token=OLD_TOKEN, expires_at=int(time.time()) - 10)
    result = _invoke("login")
    assert result.exit_code == 0, result.output
    assert fake_broker.requests_to("/cli/logout") == []


def test_login_replaces_unsafe_file_with_warning(fake_broker, opened) -> None:
    _save(fake_broker, token=OLD_TOKEN)
    os.chmod(store.credentials_path(), 0o644)
    result = _invoke("login")
    assert result.exit_code == 0, result.output
    assert "accessible by other users" in result.stderr
    assert store.load().access_token == SESSION_TOKEN


def test_login_denied(fake_broker, opened) -> None:
    fake_broker.token_script.clear()
    fake_broker.token_script.append((400, {"error": "access_denied"}))
    result = _invoke("login")
    assert result.exit_code == 1
    assert "denied" in result.stderr
    assert not store.exists()


def test_login_ctrl_c_is_clean(fake_broker, monkeypatch) -> None:
    def interrupt(_s):
        raise KeyboardInterrupt

    monkeypatch.setattr(device.time, "sleep", interrupt)
    monkeypatch.setattr(device.webbrowser, "open", lambda _u: None)
    result = _invoke("login")
    assert result.exit_code == 130
    assert "Login cancelled." in result.stderr
    assert "Traceback" not in result.output
    assert not store.exists()


def test_login_rejects_control_chars_in_label(fake_broker, opened) -> None:
    result = _invoke("login", "--label", "evil\x1b[2J")
    assert result.exit_code == 1
    assert fake_broker.requests == []


def test_login_refuses_cleartext_remote_broker(monkeypatch, opened) -> None:
    monkeypatch.setenv("POCKETSHELL_BROKER_URL", "http://broker.example.com")
    monkeypatch.delenv("POCKETSHELL_BROKER_INSECURE_DEV", raising=False)
    result = _invoke("login")
    assert result.exit_code == 1
    assert "https" in result.stderr


def test_whoami_not_logged_in(fake_broker) -> None:
    result = _invoke("whoami")
    assert result.exit_code == 1
    assert "pocketshell login" in result.stderr
    result = _invoke("whoami", "--json")
    assert result.exit_code == 1
    assert json.loads(result.stdout) == {"logged_in": False}


def test_whoami_shows_verified_session(fake_broker) -> None:
    _save(fake_broker)
    fake_broker.label = "laptop\x1b]0;pwned\x07"
    result = _invoke("whoami")
    assert result.exit_code == 0, result.output
    assert "Logged in as me@example.com" in result.stdout
    assert "verified: yes" in result.stdout
    assert "https://app.pocketshell.io/device/sessions" in result.stdout
    assert "\x1b" not in result.stdout and "\x07" not in result.stdout
    _assert_no_secrets(result)


def test_whoami_json(fake_broker) -> None:
    _save(fake_broker)
    result = _invoke("whoami", "--json")
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["logged_in"] is True and data["verified"] is True
    assert data["email"] == "me@example.com"
    assert data["broker_url"] == fake_broker.url
    assert "access_token" not in data
    _assert_no_secrets(result)


def test_whoami_revoked_session(fake_broker) -> None:
    _save(fake_broker)
    fake_broker.logged_out = True
    result = _invoke("whoami")
    assert result.exit_code == 1
    assert "no longer valid" in result.stderr


def test_whoami_offline_falls_back_to_local_info(fake_broker, monkeypatch) -> None:
    _save(fake_broker, broker_url="http://127.0.0.1:1")
    monkeypatch.setenv("POCKETSHELL_BROKER_URL", "http://127.0.0.1:1")
    result = _invoke("whoami", "--json")
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["verified"] is False
    assert "could not verify" in result.stderr


def test_whoami_does_not_send_session_to_env_broker(fake_broker, monkeypatch) -> None:
    _save(fake_broker)
    monkeypatch.setenv("POCKETSHELL_BROKER_URL", "https://other.example.com")
    result = _invoke("whoami", "--json")
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["verified"] is False
    assert "differs from the broker you logged in to" in result.stderr
    assert fake_broker.requests == []


def test_logout_with_env_broker_mismatch_deletes_without_sending(fake_broker, monkeypatch) -> None:
    _save(fake_broker)
    monkeypatch.setenv("POCKETSHELL_BROKER_URL", "https://other.example.com")
    result = _invoke("logout")
    assert result.exit_code == 0, result.output
    assert "could not revoke" in result.stderr
    assert fake_broker.requests == []
    assert not store.exists()


def test_logout_revokes_and_deletes(fake_broker) -> None:
    _save(fake_broker)
    result = _invoke("logout")
    assert result.exit_code == 0, result.output
    assert "Logged out." in result.stdout
    assert fake_broker.logged_out is True
    [req] = fake_broker.requests_to("/cli/logout")
    assert req["method"] == "POST"
    assert not store.exists()
    result = _invoke("logout")
    assert result.exit_code == 0
    assert "Not logged in." in result.stdout
    _assert_no_secrets(result)


def test_logout_still_deletes_when_broker_unreachable(fake_broker, monkeypatch) -> None:
    _save(fake_broker, broker_url="http://127.0.0.1:1")
    monkeypatch.delenv("POCKETSHELL_BROKER_URL")
    result = _invoke("logout")
    assert result.exit_code == 0, result.output
    assert "could not revoke" in result.stderr
    assert "Could not reach" in result.stderr
    assert not store.exists()


def test_logout_revokes_a_leaked_mode_file(fake_broker) -> None:
    _save(fake_broker)
    os.chmod(store.credentials_path(), 0o644)
    result = _invoke("logout")
    assert result.exit_code == 0, result.output
    assert fake_broker.logged_out is True
    assert not store.exists()


def test_logout_removes_symlink_without_contacting_broker(fake_broker, tmp_path) -> None:
    _save(fake_broker)
    path = store.credentials_path()
    real = tmp_path / "elsewhere.json"
    os.replace(path, real)
    path.symlink_to(real)
    result = _invoke("logout")
    assert result.exit_code == 0, result.output
    assert fake_broker.requests == []
    assert not os.path.lexists(path)
    assert real.exists()


def test_logout_with_already_revoked_session_is_clean(fake_broker) -> None:
    """Broker answers 401 invalid_token: already logged out, no warning, file gone."""
    _save(fake_broker, token=OLD_TOKEN)
    result = _invoke("logout")
    assert result.exit_code == 0, result.output
    assert "Logged out." in result.stdout
    assert "could not revoke" not in result.stderr
    assert len(fake_broker.requests_to("/cli/logout")) == 1
    assert not store.exists()


def test_unexpected_exception_is_one_line_without_traceback(fake_broker, monkeypatch) -> None:
    def boom(*_a, **_k):
        raise RuntimeError("server said \x1b[2J" + SESSION_TOKEN)

    monkeypatch.setattr(device.broker, "start_device", boom)
    result = _invoke("login")
    assert result.exit_code == 1
    assert result.stderr.strip() == "error: unexpected internal error (RuntimeError)."
    assert "Traceback" not in result.output
    _assert_no_secrets(result)


def test_network_error_text_is_sanitized(fake_broker, monkeypatch) -> None:
    import urllib.error

    from pocketshell.account import broker as client

    class EvilOpener:
        def open(self, *_a, **_k):
            raise urllib.error.URLError("\x1b]0;owned\x07 dns failure")

    monkeypatch.setattr(client, "_build_opener", lambda: EvilOpener())
    _save(fake_broker)
    result = _invoke("whoami")
    assert result.exit_code == 0, result.output
    assert "\x1b" not in result.stderr and "\x07" not in result.stderr
    assert "]0;owned dns failure" in result.stderr


# --- broker rate limiting (429 rate_limited) and idle sessions ----------------

RATE_LIMITED = (429, {"error": "rate_limited"})


def test_logout_on_429_keeps_the_credentials_and_says_retry(fake_broker) -> None:
    _save(fake_broker)
    fake_broker.overrides[("POST", "/cli/logout")] = RATE_LIMITED
    result = _invoke("logout")
    assert result.exit_code == 1
    assert "rate limiting" in result.stderr
    assert "run `pocketshell logout` again" in result.stderr
    assert "Logged out." not in result.stdout
    assert store.exists()
    assert store.load().access_token == SESSION_TOKEN
    _assert_no_secrets(result)
    # Once the broker stops throttling, logout works as usual.
    del fake_broker.overrides[("POST", "/cli/logout")]
    result = _invoke("logout")
    assert result.exit_code == 0, result.output
    assert not store.exists()


def test_whoami_on_429_is_not_logged_out(fake_broker) -> None:
    _save(fake_broker)
    fake_broker.overrides[("GET", "/cli/session")] = RATE_LIMITED
    result = _invoke("whoami", "--json")
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["verified"] is False
    assert "rate limiting" in result.stderr
    assert store.exists()


def test_idle_session_401_invalid_token_is_not_logged_in(fake_broker) -> None:
    _save(fake_broker)
    fake_broker.overrides[("GET", "/cli/session")] = (401, {"error": "invalid_token"})
    result = _invoke("whoami")
    assert result.exit_code == 1
    assert "no longer valid" in result.stderr


def test_no_request_ever_carries_an_origin_header(fake_broker, opened) -> None:
    """The broker refuses browser-originated calls (403 browser_origin_refused)."""
    assert _invoke("login", "--no-open").exit_code == 0
    assert _invoke("whoami").exit_code == 0
    from pocketshell.account import mint_gateway_token

    mint_gateway_token()
    assert _invoke("logout").exit_code == 0
    paths = {r["path"] for r in fake_broker.requests}
    assert {
        "/auth/device/start", "/auth/device/token", "/cli/session",
        "/cli/gateway/token", "/cli/logout",
    } <= paths
    for req in fake_broker.requests:
        assert not any(h.lower() == "origin" for h in req["headers"]), req["path"]
