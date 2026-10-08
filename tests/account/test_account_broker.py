"""Broker HTTP client hardening and the public mint_gateway_token()."""

from __future__ import annotations

import json
import time

import pytest

from pocketshell.account import (
    AccountError,
    GatewayToken,
    NotLoggedIn,
    broker_url,
    mint_gateway_token,
)
from pocketshell.account import broker as client
from pocketshell.account import credentials as store

SESSION_TOKEN = "psc_" + "S" * 43  # the fake broker's session token


def _login(fake_broker, **over) -> None:
    values = dict(
        broker_url=fake_broker.url,
        access_token=SESSION_TOKEN,
        token_id="tok_123",
        email="me@example.com",
        expires_at=int(time.time()) + 3600,
        label="me@laptop",
    )
    values.update(over)
    store.save(store.Credentials(**values))


def test_mint_gateway_token_happy_path(fake_broker) -> None:
    _login(fake_broker)
    tok = mint_gateway_token()
    assert isinstance(tok, GatewayToken)
    assert tok.token == fake_broker.gateway_jwt
    assert time.time() < tok.expires_at <= time.time() + 301
    [req] = fake_broker.requests_to("/cli/gateway/token")
    assert req["method"] == "POST"
    assert req["body"] == b""
    assert req["headers"]["Authorization"] == f"Bearer {SESSION_TOKEN}"
    assert broker_url() == fake_broker.url


def test_mint_explicit_broker_url_matches_stored(fake_broker) -> None:
    _login(fake_broker)
    assert mint_gateway_token(broker_url=fake_broker.url + "/").token


def test_mint_without_login_raises_not_logged_in(fake_broker) -> None:
    with pytest.raises(NotLoggedIn, match="pocketshell login"):
        mint_gateway_token()
    assert fake_broker.requests == []


def test_mint_with_expired_session_does_not_call_broker(fake_broker) -> None:
    _login(fake_broker, expires_at=int(time.time()) - 5)
    with pytest.raises(NotLoggedIn, match="expired"):
        mint_gateway_token()
    assert fake_broker.requests == []


def test_mint_on_401_raises_not_logged_in(fake_broker) -> None:
    _login(fake_broker)
    fake_broker.logged_out = True
    with pytest.raises(NotLoggedIn, match="run `pocketshell login`") as info:
        mint_gateway_token()
    assert SESSION_TOKEN not in str(info.value)


def test_mint_never_sends_session_to_a_different_broker(fake_broker, monkeypatch) -> None:
    _login(fake_broker, broker_url="https://other-broker.example.com")
    with pytest.raises(NotLoggedIn, match="different PocketShell broker"):
        mint_gateway_token()
    assert fake_broker.requests == []


def test_mint_refuses_unsafe_credentials_file(fake_broker) -> None:
    _login(fake_broker)
    store.credentials_path().chmod(0o644)
    with pytest.raises(NotLoggedIn):
        mint_gateway_token()
    assert fake_broker.requests == []


@pytest.mark.parametrize(
    "body",
    [
        {"token": "not-a-jwt", "token_type": "Bearer", "expires_in": 300},
        {"token": "a.b", "token_type": "Bearer", "expires_in": 300},
        {"token": "a.b.c.d", "token_type": "Bearer", "expires_in": 300},
        {"token": "bm90.anNvbg.c2ln", "token_type": "Bearer", "expires_in": 300},
        {"token": "x y.z.w", "token_type": "Bearer", "expires_in": 300},
        {"token": 12, "token_type": "Bearer", "expires_in": 300},
    ],
)
def test_mint_rejects_tokens_that_are_not_jwts(fake_broker, body) -> None:
    _login(fake_broker)
    body = dict(body, expires_at=int(time.time()) + 300)
    fake_broker.overrides[("POST", "/cli/gateway/token")] = (200, body)
    with pytest.raises(AccountError, match="malformed"):
        mint_gateway_token()


@pytest.mark.parametrize("delta", [-3600, 86400, None, "300", True])
def test_mint_rejects_insane_expiry(fake_broker, delta) -> None:
    _login(fake_broker)
    expires_at = int(time.time()) + delta if isinstance(delta, int) and not isinstance(
        delta, bool
    ) else delta
    fake_broker.overrides[("POST", "/cli/gateway/token")] = (
        200,
        {"token": fake_broker.make_jwt(1), "token_type": "Bearer", "expires_in": 300, "expires_at": expires_at},
    )
    with pytest.raises(AccountError):
        mint_gateway_token()


def test_mint_403_is_an_account_error_not_not_logged_in(fake_broker) -> None:
    _login(fake_broker)
    fake_broker.overrides[("POST", "/cli/gateway/token")] = (403, {"error": "forbidden"})
    with pytest.raises(AccountError, match="403") as info:
        mint_gateway_token()
    assert not isinstance(info.value, NotLoggedIn)


def test_redirects_are_not_followed(fake_broker) -> None:
    _login(fake_broker)
    fake_broker.overrides[("POST", "/cli/gateway/token")] = (307, None)
    with pytest.raises(AccountError, match="HTTP 307"):
        mint_gateway_token()
    assert len(fake_broker.requests) == 1


def test_response_body_is_capped(fake_broker) -> None:
    big = b'{"pad": "' + b"x" * (client.MAX_BODY_BYTES + 10) + b'"}'
    fake_broker.overrides[("GET", "/cli/session")] = (200, big)
    with pytest.raises(AccountError, match="too large"):
        client.request(fake_broker.url, "GET", "/cli/session")


@pytest.mark.parametrize(
    "raw",
    [b"not json", b"[1,2]", b'{"a":1,"a":2}', b'{"a": NaN}', b"\xff\xfe"],
)
def test_success_body_must_be_strict_json_object(fake_broker, raw) -> None:
    fake_broker.overrides[("GET", "/cli/session")] = (200, raw)
    with pytest.raises(AccountError, match="malformed"):
        client.request(fake_broker.url, "GET", "/cli/session")


def test_error_code_from_server_is_only_echoed_when_plain(fake_broker) -> None:
    fake_broker.overrides[("GET", "/cli/session")] = (500, {"error": "\x1b[2Jboom " + SESSION_TOKEN})
    resp = client.request(fake_broker.url, "GET", "/cli/session")
    assert resp.status == 500 and resp.error is None
    fake_broker.overrides[("GET", "/cli/session")] = (500, {"error": "server_error"})
    assert client.request(fake_broker.url, "GET", "/cli/session").error == "server_error"


def test_unreachable_broker_is_broker_unavailable(monkeypatch) -> None:
    from pocketshell.account.errors import BrokerUnavailable

    with pytest.raises(BrokerUnavailable, match="Could not reach"):
        client.request("http://127.0.0.1:1", "GET", "/cli/session", timeout=2)


def test_session_token_never_in_url_or_query(fake_broker) -> None:
    _login(fake_broker)
    mint_gateway_token()
    for req in fake_broker.requests:
        assert SESSION_TOKEN not in req["path"]
        assert "?" not in req["path"]


def test_get_session_validates_types(fake_broker) -> None:
    body = fake_broker.session_body()
    body["expires_at"] = "soon"
    fake_broker.overrides[("GET", "/cli/session")] = (200, body)
    with pytest.raises(AccountError, match="expires_at"):
        client.get_session(fake_broker.url, SESSION_TOKEN)


def test_json_body_is_sent_as_json(fake_broker) -> None:
    client.start_device(fake_broker.url, "me@laptop")
    [req] = fake_broker.requests
    assert req["headers"]["Content-Type"] == "application/json"
    assert json.loads(req["body"]) == {"label": "me@laptop"}
