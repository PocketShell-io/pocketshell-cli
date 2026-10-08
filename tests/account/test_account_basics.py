"""Public types, terminal sanitization and broker-URL policy."""

from __future__ import annotations

import pytest

from pocketshell.account import AccountError, GatewayToken, NotLoggedIn, broker_url
from pocketshell.account.config import DEFAULT_BROKER_URL, validate_broker_url
from pocketshell.account.sanitize import clean_text, https_url

SECRET_JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl"


def test_gateway_token_repr_and_str_redact_the_token() -> None:
    tok = GatewayToken(token=SECRET_JWT, expires_at=123)
    assert SECRET_JWT not in repr(tok)
    assert SECRET_JWT not in str(tok)
    assert "<redacted>" in repr(tok)
    assert tok.token == SECRET_JWT and tok.expires_at == 123
    with pytest.raises(AttributeError):
        tok.token = "x"  # type: ignore[misc]


def test_not_logged_in_is_an_account_error() -> None:
    assert issubclass(NotLoggedIn, AccountError)


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("plain text", "plain text"),
        ("\x1b[31mred\x1b[0m", "[31mred[0m"),
        ("osc\x1b]52;c;ZXZpbA==\x07end", "osc]52;c;ZXZpbA==end"),
        ("a\r\nb\tc", "abc"),
        ("bidi‮evil‬", "bidievil"),
        ("zero​width", "zerowidth"),
        ("c1\x9bcontrol", "c1control"),
        ("line sep", "linesep"),
        (None, ""),
        (42, ""),
    ],
)
def test_clean_text_strips_control_and_format_characters(raw, expected) -> None:
    assert clean_text(raw) == expected


def test_clean_text_caps_length() -> None:
    assert len(clean_text("x" * 500, max_len=50)) == 50


@pytest.mark.parametrize(
    "value, ok",
    [
        ("https://app.pocketshell.io/device", True),
        ("https://app.pocketshell.io/device?code=BCDF-GHJK", True),
        ("http://app.pocketshell.io/device", False),
        ("javascript:alert(1)", False),
        ("file:///etc/passwd", False),
        ("https://user@evil.example/device", False),
        ("https://app.pocketshell.io/dev ice", False),
        ("https://app.pocketshell.io/\x1b[2J", False),
        ("https://app.pocketshell.io/‮device", False),
        ("https:///nohost", False),
        ("https://host:notaport/", False),
        (None, False),
    ],
)
def test_https_url(value, ok) -> None:
    assert https_url(value) == (value if ok else None)


def test_broker_url_defaults_to_production(monkeypatch) -> None:
    monkeypatch.delenv("POCKETSHELL_BROKER_URL", raising=False)
    assert broker_url() == DEFAULT_BROKER_URL


def test_broker_url_override_is_normalized(monkeypatch) -> None:
    monkeypatch.setenv("POCKETSHELL_BROKER_URL", "HTTPS://Broker.Example.COM/stage/")
    assert broker_url() == "https://broker.example.com/stage"


@pytest.mark.parametrize(
    "raw",
    [
        "http://broker.example.com",
        "ftp://broker.example.com",
        "https://user:pw@broker.example.com",
        "https://broker.example.com/?x=1",
        "https://broker.example.com/#frag",
        "https://",
        "https://broker.example.com/\x1b[2J",
        "",
    ],
)
def test_broker_url_rejects_unsafe_values(raw) -> None:
    with pytest.raises(AccountError):
        validate_broker_url(raw)


def test_http_requires_dev_flag_and_loopback(monkeypatch) -> None:
    monkeypatch.delenv("POCKETSHELL_BROKER_INSECURE_DEV", raising=False)
    with pytest.raises(AccountError, match="https"):
        validate_broker_url("http://127.0.0.1:8080")
    monkeypatch.setenv("POCKETSHELL_BROKER_INSECURE_DEV", "1")
    assert validate_broker_url("http://127.0.0.1:8080/") == "http://127.0.0.1:8080"
    assert validate_broker_url("http://[::1]:9/") == "http://[::1]:9"
    assert validate_broker_url("http://localhost:9") == "http://localhost:9"
    with pytest.raises(AccountError, match="https"):
        validate_broker_url("http://broker.example.com")
    with pytest.raises(AccountError, match="https"):
        validate_broker_url("http://10.0.0.1")


def test_account_error_messages_are_sanitized_on_construction() -> None:
    exc = NotLoggedIn("bad \x1b]52;c;ZXZpbA==\x07path‮/x\nmore")
    assert str(exc) == "bad ]52;c;ZXZpbA==path/xmore"
