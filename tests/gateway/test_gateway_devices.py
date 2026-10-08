"""`pocketshell gateway devices` against a local fake identity API."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from click.testing import CliRunner

from conftest import FAKE_JWT
from gateway_keyblobs import ED25519_LINE, ED25519_LINE_2
from pocketshell.cli import cli
from pocketshell.gateway import pins
from pocketshell.gateway.devices import DevicesError, parse_devices


class _Server:
    def __init__(self):
        self.requests = []
        self.status = 200
        self.body = b'{"devices":[]}'
        self.headers = {}
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                outer.requests.append((self.path, dict(self.headers)))
                self.send_response(outer.status)
                for k, v in outer.headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(outer.body)))
                self.end_headers()
                self.wfile.write(outer.body)

            def log_message(self, *args):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def server():
    s = _Server()
    yield s
    s.close()


def _dev(id_, key=ED25519_LINE, revoked=False):
    return {
        "id": id_,
        "account_id": "acct",
        "public_key": "AAAA",
        "ssh_host_key": key,
        "revoked": revoked,
    }


def _invoke(server, *extra):
    return CliRunner().invoke(
        cli,
        [
            "gateway", "devices", "--server", server.url, "--insecure-dev",
            "--trust-gateway", "127.0.0.1", *extra,
        ],
    )


def test_lists_devices_with_bearer_header_only(server, fake_account):
    server.body = json.dumps(
        {"devices": [_dev("home-lab"), _dev("old-box", revoked=True)]}
    ).encode()
    result = _invoke(server)
    assert result.exit_code == 0, result.output
    path, headers = server.requests[0]
    assert path == "/identity/v1/devices"
    assert headers["Authorization"] == f"Bearer {FAKE_JWT}"
    assert FAKE_JWT not in result.output
    assert "home-lab" in result.output and "active" in result.output
    assert "old-box" in result.output and "revoked" in result.output
    fp = pins.parse_host_key(ED25519_LINE).fingerprint
    assert fp in result.output
    assert "UNTRUSTED" in result.output
    assert "not pinned" in result.output


def test_json_output_and_pin_state(server, fake_account):
    pins.add_pin("home-lab", pins.parse_host_key(ED25519_LINE))
    pins.add_pin("other-box", pins.parse_host_key(ED25519_LINE))
    server.body = json.dumps(
        {"devices": [_dev("home-lab"), _dev("other-box", key=ED25519_LINE_2), _dev("new-box", key="")]}
    ).encode()
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "gateway", "devices", "--json", "--server", server.url,
            "--insecure-dev", "--trust-gateway", "127.0.0.1",
        ],
    )
    assert result.exit_code == 0, result.output
    doc = json.loads(result.stdout)
    by_id = {d["id"]: d for d in doc["devices"]}
    fp1 = pins.parse_host_key(ED25519_LINE).fingerprint
    assert by_id["home-lab"]["pinned_fingerprint"] == fp1
    assert by_id["home-lab"]["advertised_fingerprint"] == fp1
    assert by_id["other-box"]["advertised_fingerprint"] != fp1
    assert by_id["new-box"]["advertised_fingerprint"] is None
    # never the paste-able key line (no `jq | gateway pin` TOFU)
    assert ED25519_LINE.split()[1] not in result.stdout
    assert "advertised_ssh_host_key" not in result.stdout
    assert by_id["new-box"]["pinned_fingerprint"] is None
    text = _invoke(server)
    assert "pinned (DIFFERS from advertised)" in text.output


def test_hostile_ids_are_sanitized_for_display(server, fake_account):
    evil = "\x1b]0;pwned\x07\x1b[31mevil‮id\r\nfake-line"
    server.body = json.dumps({"devices": [_dev(evil, key="garbage")]}).encode()
    result = _invoke(server)
    assert result.exit_code == 0, result.output
    assert "\x1b" not in result.output
    assert "‮" not in result.output
    assert "\r" not in result.output
    assert "invalid id" in result.output


@pytest.mark.parametrize(
    "body",
    [
        b"not json",
        b"[]",
        b'{"devices": {}}',
        b'{"devices": [1]}',
        b'{"devices": [{"id": "abc"}]}',
        b'{"devices": [], "devices": []}',
        b'{"devices": [{"id":"abc","account_id":"a","public_key":"p",'
        b'"ssh_host_key":"k","revoked":"no"}]}',
        b'{"devices": NaN}',
    ],
)
def test_malformed_lists_are_refused(body):
    with pytest.raises(DevicesError):
        parse_devices(body)


@pytest.mark.parametrize(
    ("status", "needle"),
    [(401, "rejected the token"), (404, "does not serve"), (500, "HTTP 500")],
)
def test_http_errors(server, fake_account, status, needle):
    server.status = status
    server.body = b'{"error":"\x1b[31mboom"}'
    result = _invoke(server)
    assert result.exit_code == 1
    assert needle in result.output
    assert "\x1b" not in result.output


def test_redirects_are_not_followed(server, fake_account):
    other = _Server()
    try:
        server.status = 302
        server.headers = {"Location": other.url + "/identity/v1/devices"}
        result = _invoke(server)
        assert result.exit_code == 1
        assert "redirect" in result.output
        assert other.requests == []  # the bearer token never left for the target
    finally:
        other.close()


def test_not_logged_in_exits_3(server, fake_account):
    fake_account.error = fake_account.module.NotLoggedIn("no credentials")
    result = _invoke(server)
    assert result.exit_code == 3
    assert "pocketshell login" in result.output
    assert server.requests == []


def test_missing_login_support_exits_3(server, no_account):
    result = _invoke(server)
    assert result.exit_code == 3
    assert server.requests == []


def test_account_error_message_is_sanitized(server, fake_account):
    fake_account.error = fake_account.module.AccountError("broker \x1b[2Jdown")
    result = _invoke(server)
    assert result.exit_code == 1
    assert "broker down" in result.output
    assert "\x1b" not in result.output


@pytest.mark.parametrize(
    "args",
    [
        ["--trust-gateway", "127.0.0.1"],  # plain http without --insecure-dev
        ["--insecure-dev"],  # non-production host without --trust-gateway
        ["--insecure-dev", "--trust-gateway", "localhost"],  # trust must match exactly
    ],
)
def test_refused_endpoints_never_mint_or_send(server, fake_account, args):
    result = CliRunner().invoke(cli, ["gateway", "devices", "--server", server.url, *args])
    assert result.exit_code == 2
    assert server.requests == []
    assert fake_account.calls == 0


def test_env_proxies_are_ignored(server, fake_account, monkeypatch):
    """HTTPS_PROXY/http_proxy must not see the broker JWT (cleartext in dev)."""
    from tests.account.test_account_tls import PROXY_VARS, RecordingProxy

    proxy = RecordingProxy()
    try:
        for name in PROXY_VARS:
            monkeypatch.setenv(name, proxy.url)
        monkeypatch.delenv("NO_PROXY", raising=False)
        monkeypatch.delenv("no_proxy", raising=False)
        result = _invoke(server)
        assert result.exit_code == 0, result.output
        assert server.requests[0][1]["Authorization"] == f"Bearer {FAKE_JWT}"
        assert proxy.seen == []
    finally:
        proxy.close()
