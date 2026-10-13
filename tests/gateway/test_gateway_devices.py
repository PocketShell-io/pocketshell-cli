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


@pytest.mark.parametrize(
    "raw",
    [
        b"HTTP/1.1 \x1b]52;c;ZXZpbA==\x07 200 OK\r\n\r\n",  # BadStatusLine
        b"\x1b[2J\x1b]0;pwned\x07garbage\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\x1b[31m\r\n",
    ],
)
def test_malformed_http_response_is_a_clean_error(fake_account, raw):
    import socket

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(4)
    port = sock.getsockname()[1]

    def serve():
        try:
            conn, _ = sock.accept()
            with conn:
                conn.recv(65536)
                conn.sendall(raw)
        except OSError:
            pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        result = CliRunner().invoke(
            cli,
            [
                "gateway", "devices", "--server", f"http://127.0.0.1:{port}",
                "--insecure-dev", "--trust-gateway", "127.0.0.1",
            ],
        )
    finally:
        t.join(5)
        sock.close()
    assert result.exit_code == 1, result.output
    assert "malformed HTTP response from the gateway" in result.output
    assert "\x1b" not in result.output and "\x07" not in result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)


# --- presence (gateways that report host-agent liveness) -------------------

OBSERVED = "2026-10-10T12:01:00.250Z"


def _presence(online, since=None, generation=None, observed=OBSERVED):
    p = {"online": online, "observed_at": observed}
    if since is not None:
        p["connected_since"] = since
    if generation is not None:
        p["session_generation"] = generation
    return p


def _rows(output):
    return {line.split()[0]: line.split() for line in output.splitlines() if line.strip()}


def test_online_column_when_gateway_reports_presence(server, fake_account):
    up = _dev("home-lab")
    up["presence"] = _presence(True, "2026-10-10T11:58:12.004Z", 3)
    down = _dev("spare-box")
    down["presence"] = _presence(False)
    gone = _dev("old-box", revoked=True)
    gone["presence"] = _presence(True, "2026-10-10T11:00:00.000Z", 1)  # never trusted
    server.body = json.dumps({"devices": [up, down, gone]}).encode()
    result = _invoke(server)
    assert result.exit_code == 0, result.output
    rows = _rows(result.output)
    assert rows["DEVICE"][:3] == ["DEVICE", "STATE", "ONLINE"]
    assert rows["home-lab"][1:3] == ["active", "yes"]
    assert rows["spare-box"][1:3] == ["active", "no"]
    assert rows["old-box"][1:3] == ["revoked", "no"]
    assert f"as of {OBSERVED} (gateway clock)" in result.output

    js = CliRunner().invoke(
        cli,
        ["gateway", "devices", "--json", "--server", server.url,
         "--insecure-dev", "--trust-gateway", "127.0.0.1"],
    )
    assert js.exit_code == 0, js.output
    by_id = {d["id"]: d for d in json.loads(js.stdout)["devices"]}
    assert by_id["home-lab"]["online"] is True
    assert by_id["home-lab"]["observed_at"] == OBSERVED
    assert by_id["home-lab"]["connected_since"] == "2026-10-10T11:58:12.004Z"
    assert by_id["home-lab"]["session_generation"] == 3
    assert by_id["spare-box"]["online"] is False
    assert by_id["spare-box"]["connected_since"] is None
    assert by_id["old-box"]["online"] is False
    assert by_id["old-box"]["connected_since"] is None
    assert by_id["old-box"]["session_generation"] is None


def test_no_presence_keeps_previous_layout(server, fake_account):
    server.body = json.dumps({"devices": [_dev("home-lab")]}).encode()
    result = _invoke(server)
    assert result.exit_code == 0, result.output
    assert "ONLINE" not in result.output
    assert _rows(result.output)["DEVICE"][:3] == ["DEVICE", "STATE", "ADVERTISED"]
    js = CliRunner().invoke(
        cli,
        ["gateway", "devices", "--json", "--server", server.url,
         "--insecure-dev", "--trust-gateway", "127.0.0.1"],
    )
    dev = json.loads(js.stdout)["devices"][0]
    assert dev["online"] is None and dev["observed_at"] is None


def test_mixed_presence_marks_unreported_as_unknown(server, fake_account):
    up = _dev("home-lab")
    up["presence"] = _presence(True, "2026-10-10T11:58:12.004Z", 1)
    server.body = json.dumps({"devices": [up, _dev("legacy-box")]}).encode()
    result = _invoke(server)
    assert result.exit_code == 0, result.output
    rows = _rows(result.output)
    assert rows["home-lab"][2] == "yes"
    assert rows["legacy-box"][2] == "?"


@pytest.mark.parametrize(
    "raw",
    [
        "yes",
        [],
        {},
        {"online": "true"},
        {"online": 1},
        {"online": None},
    ],
)
def test_malformed_presence_is_unknown_not_an_error(raw):
    item = _dev("home-lab")
    item["presence"] = raw
    (dev,) = parse_devices(json.dumps({"devices": [item]}).encode())
    assert dev.presence is None


def test_hostile_presence_fields_are_dropped(server, fake_account):
    item = _dev("home-lab")
    item["presence"] = {
        "online": True,
        "observed_at": "\x1b]0;pwned\x07",
        "connected_since": "2026-10-10T11:58:12Z\x1b[31m",
        "session_generation": True,  # bool is not a generation
    }
    (dev,) = parse_devices(json.dumps({"devices": [item]}).encode())
    assert dev.presence is not None and dev.presence.online is True
    assert dev.presence.observed_at is None
    assert dev.presence.connected_since is None
    assert dev.presence.session_generation is None
    server.body = json.dumps({"devices": [item]}).encode()
    result = _invoke(server)
    assert result.exit_code == 0, result.output
    assert "\x1b" not in result.output and "\x07" not in result.output
    assert "as of" not in result.output  # no trustworthy observation time


def test_offline_presence_drops_session_fields():
    item = _dev("home-lab")
    item["presence"] = _presence(False, "2026-10-10T11:58:12.004Z", 9)
    (dev,) = parse_devices(json.dumps({"devices": [item]}).encode())
    assert dev.presence.online is False
    assert dev.presence.connected_since is None
    assert dev.presence.session_generation is None
    assert dev.presence.observed_at == OBSERVED
