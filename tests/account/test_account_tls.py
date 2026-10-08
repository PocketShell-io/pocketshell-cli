"""Token-bearing requests ignore environment proxies and CA overrides.

``HTTPS_PROXY``/``http_proxy`` would route the session token or broker JWT
through whoever the environment names; ``SSL_CERT_FILE``/``SSL_CERT_DIR``
would let an attacker CA terminate TLS. Both are ignored by
:mod:`pocketshell.tokentls`.
"""

from __future__ import annotations

import datetime
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from pocketshell.account import broker as client
from pocketshell.account import credentials as store
from pocketshell import tokentls as tls
from pocketshell.account import mint_gateway_token
from pocketshell.account.errors import BrokerUnavailable

SESSION_TOKEN = "psc_" + "S" * 43

PROXY_VARS = (
    "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy",
)


class RecordingProxy:
    """A TCP listener that records every connection (and its first bytes)."""

    def __init__(self) -> None:
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.sock.settimeout(0.05)
        self.seen: list[bytes] = []
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.sock.getsockname()[1]}"

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except (TimeoutError, socket.timeout, OSError):
                continue
            with conn:
                conn.settimeout(1)
                try:
                    self.seen.append(conn.recv(65536))
                except OSError:
                    self.seen.append(b"")
                try:
                    conn.sendall(b"HTTP/1.0 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                except OSError:
                    pass

    def close(self) -> None:
        self._stop.set()
        self.thread.join(2)
        self.sock.close()


@pytest.fixture
def hostile_proxy(monkeypatch):
    proxy = RecordingProxy()
    for name in PROXY_VARS:
        monkeypatch.setenv(name, proxy.url)
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    try:
        yield proxy
    finally:
        proxy.close()


def _login(url: str) -> None:
    store.save(
        store.Credentials(
            broker_url=url,
            access_token=SESSION_TOKEN,
            token_id="tok_123",
            email="me@example.com",
            expires_at=int(time.time()) + 3600,
            label="me@laptop",
        )
    )


def test_stdlib_would_use_the_env_proxy(hostile_proxy) -> None:
    """Sanity: the fixture really is a proxy urllib would pick up by default."""
    assert urllib.request.getproxies().get("http") == hostile_proxy.url
    with pytest.raises(urllib.error.HTTPError):
        urllib.request.build_opener().open("http://127.0.0.1:9/x", timeout=5)
    assert hostile_proxy.seen and hostile_proxy.seen[0].startswith(b"GET http://127.0.0.1:9/x")


def test_broker_requests_ignore_env_proxies(fake_broker, hostile_proxy) -> None:
    _login(fake_broker.url)
    assert mint_gateway_token().token == fake_broker.gateway_jwt
    [req] = fake_broker.requests_to("/cli/gateway/token")
    assert req["headers"]["Authorization"] == f"Bearer {SESSION_TOKEN}"
    assert hostile_proxy.seen == []


def test_token_opener_installs_no_proxy_handler(hostile_proxy) -> None:
    def proxy_handlers(opener):
        return [h for h in opener.handlers if isinstance(h, urllib.request.ProxyHandler)]

    # The default opener would carry a ProxyHandler for the env proxies; the
    # empty ProxyHandler({}) replaces it and registers no *_open methods.
    assert proxy_handlers(urllib.request.build_opener())
    assert proxy_handlers(tls.token_opener()) == []


# -- CA overrides -------------------------------------------------------------


def _make_ca_and_leaf(tmp_path):
    x509 = pytest.importorskip("cryptography.x509")
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pocketshell evil test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    import ipaddress

    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    pem = serialization.Encoding.PEM
    ca_file = tmp_path / "evil-ca.pem"
    ca_file.write_bytes(ca.public_bytes(pem))
    leaf_file = tmp_path / "leaf.pem"
    leaf_file.write_bytes(leaf.public_bytes(pem))
    key_file = tmp_path / "leaf.key"
    key_file.write_bytes(
        leaf_key.private_bytes(
            pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    return ca_file, leaf_file, key_file


@pytest.fixture
def evil_tls_server(tmp_path):
    ca_file, leaf_file, key_file = _make_ca_and_leaf(tmp_path)
    seen = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            seen.append(dict(self.headers))
            self.send_response(500)
            self.send_header("Content-Length", "0")
            self.end_headers()

        do_GET = do_POST

        def log_message(self, *args):
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    sctx.load_cert_chain(str(leaf_file), str(key_file))
    httpd.socket = sctx.wrap_socket(httpd.socket, server_side=True)
    thread = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    try:
        yield f"https://127.0.0.1:{httpd.server_address[1]}", ca_file, seen
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_ssl_cert_file_and_dir_are_ignored(evil_tls_server, tmp_path, monkeypatch) -> None:
    url, ca_file, seen = evil_tls_server
    monkeypatch.setenv("SSL_CERT_FILE", str(ca_file))
    monkeypatch.setenv("SSL_CERT_DIR", str(tmp_path))
    # Sanity: the stdlib default context trusts the attacker CA via the env.
    stdlib_ctx = ssl.create_default_context()
    assert any(
        ("commonName", "pocketshell evil test CA") in rdn
        for c in stdlib_ctx.get_ca_certs()
        for rdn in c["subject"]
    )
    ctx = tls.token_ssl_context()
    assert not any(
        ("commonName", "pocketshell evil test CA") in rdn
        for c in ctx.get_ca_certs()
        for rdn in c["subject"]
    )
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    # End to end: the broker client refuses the attacker-CA server and never
    # sends it the session token.
    with pytest.raises(BrokerUnavailable, match="TLS verification"):
        client.request(url, "GET", "/cli/session", bearer=SESSION_TOKEN, timeout=5)
    assert seen == []


def test_no_platform_trust_store_fails_closed(monkeypatch, tmp_path, evil_tls_server) -> None:
    url, ca_file, seen = evil_tls_server
    monkeypatch.setenv("SSL_CERT_FILE", str(ca_file))
    missing = str(tmp_path / "nope")
    paths = ssl.DefaultVerifyPaths(missing, missing, "SSL_CERT_FILE", missing, "SSL_CERT_DIR", missing)
    monkeypatch.setattr(tls.ssl, "get_default_verify_paths", lambda: paths)
    ctx = tls.token_ssl_context()
    assert ctx.get_ca_certs() == []
    with pytest.raises(BrokerUnavailable, match="TLS verification"):
        client.request(url, "GET", "/cli/session", bearer=SESSION_TOKEN, timeout=5)
    assert seen == []
