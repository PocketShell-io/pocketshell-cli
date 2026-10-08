"""A local fake PocketShell broker (http.server on 127.0.0.1 in a thread)."""

from __future__ import annotations

import base64
import json
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

SESSION_TOKEN = "psc_" + "S" * 43
DEVICE_CODE = "psdc_" + "D" * 43


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_jwt(exp: int) -> str:
    header = b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    payload = b64url(json.dumps({"sub": "u1", "exp": exp}).encode())
    return f"{header}.{payload}.{b64url(b'signature-bytes')}"


class FakeBroker:
    def __init__(self) -> None:
        self.requests: list[dict] = []
        self.token_script: deque = deque(
            [(400, {"error": "authorization_pending"}), (200, None)]
        )
        self.start_response: dict = {
            "device_code": DEVICE_CODE,
            "user_code": "BCDF-GHJK",
            "verification_uri": "https://app.pocketshell.io/device",
            "verification_uri_complete": "https://app.pocketshell.io/device?code=BCDF-GHJK",
            "expires_in": 600,
            "interval": 5,
        }
        self.access_token = SESSION_TOKEN
        self.email = "me@example.com"
        self.label = "me@laptop"
        self.session_expires_at = int(time.time()) + 30 * 86400
        self.overrides: dict[tuple[str, str], tuple[int, object]] = {}
        self.logged_out = False
        self.gateway_jwt = make_jwt(int(time.time()) + 300)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        )

    make_jwt = staticmethod(make_jwt)

    # -- canned bodies -------------------------------------------------------
    def token_body(self) -> dict:
        return {
            "access_token": self.access_token,
            "token_type": "Bearer",
            "token_id": "tok_123",
            "expires_in": 30 * 86400,
            "expires_at": self.session_expires_at,
            "email": self.email,
        }

    def session_body(self) -> dict:
        return {
            "email": self.email,
            "token_id": "tok_123",
            "label": self.label,
            "created_at": int(time.time()),
            "expires_at": self.session_expires_at,
        }

    def requests_to(self, path: str) -> list[dict]:
        return [r for r in self.requests if r["path"] == path]

    # -- server --------------------------------------------------------------
    def _route(self, method: str, path: str, headers, body: bytes):
        if (method, path) in self.overrides:
            return self.overrides[(method, path)]
        authed = headers.get("Authorization") == f"Bearer {self.access_token}"
        if (method, path) == ("POST", "/auth/device/start"):
            return 200, self.start_response
        if (method, path) == ("POST", "/auth/device/token"):
            if json.loads(body or b"{}").get("device_code") != DEVICE_CODE:
                return 400, {"error": "invalid_request"}
            status, payload = self.token_script.popleft() if self.token_script else (
                400, {"error": "expired_token"}
            )
            return status, (self.token_body() if payload is None else payload)
        if (method, path) == ("GET", "/cli/session"):
            if not authed or self.logged_out:
                return 401, {"error": "unauthorized"}
            return 200, self.session_body()
        if (method, path) == ("POST", "/cli/gateway/token"):
            if not authed or self.logged_out:
                return 401, {"error": "unauthorized"}
            if body:
                return 400, {"error": "invalid_request"}
            return 200, {
                "token": self.gateway_jwt,
                "token_type": "Bearer",
                "expires_in": 300,
                "expires_at": int(time.time()) + 300,
            }
        if (method, path) == ("POST", "/cli/logout"):
            if not authed:
                return 401, {"error": "unauthorized"}
            self.logged_out = True
            return 204, None
        return 404, {"error": "not_found"}

    def _handler(self):
        broker = self

        class Handler(BaseHTTPRequestHandler):
            def _handle(self, method: str) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                broker.requests.append(
                    {
                        "method": method,
                        "path": self.path,
                        "headers": dict(self.headers),
                        "body": body,
                    }
                )
                status, payload = broker._route(method, self.path, self.headers, body)
                if isinstance(payload, (bytes, bytearray)):
                    raw = bytes(payload)
                elif payload is None:
                    raw = b""
                else:
                    raw = json.dumps(payload).encode()
                self.send_response(status)
                if status in (301, 302, 307, 308):
                    self.send_header("Location", "http://127.0.0.1:1/stolen")
                self.send_header("Content-Type", "application/json")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self) -> None:  # noqa: N802
                self._handle("GET")

            def do_POST(self) -> None:  # noqa: N802
                self._handle("POST")

            def log_message(self, *args) -> None:
                pass

        return Handler


@pytest.fixture
def fake_broker(monkeypatch):
    broker = FakeBroker()
    broker.thread.start()
    monkeypatch.setenv("POCKETSHELL_BROKER_URL", broker.url)
    monkeypatch.setenv("POCKETSHELL_BROKER_INSECURE_DEV", "1")
    try:
        yield broker
    finally:
        broker.server.shutdown()
        broker.server.server_close()
