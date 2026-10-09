"""`pocketshell gateway proxy`: the OpenSSH ProxyCommand stdio bridge.

Wire protocol (pocketshell-gateway internal/tunnel, client route):

1. ``GET wss://<gw>/api/v1/hosts/<device-id>/ssh`` — no query, no Origin.
2. First TEXT frame ``{"type":"auth","v":1,"token":<broker JWT>,"device_id":<id>}``.
3. Gateway answers TEXT ``{"type":"ready","v":1,"device_id","ssh_host_key"}``
   or TEXT ``{"type":"error","v":1,"code","message"}`` + an application
   close code (4400/4401/4403/4404/4408/4429/4503).
4. After ``ready``: raw SSH bytes in BINARY messages both ways; any TEXT
   message after ``ready`` is a protocol violation and tears down.

Security posture (the gateway is NOT trusted with the session):

- stdout carries SSH payload bytes and nothing else, ever; diagnostics go
  to stderr, and anything the gateway says is sanitized first;
- ``ready.ssh_host_key`` is ignored — host trust comes only from the
  client's pin file, enforced by OpenSSH (``gateway ssh``);
- ``ready.device_id`` must equal the requested device;
- control frames are strict JSON (size cap, exact keys, exact types, no
  duplicate keys / NaN); messages are size-bounded; the whole handshake
  (TCP + TLS + upgrade + auth + ready) has one deadline;
- TLS certificate verification is always on (``ws://`` only via
  ``--insecure-dev`` to a loopback/docker host, see
  :mod:`pocketshell.gateway.endpoint`).
"""

from __future__ import annotations

import json
import logging
import os
import ssl
import sys
import threading
import time
from typing import Callable, Optional, TextIO

from pocketshell.gateway.endpoint import EndpointError, GatewayEndpoint, validate_device_id
from pocketshell.gateway.tokens import (
    GatewayTokenError,
    TokenProvider,
    obtain_token,
    sanitize_remote_text,
)

# Exit statuses, one per failure class (documented in docs/gateway.md).
EXIT_OK = 0
EXIT_INTERNAL = 1  # unexpected local error (no traceback is printed)
EXIT_USAGE = 2
EXIT_NO_TOKEN = 3  # not logged in / account layer could not mint a token
EXIT_CONNECT = 4  # DNS/TCP/TLS/HTTP-upgrade failure, or an unclassified refusal
EXIT_TIMEOUT = 5  # handshake deadline (local) or close 4408
EXIT_PROTOCOL = 6  # gateway protocol violation (local detection) or close 4400
EXIT_UNAUTHORIZED = 7  # close 4401 / 4403
EXIT_NOT_FOUND = 8  # close 4404: unknown, revoked or not your device
EXIT_HOST_OFFLINE = 9  # close 4503
EXIT_QUOTA = 10  # close 4429
EXIT_LOST = 11  # connection dropped abnormally after ready

CLOSE_CODE_EXIT = {
    4400: EXIT_PROTOCOL,
    4401: EXIT_UNAUTHORIZED,
    4403: EXIT_UNAUTHORIZED,
    4404: EXIT_NOT_FOUND,
    4408: EXIT_TIMEOUT,
    4429: EXIT_QUOTA,
    4503: EXIT_HOST_OFFLINE,
}
ERROR_CODE_EXIT = {
    "protocol": EXIT_PROTOCOL,
    "unauthorized": EXIT_UNAUTHORIZED,
    "signature": EXIT_UNAUTHORIZED,
    "revoked": EXIT_UNAUTHORIZED,
    "not_found": EXIT_NOT_FOUND,
    "host_offline": EXIT_HOST_OFFLINE,
    "quota": EXIT_QUOTA,
    "timeout": EXIT_TIMEOUT,
}

HANDSHAKE_TIMEOUT_SECONDS = 30.0
# The gateway writes host→client data in ≤ 32 KiB messages and reads client
# messages up to MaxFramePayload (32 KiB in production) + 4096; stay under.
CHUNK_BYTES = 32 * 1024
# Inbound message cap (bounded memory: × MAX_QUEUE). Headroom over the
# gateway's 32 KiB writes, small enough that a hostile peer cannot balloon us.
MAX_MESSAGE_BYTES = 64 * 1024
MAX_QUEUE = 4
MAX_CONTROL_BYTES = 16 * 1024
ERROR_CLOSE_WAIT_SECONDS = 2.0
PROTOCOL_VERSION = 1

_READY_KEYS = frozenset({"type", "v", "device_id", "ssh_host_key"})
_ERROR_KEYS = frozenset({"type", "v", "code", "message"})


class ProxyExit(Exception):
    """Terminate the bridge with ``code``; ``message`` (already safe) goes
    to stderr when non-empty."""

    def __init__(self, code: int, message: str = "") -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class _ControlFrameError(ValueError):
    pass


def _strict_pairs(pairs):
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise _ControlFrameError("duplicate key")
        seen[key] = value
    return seen


def _reject_constant(_token):
    raise _ControlFrameError("non-JSON constant")


def parse_control_frame(text: str) -> dict:
    """Strictly parse a pre-ready TEXT frame into ``ready`` or ``error``.

    Raises :class:`_ControlFrameError` on anything else: oversize, not a
    JSON object, duplicate keys, NaN/Infinity, unknown type, missing or
    extra keys, mistyped values (``v`` must be the integer 1, not a bool
    or float).
    """
    if len(text.encode("utf-8", "surrogatepass")) > MAX_CONTROL_BYTES:
        raise _ControlFrameError("control frame too large")
    try:
        doc = json.loads(
            text, object_pairs_hook=_strict_pairs, parse_constant=_reject_constant
        )
    except (ValueError, RecursionError) as exc:
        raise _ControlFrameError("control frame is not strict JSON") from exc
    if not isinstance(doc, dict):
        raise _ControlFrameError("control frame is not a JSON object")
    kind = doc.get("type")
    if kind == "ready":
        expected = _READY_KEYS
        strings = ("device_id", "ssh_host_key")
    elif kind == "error":
        expected = _ERROR_KEYS
        strings = ("code", "message")
    else:
        raise _ControlFrameError("unexpected control frame type")
    if set(doc) != expected:
        raise _ControlFrameError(f"{kind} frame has unexpected or missing fields")
    v = doc["v"]
    if type(v) is not int or v != PROTOCOL_VERSION:
        raise _ControlFrameError(f"{kind} frame has an unsupported version")
    for name in strings:
        if not isinstance(doc[name], str):
            raise _ControlFrameError(f"{kind} frame field {name} is not a string")
    return doc


def _close_code(exc: BaseException) -> Optional[int]:
    rcvd = getattr(exc, "rcvd", None)
    return getattr(rcvd, "code", None) if rcvd is not None else None


def _sent_code(exc: BaseException) -> Optional[int]:
    sent = getattr(exc, "sent", None)
    return getattr(sent, "code", None) if sent is not None else None


def _exit_for_close(exc: BaseException, default: int) -> ProxyExit:
    code = _close_code(exc)
    if _sent_code(exc) == 1009:
        return ProxyExit(EXIT_PROTOCOL, "gateway sent an oversize message")
    if code in CLOSE_CODE_EXIT:
        return ProxyExit(CLOSE_CODE_EXIT[code], f"gateway closed the connection (code {code})")
    if code is None:
        return ProxyExit(default, "connection to the gateway was lost")
    return ProxyExit(default, f"gateway closed the connection (code {code})")


# The websockets library logs connection errors (which can quote peer
# data) through its logger; with no handler configured Python would fall
# back to printing them on stderr unsanitized. Route them nowhere.
_WS_LOGGER = logging.getLogger("pocketshell.gateway.proxy.websockets")
_WS_LOGGER.addHandler(logging.NullHandler())
_WS_LOGGER.propagate = False


def _ssl_context() -> ssl.SSLContext:
    # CERT_REQUIRED + hostname checking, TLS >= 1.2, trust store from the
    # platform defaults only (SSL_CERT_FILE/SSL_CERT_DIR are ignored).
    from pocketshell.tokentls import token_ssl_context

    return token_ssl_context()


def _connect(url: str, *, secure: bool, timeout: float):
    from websockets.sync.client import connect

    kwargs = dict(
        ssl=_ssl_context() if secure else None,
        compression=None,  # SSH bytes are encrypted; no inflate-bomb surface
        open_timeout=timeout,
        max_size=MAX_MESSAGE_BYTES,
        max_queue=MAX_QUEUE,
        close_timeout=5,
        user_agent_header="pocketshell-cli",
        additional_headers=None,
        origin=None,
        # Never via an environment-configured proxy: the token goes to the
        # gateway the user named and nowhere else (websockets >= 15).
        proxy=None,
        logger=_WS_LOGGER,
    )
    return connect(url, **kwargs)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view) :]


class _Bridge:
    def __init__(self, ws, stdin_fd: int, stdout_fd: int) -> None:
        self.ws = ws
        self.stdin_fd = stdin_fd
        self.stdout_fd = stdout_fd
        self.stdin_eof = threading.Event()

    def _pump_stdin(self) -> None:
        from websockets.exceptions import ConnectionClosed

        try:
            while True:
                chunk = os.read(self.stdin_fd, CHUNK_BYTES)
                if not chunk:
                    # ssh closed our stdin: the session is over. The gateway
                    # protocol has no half-close, so close the WebSocket; the
                    # receive loop then ends with a normal close.
                    self.stdin_eof.set()
                    self.ws.close()
                    return
                self.ws.send(chunk)  # bytes → one BINARY message ≤ 32 KiB
        except ConnectionClosed:
            return
        except Exception:  # stdin error or teardown race: end the session quietly
            self.stdin_eof.set()
            try:
                self.ws.close()
            except Exception:
                pass

    def run(self) -> int:
        from websockets.exceptions import ConnectionClosed

        pump = threading.Thread(target=self._pump_stdin, name="stdin-pump", daemon=True)
        pump.start()
        try:
            while True:
                message = self.ws.recv()
                if isinstance(message, str):
                    self.ws.close(1002, "text after ready")
                    raise ProxyExit(
                        EXIT_PROTOCOL,
                        "gateway sent a text message after ready (protocol "
                        "violation); connection aborted",
                    )
                try:
                    _write_all(self.stdout_fd, message)
                except OSError:
                    # ssh went away (EPIPE): nothing left to deliver to.
                    self.ws.close()
                    return EXIT_OK
        except ConnectionClosed as exc:
            if self.stdin_eof.is_set() or _close_code(exc) in (1000, 1001):
                return EXIT_OK
            raise _exit_for_close(exc, EXIT_LOST) from None


def run_proxy(
    device_id: str,
    endpoint: GatewayEndpoint,
    token_provider: TokenProvider,
    *,
    stdin_fd: int = 0,
    stdout_fd: int = 1,
    stderr: Optional[TextIO] = None,
    handshake_timeout: float = HANDSHAKE_TIMEOUT_SECONDS,
    connect: Optional[Callable] = None,
    platform: Optional[str] = None,
) -> int:
    """Run the bridge; return the process exit status. Never raises for
    expected conditions; writes one diagnostic line to ``stderr``.

    On Windows the proxy shares ssh.exe's console, so console Ctrl+C /
    Ctrl+Break events reach it as well: they are ignored (ssh.exe owns
    them); the bridge ends on stdin EOF, a WebSocket close or an error.
    stdin is read by a blocking thread (no ``select`` on pipes) and every
    chunk is written straight to the stdout descriptor (unbuffered)."""
    if (sys.platform if platform is None else platform) == "win32":
        from pocketshell.gateway.winssh import ignore_console_interrupts

        ignore_console_interrupts()
    err = stderr if stderr is not None else sys.stderr
    try:
        return _run(
            device_id, endpoint, token_provider, stdin_fd, stdout_fd,
            handshake_timeout, connect or _connect,
        )
    except ProxyExit as exc:
        code, message = exc.code, exc.message
    except EndpointError as exc:
        code, message = EXIT_USAGE, str(exc)
    except Exception as exc:  # never a traceback: peer text could be in it
        code, message = EXIT_INTERNAL, f"internal error ({type(exc).__name__})"
    if message:
        try:
            err.write(f"pocketshell gateway proxy: {message}\n")
            err.flush()
        except (OSError, ValueError):
            pass
    return code


def _run(device_id, endpoint, token_provider, stdin_fd, stdout_fd, handshake_timeout, connect):
    try:
        import websockets  # noqa: F401
    except ImportError:
        raise ProxyExit(
            EXIT_USAGE,
            "the gateway client needs the `websockets` package: "
            "pip install 'pocketshell[link]'",
        ) from None
    from websockets.exceptions import ConnectionClosed, InvalidHandshake, InvalidStatus

    validate_device_id(device_id)
    url = endpoint.client_ssh_url(device_id)
    try:
        token = obtain_token(token_provider)
    except GatewayTokenError as exc:
        raise ProxyExit(EXIT_NO_TOKEN, str(exc)) from None

    deadline = time.monotonic() + handshake_timeout

    def remaining() -> float:
        left = deadline - time.monotonic()
        if left <= 0:
            raise ProxyExit(EXIT_TIMEOUT, "gateway handshake timed out")
        return left

    try:
        ws = connect(url, secure=endpoint.ws_base.startswith("wss://"), timeout=remaining())
    except InvalidStatus as exc:
        status = getattr(getattr(exc, "response", None), "status_code", "?")
        raise ProxyExit(
            EXIT_CONNECT, f"gateway refused the WebSocket upgrade (HTTP {status})"
        ) from None
    except TimeoutError:
        raise ProxyExit(EXIT_TIMEOUT, "gateway handshake timed out") from None
    except ssl.SSLError as exc:
        raise ProxyExit(
            EXIT_CONNECT,
            f"TLS failure talking to {endpoint.host}: "
            f"{sanitize_remote_text(getattr(exc, 'reason', None) or str(exc))}",
        ) from None
    except (OSError, InvalidHandshake) as exc:
        raise ProxyExit(
            EXIT_CONNECT,
            f"cannot connect to {endpoint.host}: {sanitize_remote_text(str(exc))}",
        ) from None

    try:
        try:
            ws.send(
                json.dumps(
                    {"type": "auth", "v": PROTOCOL_VERSION, "token": token, "device_id": device_id},
                    separators=(",", ":"),
                )
            )
            del token
            first = ws.recv(timeout=remaining())
        except TimeoutError:
            raise ProxyExit(
                EXIT_TIMEOUT, "gateway did not answer the auth frame in time"
            ) from None
        except ConnectionClosed as exc:
            raise _exit_for_close(exc, EXIT_CONNECT) from None

        if isinstance(first, bytes):
            ws.close(1002, "binary before ready")
            raise ProxyExit(
                EXIT_PROTOCOL, "gateway sent SSH data before ready (protocol violation)"
            )
        try:
            frame = parse_control_frame(first)
        except _ControlFrameError as exc:
            ws.close(1002, "bad control frame")
            raise ProxyExit(
                EXIT_PROTOCOL, f"gateway sent an invalid control frame: {exc}"
            ) from None

        if frame["type"] == "error":
            code = sanitize_remote_text(frame["code"], 40)
            message = sanitize_remote_text(frame["message"])
            exit_code = ERROR_CODE_EXIT.get(frame["code"], EXIT_CONNECT)
            try:
                ws.recv(timeout=min(ERROR_CLOSE_WAIT_SECONDS, max(0.0, deadline - time.monotonic())))
            except ConnectionClosed as exc:
                close = _close_code(exc)
                if close in CLOSE_CODE_EXIT:
                    exit_code = CLOSE_CODE_EXIT[close]
            except Exception:
                pass
            raise ProxyExit(exit_code, f"gateway refused: {code}: {message}")

        if frame["device_id"] != device_id:
            ws.close(1002, "device mismatch")
            raise ProxyExit(
                EXIT_PROTOCOL,
                "gateway answered ready for a different device (protocol "
                "violation); connection aborted",
            )
        # frame["ssh_host_key"] is advisory registry metadata and is
        # deliberately ignored: OpenSSH verifies the host key against the
        # client's own pin file.
        return _Bridge(ws, stdin_fd, stdout_fd).run()
    finally:
        try:
            ws.close()
        except Exception:
            pass
