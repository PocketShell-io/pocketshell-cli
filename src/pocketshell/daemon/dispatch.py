"""JSON-RPC request dispatch: validation, method registry, cache, responses.

Transport-agnostic: :class:`RequestDispatcher` owns everything that happens
between a received frame and the written response — envelope validation,
built-ins, registry lookup, the per-method response cache, and failure
classification. The :class:`~pocketshell.daemon.server.Daemon` accept loop
hands it one open client socket per request.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import threading
import traceback
from typing import Any, Callable, Mapping, Optional

from pocketshell.daemon.cache import METHOD_TTLS, _Cache, _CacheKey
from pocketshell.daemon.failures import (
    JSONRPC_INTERNAL_ERROR,
    JSONRPC_INVALID_PARAMS,
    JSONRPC_INVALID_REQUEST,
    JSONRPC_METHOD_NOT_FOUND,
    JSONRPC_PARSE_ERROR,
    DaemonFailureReason,
    _RpcError,
    _safe_method,
    _safe_version,
)
from pocketshell.daemon.methods import METHOD_CACHE_INVALIDATIONS, RpcHandler
from pocketshell.daemon.protocol import FramingError, recv_json, send_json


class RequestDispatcher:
    """Serve JSON-RPC requests from a registered handler map + result cache.

    ``daemon_version_fn`` and ``shutdown_fn`` are injected so the dispatcher
    never holds a hard reference to the owning daemon: version sanitization
    must observe late mutations of the daemon's version (tests do this),
    and the ``daemon.shutdown`` built-in triggers the transport's clean exit
    only after the response is on the wire.
    """

    def __init__(
        self,
        *,
        cache: _Cache,
        daemon_version_fn: Callable[[], Optional[str]],
        shutdown_fn: Callable[[], None],
        methods: Optional[Mapping[str, RpcHandler]] = None,
    ) -> None:
        self._methods: dict[str, RpcHandler] = dict(
            methods if methods is not None else {}
        )
        self._cache = cache
        self._daemon_version_fn = daemon_version_fn
        self._shutdown_fn = shutdown_fn

    def register_method(self, name: str, handler: RpcHandler) -> None:
        self._methods[name] = handler

    def handle_one(self, client_sock: socket.socket) -> None:
        """Read one JSON-RPC request, dispatch, write the response."""
        client_sock.settimeout(5.0)
        request = self._read_request(client_sock)
        if request is None:
            return
        fields = self._validated_fields(client_sock, request)
        if fields is None:
            return
        request_id, client_version, method, params = fields
        if self._handle_builtin(client_sock, request_id, method):
            return
        handler = self._methods.get(method)
        if handler is None:
            self._method_not_found(client_sock, request_id, client_version, method)
            return
        cached = self._cached_result(method, params)
        if cached is not None:
            self._send_result(client_sock, request_id, cached, cached_hit=True)
            return
        handled, result = self._invoke_handler(
            client_sock, request_id, client_version, method, handler, params
        )
        if not handled:
            return
        if self._succeeded_for_cache(result):
            self._update_cache(method, params, result)
        self._send_result(client_sock, request_id, result, cached_hit=False)

    # -- request validation ----------------------------------------------

    def _read_request(self, client_sock: socket.socket) -> Optional[Any]:
        """Read one JSON frame; report parse failures on the wire."""
        try:
            return recv_json(client_sock)
        except (FramingError, json.JSONDecodeError) as exc:
            self._send_error(
                client_sock,
                request_id=None,
                code=JSONRPC_PARSE_ERROR,
                message=f"parse error: {exc}",
            )
            return None

    def _validated_fields(
        self, client_sock: socket.socket, request: Any
    ) -> Optional[tuple[Any, Optional[str], Any, Any]]:
        """Validate the envelope; ``None`` means the error was already sent."""
        if not isinstance(request, dict):
            self._send_error(
                client_sock,
                request_id=None,
                code=JSONRPC_INVALID_REQUEST,
                message="request must be a JSON object",
            )
            return None
        request_id = request.get("id")
        client_version = _safe_version(request.get("client_version"))
        method = request.get("method")
        params = request.get("params") or {}
        if not isinstance(method, str):
            self._send_error(
                client_sock, request_id=request_id, code=JSONRPC_INVALID_REQUEST,
                message="`method` must be a string",
            )
            return None
        if not isinstance(params, Mapping):
            self._send_error(
                client_sock, request_id=request_id, code=JSONRPC_INVALID_PARAMS,
                message="`params` must be an object",
            )
            return None
        return request_id, client_version, method, params

    def _handle_builtin(
        self, client_sock: socket.socket, request_id: Any, method: str
    ) -> bool:
        """Serve daemon.ping / daemon.shutdown; they bypass the registry.

        These do NOT touch the registered handlers so a handler registry
        mutation in tests cannot accidentally unbind ``daemon.ping``.
        """
        if method == "daemon.ping":
            self._send_result(client_sock, request_id, {"ok": True, "pid": os.getpid()})
            return True
        if method == "daemon.shutdown":
            self._send_result(client_sock, request_id, {"ok": True})
            # Defer the shutdown until after the response is on the wire.
            threading.Thread(target=self._shutdown_fn, daemon=True).start()
            return True
        return False

    def _method_not_found(
        self,
        client_sock: socket.socket,
        request_id: Any,
        client_version: Optional[str],
        method: str,
    ) -> None:
        self._send_error(
            client_sock,
            request_id=request_id,
            code=JSONRPC_METHOD_NOT_FOUND,
            message=f"unknown method: {_safe_method(method)}",
            data=self.failure_data(DaemonFailureReason.SUPPORTED_SKEW, client_version),
        )

    # -- cache ------------------------------------------------------------

    def _cached_result(self, method: str, params: Mapping[str, Any]) -> Optional[Any]:
        """Return the cached envelope for this call, if caching applies."""
        if bool(params.get("no_cache", False)):
            return None
        ttl = METHOD_TTLS.get(method, 0.0)
        if ttl <= 0:
            return None
        return self._cache.get(_CacheKey.of(method, params))

    def _succeeded_for_cache(self, result: Any) -> bool:
        """Decide whether a result is safe to pin in the cache.

        ``usage.fetch`` carries its own returncode inside the envelope;
        treat non-zero as a failure so a transient quse error does not pin
        a bad result. ``repos.*`` envelopes carry ``status`` instead.
        """
        if isinstance(result, dict) and "returncode" in result:
            return result.get("returncode") == 0
        if isinstance(result, dict) and result.get("status") == "error":
            return False
        return True

    def _update_cache(
        self, method: str, params: Mapping[str, Any], result: Any
    ) -> None:
        """Pin a successful result and evict dependents of a mutation.

        A successful ``repos.clone`` evicts ``repos.list_local`` so the
        next read reflects the mutation immediately rather than serving a
        stale cached scan for the remainder of its TTL.
        """
        no_cache = bool(params.get("no_cache", False))
        ttl = METHOD_TTLS.get(method, 0.0)
        if ttl > 0 and not no_cache:
            self._cache.put(_CacheKey.of(method, params), result, ttl)
        for dependent in METHOD_CACHE_INVALIDATIONS.get(method, ()):
            self._cache.invalidate_method(dependent)

    # -- handler invocation -----------------------------------------------

    def _invoke_handler(
        self,
        client_sock: socket.socket,
        request_id: Any,
        client_version: Optional[str],
        method: str,
        handler: RpcHandler,
        params: Mapping[str, Any],
    ) -> tuple[bool, Any]:
        """Run the handler; classify failures and report them on the wire.

        Returns ``(handled, result)`` — ``handled`` is False when an error
        response was already sent.
        """
        try:
            return True, handler(params)
        except _RpcError as exc:
            self._send_rpc_failure(client_sock, request_id, client_version, exc)
            return False, None
        except Exception:  # noqa: BLE001 — JSON-RPC envelope
            self._send_internal_failure(
                client_sock, request_id, client_version, method
            )
            return False, None

    def _send_rpc_failure(
        self,
        client_sock: socket.socket,
        request_id: Any,
        client_version: Optional[str],
        exc: _RpcError,
    ) -> None:
        """Report a handler-raised ``_RpcError`` with its JSON-RPC code."""
        message = (
            "invalid parameters: must be a list or object as required"
            if exc.code == JSONRPC_INVALID_PARAMS
            else "daemon request failed"
        )
        self._send_error(
            client_sock,
            request_id=request_id,
            code=exc.code,
            message=message,
            data=self.failure_data(
                DaemonFailureReason.DAEMON_INTERNAL_ERROR, client_version
            ),
        )

    def _send_internal_failure(
        self,
        client_sock: socket.socket,
        request_id: Any,
        client_version: Optional[str],
        method: str,
    ) -> None:
        """Log the traceback locally; return a generic message on the wire.

        Raw ``str(exc)`` can embed internal filesystem paths / config
        values, so the socket only ever sees a detail-free message.
        """
        traceback.print_exc(file=sys.stderr)
        self._send_error(
            client_sock,
            request_id=request_id,
            code=JSONRPC_INTERNAL_ERROR,
            message=f"internal error handling {_safe_method(method)}",
            data=self.failure_data(
                DaemonFailureReason.DAEMON_INTERNAL_ERROR, client_version
            ),
        )

    # -- failure metadata -------------------------------------------------

    def failure_data(
        self,
        reason: DaemonFailureReason,
        client_version: Optional[str],
    ) -> dict[str, str]:
        """Return safe classification metadata for an RPC error envelope."""
        data: dict[str, str] = {"failure_reason": reason.value}
        if client_version := _safe_version(client_version):
            data["client_version"] = client_version
        if daemon_version := _safe_version(self._daemon_version_fn()):
            data["daemon_version"] = daemon_version
        return data

    # -- wire helpers -------------------------------------------------------

    def _send_result(
        self,
        sock: socket.socket,
        request_id: Any,
        result: Any,
        *,
        cached_hit: bool = False,
    ) -> None:
        envelope = {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": result,
            # ``cached`` is a PocketShell extension; the JSON-RPC 2.0
            # spec allows extra top-level keys on responses. Used by
            # the test suite to assert the second of two clients sees a
            # cache hit.
            "cached": cached_hit,
        }
        try:
            send_json(sock, envelope)
        except (OSError, FramingError):
            # Peer hung up before we wrote — nothing to do; the client
            # will reconnect or fall through to the no-daemon path.
            pass

    def _send_error(
        self,
        sock: socket.socket,
        *,
        request_id: Any,
        code: int,
        message: str,
        data: Any = None,
    ) -> None:
        error: dict[str, Any] = {"code": code, "message": message}
        if data is not None:
            error["data"] = data
        envelope = {"jsonrpc": "2.0", "id": request_id, "error": error}
        try:
            send_json(sock, envelope)
        except (OSError, FramingError):
            pass
