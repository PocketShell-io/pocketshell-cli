"""In-process wire tests for the daemon server (``pocketshell daemon``).

``tests/test_daemon.py`` exercises the daemon through real subprocesses,
which no in-process coverage run can see. These tests run
``Daemon.serve()`` on a thread and drive the framed JSON-RPC wire directly,
covering the server loop, every registered handler shim, the cache policy,
and the client-side failure classification branch by branch.
"""

from __future__ import annotations

import fcntl
import itertools
import json
import os
import socket
import struct
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

import pytest

from pocketshell.daemon import cache as dcache
from pocketshell.daemon import client as dclient
from pocketshell.daemon import dispatch as ddispatch
from pocketshell.daemon import failures as dfailures
from pocketshell.daemon import lifecycle as dlifecycle
from pocketshell.daemon import paths as dpaths
from pocketshell.daemon import protocol as dprotocol
from pocketshell.daemon import server as dserver
from pocketshell import usage as usage_mod


@pytest.fixture()
def no_signal_handlers(monkeypatch: pytest.MonkeyPatch) -> None:
    """Let ``Daemon.serve`` run on a worker thread.

    ``signal.signal`` raises ``ValueError`` outside the main thread; the
    server only uses it to trap SIGTERM, which these tests exercise via
    ``daemon.shutdown`` instead.
    """
    monkeypatch.setattr(dserver.signal, "signal", lambda *args: None)


class ThreadedDaemon:
    """Run a real ``Daemon`` accept loop beside the test."""

    def __init__(self, socket_path: Path, daemon: dserver.Daemon) -> None:
        self.socket_path = socket_path
        self.daemon = daemon
        self.thread = threading.Thread(target=daemon.serve, daemon=True)

    def __enter__(self) -> "ThreadedDaemon":
        self.thread.start()
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if dclient.is_daemon_running(self.socket_path):
                return self
            time.sleep(0.01)
        raise AssertionError("threaded daemon did not become ready")

    def __exit__(self, *exc_info: object) -> None:
        self.daemon.shutdown()
        self.thread.join(timeout=5)
        assert not self.thread.is_alive()

    def call(self, method: str, params: dict[str, Any] | None = None) -> Any:
        return dclient.call(method, params, socket_path=self.socket_path)


@pytest.fixture()
def server(
    tmp_path: Path, no_signal_handlers: None, monkeypatch: pytest.MonkeyPatch
) -> Iterator[ThreadedDaemon]:
    socket_path = tmp_path / "wire.sock"
    daemon = dserver.Daemon(socket_path=socket_path, idle_timeout=0.0)
    with ThreadedDaemon(socket_path, daemon) as running:
        yield running


# ---------------------------------------------------------------------------
# Server loop and protocol envelope
# ---------------------------------------------------------------------------


def test_ping_round_trip(server: ThreadedDaemon) -> None:
    assert server.call("daemon.ping")["ok"] is True


def test_shutdown_method_responds_then_stops(server: ThreadedDaemon) -> None:
    assert server.call("daemon.shutdown") == {"ok": True}
    server.thread.join(timeout=5)
    assert not server.thread.is_alive()


def test_unknown_method_is_supported_skew(server: ThreadedDaemon) -> None:
    with pytest.raises(dfailures.DaemonClientError) as excinfo:
        server.call("no.such.method")

    failure = excinfo.value.failure
    assert failure.reason is dfailures.DaemonFailureReason.SUPPORTED_SKEW
    assert failure.rpc_code == dfailures.JSONRPC_METHOD_NOT_FOUND


def test_non_object_request_is_invalid_request(server: ThreadedDaemon) -> None:
    with raw_client(server.socket_path) as sock:
        dprotocol.send_json(sock, ["not", "an", "object"])
        response = dprotocol.recv_json(sock)

    assert response["error"]["code"] == dfailures.JSONRPC_INVALID_REQUEST


def test_garbage_frame_is_parse_error(server: ThreadedDaemon) -> None:
    with raw_client(server.socket_path) as sock:
        dprotocol.send_frame(sock, b"{not json")
        response = dprotocol.recv_json(sock)

    assert response["error"]["code"] == dfailures.JSONRPC_PARSE_ERROR


def test_partial_frame_then_close_is_parse_error(server: ThreadedDaemon) -> None:
    with raw_client(server.socket_path) as sock:
        header = struct.pack(dprotocol._LENGTH_PREFIX_FORMAT, 16)
        sock.sendall(header + b"half")
        sock.shutdown(socket.SHUT_WR)
        response = dprotocol.recv_json(sock)

    assert response["error"]["code"] == dfailures.JSONRPC_PARSE_ERROR


def test_oversized_length_prefix_is_parse_error(server: ThreadedDaemon) -> None:
    with raw_client(server.socket_path) as sock:
        sock.sendall(struct.pack(dprotocol._LENGTH_PREFIX_FORMAT, 1 << 30))
        response = dprotocol.recv_json(sock)

    assert response["error"]["code"] == dfailures.JSONRPC_PARSE_ERROR


def test_zero_length_frame_is_parse_error(server: ThreadedDaemon) -> None:
    with raw_client(server.socket_path) as sock:
        sock.sendall(struct.pack(dprotocol._LENGTH_PREFIX_FORMAT, 0))
        response = dprotocol.recv_json(sock)

    assert response["error"]["code"] == dfailures.JSONRPC_PARSE_ERROR


def test_non_string_method_is_invalid_request(server: ThreadedDaemon) -> None:
    with raw_client(server.socket_path) as sock:
        dprotocol.send_json(sock, {"jsonrpc": "2.0", "id": 1, "method": 7})
        response = dprotocol.recv_json(sock)

    assert response["error"]["code"] == dfailures.JSONRPC_INVALID_REQUEST


def test_non_mapping_params_are_invalid_params(server: ThreadedDaemon) -> None:
    with raw_client(server.socket_path) as sock:
        dprotocol.send_json(
            sock,
            {"jsonrpc": "2.0", "id": 1, "method": "daemon.ping", "params": [1]},
        )
        response = dprotocol.recv_json(sock)

    assert response["error"]["code"] == dfailures.JSONRPC_INVALID_PARAMS


def test_handler_rpc_error_maps_to_envelope(server: ThreadedDaemon) -> None:
    def boom(params: object) -> None:
        raise dfailures._RpcError(
            dfailures.JSONRPC_INVALID_PARAMS, "bad params"
        )

    server.daemon.register_method("test.rpc_error", boom)

    with pytest.raises(dfailures.DaemonClientError) as excinfo:
        server.call("test.rpc_error")

    assert excinfo.value.failure.rpc_code == dfailures.JSONRPC_INVALID_PARAMS


def test_handler_generic_error_hides_detail(
    server: ThreadedDaemon, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(params: object) -> None:
        raise RuntimeError("/host/secret/path leaked")

    server.daemon.register_method("test.boom", boom)

    with raw_client(server.socket_path) as sock:
        dprotocol.send_json(
            sock, {"jsonrpc": "2.0", "id": 1, "method": "test.boom"}
        )
        response = dprotocol.recv_json(sock)

    error = response["error"]
    assert error["code"] == dfailures.JSONRPC_INTERNAL_ERROR
    assert "/host/secret/path" not in error["message"]
    assert error["message"] == "internal error handling test.boom"
    assert "leaked" in capsys.readouterr().err


def test_send_failure_is_silently_ignored(
    server: ThreadedDaemon, monkeypatch: pytest.MonkeyPatch
) -> None:
    def failing_send(sock: socket.socket, payload: bytes) -> None:
        raise OSError("peer went away")

    monkeypatch.setattr(ddispatch, "send_json", failing_send)
    server.daemon.register_method("test.ok", lambda params: {"fine": True})

    with raw_client(server.socket_path) as sock:
        request = json.dumps(
            {"jsonrpc": "2.0", "id": 1, "method": "test.ok"}
        ).encode("utf-8")
        dprotocol.send_frame(sock, request)
        with pytest.raises(dprotocol.FramingError):
            dprotocol.recv_json(sock)


def test_daemon_version_sanitized_out_of_error_data(tmp_path: Path) -> None:
    daemon = dserver.Daemon(socket_path=tmp_path / "v.sock")
    daemon.daemon_version = None

    data = daemon._failure_data(
        dfailures.DaemonFailureReason.DAEMON_INTERNAL_ERROR, "1.2.3"
    )

    assert data == {
        "failure_reason": "daemon_internal_error",
        "client_version": "1.2.3",
    }


def test_serve_returns_quietly_when_lock_is_held(
    tmp_path: Path, no_signal_handlers: None
) -> None:
    socket_path = tmp_path / "owned.sock"
    lock_path = dpaths.resolve_lock_path(socket_path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    holder = open(lock_path, "a+")
    fcntl.flock(holder, fcntl.LOCK_EX)

    daemon = dserver.Daemon(socket_path=socket_path, idle_timeout=0.0)
    daemon.serve()

    assert not socket_path.exists()
    holder.close()


def test_write_pid_file_failure_is_best_effort(tmp_path: Path) -> None:
    daemon = dserver.Daemon(
        socket_path=tmp_path / "s.sock", pid_path=tmp_path / "as-dir"
    )
    (tmp_path / "as-dir").mkdir()

    daemon._write_pid_file()

    assert not (tmp_path / "as-dir").exists() or (tmp_path / "as-dir").is_dir()


def test_ensure_socket_dir_survives_chmod_permission_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_chmod = os.chmod

    def deny_dir_chmod(path: object, mode: int) -> None:
        if Path(path) == tmp_path:
            raise PermissionError("read-only mount")
        real_chmod(path, mode)  # type: ignore[arg-type]

    monkeypatch.setattr(dpaths.os, "chmod", deny_dir_chmod)

    dpaths._ensure_socket_dir(tmp_path / "nested" / "daemon.sock")

    assert (tmp_path / "nested").exists()


# ---------------------------------------------------------------------------
# Cache policy
# ---------------------------------------------------------------------------


def test_cache_expired_entry_is_evicted_lazily() -> None:
    now = 100.0
    clock = lambda: now  # noqa: E731
    cache = dcache._Cache(clock=clock)
    key = dcache._CacheKey.of("m", {})

    cache.put(key, {"v": 1}, ttl_secs=5)
    now = 200.0

    assert cache.get(key) is None
    assert cache.get(key) is None
    cache.put(key, {"v": 2}, ttl_secs=0)
    assert cache.get(key) is None
    cache.put(key, {"v": 3}, ttl_secs=5)
    cache.clear()
    assert cache.get(key) is None


def test_second_call_is_cached_hit(server: ThreadedDaemon) -> None:
    server.daemon.register_method(
        "usage.fetch", lambda params: {"stdout": "ok", "stderr": "", "returncode": 0}
    )
    request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "usage.fetch"}).encode()

    with raw_client(server.socket_path) as sock:
        dprotocol.send_frame(sock, request)
        first = dprotocol.recv_json(sock)
    with raw_client(server.socket_path) as sock:
        dprotocol.send_frame(sock, request)
        second = dprotocol.recv_json(sock)

    assert first["cached"] is False
    assert second["cached"] is True
    assert second["result"] == first["result"]


def test_failed_envelopes_are_never_cached(server: ThreadedDaemon) -> None:
    calls: list[int] = []

    def failing(params: object) -> dict[str, object]:
        calls.append(1)
        return {"status": "error", "error_code": "nope"}

    server.daemon.register_method("test.failing", failing)

    request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "test.failing"}).encode()
    with raw_client(server.socket_path) as sock:
        dprotocol.send_frame(sock, request)
        first = dprotocol.recv_json(sock)
    with raw_client(server.socket_path) as sock:
        dprotocol.send_frame(sock, request)
        second = dprotocol.recv_json(sock)

    assert first["result"] == second["result"]
    assert len(calls) == 2
    assert second["cached"] is False


def test_nonzero_returncode_envelope_is_never_cached(
    server: ThreadedDaemon,
) -> None:
    calls: list[int] = []

    def failing(params: object) -> dict[str, object]:
        calls.append(1)
        return {"stdout": "", "stderr": "boom", "returncode": 3}

    server.daemon.register_method("test.rc", failing)
    request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "test.rc"}).encode()
    with raw_client(server.socket_path) as sock:
        dprotocol.send_frame(sock, request)
        dprotocol.recv_json(sock)
    with raw_client(server.socket_path) as sock:
        dprotocol.send_frame(sock, request)
        second = dprotocol.recv_json(sock)

    assert len(calls) == 2
    assert second["cached"] is False


def test_clone_success_invalidates_list_cache(server: ThreadedDaemon) -> None:
    server.daemon.register_method("repos.clone", lambda params: {"status": "cloned"})
    server.daemon._cache.put(
        dcache._CacheKey.of("repos.list_local", {}), ["stale"], ttl_secs=60
    )

    server.call("repos.clone", {})

    assert server.daemon._cache.get(
        dcache._CacheKey.of("repos.list_local", {})
    ) is None


# ---------------------------------------------------------------------------
# Registered handler shims
# ---------------------------------------------------------------------------


@pytest.fixture()
def shimmed_backends(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Stub each lazily-imported backend function the shims delegate to."""
    calls: dict[str, Any] = {}

    def stub(target: str, result: Any) -> None:
        def fake(params: object) -> Any:
            calls[target] = params
            return result

        monkeypatch.setattr(target, fake)

    stub("pocketshell.repos.daemon_handler_local", [{"full_name": "local"}])
    stub("pocketshell.repos.daemon_handler_remote", [{"full_name": "remote"}])
    stub("pocketshell.repos.daemon_handler_clone", {"status": "cloned"})
    stub("pocketshell.repos.daemon_handler_open", {"status": "open"})
    stub("pocketshell.sessions.daemon_handler_list", {"sessions": []})
    stub("pocketshell.runtime.cgroups.kind_for_panes", [{"pane_id": "%0"}])
    stub("pocketshell.tree.daemon_handler_get", {"nodes": []})
    stub("pocketshell.tree.daemon_handler_upsert", {"ok": True})
    stub("pocketshell.tree.daemon_handler_reconcile", {"ok": True})
    stub("pocketshell.tree.daemon_handler_workspace_get", {"tabs": []})
    stub("pocketshell.tree.daemon_handler_workspace_upsert", {"ok": True})
    return calls


@pytest.mark.parametrize(
    ("method", "params", "expected"),
    [
        ("repos.list_local", {"roots": ["/tmp"]}, [{"full_name": "local"}]),
        ("repos.list_remote", {}, [{"full_name": "remote"}]),
        ("repos.clone", {"full_name": "a/b"}, {"status": "cloned"}),
        ("repos.open", {"full_name": "a/b"}, {"status": "open"}),
        ("sessions.list", {}, {"sessions": []}),
        ("tree.get", {}, {"nodes": []}),
        ("tree.upsert", {"nodes": []}, {"ok": True}),
        ("tree.reconcile", {}, {"ok": True}),
        ("tree.workspace.get", {}, {"tabs": []}),
        ("tree.workspace.upsert", {}, {"ok": True}),
    ],
)
def test_handler_shims_delegate(
    server: ThreadedDaemon,
    shimmed_backends: dict[str, Any],
    method: str,
    params: dict[str, Any],
    expected: Any,
) -> None:
    assert server.call(method, params) == expected


def test_kind_for_panes_shim_filters_non_mapping_panes(
    server: ThreadedDaemon,
    shimmed_backends: dict[str, Any],
) -> None:
    result = server.call(
        "agents.kind_for_panes",
        {"panes": [{"pane_id": "%0"}, "junk", 42]},
    )

    assert result == {"results": [{"pane_id": "%0"}]}
    with pytest.raises(dfailures.DaemonClientError) as excinfo:
        server.call("agents.kind_for_panes", {"panes": "nope"})
    assert excinfo.value.failure.rpc_code == dfailures.JSONRPC_INVALID_PARAMS


# ---------------------------------------------------------------------------
# usage.fetch handler
# ---------------------------------------------------------------------------


def test_usage_fetch_without_quse_reports_missing(
    server: ThreadedDaemon, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(usage_mod, "_resolve_quse_binary", lambda: None)

    envelope = server.call("usage.fetch", {})

    assert envelope["returncode"] == usage_mod._QUSE_MISSING_EXIT_CODE
    assert usage_mod._QUSE_MISSING_MESSAGE in envelope["stderr"]


def test_usage_fetch_flattens_successful_quse_output(
    server: ThreadedDaemon, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    quse = tmp_path / "quse"
    quse.write_text(
        "#!/bin/sh\ncat tests/data/quse-0.0.15-usage.json\n",
        encoding="utf-8",
    )
    quse.chmod(0o755)
    monkeypatch.chdir(Path(__file__).resolve().parents[1])
    monkeypatch.setattr(usage_mod, "_resolve_quse_binary", lambda: str(quse))

    envelope = server.call("usage.fetch", {"provider": "codex"})

    assert envelope["returncode"] == 0
    assert envelope["provider"] == "codex"
    assert '"provider": "codex"' in envelope["stdout"]
    assert envelope["stdout"].count("\n") == 6


def test_usage_fetch_proxies_failed_quse_raw(
    server: ThreadedDaemon, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    quse = tmp_path / "quse"
    quse.write_text("#!/bin/sh\necho broken >&2\nexit 4\n", encoding="utf-8")
    quse.chmod(0o755)
    monkeypatch.setattr(usage_mod, "_resolve_quse_binary", lambda: str(quse))

    envelope = server.call("usage.fetch", {})

    assert envelope["returncode"] == 4
    assert "broken" in envelope["stderr"]


def test_usage_fetch_rejects_non_string_provider(server: ThreadedDaemon) -> None:
    with pytest.raises(dfailures.DaemonClientError) as excinfo:
        server.call("usage.fetch", {"provider": 7})

    assert excinfo.value.failure.rpc_code == dfailures.JSONRPC_INVALID_PARAMS


# ---------------------------------------------------------------------------
# Client-side classification branches
# ---------------------------------------------------------------------------


@pytest.fixture()
def up_server(tmp_path: Path, no_signal_handlers: None) -> Iterator[ThreadedDaemon]:
    """A daemon whose handler echoes params back."""
    socket_path = tmp_path / "echo.sock"
    daemon = dserver.Daemon(
        socket_path=socket_path,
        idle_timeout=0.0,
        methods={"echo": lambda params: dict(params)},
    )
    with ThreadedDaemon(socket_path, daemon) as running:
        yield running


def test_call_outcome_connect_timeout_is_typed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    socket_path = tmp_path / "slow-connect.sock"
    socket_path.write_bytes(b"")

    def timing_out_connect(path: Path, *, timeout: float) -> socket.socket:
        raise socket.timeout()

    monkeypatch.setattr(dclient, "_connect", timing_out_connect)

    outcome = dclient.call_outcome("m", socket_path=socket_path)

    assert outcome.failure is not None
    assert outcome.failure.reason is dfailures.DaemonFailureReason.TRANSPORT_TIMEOUT
    assert outcome.failure.phase == "connect"


def test_call_outcome_setup_failures_are_classified(
    up_server: ThreadedDaemon, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FakeSock:
        def __init__(self, exc: Exception) -> None:
            self._exc = exc

        def settimeout(self, value: float) -> None:
            raise self._exc

        def close(self) -> None:
            pass

    monkeypatch.setattr(
        dclient, "_connect", lambda path, *, timeout: FakeSock(socket.timeout())
    )
    outcome = dclient.call_outcome("echo", socket_path=up_server.socket_path)
    assert outcome.failure is not None
    assert outcome.failure.phase == "setup"
    assert outcome.failure.reason is dfailures.DaemonFailureReason.TRANSPORT_TIMEOUT

    monkeypatch.setattr(
        dclient, "_connect", lambda path, *, timeout: FakeSock(OSError("fd gone"))
    )
    outcome = dclient.call_outcome("echo", socket_path=up_server.socket_path)
    assert outcome.failure is not None
    assert outcome.failure.phase == "setup"
    assert outcome.failure.reason is dfailures.DaemonFailureReason.DAEMON_INTERNAL_ERROR


def test_call_outcome_write_failures_are_classified(
    up_server: ThreadedDaemon, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_send_json = dprotocol.send_json

    def timeout_send(sock: socket.socket, payload: bytes) -> None:
        raise socket.timeout()

    def framing_send(sock: socket.socket, payload: bytes) -> None:
        raise dprotocol.FramingError("frame too big")

    monkeypatch.setattr(dclient, "send_json", timeout_send)
    outcome = dclient.call_outcome("echo", socket_path=up_server.socket_path)
    assert outcome.failure is not None
    assert outcome.failure.phase == "write"
    assert outcome.failure.reason is dfailures.DaemonFailureReason.TRANSPORT_TIMEOUT

    monkeypatch.setattr(dclient, "send_json", framing_send)
    outcome = dclient.call_outcome("echo", socket_path=up_server.socket_path)
    assert outcome.failure is not None
    assert outcome.failure.phase == "write"
    assert outcome.failure.reason is dfailures.DaemonFailureReason.DAEMON_INTERNAL_ERROR

    monkeypatch.setattr(dclient, "send_json", real_send_json)


def test_call_outcome_read_timeout_is_typed(tmp_path: Path) -> None:
    with rpc_peer(tmp_path, lambda conn: time.sleep(1)) as peer:
        outcome = dclient.call_outcome("echo", socket_path=peer, timeout=0.2)

    assert outcome.failure is not None
    assert outcome.failure.phase == "read"
    assert outcome.failure.reason is dfailures.DaemonFailureReason.TRANSPORT_TIMEOUT


@pytest.mark.parametrize(
    ("script", "expected_reason"),
    [
        # Peer closes without replying: an unusable, unhealthy daemon.
        (lambda conn: None, dfailures.DaemonFailureReason.DAEMON_INTERNAL_ERROR),
        # Declared frame length exceeds the protocol cap.
        (
            lambda conn: conn.sendall(struct.pack("!I", 1 << 30)),
            dfailures.DaemonFailureReason.DAEMON_INTERNAL_ERROR,
        ),
        # Well-formed frame whose payload is not JSON.
        (
            lambda conn: dprotocol.send_frame(conn, b"{not json"),
            dfailures.DaemonFailureReason.DAEMON_INTERNAL_ERROR,
        ),
        # Well-formed frame whose payload is not valid UTF-8.
        (
            lambda conn: dprotocol.send_frame(conn, b"\xff\xfe\xfd"),
            dfailures.DaemonFailureReason.DAEMON_INTERNAL_ERROR,
        ),
    ],
)
def test_call_outcome_unusable_reads_are_internal(
    tmp_path: Path, script: object, expected_reason: object
) -> None:
    # A generous client timeout keeps a loaded CI box from turning the
    # scripted peer's slow accept into an unrelated transport-timeout.
    with rpc_peer(tmp_path, script) as peer:
        outcome = dclient.call_outcome("echo", socket_path=peer, timeout=10.0)

    assert outcome.failure is not None
    assert outcome.failure.phase == "read"
    assert outcome.failure.reason is expected_reason


def test_call_outcome_malformed_envelopes_are_internal(
    tmp_path: Path,
) -> None:
    with rpc_peer(tmp_path, lambda conn: dprotocol.send_json(conn, ["x"])) as peer:
        outcome = dclient.call_outcome("echo", socket_path=peer)
    assert outcome.failure is not None
    assert outcome.failure.phase == "response"

    with rpc_peer(
        tmp_path, lambda conn: dprotocol.send_json(conn, {"jsonrpc": "2.0", "id": 1})
    ) as peer:
        outcome = dclient.call_outcome("echo", socket_path=peer)
    assert outcome.failure is not None
    assert outcome.failure.phase == "response"


def test_call_outcome_rpc_error_envelope_sanitized(tmp_path: Path) -> None:
    def send_error(conn: socket.socket) -> None:
        dprotocol.send_json(
            conn,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "error": {
                    "code": -32601,
                    "message": "junk",
                    "data": {
                        "failure_reason": "supported_skew",
                        "daemon_version": "9.9.9",
                        "evil\nkey": "x",
                        "secret": "leak",
                    },
                },
            },
        )

    with rpc_peer(tmp_path, send_error) as peer:
        outcome = dclient.call_outcome("echo", socket_path=peer)

    assert outcome.failure is not None
    assert outcome.failure.reason is dfailures.DaemonFailureReason.SUPPORTED_SKEW
    assert outcome.failure.daemon_version == "9.9.9"


def test_connect_closes_socket_when_connect_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    closed: list[bool] = []

    class FakeSocket:
        def connect(self, address: object) -> None:
            raise OSError("refused")

        def settimeout(self, value: float) -> None:
            pass

        def close(self) -> None:
            closed.append(True)

    fake = FakeSocket()
    monkeypatch.setattr(dclient.socket, "socket", lambda *a, **k: fake)

    with pytest.raises(OSError):
        dclient._connect(Path("/tmp/nope.sock"), timeout=0.1)

    assert closed == [True]


# ---------------------------------------------------------------------------
# Lifecycle helpers
# ---------------------------------------------------------------------------


def test_stop_daemon_stops_running_daemon(
    up_server: ThreadedDaemon,
) -> None:
    stopped = dclient.stop_daemon(
        socket_path=up_server.socket_path, timeout=5.0
    )

    assert stopped is True
    assert not up_server.socket_path.exists()
    up_server.thread.join(timeout=5)
    assert not up_server.thread.is_alive()


def test_stop_daemon_without_daemon_is_clean(tmp_path: Path) -> None:
    socket_path = tmp_path / "absent.sock"

    assert dclient.stop_daemon(socket_path=socket_path, timeout=0.5) is False


def test_stop_daemon_removes_stale_paths_when_lock_is_free(
    tmp_path: Path,
) -> None:
    socket_path = tmp_path / "stale.sock"
    socket_path.write_bytes(b"")
    pid_path = dpaths.resolve_pid_path(socket_path)
    pid_path.write_text("999999\n")

    assert dclient.stop_daemon(socket_path=socket_path, timeout=0.5) is False
    assert not socket_path.exists()
    assert not pid_path.exists()


def test_stop_daemon_leaves_paths_when_lock_is_held(tmp_path: Path) -> None:
    socket_path = tmp_path / "guarded.sock"
    socket_path.write_bytes(b"")
    pid_path = dpaths.resolve_pid_path(socket_path)
    pid_path.write_text("1\n")
    lock_path = dpaths.resolve_lock_path(socket_path)
    holder = open(lock_path, "a+")
    fcntl.flock(holder, fcntl.LOCK_EX)
    try:
        assert dclient.stop_daemon(socket_path=socket_path, timeout=0.2) is False
        assert socket_path.exists()
    finally:
        holder.close()


def test_wait_until_ready_times_out(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        "POCKETSHELL_DAEMON_SOCKET", "/nonexistent-pshell-test/daemon.sock"
    )

    ready = dclient.wait_until_ready(deadline=0.05, poll_interval=0.01)

    assert ready is False


def test_read_pid_handles_missing_and_invalid(tmp_path: Path) -> None:
    assert dpaths.read_pid(tmp_path / "missing.pid") is None
    bad = tmp_path / "bad.pid"
    bad.write_text("not-a-pid\n")
    assert dpaths.read_pid(bad) is None
    good = tmp_path / "good.pid"
    good.write_text("4242\n")
    assert dpaths.read_pid(good) == 4242


def test_spawn_detached_builds_serve_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, Any] = []

    class FakeProc:
        pid = 4321

    def fake_popen(cmd: list[str], **kwargs: object) -> FakeProc:
        captured.append({"cmd": cmd, "kwargs": kwargs})
        return FakeProc()

    monkeypatch.setattr(dlifecycle.subprocess, "Popen", fake_popen)

    pid = dclient.spawn_detached(
        socket_path=tmp_path / "spawn.sock",
        idle_timeout=7.5,
        python_executable="/opt/py",
    )

    assert pid == 4321
    assert captured[0]["cmd"] == [
        "/opt/py",
        "-m",
        "pocketshell",
        "daemon",
        "_serve",
    ]
    env = captured[0]["kwargs"]["env"]
    assert env["POCKETSHELL_DAEMON_SOCKET"] == str(tmp_path / "spawn.sock")
    assert env["POCKETSHELL_DAEMON_IDLE_SECS"] == "7.5"
    assert captured[0]["kwargs"]["start_new_session"] is True


def test_serve_foreground_honors_env_and_refuses_second_daemon(
    tmp_path: Path,
    up_server: ThreadedDaemon,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("POCKETSHELL_DAEMON_IDLE_SECS", "not-a-float")

    assert (
        dclient.serve_foreground(socket_path=up_server.socket_path) == 0
    )


def test_serve_foreground_parses_idle_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_signal_handlers: None
) -> None:
    captured: dict[str, float] = {}

    class FakeDaemon:
        def __init__(self, *, socket_path: Path, idle_timeout: float) -> None:
            captured["idle_timeout"] = idle_timeout

        def serve(self) -> None:
            pass

    monkeypatch.setenv("POCKETSHELL_DAEMON_IDLE_SECS", "3.25")
    monkeypatch.setattr(dlifecycle, "Daemon", FakeDaemon)

    dclient.serve_foreground(socket_path=tmp_path / "x.sock")

    assert captured["idle_timeout"] == 3.25


# ---------------------------------------------------------------------------
# Sanitization helpers
# ---------------------------------------------------------------------------


def test_safe_version_and_method_redaction() -> None:
    assert dfailures._safe_version(7) is None
    assert dfailures._safe_version(" 1.2.3 ") == "1.2.3"
    assert dfailures._safe_version("bad version!") is None
    assert dfailures._safe_method("tree.get") == "tree.get"
    assert dfailures._safe_method(42) == "<redacted>"
    assert dfailures._safe_method("bad method!") == "<redacted>"


def test_safe_error_data_rejects_non_mapping_and_junk() -> None:
    assert dfailures._safe_error_data("junk") is None
    assert dfailures._safe_error_data({"unknown": 1}) is None
    safe = dfailures._safe_error_data(
        {"failure_reason": "supported_skew", "cli_version": "0.5.8"}
    )
    assert safe == {"failure_reason": "supported_skew", "cli_version": "0.5.8"}


def test_failure_user_message_special_cases_invalid_params() -> None:
    failure = dfailures._failure(
        dfailures.DaemonFailureReason.DAEMON_INTERNAL_ERROR,
        "usage.fetch",
        cli_version="0.5.8",
        rpc_code=dfailures.JSONRPC_INVALID_PARAMS,
        phase="rpc",
    )

    message = failure.user_message()
    assert "invalid parameters" in message
    assert failure.fallback_allowed is False


def test_outcome_properties_and_installed_version_probe() -> None:
    outcome = dfailures.DaemonCallOutcome(result=5)
    assert outcome.succeeded is True
    failure = dfailures.DaemonFailure(
        reason=dfailures.DaemonFailureReason.ABSENT_OR_UNAVAILABLE,
        method="m",
        phase="probe",
    )
    assert dfailures.DaemonCallOutcome(failure=failure).succeeded is False
    assert failure.fallback_allowed is True
    assert "absent_or_unavailable" in str(failure.telemetry())
    assert dfailures._installed_cli_version()  # the real package version


def test_framing_error_message_on_short_read() -> None:
    client, server = socket.socketpair()
    try:
        client.sendall(b"abc")
        client.shutdown(socket.SHUT_WR)
        with pytest.raises(dprotocol.FramingError) as excinfo:
            dprotocol._recv_exact(server, 10)
        assert "3/10" in str(excinfo.value)
    finally:
        client.close()
        server.close()


def test_send_frame_rejects_oversized_payload() -> None:
    client, server = socket.socketpair()
    try:
        with pytest.raises(dprotocol.FramingError):
            dprotocol.send_frame(client, b"x" * (dprotocol._MAX_FRAME_BYTES + 1))
    finally:
        client.close()
        server.close()


_peer_counter = itertools.count()


_peer_counter = itertools.count()


@contextmanager
def rpc_peer(tmp_path: Path, script: object) -> Iterator[Path]:
    """A raw UNIX-socket peer that serves ``script(conn)`` per connection."""
    peer_path = tmp_path / f"peer-{next(_peer_counter)}.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(peer_path))
    listener.listen(4)
    stop = threading.Event()

    def serve_peers() -> None:
        listener.settimeout(0.1)
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                script(conn)
                # Drain until EOF (bounded) before closing. A close with the
                # client's request still unread sends RST, which can overtake
                # the scripted response and fail the client's write (flake
                # under machine load). One recv is not enough: it can return
                # while sendall is still mid-flight. The client closes after
                # parsing the response, so EOF ends this loop quickly on the
                # happy path; the bound only applies to no-response scripts.
                conn.settimeout(0.05)
                deadline = time.monotonic() + 0.25
                try:
                    while time.monotonic() < deadline:
                        if not conn.recv(65536):
                            break
                except OSError:
                    pass
            except OSError:
                pass
            finally:
                conn.close()
        listener.close()

    thread = threading.Thread(target=serve_peers, daemon=True)
    thread.start()
    try:
        yield peer_path
    finally:
        stop.set()
        thread.join(timeout=2)


@contextmanager
def raw_client(socket_path: Path) -> Iterator[socket.socket]:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    sock.connect(str(socket_path))
    try:
        yield sock
    finally:
        sock.close()
