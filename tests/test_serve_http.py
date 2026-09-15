"""In-process HTTP tests for the ``pocketshell serve`` static server.

``tests/test_serve.py`` exercises the real foreground process boundary;
these tests drive the same server objects in-process so the request
translation and containment logic stays covered without a subprocess.
"""

from __future__ import annotations

import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from click.testing import CliRunner

from pocketshell import serve as serve_mod
from pocketshell.cli import cli


class _ServingThread:
    """Run the real StaticHTTPServer on a free port for one test."""

    def __init__(self, root: Path) -> None:
        self.server = serve_mod.create_server(root, bind="127.0.0.1", port=0)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> "_ServingThread":
        self.thread.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def get(self, path: str) -> tuple[int, bytes]:
        with urllib.request.urlopen(
            f"http://127.0.0.1:{self.port}{path}", timeout=2
        ) as response:
            return response.status, response.read()


def test_serves_files_and_index_fallback_in_process(tmp_path: Path) -> None:
    (tmp_path / "index.html").write_text("home", encoding="utf-8")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "index.html").write_text("docs", encoding="utf-8")
    (tmp_path / "data.json").write_text("{}", encoding="utf-8")

    with _ServingThread(tmp_path) as http:
        assert http.get("/") == (200, b"home")
        assert http.get("/docs/") == (200, b"docs")
        assert http.get("/data.json") == (200, b"{}")


@pytest.mark.parametrize(
    "path",
    [
        "/../outside.txt",
        "/%2e%2e/outside.txt",
        "/link/secret.txt",
    ],
)
def test_escaping_requests_get_forbidden(tmp_path: Path, path: str) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("secret", encoding="utf-8")
    root = tmp_path / "root"
    root.mkdir()
    (root / "link").symlink_to(outside, target_is_directory=True)

    with _ServingThread(root) as http, pytest.raises(urllib.error.HTTPError) as error:
        http.get(path)

    assert error.value.code == 403


def test_index_symlink_escaping_root_gets_forbidden(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "index.html").write_text("outside", encoding="utf-8")
    root = tmp_path / "root"
    root.mkdir()
    (root / "index.html").symlink_to(outside / "index.html")

    with _ServingThread(root) as http, pytest.raises(urllib.error.HTTPError) as error:
        http.get("/")

    assert error.value.code == 403


def test_missing_file_is_a_normal_404(tmp_path: Path) -> None:
    with _ServingThread(tmp_path) as http, pytest.raises(urllib.error.HTTPError) as error:
        http.get("/missing.html")

    assert error.value.code == 404


def test_resolve_contained_path_rejects_symlink_loop_root(tmp_path: Path) -> None:
    loop = tmp_path / "loop"
    loop.symlink_to(loop)

    assert serve_mod.resolve_contained_path(loop, loop / "child") is None


def test_translate_path_falls_back_when_decoding_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "index.html").write_text("home", encoding="utf-8")
    calls: list[str] = []
    real_unquote = serve_mod.urllib.parse.unquote

    def flaky_unquote(raw_path: str, **kwargs: object) -> str:
        calls.append(raw_path)
        if len(calls) == 1:
            raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")
        return real_unquote(raw_path)

    monkeypatch.setattr(serve_mod.urllib.parse, "unquote", flaky_unquote)

    with _ServingThread(tmp_path) as http:
        assert http.get("/") == (200, b"home")

    assert len(calls) >= 2


def test_send_head_guard_catches_escape_from_stdlib_handler(tmp_path: Path) -> None:
    """The stdlib handler re-translates paths; the guard must still answer 403."""
    import socket
    from http.server import SimpleHTTPRequestHandler

    (tmp_path / "index.html").write_text("home", encoding="utf-8")
    client_sock, server_sock = socket.socketpair()
    try:
        client_sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
        original = SimpleHTTPRequestHandler.send_head

        def escaping_send_head(self: object):  # type: ignore[no-untyped-def]
            raise serve_mod._PathOutsideRoot("/escaped")

        SimpleHTTPRequestHandler.send_head = escaping_send_head
        try:
            handler = serve_mod.StaticRequestHandler(
                server_sock,
                ("127.0.0.1", 54321),
                directory=str(tmp_path),
                server=object(),
            )
        finally:
            SimpleHTTPRequestHandler.send_head = original

        response = client_sock.recv(4096).decode("utf-8", "replace")
        assert handler is not None
        assert "403" in response.splitlines()[0]
    finally:
        client_sock.close()
        server_sock.close()


def test_resolve_contained_path_rejects_malformed_path(tmp_path: Path) -> None:
    candidate = tmp_path / "bad\x00name"

    assert serve_mod.resolve_contained_path(tmp_path, candidate) is None


def test_resolve_contained_path_accepts_root_itself(tmp_path: Path) -> None:
    resolved = serve_mod.resolve_contained_path(tmp_path, tmp_path)

    assert resolved == tmp_path.resolve()


def test_serve_directory_bind_failure_raises_click_exception(tmp_path: Path) -> None:
    with pytest.raises(Exception) as excinfo:
        serve_mod.serve_directory(tmp_path, bind="999.999.999.999", port=0)

    assert "could not bind HTTP server" in str(excinfo.value)


def test_serve_directory_returns_cleanly_on_interrupt(tmp_path: Path) -> None:
    closed: list[bool] = []

    class InterruptedServer:
        server_address = ("127.0.0.1", 43125)

        def serve_forever(self) -> None:
            raise KeyboardInterrupt

        def server_close(self) -> None:
            closed.append(True)

    serve_mod.create_server = lambda directory, *, bind, port: InterruptedServer()  # type: ignore[assignment]

    serve_mod.serve_directory(tmp_path, bind="127.0.0.1", port=0)

    assert closed == [True]


def test_serve_rejects_file_as_directory(tmp_path: Path) -> None:
    target = tmp_path / "plain-file.txt"
    target.write_text("not a directory", encoding="utf-8")

    result = CliRunner().invoke(cli, ["serve", "--dir", str(target)])

    assert result.exit_code == 2
    assert "directory does not exist" in result.output
