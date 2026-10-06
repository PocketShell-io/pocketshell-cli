"""CLI-surface tests: `pocketshell relay serve` and `pocketshell link run`.

The loopback suites drive LinkDaemon/Relay in-process; this suite covers
the Click layer a real operator touches: argument validation, the three
token paths (flag, env var, stdin '-'), and both binaries cooperating as
actual subprocesses across a real socket.
"""

import asyncio
import os
import select
import signal
import socket
import subprocess
import sys
import time

import pytest

from click.testing import CliRunner

pytest.importorskip("websockets")
pocketshell = pytest.importorskip("pocketshell")

from pocketshell.link.cli import link_group, relay_group  # noqa: E402
from pocketshell.link.client import LinkClient, LinkError  # noqa: E402

TOKEN = "cli-e2e-token"
HOST_ID = "cli-host"
OP_TIMEOUT = 15.0


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_listen_flag_is_validated():
    result = CliRunner().invoke(relay_group, ["serve", "--listen", "no-port-here", "--token", "t"])
    assert result.exit_code != 0
    assert "--listen expects HOST:PORT" in result.output


def test_missing_token_is_rejected():
    result = CliRunner().invoke(link_group, ["run", "--relay", "ws://127.0.0.1:1", "--host-id", "h"])
    assert result.exit_code != 0
    assert "token" in result.output.lower()


def test_empty_stdin_token_is_rejected():
    result = CliRunner().invoke(relay_group, ["serve", "--token", "-"], input="")
    assert result.exit_code != 0
    assert "empty line" in result.output


def _wait_for_line(proc, needle: str, timeout: float) -> str:
    """Read subprocess stdout until `needle` appears; returns the buffer."""
    buf = ""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ready, _, _ = select.select([proc.stdout], [], [], 0.2)
        if ready:
            line = proc.stdout.readline()
            buf += line
            if needle in buf:
                return buf
        if proc.poll() is not None:
            break
    raise AssertionError(f"never saw {needle!r} from subprocess; got:\n{buf}")


async def _exec_via_link(url: str, cmd: str) -> object:
    """Connect with retries until the CLI daemon registers, then exec."""
    for _ in range(150):
        try:
            client = await asyncio.wait_for(LinkClient(url, TOKEN, HOST_ID).connect(), 5.0)
        except (LinkError, OSError, EOFError) as exc:
            # Refused connections and mid-handshake closes mean the relay or
            # daemon is still starting; retry those, not real protocol errors.
            if isinstance(exc, LinkError) and exc.code != "HOST_OFFLINE":
                raise
            await asyncio.sleep(0.2)
            continue
        result = await asyncio.wait_for(client.exec(cmd), OP_TIMEOUT)
        await client.close()
        return result
    raise AssertionError("link daemon never became reachable via the CLI relay")


@pytest.mark.skipif(os.name != "posix", reason="uses POSIX signals")
def test_cli_relay_serve_and_link_run_end_to_end():
    """The two CLI binaries cooperate as real subprocesses over a real socket."""
    preflight = subprocess.run(
        [sys.executable, "-c", "import pocketshell"], capture_output=True
    )
    if preflight.returncode != 0:
        pytest.skip("pocketshell not importable by sys.executable")

    port = _free_port()
    url = f"ws://127.0.0.1:{port}"
    env = dict(os.environ, POCKETSHELL_LINK_TOKEN=TOKEN)
    relay = subprocess.Popen(
        [sys.executable, "-m", "pocketshell", "relay", "serve",
         "--listen", f"127.0.0.1:{port}"],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    relay_out = ""
    try:
        relay_out += _wait_for_line(relay, "relay listening", 30.0)
        # The needle once matched inside a crash traceback; require a live relay.
        assert relay.poll() is None, f"relay died at startup:\n{relay_out}"

        daemon = subprocess.Popen(
            [sys.executable, "-m", "pocketshell", "link", "run",
             "--relay", url, "--token", "-", "--host-id", HOST_ID,
             "--name", "CLI Host"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True,
        )
        try:
            assert daemon.stdin is not None
            daemon.stdin.write(TOKEN + "\n")
            daemon.stdin.flush()

            result = asyncio.run(_exec_via_link(url, "echo cli-e2e"))
            assert result.stdout.strip() == b"cli-e2e"  # type: ignore[attr-defined]
        finally:
            daemon.terminate()
            try:
                daemon.wait(timeout=15)
            except subprocess.TimeoutExpired:
                daemon.kill()
                daemon.wait(timeout=15)

        relay.send_signal(signal.SIGINT)
        try:
            relay.wait(timeout=15)
        except subprocess.TimeoutExpired:
            relay.kill()
            relay.wait(timeout=15)
        relay_out += relay.stdout.read() if relay.stdout is not None else ""
        assert relay.returncode == 0, f"relay exited {relay.returncode}"
        assert "relay: stopped" in relay_out
    finally:
        if relay.poll() is None:
            relay.kill()
            relay.wait(timeout=15)
