"""Host-side link daemon: dial the relay, execute exec/PTY channels.

Runs on machines WITHOUT inbound reachability (laptops, home/office boxes
behind NAT).  Everything above the channel layer is deliberately generic:
the daemon execs shell commands and hosts PTYs — it knows nothing about
sessions, aplexer or workspaces.  Clients drive PocketShell exactly as they
would over SSH, by execing `pocketshell ...` and attaching `a attach ...`
through those channels.
"""

from __future__ import annotations

import asyncio
import fcntl
import logging
import os
import random
import signal
import struct
import subprocess
import termios
import time
import urllib.parse
from typing import Any, Union

import websockets.asyncio.client
from websockets.asyncio.client import ClientConnection
from websockets.exceptions import ConnectionClosed

from . import protocol

log = logging.getLogger(__name__)

_BACKOFF_MIN = 0.5
_BACKOFF_MAX = 30.0
_HEALTHY_UPTIME = 60.0
_READ_CHUNK = 65536
# Host channel ids are handed out by the relay; exec stderr rides a sibling
# channel the daemon derives from the main id in the upper half of the u32
# space, so the two allocators can never collide (protocol v1 guarantee).
_ERR_CHANNEL_BASE = 0x40000000


def build_host_url(relay_url: str, token: str, host_id: str) -> str:
    split = urllib.parse.urlsplit(relay_url)
    query = urllib.parse.urlencode({"token": token, "host_id": host_id})
    path = split.path.rstrip("/") + "/host"
    return urllib.parse.urlunsplit((split.scheme, split.netloc, path, query, ""))


class _ExecChannel:
    """One exec: shell command, stdout on the channel, stderr on a sibling."""

    def __init__(self, daemon: "LinkDaemon", channel: int, cmd: str, timeout_ms: int | None) -> None:
        self.daemon = daemon
        self.channel = channel
        self.err_channel = _ERR_CHANNEL_BASE + channel
        self.cmd = cmd
        self.timeout_ms = timeout_ms
        self.proc: subprocess.Popen[bytes] | None = None
        self.timed_out = False
        self._timer: asyncio.TimerHandle | None = None
        self._pump_tasks: list[asyncio.Task] = []
        self._stdin_lock = asyncio.Lock()

    async def start(self) -> None:
        try:
            self.proc = subprocess.Popen(
                self.cmd,
                shell=True,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
        except OSError as exc:
            await self.daemon.send_control(
                "opened", ch=self.channel, ok=False,
                code=protocol.EXEC_SPAWN_FAILED, message=str(exc),
            )
            self.daemon.forget_channel(self.channel)
            self.daemon.forget_channel(self.err_channel)
            return
        await self.daemon.send_control(
            "opened", ch=self.channel, ok=True, err_ch=self.err_channel
        )
        assert self.proc is not None
        self._pump_tasks = [
            asyncio.create_task(self._pump(self.proc.stdout, self.channel)),
            asyncio.create_task(self._pump(self.proc.stderr, self.err_channel)),
        ]
        asyncio.create_task(self._wait())
        if self.timeout_ms is not None and self.timeout_ms > 0:
            self._timer = asyncio.get_running_loop().call_later(
                self.timeout_ms / 1000.0, self._on_timeout
            )

    def _on_timeout(self) -> None:
        self.timed_out = True
        self.kill()

    async def _pump(self, stream: Any, channel: int) -> None:
        while True:
            chunk = await asyncio.to_thread(stream.read, _READ_CHUNK)
            if not chunk:
                return
            await self.daemon.send_data(channel, chunk)

    async def _wait(self) -> None:
        assert self.proc is not None
        code = await asyncio.to_thread(self.proc.wait)
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
        # Draining the pipes before exit keeps stream order honest for the
        # client; the cap means a daemonized grandchild holding the pipes
        # cannot wedge the exit frame (SSH would wait forever here).
        await asyncio.wait(self._pump_tasks, timeout=2.0)
        await self.daemon.send_control(
            "exit", ch=self.channel, exit_code=code, timed_out=self.timed_out
        )
        self.daemon.forget_channel(self.channel)
        self.daemon.forget_channel(self.err_channel)

    async def write_stdin(self, payload: bytes) -> None:
        """Feed one client data frame to the child's stdin.

        Clients only send these after `opened`, and `opened` only goes out
        after the spawn, so `proc.stdin` is live here. A full pipe would
        block the event loop on a plain write, so the write rides a thread.
        """
        stdin = self.proc.stdin if self.proc is not None else None
        if stdin is None or stdin.closed:
            return
        async with self._stdin_lock:
            if stdin.closed:
                return
            await asyncio.to_thread(self._write_all, stdin, payload)

    async def close_stdin(self) -> None:
        """Client-side stdin EOF: close the pipe so the reader sees EOF."""
        stdin = self.proc.stdin if self.proc is not None else None
        if stdin is None or stdin.closed:
            return
        async with self._stdin_lock:
            if not stdin.closed:
                try:
                    stdin.close()
                except OSError:
                    pass

    @staticmethod
    def _write_all(stdin: Any, payload: bytes) -> None:
        try:
            stdin.write(payload)
            stdin.flush()
        except (OSError, ValueError):
            pass  # the child is gone; the wait task settles the channel

    def kill(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGKILL)
            except OSError:
                try:
                    self.proc.kill()
                except OSError:
                    pass


class _PtyChannel:
    """One PTY: real controlling terminal, resize, io, SIGHUP-clean teardown."""

    def __init__(
        self,
        daemon: "LinkDaemon",
        channel: int,
        cmd: str,
        cols: int,
        rows: int,
        term: str | None,
    ) -> None:
        self.daemon = daemon
        self.channel = channel
        self.cmd = cmd
        self.cols = cols
        self.rows = rows
        self.term = term
        self.master: int | None = None
        self.proc: subprocess.Popen[bytes] | None = None

    async def start(self) -> None:
        master, slave = os.openpty()
        os.set_blocking(master, False)
        self._set_winsize(master)
        env = dict(os.environ)
        env["TERM"] = self.term or "xterm-256color"
        try:
            self.proc = subprocess.Popen(
                self.cmd,
                shell=True,
                stdin=slave,
                stdout=slave,
                stderr=slave,
                preexec_fn=self._child_tty(slave),
                env=env,
            )
        except OSError as exc:
            os.close(master)
            os.close(slave)
            await self.daemon.send_control(
                "opened", ch=self.channel, ok=False,
                code=protocol.PTY_OPEN_FAILED, message=str(exc),
            )
            self.daemon.forget_channel(self.channel)
            return
        os.close(slave)
        self.master = master
        await self.daemon.send_control("opened", ch=self.channel, ok=True)
        asyncio.get_running_loop().add_reader(master, self._on_readable)
        asyncio.create_task(self._wait())

    @staticmethod
    def _child_tty(slave: int):
        def _setup() -> None:
            os.setsid()
            fcntl.ioctl(slave, termios.TIOCSCTTY, 0)

        return _setup

    def _set_winsize(self, fd: int) -> None:
        fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", self.rows, self.cols, 0, 0))

    def _on_readable(self) -> None:
        assert self.master is not None
        try:
            data = os.read(self.master, _READ_CHUNK)
        except OSError:
            return  # EAGAIN: nothing more now; EIO: the wait task sends eof/exit
        if data:
            asyncio.create_task(self.daemon.send_data(self.channel, data))
            return
        loop = asyncio.get_running_loop()
        loop.remove_reader(self.master)
        os.close(self.master)
        self.master = None

    def write(self, payload: bytes) -> None:
        if self.master is None:
            return
        try:
            os.write(self.master, payload)
        except OSError:
            pass

    def resize(self, cols: int, rows: int) -> None:
        if self.master is None:
            return
        fcntl.ioctl(self.master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))

    def kill(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGKILL)
            except OSError:
                try:
                    self.proc.kill()
                except OSError:
                    pass

    async def _wait(self) -> None:
        assert self.proc is not None
        code = await asyncio.to_thread(self.proc.wait)
        master = self.master
        if master is not None:
            try:
                asyncio.get_running_loop().remove_reader(master)
            except (ValueError, OSError):
                pass
            # Final non-blocking drain so buffered output precedes eof/exit.
            while True:
                try:
                    data = os.read(master, _READ_CHUNK)
                except OSError:
                    break
                if not data:
                    break
                await self.daemon.send_data(self.channel, data)
            try:
                os.close(master)
            except OSError:
                pass
            self.master = None
        await self.daemon.send_control("eof", ch=self.channel)
        await self.daemon.send_control(
            "exit", ch=self.channel, exit_code=code, timed_out=False
        )
        self.daemon.forget_channel(self.channel)


_Channel = Union[_ExecChannel, _PtyChannel]


class LinkDaemon:
    """Dials the relay's /host leg and serves channels until dropped."""

    def __init__(
        self,
        relay_url: str,
        token: str,
        host_id: str,
        name: str | None = None,
        *,
        reconnect: bool = True,
    ) -> None:
        self._url = build_host_url(relay_url, token, host_id)
        self._host_id = host_id
        self._name = name or host_id
        self._reconnect = reconnect
        self._ws: ClientConnection | None = None
        self._channels: dict[int, _Channel] = {}

    def forget_channel(self, channel: int) -> None:
        self._channels.pop(channel, None)

    async def send_control(self, frame_type: str, **fields: Any) -> None:
        ws = self._ws
        if ws is None:
            return
        try:
            await ws.send(protocol.encode_control(frame_type, **fields))
        except ConnectionClosed:
            pass

    async def send_data(self, channel: int, payload: bytes) -> None:
        ws = self._ws
        if ws is None:
            return
        try:
            await ws.send(protocol.encode_data(channel, payload))
        except ConnectionClosed:
            pass

    async def run_forever(self) -> None:
        """Serve, reconnecting with capped jittered backoff until stopped."""
        delay = _BACKOFF_MIN
        while True:
            started = time.monotonic()
            try:
                await self._serve_once()
            except (ConnectionClosed, OSError, protocol.ProtocolError) as exc:
                log.warning("link: connection to relay lost (%s)", exc)
            if not self._reconnect:
                return
            uptime = time.monotonic() - started
            delay = _BACKOFF_MIN if uptime >= _HEALTHY_UPTIME else min(delay * 2, _BACKOFF_MAX)
            pause = delay * (0.5 + random.random() / 2)
            log.info("link: reconnecting in %.1fs", pause)
            await asyncio.sleep(pause)

    async def _serve_once(self) -> None:
        async with websockets.asyncio.client.connect(self._url, max_size=None) as ws:
            self._ws = ws
            try:
                await ws.send(
                    protocol.encode_control(
                        "hello", role="host", host_id=self._host_id,
                        proto=protocol.LINK_PROTO_VERSION, name=self._name,
                    )
                )
                while True:
                    raw = await ws.recv()
                    if isinstance(raw, str) and protocol.decode_control(raw).get("t") == "ready":
                        break
                log.info("link: connected to relay as %r", self._host_id)
                async for raw in ws:
                    if isinstance(raw, str):
                        await self._on_control(protocol.decode_control(raw))
                    else:
                        await self._on_data(raw)
            finally:
                self._ws = None
                for channel in list(self._channels.values()):
                    channel.kill()

    async def _on_control(self, frame: dict[str, Any]) -> None:
        kind = frame.get("t")
        channel = frame.get("ch")
        if kind == "open":
            if not isinstance(channel, int) or channel in self._channels:
                return
            await self._open(channel, frame)
        elif kind == "resize":
            chan = self._channels.get(channel) if isinstance(channel, int) else None
            if isinstance(chan, _PtyChannel):
                chan.resize(int(frame.get("cols") or 80), int(frame.get("rows") or 24))
        elif kind == "eof":
            # Client→host `eof` on an exec channel is stdin EOF (host→client
            # `eof` keeps its meaning: the PTY child ended).
            chan = self._channels.get(channel) if isinstance(channel, int) else None
            if isinstance(chan, _ExecChannel):
                asyncio.create_task(chan.close_stdin())
        elif kind == "close":
            chan = self._channels.get(channel) if isinstance(channel, int) else None
            if chan is not None:
                chan.kill()
        # Unknown types are ignored (compatibility rule).

    async def _open(self, channel: int, frame: dict[str, Any]) -> None:
        mode = frame.get("mode")
        cmd = frame.get("cmd")
        if mode not in ("exec", "pty") or not isinstance(cmd, str) or not cmd:
            await self.send_control(
                "opened", ch=channel, ok=False,
                code=protocol.PROTOCOL_ERROR, message="bad open",
            )
            return
        if mode == "exec":
            timeout_ms = frame.get("timeout_ms")
            chan: _Channel = _ExecChannel(
                self, channel, cmd, timeout_ms if isinstance(timeout_ms, int) else None
            )
        else:
            chan = _PtyChannel(
                self, channel, cmd,
                int(frame.get("cols") or 80), int(frame.get("rows") or 24),
                frame.get("term"),
            )
        self._channels[channel] = chan
        await chan.start()

    async def _on_data(self, raw: bytes) -> None:
        try:
            channel, payload = protocol.decode_data(raw)
        except protocol.ProtocolError:
            return
        chan = self._channels.get(channel)
        if isinstance(chan, _PtyChannel):
            chan.write(payload)
        elif isinstance(chan, _ExecChannel):
            # Client data on an exec channel is the command's stdin
            # (`pocketshell env set` feeds its JSON payload this way).
            asyncio.create_task(chan.write_stdin(payload))
