"""Adversarial security/resilience probes for the link transport.

Attacks the reference daemon/relay the way a hostile peer would:
malformed-but-decodable control frames (valid JSON with hostile field
types), a stolen-token host impersonation, an unbounded open flood,
oversized hello metadata and a missing-hello slowloris.

Naming convention: ``*_does_not_*`` / ``*_is_bounded`` / ``*_is_capped`` /
``*_is_eventually_reaped`` encode the DESIRED (hardened) behavior and fail
while the gap exists.  ``test_stolen_token_*`` is the inverse: it asserts
the attack succeeds today, as executable documentation of the shared-token
trust model.

Runs under pytest or plain unittest.

Probe status 2026-10-07: the five hardening gaps below were confirmed
against the tree and closed the same day, so the probes run unmarked.
Hostile resize/open fields are coerced per-channel inside the daemon
(winsize clamped into the ioctl's range, TERM string-checked, and any
stray exception costs only its own channel); the open flood is capped by
a 64-slot route reservation per host; hello metadata is truncated to 200
characters; and a leg that never sends hello is reaped after 3s.
test_stolen_token_* PASSES by design: with the single shared token,
re-registering a victim's host_id is a full MITM.  When per-host
credentials land, invert it into a negative assertion.  The two
always-passing tests pin behavior that must not regress: wrong-token
rejection and err-id-space squat harmlessness.
"""

from __future__ import annotations

import asyncio
import json
import unittest

import websockets.asyncio.client

from pocketshell.link import client as link_client
from pocketshell.link import daemon as link_daemon
from pocketshell.link import protocol
from pocketshell.link import relay as link_relay

TOKEN = "adversarial-token"
HOST_ID = "adv-host"


def _client_url(port: int, token: str = TOKEN, host_id: str = HOST_ID) -> str:
    return f"ws://127.0.0.1:{port}/client?token={token}&host_id={host_id}"


class AdversarialLinkCase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.relay = link_relay.Relay(TOKEN)
        self.server = await self.relay.serve("127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def asyncTearDown(self) -> None:
        self.server.close()
        await self.server.wait_closed()

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    async def _raw_ws(self, url: str):
        return await websockets.asyncio.client.connect(
            url, max_size=None, open_timeout=5
        )

    async def _register_host_leg(self, name: str = "attacker"):
        ws = await self._raw_ws(f"ws://127.0.0.1:{self.port}/host?token={TOKEN}&host_id={HOST_ID}")
        await ws.send(protocol.encode_control(
            "hello", role="host", host_id=HOST_ID,
            proto=protocol.LINK_PROTO_VERSION, name=name,
        ))
        first = json.loads(await asyncio.wait_for(ws.recv(), 5))
        if first.get("t") != "ready":
            raise AssertionError(f"unexpected first frame on host leg: {first}")
        return ws

    async def _start_daemon(self):
        daemon = link_daemon.LinkDaemon(
            f"ws://127.0.0.1:{self.port}", TOKEN, HOST_ID, reconnect=False
        )
        task = asyncio.create_task(daemon.run_forever())
        for _ in range(50):
            if HOST_ID in self.relay.hosts:
                return task
            await asyncio.sleep(0.02)
        task.cancel()
        raise AssertionError("daemon never registered with the relay")

    async def _cleanup(self, daemon_task, client) -> None:
        await client.close()
        daemon_task.cancel()
        try:
            await daemon_task
        except BaseException:
            pass

    async def _live_daemon_and_client(self):
        daemon_task = await self._start_daemon()
        try:
            client = await asyncio.wait_for(
                link_client.LinkClient(
                    f"ws://127.0.0.1:{self.port}", TOKEN, HOST_ID
                ).connect(),
                5,
            )
            return daemon_task, client
        except BaseException:
            daemon_task.cancel()
            raise

    async def _daemon_survives_resize(self, cols) -> None:
        """A hostile resize must not stop the daemon serving honest traffic."""
        daemon_task, client = await self._live_daemon_and_client()
        try:
            pty = await client.open_pty("cat", cols=80, rows=24)
            await client._ws.send(protocol.encode_control(
                "resize", ch=pty.channel, cols=cols, rows=24,
            ))
            # The liveness probe rides a second leg: one LinkClient carries
            # exactly one concurrent workload (the pty's read loop owns the
            # socket's recv slot).
            probe = await asyncio.wait_for(
                link_client.LinkClient(
                    f"ws://127.0.0.1:{self.port}", TOKEN, HOST_ID
                ).connect(),
                5,
            )
            try:
                result = await asyncio.wait_for(probe.exec("echo still-alive"), 10)
                self.assertEqual(
                    result.stdout.strip(), b"still-alive",
                    "daemon stopped serving honest traffic after the hostile resize",
                )
            finally:
                await probe.close()
            await pty.close()
        finally:
            await self._cleanup(daemon_task, client)

    async def _recv_until_exit(self, ws, ch: int, deadline: float = 10.0):
        stdout = bytearray()
        loop = asyncio.get_running_loop()
        end = loop.time() + deadline
        while True:
            remaining = end - loop.time()
            if remaining <= 0:
                raise AssertionError(f"no exit frame for ch={ch} within deadline")
            raw = await asyncio.wait_for(ws.recv(), remaining)
            if isinstance(raw, bytes):
                try:
                    data_ch, payload = protocol.decode_data(raw)
                except protocol.ProtocolError:
                    continue
                if data_ch == ch:
                    stdout += payload
                continue
            frame = json.loads(raw)
            if frame.get("t") == "exit" and frame.get("ch") == ch:
                return bytes(stdout), frame

    # ------------------------------------------------------------------
    # hostile control frames aimed at the daemon
    # ------------------------------------------------------------------

    async def test_resize_negative_cols_does_not_kill_daemon(self):
        await self._daemon_survives_resize(-1)

    async def test_resize_string_cols_does_not_kill_daemon(self):
        await self._daemon_survives_resize("not-a-number")

    async def test_resize_huge_cols_does_not_kill_daemon(self):
        await self._daemon_survives_resize(2 ** 62)

    async def test_pty_open_with_nonstring_term_does_not_kill_daemon(self):
        daemon_task, client = await self._live_daemon_and_client()
        try:
            await client._ws.send(protocol.encode_control(
                "open", ch=0x70000001, mode="pty", cmd="cat",
                cols=80, rows=24, term=123,
            ))
            probe = await asyncio.wait_for(
                link_client.LinkClient(
                    f"ws://127.0.0.1:{self.port}", TOKEN, HOST_ID
                ).connect(),
                5,
            )
            try:
                result = await asyncio.wait_for(probe.exec("echo still-alive"), 10)
                self.assertEqual(
                    result.stdout.strip(), b"still-alive",
                    "daemon died after open with term=123 (uncaught TypeError?)",
                )
            finally:
                await probe.close()
        finally:
            await self._cleanup(daemon_task, client)

    # ------------------------------------------------------------------
    # auth surface
    # ------------------------------------------------------------------

    async def test_wrong_token_is_rejected_before_upgrade(self):
        with self.assertRaises(Exception):
            await self._raw_ws(_client_url(self.port, token="WRONG"))

    async def test_stolen_token_lets_attacker_impersonate_the_host(self):
        daemon_task = await self._start_daemon()
        try:
            # The attacker holds the (single, shared) token and re-registers
            # the victim host_id; the relay drops the real daemon's leg and
            # hands every NEW client to the attacker.
            attacker = await self._register_host_leg("attacker")
            client = await asyncio.wait_for(
                link_client.LinkClient(
                    f"ws://127.0.0.1:{self.port}", TOKEN, HOST_ID
                ).connect(),
                5,
            )
            try:
                await client._ws.send(protocol.encode_control(
                    "open", ch=1, mode="exec", cmd="echo secret-payload",
                ))
                opened = json.loads(await asyncio.wait_for(attacker.recv(), 5))
                self.assertEqual(opened.get("t"), "open", f"attacker saw {opened}")
                self.assertIn(
                    "secret-payload", opened.get("cmd", ""),
                    "attacker did not receive the client's command",
                )
                await attacker.send(protocol.encode_control(
                    "opened", ch=opened["ch"], ok=True,
                ))
                await attacker.send(protocol.encode_control(
                    "exit", ch=opened["ch"], exit_code=0,
                ))
                first = json.loads(await asyncio.wait_for(client._ws.recv(), 5))
                self.assertEqual(first.get("t"), "opened")
                verdict = json.loads(await asyncio.wait_for(client._ws.recv(), 5))
                self.assertEqual(verdict.get("t"), "exit")
            finally:
                await client.close()
            await attacker.close()
        finally:
            daemon_task.cancel()
            try:
                await daemon_task
            except BaseException:
                pass

    # ------------------------------------------------------------------
    # resource bounds
    # ------------------------------------------------------------------

    async def test_client_open_flood_is_bounded(self):
        daemon_task, client = await self._live_daemon_and_client()
        try:
            for i in range(1, 151):
                await client._ws.send(protocol.encode_control(
                    "open", ch=i, mode="exec", cmd="sleep 30",
                ))
            await asyncio.sleep(2.0)
            reg = self.relay.hosts.get(HOST_ID)
            live = len(reg.routes) if reg is not None else 0
            self.assertLessEqual(
                live, 64,
                f"relay held {live} concurrent client channels under an open flood",
            )
        finally:
            await self._cleanup(daemon_task, client)

    async def test_oversized_hello_name_is_capped(self):
        attacker = await self._register_host_leg("A" * 1_000_000)
        try:
            raw = await self._raw_ws(_client_url(self.port))
            try:
                await raw.send(protocol.encode_control(
                    "hello", role="client", host_id=HOST_ID,
                    proto=protocol.LINK_PROTO_VERSION,
                ))
                ready = await asyncio.wait_for(raw.recv(), 5)
                self.assertLessEqual(
                    len(ready), 4096,
                    f"relay forwarded {len(ready)} bytes of hello metadata to the client",
                )
            finally:
                await raw.close()
        finally:
            await attacker.close()

    async def test_host_leg_without_hello_is_eventually_reaped(self):
        ws = await self._raw_ws(f"ws://127.0.0.1:{self.port}/host?token={TOKEN}&host_id={HOST_ID}")
        try:
            reaped = False
            try:
                # The relay announces the reaping with an error frame, then
                # closes: drain frames until the close lands.  Still parked
                # after 5s of silence means no reaping.
                while True:
                    await asyncio.wait_for(ws.recv(), 5)
            except asyncio.TimeoutError:
                reaped = False
            except Exception:
                reaped = True  # relay closed the socket: reaped
            self.assertTrue(
                reaped,
                "socket that never sent hello was still parked after 5s (slowloris)",
            )
        finally:
            await ws.close()

    async def test_client_channel_in_err_space_does_not_corrupt_routing(self):
        daemon_task, client = await self._live_daemon_and_client()
        try:
            squat = 0x40000001  # inside the stderr id space the relay rewrites into
            await client._ws.send(protocol.encode_control(
                "open", ch=squat, mode="exec", cmd="echo squat-out",
            ))
            stdout, exit_frame = await self._recv_until_exit(client._ws, squat)
            self.assertEqual(
                stdout, b"squat-out\n",
                f"stdout of a client channel squatting the err-id space was "
                f"misrouted (exit frame: {exit_frame})",
            )
            after = await asyncio.wait_for(client.exec("echo after-squat"), 10)
            self.assertEqual(after.stdout.strip(), b"after-squat")
        finally:
            await self._cleanup(daemon_task, client)


if __name__ == "__main__":
    unittest.main()
