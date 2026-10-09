"""A fake pocketshell gateway that bridges the client route to a TCP sshd.

Shared by the POSIX e2e (tests/gateway/test_gateway_connect_e2e.py) and the
native Windows e2e (tests/gateway/test_windows_gateway_e2e.py). It speaks
`/api/v1/hosts/<id>/ssh`: JSON auth -> ready (advertising a WRONG
``ssh_host_key`` that the client must ignore) -> raw bytes in binary
messages, pumped to ``127.0.0.1:<target_port>``. Pure Python threads and
blocking sockets, so it runs the same on Windows.

``drop_all()`` aborts every live tunnel without a close handshake (TCP
reset of the WebSocket), the way a crashed gateway or a lost network
looks to the client.
"""

from __future__ import annotations

import json
import os
import socket
import struct
import threading

from websockets.exceptions import ConnectionClosed
from websockets.sync.server import serve

from gateway_keyblobs import ED25519_LINE


class BridgeGateway:
    def __init__(self, target_port: int, *, target_host: str = "127.0.0.1",
                 advertised_key: str = ED25519_LINE) -> None:
        self.target = (target_host, target_port)
        self.advertised_key = advertised_key
        self.seen: dict = {"connections": 0}
        self._live: list = []
        self._lock = threading.Lock()
        self.server = serve(self._handle, "127.0.0.1", 0, compression=None)
        self.port = self.server.socket.getsockname()[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()

    def drop_all(self) -> int:
        with self._lock:
            live = list(self._live)
        linger = struct.pack("HH" if os.name == "nt" else "ii", 1, 0)
        for ws, tcp in live:
            for sock in (ws.socket, tcp):
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
                except OSError:
                    pass
                try:  # wakes the blocked pump threads; close() then resets
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                try:
                    sock.close()
                except OSError:
                    pass
        return len(live)

    def live_count(self) -> int:
        with self._lock:
            return len(self._live)

    def _handle(self, ws) -> None:
        seen = self.seen
        seen["connections"] += 1
        raw = ws.recv(timeout=10)
        auth = json.loads(raw)
        seen["raw"] = raw
        seen["auth"] = auth
        seen["path"] = ws.request.path
        seen["headers"] = str(ws.request.headers)
        # A hostile/compromised gateway's advertised key: must be ignored.
        ws.send(json.dumps({
            "type": "ready", "v": 1, "device_id": auth["device_id"],
            "ssh_host_key": self.advertised_key,
        }))
        tcp = socket.create_connection(self.target)
        pair = (ws, tcp)
        with self._lock:
            self._live.append(pair)

        def down():
            try:
                while True:
                    data = tcp.recv(32768)
                    if not data:
                        break
                    ws.send(data)
            except (OSError, ConnectionClosed):
                pass
            finally:
                try:
                    ws.close()
                except Exception:
                    pass

        t = threading.Thread(target=down, daemon=True)
        t.start()
        try:
            while True:
                msg = ws.recv()
                if isinstance(msg, str):
                    break
                tcp.sendall(msg)
        except (ConnectionClosed, OSError):
            pass
        finally:
            with self._lock:
                if pair in self._live:
                    self._live.remove(pair)
            try:
                tcp.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            tcp.close()
            t.join(5)
