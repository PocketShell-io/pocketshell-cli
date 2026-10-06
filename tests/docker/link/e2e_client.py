"""Docker E2E client: prove a link host is drivable through the relay alone.

The client container has no route to the host container except the relay.
It execs commands and drives a PTY inside the host container — the exact
operations PocketShell's session flow needs (`sessions create` = exec,
`a attach` = PTY).
"""

import asyncio
import os
import sys

sys.path.insert(0, "/srv/src")

from pocketshell.link.client import LinkClient


async def main() -> None:
    relay_url = os.environ["LINK_RELAY_URL"]
    token = os.environ["LINK_TOKEN"]
    host_id = os.environ["LINK_HOST_ID"]

    client = await LinkClient(relay_url, token, host_id).connect()
    print("client: paired with", host_id, flush=True)

    # 1. exec — what `pocketshell sessions create` rides on
    result = await asyncio.wait_for(
        client.exec("echo e2e-exec-ok && uname -s"), timeout=15
    )
    assert result.stdout.startswith(b"e2e-exec-ok"), result.stdout
    assert result.exit_code == 0, result
    print("client: exec ok:", result.stdout.decode().strip().splitlines(), flush=True)

    # 2. exec with stderr separation
    result = await asyncio.wait_for(
        client.exec("echo out; echo err >&2; exit 3"), timeout=15
    )
    assert result.stdout.strip() == b"out", result
    assert result.stderr.strip() == b"err", result
    assert result.exit_code == 3, result
    print("client: exec stderr/exit-code ok", flush=True)

    # 3. PTY — what `a attach` rides on: write, see the echo, resize, exit
    pty = await asyncio.wait_for(client.open_pty("cat", cols=80, rows=24), timeout=15)
    pty.write(b"e2e-pty-ping\n")
    data = b""
    for _ in range(50):
        data += await pty.read(timeout=0.3)
        if b"e2e-pty-ping" in data:
            break
    assert b"e2e-pty-ping" in data, data
    await pty.resize(cols=120, rows=40)
    await pty.close()
    for _ in range(50):
        await pty.read(timeout=0.3)
        if pty.exit_code is not None:
            break
    assert pty.exit_code is not None, "pty never exited after close"
    print("client: pty roundtrip ok (exit", pty.exit_code, ")", flush=True)

    await client.close()
    print("E2E-CLIENT-OK", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
