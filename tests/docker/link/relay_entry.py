"""Docker E2E entry: the reference relay inside a container.

Listens on 0.0.0.0:8765; the e2e.sh orchestrator publishes that ONE port to
the operator's loopback. The host container never reaches this process's
published port — containers reach it over the shared docker network, the
same way a NAT'd laptop reaches a public relay.
"""

import asyncio
import logging
import os
import sys

sys.path.insert(0, "/srv/src")

from pocketshell.link.relay import Relay


async def main() -> None:
    relay = Relay(os.environ["LINK_TOKEN"])
    server = await relay.serve("0.0.0.0", 8765)
    print("relay ready on 8765", flush=True)
    await server.serve_forever()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
