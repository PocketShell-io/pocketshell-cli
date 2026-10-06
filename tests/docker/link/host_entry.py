"""Docker E2E entry: the link daemon inside the host container.

This container has ZERO published ports — the whole point. Everything it
sends travels out over the daemon's single outbound WebSocket to the relay.
"""

import asyncio
import logging
import os
import sys

sys.path.insert(0, "/srv/src")

from pocketshell.link.daemon import LinkDaemon


async def main() -> None:
    daemon = LinkDaemon(
        os.environ["LINK_RELAY_URL"],
        os.environ["LINK_TOKEN"],
        os.environ["LINK_HOST_ID"],
        "Docker Laptop",
        reconnect=True,
    )
    await daemon.run_forever()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
