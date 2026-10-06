"""Click surface for the link transport.

``pocketshell link run`` — the host daemon for machines without inbound SSH.
``pocketshell relay serve`` — the reference relay to run wherever inbound
TCP works.  See docs/link-transport.md.  ``websockets`` is imported lazily
so the base install never pays for the transport.
"""

from __future__ import annotations

import asyncio
import logging
import sys

import click


def _require_websockets() -> None:
    try:
        import websockets  # noqa: F401
    except ImportError as exc:
        raise click.UsageError(
            "the link transport needs the [link] extra: pip install 'pocketshell[link]'"
        ) from exc


def _read_token(token: str) -> str:
    if token != "-":
        return token
    line = sys.stdin.readline()
    if not line.strip():
        raise click.UsageError("--token - read an empty line from stdin")
    return line.strip()


def _parse_listen(listen: str) -> tuple[str, int]:
    host, _, port = listen.rpartition(":")
    if not host or not port.isdigit():
        raise click.UsageError("--listen expects HOST:PORT")
    return host, int(port)


@click.group(
    name="link",
    context_settings={"help_option_names": ["-h", "--help"]},
    help="Link transport: reach hosts that have no inbound SSH.",
)
def link_group() -> None:
    """Host-side link transport commands."""


@link_group.command("run")
@click.option("--relay", required=True, metavar="URL", help="Relay endpoint, e.g. wss://relay.example:8765.")
@click.option(
    "--token",
    required=True,
    envvar="POCKETSHELL_LINK_TOKEN",
    metavar="TEXT",
    help="Shared relay token ('-' reads one line from stdin).",
)
@click.option("--host-id", required=True, metavar="ID", help="Stable id clients use to reach this host.")
@click.option("--name", default=None, metavar="TEXT", help="Human-readable name shown to clients.")
@click.option("--no-reconnect", is_flag=True, help="Exit when the relay connection drops (debugging/tests).")
def link_run(relay: str, token: str, host_id: str, name: str | None, no_reconnect: bool) -> None:
    """Run the host-side link daemon (dials OUT to the relay).

    Keeps one outbound WebSocket to the relay alive, reconnecting with
    backoff, and serves exec/PTY channels to paired clients.  Run this on
    the machine that has no inbound SSH.
    """
    _require_websockets()
    from pocketshell.link.daemon import LinkDaemon

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s"
    )
    token = _read_token(token)
    daemon = LinkDaemon(relay, token, host_id, name, reconnect=not no_reconnect)
    try:
        asyncio.run(daemon.run_forever())
    except KeyboardInterrupt:
        click.echo("link: stopped")


@click.group(
    name="relay",
    context_settings={"help_option_names": ["-h", "--help"]},
    help="Reference relay for the link transport.",
)
def relay_group() -> None:
    """Relay commands."""


@relay_group.command("serve")
@click.option(
    "--listen",
    default="127.0.0.1:8765",
    show_default=True,
    metavar="HOST:PORT",
    help="Address to bind. Serve WSS (or behind a TLS terminator) in production.",
)
@click.option(
    "--token",
    required=True,
    envvar="POCKETSHELL_LINK_TOKEN",
    metavar="TEXT",
    help="Shared token both legs must present ('-' reads one line from stdin).",
)
def relay_serve(listen: str, token: str) -> None:
    """Serve the reference relay (run wherever inbound TCP works).

    Pairs link hosts and clients by host_id and namespaces their channel
    ids; it never inspects payload bytes.
    """
    _require_websockets()
    from pocketshell.link.relay import Relay

    host, port = _parse_listen(listen)
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s"
    )
    token = _read_token(token)

    async def _serve() -> None:
        server = await Relay(token).serve(host, port)
        click.echo(f"relay listening on {host}:{port}")
        sys.stdout.flush()  # click 8.2+ echo() takes no flush=; readers wait on this line
        await server.serve_forever()

    try:
        asyncio.run(_serve())
    except KeyboardInterrupt:
        click.echo("relay: stopped")
