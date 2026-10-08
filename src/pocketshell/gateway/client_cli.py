"""Client-side `pocketshell gateway …` commands: reach an enrolled host.

``devices`` / ``pin`` / ``unpin`` / ``proxy`` / ``ssh`` run on the client
laptop (the host-side ``enroll`` / ``run`` / ``show`` wrappers live in
:mod:`pocketshell.gateway.cli`). Flow: ``pocketshell login`` →
``gateway devices`` → ``gateway pin`` (key from the host, out of band) →
``gateway ssh``. See docs/gateway.md §9.
"""

from __future__ import annotations

import click

from pocketshell.gateway import pins as gateway_pins


@click.command("pin")
@click.argument("device_id", metavar="DEVICE_ID")
@click.argument("host_key", metavar="'KEYTYPE BASE64'")
@click.option(
    "--replace",
    is_flag=True,
    help="Replace a DIFFERENT key already pinned for this device (host re-keyed).",
)
def pin(device_id: str, host_key: str, replace: bool) -> None:
    """Trust HOST_KEY as the SSH host key of DEVICE_ID (client side).

    This is the ONLY way a host key becomes trusted for `gateway ssh`.
    Get the line by running `pocketshell gateway show --pin-command` ON
    THE HOST and copy it over a channel you trust — never from the
    gateway or `gateway devices` (that key is advertised, untrusted).
    """
    try:
        key = gateway_pins.parse_host_key(host_key)
        changed = gateway_pins.add_pin(device_id, key, replace=replace)
    except gateway_pins.PinError as exc:
        raise click.ClickException(str(exc)) from None
    verb = "pinned" if changed else "already pinned"
    click.echo(f"{verb} {device_id}: {key.fingerprint} ({key.label})")
    click.echo(f"pin file: {gateway_pins.pin_file_path()}")


@click.command("unpin")
@click.argument("device_id", metavar="DEVICE_ID")
def unpin(device_id: str) -> None:
    """Forget the pinned SSH host key of DEVICE_ID (client side)."""
    try:
        key = gateway_pins.remove_pin(device_id)
    except gateway_pins.PinError as exc:
        raise click.ClickException(str(exc)) from None
    click.echo(f"unpinned {device_id}: {key.fingerprint} ({key.label})")


CLIENT_COMMANDS = (pin, unpin)
