"""Client-side `pocketshell gateway …` commands: reach an enrolled host.

``devices`` / ``pin`` / ``unpin`` / ``proxy`` / ``ssh`` run on the client
laptop (the host-side ``enroll`` / ``run`` / ``show`` wrappers live in
:mod:`pocketshell.gateway.cli`). Flow: ``pocketshell login`` →
``gateway devices`` → ``gateway pin`` (key from the host, out of band) →
``gateway ssh``. See docs/gateway.md §9.
"""

from __future__ import annotations

import json
from typing import Optional

import click

from pocketshell.gateway import devices as gateway_devices
from pocketshell.gateway import endpoint as gateway_endpoint
from pocketshell.gateway import pins as gateway_pins
from pocketshell.gateway import tokens as gateway_tokens

# Exit status when no usable `pocketshell login` session exists (distinct
# from generic failures so scripts can branch on it).
EXIT_NOT_LOGGED_IN = 3


class _NotLoggedIn(click.ClickException):
    exit_code = EXIT_NOT_LOGGED_IN


def _token_provider() -> gateway_tokens.TokenLike:
    # Looked up at call time so the account layer stays a lazy import.
    return gateway_tokens.default_token_provider()


def _resolve_endpoint(
    server: Optional[str], insecure_dev: bool, trust_gateway: Optional[str]
) -> gateway_endpoint.GatewayEndpoint:
    try:
        ep = gateway_endpoint.resolve_endpoint(server, insecure_dev, trust_gateway)
    except gateway_endpoint.EndpointError as exc:
        raise click.UsageError(str(exc)) from None
    if ep.warning:
        click.echo(ep.warning, err=True)
    return ep


def _server_options(func):
    func = click.option(
        "--trust-gateway",
        default=None,
        metavar="HOST",
        help=(
            "Required with a non-production --server: the exact gateway "
            "host you trust with your (replayable, ≤ 5 min) gateway token."
        ),
    )(func)
    func = click.option(
        "--insecure-dev",
        is_flag=True,
        help=(
            "DEV ONLY: allow plain ws:// / http:// to a loopback or "
            "single-label docker host. Never for production."
        ),
    )(func)
    func = click.option(
        "--server",
        default=None,
        metavar="URL",
        help=f"Gateway URL (default: {gateway_endpoint.DEFAULT_SERVER}).",
    )(func)
    return func


@click.command("devices")
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
@_server_options
def devices(
    as_json: bool, server: Optional[str], insecure_dev: bool, trust_gateway: Optional[str]
) -> None:
    """List the hosts enrolled under your account (client side).

    Needs `pocketshell login`. The host keys shown are ADVERTISED by the
    gateway and NOT trusted: pin the key you get from the host itself
    (`pocketshell gateway show --pin-command` on the host).
    """
    endpoint = _resolve_endpoint(server, insecure_dev, trust_gateway)
    try:
        listed = gateway_devices.fetch_devices(endpoint, _token_provider)
    except gateway_tokens.NotLoggedInError as exc:
        raise _NotLoggedIn(str(exc)) from None
    except (gateway_tokens.GatewayTokenError, gateway_devices.DevicesError) as exc:
        raise click.ClickException(str(exc)) from None
    try:
        local_pins = gateway_pins.load_pins()
    except gateway_pins.PinError as exc:
        click.echo(f"warning: ignoring pin file: {exc}", err=True)
        local_pins = {}

    def pin_state(dev: gateway_devices.DeviceInfo) -> tuple[Optional[str], str]:
        pinned = local_pins.get(dev.id) if dev.id_valid else None
        if pinned is None:
            return None, "not pinned"
        if dev.advertised_key is None or dev.advertised_key == pinned:
            return pinned.fingerprint, "pinned"
        return pinned.fingerprint, "pinned (DIFFERS from advertised)"

    if as_json:
        # Fingerprints only, never the advertised key line itself: a
        # `devices --json | jq … | gateway pin` pipeline would turn the
        # gateway's untrusted claim into a pin (trust on first use).
        doc = {
            "gateway": endpoint.host,
            "devices": [
                {
                    "id": dev.id,
                    "id_valid": dev.id_valid,
                    "revoked": dev.revoked,
                    "advertised_fingerprint": (
                        dev.advertised_key.fingerprint if dev.advertised_key else None
                    ),
                    "pinned_fingerprint": pin_state(dev)[0],
                }
                for dev in listed
            ],
        }
        click.echo(json.dumps(doc, indent=2, sort_keys=True))
        return
    if not listed:
        click.echo("no devices enrolled under this account")
        return
    rows = [("DEVICE", "STATE", "ADVERTISED HOST KEY (UNTRUSTED)", "LOCAL PIN")]
    for dev in listed:
        advertised = (
            f"{dev.advertised_key.fingerprint} ({dev.advertised_key.label})"
            if dev.advertised_key
            else "-"
        )
        state = "revoked" if dev.revoked else "active"
        if not dev.id_valid:
            state += ", invalid id"
        rows.append((dev.display_id, state, advertised, pin_state(dev)[1]))
    widths = [max(len(r[i]) for r in rows) for i in range(3)]
    for r in rows:
        click.echo("  ".join(r[i].ljust(widths[i]) for i in range(3)) + "  " + r[3])
    click.echo(
        "\nAdvertised keys come from the gateway and are never trusted. Pin the "
        "key printed by `pocketshell gateway show --pin-command` on the host."
    )


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


CLIENT_COMMANDS = (devices, pin, unpin)
