"""Client-side `pocketshell gateway …` commands: reach an enrolled host.

``devices`` / ``pin`` / ``unpin`` / ``proxy`` / ``ssh`` run on the client
laptop (the host-side ``enroll`` / ``run`` / ``show`` wrappers live in
:mod:`pocketshell.gateway.cli`). Flow: ``pocketshell login`` →
``gateway devices`` → ``gateway pin`` (key from the host, out of band) →
``gateway ssh``. See docs/gateway.md §9.
"""

from __future__ import annotations

import json
import os
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


def _require_login() -> None:
    gateway_tokens.require_login()


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
    (`pocketshell gateway show --host-key` on the host). When the gateway
    reports presence, an ONLINE column shows whether each host agent is
    connected to the gateway right now (`?` = not reported).
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
                    # null = the gateway did not report presence (unknown)
                    "online": dev.presence.online if dev.presence else None,
                    "observed_at": dev.presence.observed_at if dev.presence else None,
                    "connected_since": (
                        dev.presence.connected_since if dev.presence else None
                    ),
                    "session_generation": (
                        dev.presence.session_generation if dev.presence else None
                    ),
                }
                for dev in listed
            ],
        }
        click.echo(json.dumps(doc, indent=2, sort_keys=True))
        return
    if not listed:
        click.echo("no devices enrolled under this account")
        return
    # The ONLINE column appears only when the gateway reports presence for
    # at least one device; older gateways keep the exact previous layout.
    with_presence = any(dev.presence is not None for dev in listed)

    def online_cell(dev: gateway_devices.DeviceInfo) -> str:
        if dev.presence is None:
            return "?"
        return "yes" if dev.presence.online else "no"

    header = ("DEVICE", "STATE", "ADVERTISED HOST KEY (UNTRUSTED)", "LOCAL PIN")
    if with_presence:
        header = ("DEVICE", "STATE", "ONLINE") + header[2:]
    rows = [header]
    for dev in listed:
        advertised = (
            f"{dev.advertised_key.fingerprint} ({dev.advertised_key.label})"
            if dev.advertised_key
            else "-"
        )
        state = "revoked" if dev.revoked else "active"
        if not dev.id_valid:
            state += ", invalid id"
        row = (dev.display_id, state, advertised, pin_state(dev)[1])
        if with_presence:
            row = (dev.display_id, state, online_cell(dev)) + row[2:]
        rows.append(row)
    padded = len(header) - 1
    widths = [max(len(r[i]) for r in rows) for i in range(padded)]
    for r in rows:
        click.echo(
            "  ".join(r[i].ljust(widths[i]) for i in range(padded)) + "  " + r[padded]
        )
    if with_presence:
        observed = next(
            (d.presence.observed_at for d in listed if d.presence and d.presence.observed_at),
            None,
        )
        click.echo(
            f"\nONLINE = host agent connected to the gateway"
            f"{f' as of {observed} (gateway clock)' if observed else ''}; "
            "`?` = not reported."
        )
    click.echo(
        "\nAdvertised keys come from the gateway and are never trusted. Pin the "
        "key printed by `pocketshell gateway show --host-key` on the host."
    )


MAX_PIN_INPUT_BYTES = 16384


def _read_host_key_input() -> str:
    """One host-key line from an interactive prompt or from stdin.

    Exactly one line: a single trailing newline is tolerated, anything
    after it (a second line) is refused by the strict parser.
    """
    stdin = click.get_text_stream("stdin")
    if stdin.isatty():
        return click.prompt(
            "Paste the host key line printed by `pocketshell gateway show "
            "--host-key` ON THE HOST",
            prompt_suffix=":\n",
        )
    data = stdin.read(MAX_PIN_INPUT_BYTES + 1)
    if len(data) > MAX_PIN_INPUT_BYTES:
        raise gateway_pins.PinError("host key input is too large")
    if data.endswith("\r\n"):
        data = data[:-2]
    elif data.endswith("\n"):
        data = data[:-1]
    return data


@click.command("pin")
@click.argument("device_id", metavar="DEVICE_ID")
@click.argument("host_key", metavar="['KEYTYPE BASE64']", required=False)
@click.option(
    "--replace",
    is_flag=True,
    help="Replace a DIFFERENT key already pinned for this device (host re-keyed).",
)
def pin(device_id: str, host_key: Optional[str], replace: bool) -> None:
    """Trust a host key as the SSH host key of DEVICE_ID (client side).

    This is the ONLY way a host key becomes trusted for `gateway ssh`.
    On the HOST run `pocketshell gateway show --host-key`; bring that one
    line over a channel you trust and paste it at the prompt (or pipe it
    on stdin). It is a bare `<keytype> <base64>` line, never a command to
    run. Never take it from the gateway or `gateway devices` — that key is
    advertised, untrusted.
    """
    try:
        gateway_endpoint.validate_device_id(device_id)
        text = host_key if host_key is not None else _read_host_key_input()
        key = gateway_pins.parse_host_key(text)
        changed = gateway_pins.add_pin(device_id, key, replace=replace)
    except (gateway_pins.PinError, gateway_endpoint.EndpointError) as exc:
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


@click.command("proxy")
@click.argument("device_id", metavar="DEVICE_ID")
@_server_options
@click.pass_context
def proxy(
    ctx: click.Context,
    device_id: str,
    server: Optional[str],
    insecure_dev: bool,
    trust_gateway: Optional[str],
) -> None:
    """OpenSSH ProxyCommand: bridge stdin/stdout to DEVICE_ID via the gateway.

    Normally started by `pocketshell gateway ssh`, not by hand. stdout
    carries SSH bytes only; diagnostics go to stderr. Exit status: 0 clean,
    2 usage, 3 not logged in, 4 connect/TLS failure, 5 handshake timeout,
    6 gateway protocol violation, 7 unauthorized, 8 unknown/forbidden
    device, 9 host offline, 10 quota, 11 connection lost.
    """
    from pocketshell.gateway import proxy as gateway_proxy

    try:
        gateway_endpoint.validate_device_id(device_id)
    except gateway_endpoint.EndpointError as exc:
        raise click.UsageError(str(exc)) from None
    endpoint = _resolve_endpoint(server, insecure_dev, trust_gateway)
    ctx.exit(gateway_proxy.run_proxy(device_id, endpoint, _token_provider))


def _exec_ssh(path: str, argv: list[str], env: dict) -> None:
    """Replace this process with ssh (tests swap this seam)."""
    os.execve(path, argv, env)


@click.command("ssh")
@click.argument("device_id", metavar="DEVICE_ID")
@click.option("-l", "--login", "login_name", default=None, metavar="USER",
              help="Remote user name (default: your local user name).")
@click.option("-i", "--identity", default=None, metavar="KEYFILE",
              help="Private key for user authentication (IdentitiesOnly is always on).")
@click.option("--key", "vault_key", default=None, metavar="NAME",
              help="Use key NAME from the device-password vault (`pocketshell keys`, "
              "docs/keys.md) via a private, short-lived ssh-agent. Not with -i.")
@_server_options
@click.argument("extra", nargs=-1, type=click.UNPROCESSED, metavar="[-- SSH_ARGS…]")
def ssh(
    device_id: str,
    login_name: Optional[str],
    identity: Optional[str],
    vault_key: Optional[str],
    server: Optional[str],
    insecure_dev: bool,
    trust_gateway: Optional[str],
    extra: tuple[str, ...],
) -> None:
    """SSH to an enrolled host through the gateway (client side).

    Runs OpenSSH with a hardened explicit configuration: your ~/.ssh/config
    is ignored (-F none), the host key must match the pin from
    `pocketshell gateway pin` (StrictHostKeyChecking=yes, nothing else is
    trusted), agent/X11 forwarding, password and keyboard-interactive
    auth are off. After `--` only -L SPEC, -D SPEC, -N, -T, -t, -v, -q
    and a remote command are accepted, e.g.

        pocketshell gateway ssh home-lab -l me -- -N -L 8080:localhost:80
        pocketshell gateway ssh home-lab -- uptime
    """
    from pocketshell.gateway import sshcmd as gateway_sshcmd

    if vault_key is not None and identity is not None:
        raise click.UsageError("--key and -i are mutually exclusive")
    try:
        gateway_endpoint.validate_device_id(device_id)
    except gateway_endpoint.EndpointError as exc:
        raise click.UsageError(str(exc)) from None
    endpoint = _resolve_endpoint(server, insecure_dev, trust_gateway)
    try:
        pin_entry = gateway_pins.require_pin_entry(device_id)
        ssh_path = gateway_sshcmd.find_ssh()
        argv = gateway_sshcmd.build_ssh_argv(
            ssh=ssh_path,
            device_id=device_id,
            endpoint=endpoint,
            pin_file=gateway_pins.pin_file_path(),
            user=login_name,
            identity=identity,
            extra=extra,
            insecure_dev=insecure_dev,
            alias=pin_entry.alias,
        )
    except gateway_pins.PinError as exc:
        raise click.ClickException(str(exc)) from None
    except gateway_sshcmd.SshArgsError as exc:
        raise click.UsageError(str(exc)) from None
    # The ProxyCommand mints the gateway token, but its exit status is lost
    # behind ssh's 255: check the login here (locally, no network) so "not
    # logged in" is exit 3 before ssh or the gateway is ever started.
    try:
        _require_login()
    except gateway_tokens.NotLoggedInError as exc:
        raise _NotLoggedIn(str(exc)) from None
    except gateway_tokens.GatewayTokenError as exc:
        raise click.ClickException(str(exc)) from None
    if vault_key is not None:
        from pocketshell.keys.session import run_vault_key_ssh

        raise SystemExit(run_vault_key_ssh(vault_key, argv, gateway_sshcmd.ssh_environment()))
    _exec_ssh(ssh_path, argv, gateway_sshcmd.ssh_environment())


CLIENT_COMMANDS = (devices, pin, unpin, proxy, ssh)
