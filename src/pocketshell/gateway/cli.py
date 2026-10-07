"""Click surface for the gateway host agent: ``pocketshell gateway …``.

``enroll`` / ``run`` / ``show`` wrap the installed Go helper
`pocketshell-link` (pocketshell-gateway-tunnel); :mod:`pocketshell.gateway.helper`
owns resolution and the exec boundary. This is the reverse-tunnel transport
for hosts without inbound SSH and is **not** interoperable with the legacy
shared-token ``pocketshell link`` / ``pocketshell relay`` commands — those
keep their own protocol and CLI untouched.
"""

from __future__ import annotations

from typing import Optional, Sequence

import click

from pocketshell.gateway import helper as gateway_helper


def _run_helper(argv: Sequence[str], ctx: click.Context) -> None:
    """Resolve the Go helper and exec it (see :mod:`...gateway.helper`)."""
    try:
        binary = gateway_helper.resolve_helper()
    except gateway_helper.HelperNotFoundError as exc:
        click.echo(f"error: {exc}", err=True)
        ctx.exit(127)
    gateway_helper.exec_helper(binary, list(argv))


@click.group(
    name="gateway",
    context_settings={"help_option_names": ["-h", "--help"]},
    help=(
        "Gateway host agent: enroll this host and hold the reverse tunnel "
        "to the SSH gateway (hosts without inbound SSH).\n\n"
        "Wraps the Go `pocketshell-link` helper, which must be installed "
        "separately (build it from the pocketshell-gateway-tunnel repo). "
        "This transport uses per-device keys enrolled with the gateway and "
        "is NOT the legacy shared-token `link`/`relay` transport."
    ),
)
def gateway_group() -> None:
    """Gateway host agent commands (Go `pocketshell-link` wrappers)."""


@click.command("enroll")
@click.option(
    "--token-stdin",
    is_flag=True,
    help=(
        "Read the device's Google ID token from stdin (required). The "
        "token is never accepted as a CLI flag — that would leak through "
        "shell history and process listings."
    ),
)
@click.option(
    "--server",
    default=None,
    metavar="URL",
    help=(
        "Gateway base URL, wss:// (or ws:// only with --insecure-dev). "
        "Default: the helper's built-in production gateway."
    ),
)
@click.option(
    "--config-dir",
    default=None,
    metavar="DIR",
    help="Agent state directory (default: ${XDG_CONFIG_HOME:-$HOME/.config}/pocketshell-link).",
)
@click.option(
    "--device-id",
    default=None,
    metavar="ID",
    help="Device ID (default: auto-generated from the hostname).",
)
@click.option(
    "--ssh-host",
    default=None,
    metavar="HOST:PORT",
    help="Local SSH endpoint, loopback only (default: 127.0.0.1:22).",
)
@click.option(
    "--expect-host-key",
    default=None,
    metavar="KEY",
    help=(
        "authorized_keys line or SHA256 fingerprint the local sshd must "
        "present, else enroll aborts. Recommended: pin it explicitly."
    ),
)
@click.option(
    "--insecure-dev",
    is_flag=True,
    help="DEV ONLY: allow plain ws:// / http:// gateway URLs (e.g. docker). Never for production.",
)
@click.option("--verbose", is_flag=True, help="Log debug output.")
@click.pass_context
def enroll(
    ctx: click.Context,
    token_stdin: bool,
    server: Optional[str],
    config_dir: Optional[str],
    device_id: Optional[str],
    ssh_host: Optional[str],
    expect_host_key: Optional[str],
    insecure_dev: bool,
    verbose: bool,
) -> None:
    """Generate the device key, pin the local sshd host key, enroll.

    The Google ID token arrives on stdin (`--token-stdin`):

        pocketshell gateway enroll --token-stdin < id-token.txt

    The token only travels inside the enroll request body — never in a
    URL, argv, or log line. On success the host key of the local sshd is
    pinned in the config dir; `gateway show` prints the enrolled state.
    """
    if not token_stdin:
        raise click.UsageError(
            "enroll requires --token-stdin: pipe the device's Google ID token, e.g.\n"
            "  google-token print | pocketshell gateway enroll --token-stdin\n"
            "There is deliberately no token CLI flag (history/process-listing leak)."
        )
    argv = gateway_helper.build_helper_argv(
        "enroll",
        server=server,
        config_dir=config_dir,
        insecure_dev=insecure_dev,
        verbose=verbose,
        token_stdin=token_stdin,
        device_id=device_id,
        ssh_host=ssh_host,
        expect_host_key=expect_host_key,
    )
    _run_helper(argv, ctx)


@click.command("run")
@click.option(
    "--server",
    default=None,
    metavar="URL",
    help=(
        "Override the enrolled gateway URL (wss://, or ws:// only with "
        "--insecure-dev). Default: the server recorded at enroll time."
    ),
)
@click.option(
    "--config-dir",
    default=None,
    metavar="DIR",
    help="Agent state directory (default: ${XDG_CONFIG_HOME:-$HOME/.config}/pocketshell-link).",
)
@click.option(
    "--insecure-dev",
    is_flag=True,
    help="DEV ONLY: allow plain ws:// / http:// gateway URLs (e.g. docker). Never for production.",
)
@click.option("--verbose", is_flag=True, help="Log debug output.")
@click.pass_context
def run(
    ctx: click.Context,
    server: Optional[str],
    config_dir: Optional[str],
    insecure_dev: bool,
    verbose: bool,
) -> None:
    """Hold the reverse tunnel to the gateway (foreground).

    Maintains the outbound WSS control connection; the gateway can open
    multiplexed streams, each bridged to the loopback-only local sshd. No
    inbound ports are opened. Stops cleanly on SIGINT/SIGTERM.
    """
    argv = gateway_helper.build_helper_argv(
        "run",
        server=server,
        config_dir=config_dir,
        insecure_dev=insecure_dev,
        verbose=verbose,
    )
    _run_helper(argv, ctx)


@click.command("show")
@click.option(
    "--config-dir",
    default=None,
    metavar="DIR",
    help="Agent state directory (default: ${XDG_CONFIG_HOME:-$HOME/.config}/pocketshell-link).",
)
@click.pass_context
def show(ctx: click.Context, config_dir: Optional[str]) -> None:
    """Print the enrolled configuration (no secrets).

    Reports the gateway URL, device ID, local SSH endpoint, device key
    fingerprint, and the pinned sshd host key.
    """
    argv = gateway_helper.build_helper_argv("show", config_dir=config_dir)
    _run_helper(argv, ctx)


gateway_group.add_command(enroll)
gateway_group.add_command(run)
gateway_group.add_command(show)
