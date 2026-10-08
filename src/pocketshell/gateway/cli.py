"""Click surface for the gateway host agent: ``pocketshell gateway …``.

``enroll`` / ``run`` / ``show`` wrap the installed Go helper
`pocketshell-link` (pocketshell-gateway repo); :mod:`pocketshell.gateway.helper`
owns resolution and the exec boundary. This is the reverse-tunnel transport
for hosts without inbound SSH and is **not** interoperable with the legacy
shared-token ``pocketshell link`` / ``pocketshell relay`` commands — those
keep their own protocol and CLI untouched.
"""

from __future__ import annotations

from typing import Optional, Sequence

import click

from pocketshell.gateway import endpoint as gateway_endpoint
from pocketshell.gateway import helper as gateway_helper

# The wrapper refuses to aim the DEV-ONLY `--dev-broker-issuer` override at
# the production gateway, whatever the URL spelling. The host set and the
# DNS-style comparison live in :mod:`pocketshell.gateway.endpoint`, shared
# with the client commands' `--insecure-dev` rules. This is a target check
# for known-bad hosts, not URL validation: the helper owns that.
_PRODUCTION_GATEWAY_HOSTS = gateway_endpoint.PRODUCTION_GATEWAY_HOSTS


def _canonical_gateway_host(server: str) -> str:
    """Canonicalize the ``--server`` host for the production-target check.

    Comparison-only canonicalization: the server URL itself is still
    forwarded verbatim. A URL urllib cannot parse at all (unbalanced
    brackets, malformed IPv6 literal) raises :class:`click.UsageError`
    here rather than a traceback later — the wrapper refuses to forward a
    ``--server`` it could not check.
    """
    try:
        return gateway_endpoint.canonical_host(server)
    except gateway_endpoint.EndpointError as exc:
        raise click.UsageError(
            f"{exc}; point it at your lab gateway instead."
        ) from exc


def _preflight_dev_broker_issuer(
    dev_broker_issuer: Optional[str], insecure_dev: bool, server: Optional[str]
) -> None:
    """Guard the DEV-ONLY `--dev-broker-issuer` override before any exec.

    Mirrors the helper's own guard (``brokerPolicy`` in the Go hostagent
    refuses the issuer override without ``--insecure-dev``) and tightens the
    lab posture: an explicit ``--server`` naming a non-production gateway is
    also required, so lab-issuer credentials can never flow to the built-in
    production default.
    """
    if dev_broker_issuer is None:
        return
    problems = []
    if not insecure_dev:
        problems.append(
            "--dev-broker-issuer is a DEV-ONLY override and requires "
            "--insecure-dev (the helper refuses it in normal mode)."
        )
    # A blank --server is not an explicit one: the Go helper's ResolveServer
    # treats "" as unset and defaults to the production gateway, so
    # forwarding `--server ''` would silently aim a lab issuer at
    # production. Only None (flag absent) and non-blank values are distinct
    # here; blank and whitespace-only both refuse.
    if server is None or not server.strip():
        problems.append(
            "--dev-broker-issuer requires an explicit non-blank --server "
            "naming your lab gateway; without it (or with a blank one) the "
            "helper would target its built-in production default."
        )
    else:
        host = _canonical_gateway_host(server)
        if host in _PRODUCTION_GATEWAY_HOSTS:
            problems.append(
                f"--dev-broker-issuer must not target the production gateway "
                f"({host}); point --server at your lab gateway instead."
            )
    if problems:
        raise click.UsageError(" ".join(problems))


def _run_helper(argv: Sequence[str], ctx: click.Context) -> None:
    """Resolve + protocol-verify the Go helper, then exec it.

    Two refusal surfaces before anything real runs: an unresolvable helper
    exits **127** (existing contract), and a resolved helper that fails
    the bounded ``version --json`` protocol gate exits **126** with a
    concise compatibility error — never the helper's own output, never a
    traceback (see :mod:`pocketshell.gateway.helper`).
    """
    try:
        binary = gateway_helper.resolve_helper()
        gateway_helper.verify_helper(binary)
    except gateway_helper.HelperNotFoundError as exc:
        click.echo(f"error: {exc}", err=True)
        ctx.exit(127)
    except gateway_helper.HelperIncompatibleError as exc:
        click.echo(f"error: {exc}", err=True)
        ctx.exit(126)
    gateway_helper.exec_helper(binary, list(argv))


@click.group(
    name="gateway",
    context_settings={"help_option_names": ["-h", "--help"]},
    help=(
        "Gateway host agent: enroll this host and hold the reverse tunnel "
        "to the SSH gateway (hosts without inbound SSH).\n\n"
        "Wraps the Go `pocketshell-link` helper, which must be installed "
        "separately (build it from the private pocketshell-gateway repo, "
        "https://github.com/PocketShell-io/pocketshell-gateway). "
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
        "Read the gateway enrollment token from stdin (required): a "
        "short-lived (≤ 5 minutes) token scoped to pocketshell-gateway, "
        "generated by the trusted enrollment service — never an account "
        "credential, and never accepted as a CLI flag (that would leak "
        "through shell history and process listings)."
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
@click.option(
    "--re-enroll",
    is_flag=True,
    help=(
        "Request explicit replacement of an existing registration (the "
        "gateway may have re-enrollment disabled). Without this flag the "
        "helper refuses to re-enroll an already-registered device."
    ),
)
@click.option(
    "--dev-broker-issuer",
    default=None,
    metavar="ISSUER",
    help=(
        "DEV ONLY: issuer of the ephemeral broker tokens your LOCAL lab "
        "mints (e.g. a docker-compose broker). Requires --insecure-dev and "
        "an explicit --server naming the lab gateway; the helper refuses "
        "every other issuer, and production enrollment never passes this. "
        "Never points at the production gateway (gateway.pocketshell.io or "
        "its relay.pocketshell.io alias, whatever the URL spelling)."
    ),
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
    re_enroll: bool,
    dev_broker_issuer: Optional[str],
    verbose: bool,
) -> None:
    """Generate the device key, pin the local sshd host key, enroll.

    The gateway enrollment token arrives on stdin (`--token-stdin`):

        pocketshell gateway enroll --token-stdin < enrollment-token.txt

    The token is minted by the trusted PocketShell enrollment service (the
    web client's "Generate enrollment token" action): it is an RS256 JWT
    scoped to pocketshell-gateway and lives at most 5 minutes. Your account
    sign-in credential itself never reaches the gateway — only this scoped
    token does, and only in the Authorization header (never in a URL,
    argv, or log line). This wrapper passes stdin through opaquely; it never
    exchanges or inspects the token.

    On success the host key of the local sshd is pinned in the config dir;
    `gateway show` prints the enrolled state. Re-enrolling an
    already-enrolled host needs `--re-enroll`.

    Against a local/Docker lab gateway, see docs/gateway.md §6: the lab's
    ephemeral broker tokens are only accepted when their issuer is passed
    explicitly via `--dev-broker-issuer` together with `--insecure-dev` and
    an explicit lab `--server`.
    """
    if not token_stdin:
        raise click.UsageError(
            "enroll requires --token-stdin: pipe a gateway enrollment token "
            "generated by the PocketShell enrollment service (web client → "
            "Gateway settings → Generate enrollment token). The token is "
            "short-lived; run enroll right after generating it. There is "
            "deliberately no token CLI flag (history/process-listing leak)."
        )
    _preflight_dev_broker_issuer(dev_broker_issuer, insecure_dev, server)
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
        dev_broker_issuer=dev_broker_issuer,
        re_enroll=re_enroll,
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
