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

from pocketshell.gateway import client_cli as gateway_client_cli
from pocketshell.gateway import endpoint as gateway_endpoint
from pocketshell.gateway import helper as gateway_helper
from pocketshell.gateway import service as gateway_service
from pocketshell.gateway import tokens as gateway_tokens

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


class _EnrollNotLoggedIn(click.ClickException):
    exit_code = 3


def _enroll_token_provider():
    # Looked up at call time so the account layer stays a lazy import.
    return gateway_tokens.default_token_provider()


def _preflight_auto_mint(
    dev_broker_issuer: Optional[str],
    insecure_dev: bool,
    server: Optional[str],
    trust_gateway: Optional[str],
) -> None:
    """Gate minting a token from the `pocketshell login` session.

    A login-minted token is a real production broker JWT, so it may only
    go to the production gateway or to a host the user explicitly vouched
    for with ``--trust-gateway`` — and through the same strict URL rules
    as the client commands (cleartext only to loopback). Lab tokens for a
    ``--dev-broker-issuer`` never come from the login session.
    """
    if dev_broker_issuer is not None:
        raise click.UsageError(
            "--dev-broker-issuer needs a lab token piped with --token-stdin; "
            "the `pocketshell login` session only mints production tokens."
        )
    try:
        gateway_endpoint.resolve_endpoint(server, insecure_dev, trust_gateway)
    except gateway_endpoint.EndpointError as exc:
        raise click.UsageError(
            f"{exc}. (Without --token-stdin, enroll mints a token from your "
            "`pocketshell login` session and sends it to this gateway.)"
        ) from None


def _verified_helper(ctx: click.Context) -> str:
    try:
        binary = gateway_helper.resolve_helper()
        gateway_helper.verify_helper(binary)
    except gateway_helper.HelperNotFoundError as exc:
        click.echo(f"error: {exc}", err=True)
        ctx.exit(127)
    except gateway_helper.HelperIncompatibleError as exc:
        click.echo(f"error: {exc}", err=True)
        ctx.exit(126)
    return binary


def _run_helper(argv: Sequence[str], ctx: click.Context) -> None:
    """Resolve + protocol-verify the Go helper, then exec it.

    Two refusal surfaces before anything real runs: an unresolvable helper
    exits **127** (existing contract), and a resolved helper that fails
    the bounded ``version --json`` protocol gate exits **126** with a
    concise compatibility error — never the helper's own output, never a
    traceback (see :mod:`pocketshell.gateway.helper`).
    """
    binary = _verified_helper(ctx)
    gateway_helper.exec_helper(binary, list(argv))


@click.group(
    name="gateway",
    context_settings={"help_option_names": ["-h", "--help"]},
    help=(
        "Gateway host agent: enroll this host and hold the reverse tunnel "
        "to the SSH gateway (hosts without inbound SSH).\n\n"
        "Durable start on this host: `service install|status|uninstall` "
        "(systemd --user unit on Linux, a hidden per-user scheduled task on "
        "Windows).\n\n"
        "Client side (on the machine you connect from): `devices`, `pin`, "
        "`unpin`, `ssh` (and `proxy`, its ProxyCommand) reach an enrolled "
        "host with OpenSSH after `pocketshell login`.\n\n"
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
        "Read the gateway enrollment token from stdin instead of minting "
        "one from your `pocketshell login` session: a short-lived "
        "(<= 5 minutes) token scoped to pocketshell-gateway, generated by "
        "the trusted enrollment service — never an account credential, "
        "and never accepted as a CLI flag (that would leak through shell "
        "history and process listings)."
    ),
)
@click.option(
    "--trust-gateway",
    default=None,
    metavar="HOST",
    help=(
        "Without --token-stdin and with a non-production --server: the "
        "exact gateway host you trust with a token minted from your login."
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
    trust_gateway: Optional[str],
) -> None:
    """Generate the device key, pin the local sshd host key, enroll.

    Logged in with `pocketshell login`? Just run

        pocketshell gateway enroll

    and a gateway enrollment token is minted from your session and handed
    to the helper on a private stdin pipe (never argv/env/file). Otherwise
    pipe a token in (`--token-stdin`):

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
    _preflight_dev_broker_issuer(dev_broker_issuer, insecure_dev, server)
    if not token_stdin:
        _preflight_auto_mint(dev_broker_issuer, insecure_dev, server, trust_gateway)
    argv = gateway_helper.build_helper_argv(
        "enroll",
        server=server,
        config_dir=config_dir,
        insecure_dev=insecure_dev,
        verbose=verbose,
        # the helper always reads the token from stdin: piped by the user,
        # or minted here and handed over through a private pipe
        token_stdin=True,
        device_id=device_id,
        ssh_host=ssh_host,
        expect_host_key=expect_host_key,
        dev_broker_issuer=dev_broker_issuer,
        re_enroll=re_enroll,
    )
    if token_stdin:
        _run_helper(argv, ctx)
        return
    # Logged-in path. Order matters: the helper is resolved and
    # protocol-verified BEFORE a token exists, the token is minted last,
    # then handed over on a pipe as the helper's whole stdin.
    binary = _verified_helper(ctx)
    try:
        token = gateway_tokens.obtain_token(_enroll_token_provider)
    except gateway_tokens.NotLoggedInError as exc:
        raise _EnrollNotLoggedIn(
            f"{str(exc).rstrip('.')}. Or pipe a gateway enrollment token instead: "
            "pocketshell gateway enroll --token-stdin < enrollment-token.txt"
        ) from None
    except gateway_tokens.GatewayTokenError as exc:
        raise click.ClickException(str(exc)) from None
    try:
        gateway_helper.exec_helper_with_stdin_token(binary, argv, token)
    except ValueError as exc:
        raise click.ClickException(str(exc)) from None


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


SHOW_TIMEOUT_SECONDS = 10.0
SHOW_MAX_OUTPUT_BYTES = 65536


def _print_host_key(ctx: click.Context, config_dir: Optional[str]) -> None:
    """``show --host-key``: print ONLY the pinned sshd host-key line.

    Runs the verified helper's ``show`` as a bounded subprocess (stdin
    detached), extracts the ``pinned ssh host key:`` value and re-validates
    it with the client's strict pin parser. stdout gets exactly one
    ``<keytype> <base64>`` line — never a shell command — so a client
    can paste it at the `pocketshell gateway pin <device-id>` prompt.
    """
    import subprocess

    from pocketshell.gateway import pins as gateway_pins

    binary = _verified_helper(ctx)
    argv = [binary, *gateway_helper.build_helper_argv("show", config_dir=config_dir)]
    try:
        proc = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            timeout=SHOW_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        click.echo("error: the gateway helper's `show` timed out", err=True)
        ctx.exit(1)
    if proc.returncode != 0:
        ctx.exit(proc.returncode)
    out = proc.stdout[:SHOW_MAX_OUTPUT_BYTES].decode("utf-8", "replace")
    fields = {}
    for line in out.splitlines():
        name, sep, value = line.partition(":")
        if sep:
            fields[name.strip()] = value.strip()
    try:
        key = gateway_pins.parse_host_key(fields.get("pinned ssh host key", ""))
    except gateway_pins.PinError as exc:
        raise click.ClickException(
            f"the enrolled state has no usable pinned host key ({exc}); "
            "re-run `pocketshell gateway enroll`"
        ) from None
    device_id = fields.get("device id", "")
    click.echo(key.line)
    if gateway_endpoint.DEVICE_ID_RE.match(device_id):
        click.echo(
            f"device {device_id}, host key {key.fingerprint} ({key.label}).\n"
            f"On the client run `pocketshell gateway pin {device_id}` and paste "
            "the key line above at its prompt.",
            err=True,
        )


@click.command("show")
@click.option(
    "--config-dir",
    default=None,
    metavar="DIR",
    help="Agent state directory (default: ${XDG_CONFIG_HOME:-$HOME/.config}/pocketshell-link).",
)
@click.option(
    "--host-key",
    "host_key",
    is_flag=True,
    help=(
        "Print only the pinned sshd host-key line, to paste at the "
        "client's `pocketshell gateway pin DEVICE_ID` prompt."
    ),
)
@click.pass_context
def show(ctx: click.Context, config_dir: Optional[str], host_key: bool) -> None:
    """Print the enrolled configuration (no secrets).

    Reports the gateway URL, device ID, local SSH endpoint, device key
    fingerprint, and the pinned sshd host key. With `--host-key`, prints
    just the host-key line a client pins with `pocketshell gateway pin`.
    """
    if host_key:
        _print_host_key(ctx, config_dir)
        return
    argv = gateway_helper.build_helper_argv("show", config_dir=config_dir)
    _run_helper(argv, ctx)


gateway_group.add_command(enroll)
gateway_group.add_command(run)
gateway_group.add_command(show)
gateway_group.add_command(gateway_service.service_group)

for _client_command in gateway_client_cli.CLIENT_COMMANDS:
    gateway_group.add_command(_client_command)


# --- `gateway agent`: the ordinary-user Windows runtime (API v1) -----------------------

from pocketshell.gateway import service_user_agent as _agent  # noqa: E402

_OPERATION_ID = click.option(
    "--operation-id", default=None, metavar="ID",
    help="Caller's operation id (1-64 of A-Z a-z 0-9 . _ -), echoed in the JSON.",
)
_JSON = click.option("--json", "as_json", is_flag=True, help="Print the versioned JSON document (API v1).")


def _check_operation_id(value):
    if value is not None and not _agent.OPERATION_ID_RE.fullmatch(value):
        raise click.UsageError("--operation-id must be 1-64 of A-Z a-z 0-9 . _ -")


def _timeout(value, default):
    if value is None:
        return default
    if not 0 < value <= _agent.MAX_TIMEOUT:
        raise click.UsageError(f"--timeout must be in (0, {_agent.MAX_TIMEOUT:g}] seconds")
    return value


def _emit(doc, code, as_json):
    import json as _json

    if as_json:
        click.echo(_json.dumps(doc, indent=1, sort_keys=False))
    else:
        line = f"{doc['state']}"
        if doc.get("error"):
            line += f": {doc['error']['code']}: {doc['error']['message']}"
        click.echo(line)
    raise SystemExit(code)


def _api_runner():
    from pocketshell.gateway import service_windows as win

    return win.WindowsApi(), None


@click.group(
    name="agent",
    context_settings={"help_option_names": ["-h", "--help"]},
    help=(
        "Ordinary-user runtime (Windows): the enrolled endpoint (guardian + daemon) and the "
        "outbound link in YOUR session, no elevation, no scheduled task. Called by the "
        "Desktop app at sign-in; see the API v1 agreement. Exit: 0 ready/done, 1 error, "
        "2 usage, 3 not ready, 4 stopped, 5 start deadline."
    ),
)
def agent_group() -> None:
    """Ordinary-user background runtime (API v1)."""


@agent_group.command("bind")
@click.option("--manifest", required=True, metavar="PATH", help="Protected guardian manifest (reviewed).")
@click.option("--config-dir", required=True, metavar="DIR", help="Enrolled helper config dir.")
@click.option("--helper", default=None, metavar="PATH", help="Reviewed pocketshell-link.exe.")
@_JSON
@_OPERATION_ID
def agent_bind(manifest, config_dir, helper, as_json, operation_id):
    """Validate and record the protected binding (once, from the owner's setup)."""
    _check_operation_id(operation_id)
    api, runner = _api_runner()
    _emit(*_agent.bind_command(manifest, config_dir, helper, api=api, runner=runner,
                               operation_id=operation_id), as_json)


@agent_group.command("status")
@_JSON
@_OPERATION_ID
def agent_status(as_json, operation_id):
    """Readiness of the endpoint and the outbound link (exit 0 ready, 3 not, 4 stopped)."""
    _check_operation_id(operation_id)
    api, runner = _api_runner()
    _emit(*_agent.status(api=api, runner=runner, operation_id=operation_id), as_json)


@agent_group.command("start")
@click.option("--timeout", type=float, default=None, help="Readiness deadline in seconds (default 60).")
@_JSON
@_OPERATION_ID
def agent_start(timeout, as_json, operation_id):
    """Start (idempotent) and wait until ready or the deadline (exit 0 / 5)."""
    _check_operation_id(operation_id)
    api, runner = _api_runner()
    _emit(*_agent.start(api=api, runner=runner, timeout=_timeout(timeout, _agent.DEFAULT_START_TIMEOUT),
                        operation_id=operation_id), as_json)


@agent_group.command("stop")
@click.option("--timeout", type=float, default=None, help="STOP acknowledgement deadline (default 45).")
@_JSON
@_OPERATION_ID
def agent_stop(timeout, as_json, operation_id):
    """Guardian STOP protocol + exact link identity (exit 0 stopped, 1 failed)."""
    _check_operation_id(operation_id)
    api, runner = _api_runner()
    _emit(*_agent.stop(api=api, runner=runner, timeout=_timeout(timeout, _agent.DEFAULT_STOP_TIMEOUT),
                       operation_id=operation_id), as_json)


def _emit_raw(doc, code):
    import json as _json

    click.echo(_json.dumps(doc, indent=1, sort_keys=False))
    raise SystemExit(code)


@agent_group.command("install")
@click.option("--user-data", required=True, metavar="DIR", help="The Desktop app's userData directory.")
@click.option("--catalog", required=True, metavar="PATH", help="resources/host-runtime-catalog.json (v2).")
@click.option("--staged", required=True, metavar="DIR", help="The staged release closure to install.")
@click.option("--dry-run", is_flag=True, help="Verify and print the receipt; write nothing.")
@_JSON
@_OPERATION_ID
def agent_install(user_data, catalog, staged, dry_run, as_json, operation_id):
    """Install the catalogued ordinary-v2 runtime and write authority.json (PROPOSED v3)."""
    _check_operation_id(operation_id)
    api, runner = _api_runner()
    _emit_raw(*_agent.install_command(user_data=user_data, catalog=catalog, staged=staged, dry_run=dry_run,
                                      api=api, runner=runner, operation_id=operation_id))


@agent_group.command("verify-paths")
@click.option("--owner-sid", required=True, metavar="SID", help="The expected owner (the current user).")
@click.option("--file", "files", multiple=True, metavar="PATH", help="Private file: owner-only, by handle.")
@click.option("--anchored-file", "anchored", multiple=True, metavar="PATH",
              help="Digest-anchored file (no ACL shape required; reparse-free, by handle).")
@click.option("--directory", "directories", multiple=True, metavar="DIR", help="Private directory.")
@click.option("--inventory", "inventories", multiple=True, metavar="DIR", help="List a private tree.")
@click.option("--max-bytes", type=int, default=1048576, help="Return bytes for files up to this size.")
@_JSON
def agent_verify_paths(owner_sid, files, anchored, directories, inventories, max_bytes, as_json):
    """Trusted native path verifier for the Desktop app (exit 0 all ok, 1 refusal)."""
    api, _runner = _api_runner()
    _emit_raw(*_agent.verify_paths_command(owner_sid=owner_sid, files=files, anchored=anchored,
                                           directories=directories, inventories=inventories,
                                           max_bytes=max_bytes, api=api))


gateway_group.add_command(agent_group)
