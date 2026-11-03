"""The display-only `pocketshell usage` Click command.

Daemon mode (issue #219): when the IPC daemon is running, ``pocketshell
usage --json`` sends a ``usage.fetch`` JSON-RPC request to
``$XDG_RUNTIME_DIR/pocketshell/daemon.sock`` instead of forking ``quse``
itself. The daemon caches the ALREADY-FLATTENED NDJSON for 30 s, so a polled
usage row in the Android app returns the second-and-later calls in
microseconds. The daemon performs the flatten before caching; the CLI proxies
the daemon's NDJSON verbatim (it is NOT re-flattened — that would fail,
NDJSON is not a provider-keyed object).

The fall-through is intentional and matches the spike's Q6 parity rule:

- ``--no-daemon`` forces the one-shot subprocess path even when a
  daemon is up (debugging / belt-and-braces).
- ``--no-cache`` is honoured by the daemon (cache miss + populate)
  but is intentionally a no-op on the subprocess path: there is no
  cache to bypass when every call is a fresh subprocess.
- The probe falls through only for an absent/unavailable daemon or an
  explicitly supported method/version skew. A transport timeout,
  malformed response, or daemon-internal error is classified and surfaced;
  it never silently runs a second copy of the operation.

"""

from __future__ import annotations

import sys
from typing import Any, Optional

import click

from pocketshell.usage.quse import (
    _run_quse,
    _run_quse_json,
)


def _try_daemon_usage_fetch(
    provider: Optional[str],
    *,
    no_cache: bool,
) -> Optional[dict[str, Any]]:
    """Probe the daemon and dispatch ``usage.fetch`` through typed fallback.

    Returns the JSON-RPC ``result`` envelope (``stdout``/``stderr``/
    ``returncode``) on success, or ``None`` when the daemon is
    absent/unavailable or explicitly supports a skewed method and the caller
    should fall through to the one-shot subprocess path. The envelope's
    ``stdout`` is ALREADY-FLATTENED per-provider NDJSON (the daemon flattens
    before caching), so callers proxy it verbatim — they must NOT re-flatten.
    """
    from pocketshell import daemon as _daemon

    socket_path = _daemon.resolve_socket_path()
    params: dict[str, Any] = {}
    if provider is not None:
        params["provider"] = provider
    if no_cache:
        params["no_cache"] = True

    return _daemon.try_call(
        "usage.fetch",
        params=params,
        socket_path=socket_path,
        timeout=5.0,
        result_validator=_daemon.is_command_envelope,
    )


def _proxy_daemon_envelope(envelope: dict[str, Any]) -> int:
    """Write an already-flattened daemon envelope verbatim; return its code.

    The daemon already flattened quse's document into NDJSON before caching;
    proxy it verbatim (re-flattening NDJSON would raise).
    """
    if envelope.get("stdout"):
        sys.stdout.write(str(envelope["stdout"]))
    if envelope.get("stderr"):
        sys.stderr.write(envelope["stderr"])
    return int(envelope.get("returncode", 0))


def _run_fallback(provider: Optional[str], *, json_output: bool) -> int:
    """Run the one-shot bundled quse subprocess; return its exit code."""
    args: list[str] = []
    if provider:
        args.append(provider)
    if json_output:
        args.append("--json")
        return _run_quse_json(args)
    return _run_quse(args)


def _daemon_usage_exit(
    ctx: click.Context,
    provider: Optional[str],
    *,
    json_output: bool,
    no_daemon: bool,
    no_cache: bool,
) -> bool:
    """Proxy the fetch through the daemon; ``True`` when fully handled.

    JSON output is the format the daemon caches against (per-provider NDJSON
    already flattened by the daemon). Human-readable output is rare and not
    on the Android hot path, so it does not get the daemon speed-up —
    falling through to subprocess is simpler than teaching the daemon to
    render two formats.
    """
    if not json_output or no_daemon:
        return False
    envelope = _try_daemon_usage_fetch(provider, no_cache=no_cache)
    if envelope is None:
        return False
    exit_code = _proxy_daemon_envelope(envelope)
    if exit_code != 0:
        ctx.exit(exit_code)
    return True


@click.command(
    context_settings={"help_option_names": ["-h", "--help"], "ignore_unknown_options": True},
)
@click.argument("provider", required=False)
@click.option(
    "--json",
    "json_output",
    is_flag=True,
    help="Emit machine-readable per-provider NDJSON (flattened from `quse --json`).",
)
@click.option(
    "--no-daemon",
    "no_daemon",
    is_flag=True,
    help=(
        "Skip the IPC daemon and run `quse` as a one-shot subprocess "
        "even if a daemon is available. Useful for debugging."
    ),
)
@click.option(
    "--no-cache",
    "no_cache",
    is_flag=True,
    help=(
        "Bypass the daemon's per-method cache (30 s for `usage.fetch`). "
        "No effect on the one-shot subprocess path, which always runs fresh."
    ),
)
@click.pass_context
def usage_command(
    ctx: click.Context,
    provider: Optional[str] = None,
    json_output: bool = False,
    no_daemon: bool = False,
    no_cache: bool = False,
) -> None:
    """Report quota / usage for coding-agent providers on this host.

    Probes the IPC daemon's socket first, falling through to the bundled
    ``quse`` one-shot. JSON output is FLATTENED into per-provider NDJSON
    (quse owns the schema).
    """
    if _daemon_usage_exit(
        ctx, provider,
        json_output=json_output, no_daemon=no_daemon, no_cache=no_cache,
    ):
        return
    exit_code = _run_fallback(provider, json_output=json_output)
    if exit_code != 0:
        ctx.exit(exit_code)
