"""The `pocketshell usage` Click command: daemon proxy, special modes, CLI.

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

``--capture`` / ``--cached`` / ``--reset-events`` bypass the stdout-proxy
path entirely: they persist or emit the cached latest reading and the
recorded reset events (see :mod:`pocketshell.usage.capture` and
:mod:`pocketshell.usage.reset`).
"""

from __future__ import annotations

import json
import sys
from typing import Any, Optional

import click

from pocketshell.usage.quse import (
    _capture_via_quse,
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


def _handle_special_modes(
    provider: Optional[str],
    *,
    no_daemon: bool,
    capture: bool,
    cached: bool,
    reset_events: bool,
) -> Optional[int]:
    """Run --reset-events/--cached/--capture; ``None`` when none applies.

    These emit the last captured reading instantly or persist a fresh one,
    bypassing the normal stdout-proxy path below.
    """
    if reset_events:
        return _emit_reset_events()
    if cached:
        return _emit_cached_usage()
    if capture:
        return _capture_usage(provider, no_daemon=no_daemon)
    return None


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


def _exit_special(ctx: click.Context, special: Optional[int]) -> bool:
    """Handle a special-mode result; ``True`` when the command is done.

    Click ignores a callback's return value, so a non-zero code must be
    raised explicitly through ``ctx.exit`` for ``main()`` (and the OS) to
    see it. ``0`` means handled-successfully (return, don't fall through).
    """
    if special is None:
        return False
    if special != 0:
        ctx.exit(special)
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
@click.option(
    "--capture",
    "capture",
    is_flag=True,
    help=(
        "Fetch usage live, write the cached latest reading + append to the "
        "history log under $XDG_STATE_HOME/pocketshell/usage/, then exit. "
        "Run this on a schedule (cron / systemd timer). Implies --json."
    ),
)
@click.option(
    "--cached",
    "cached",
    is_flag=True,
    help=(
        "Emit the last captured reading instantly (no live fetch) as a JSON "
        "document {captured_at, records} for the app's stale-while-revalidate "
        "render. Exits non-zero if no capture exists yet. Implies --json."
    ),
)
@click.option(
    "--reset-events",
    "reset_events",
    is_flag=True,
    help=(
        "Emit the recorded limit/session reset events (#690) as a JSON "
        "document {reset_events: [...]} from the history log. The app reads "
        "this to surface 'limits reset at <time>' on next open. Emits an "
        "empty list when no resets have been detected yet. Implies --json."
    ),
)
@click.pass_context
def usage_command(
    ctx: click.Context,
    provider: Optional[str] = None,
    json_output: bool = False,
    no_daemon: bool = False,
    no_cache: bool = False,
    capture: bool = False,
    cached: bool = False,
    reset_events: bool = False,
) -> None:
    """Report quota / usage for coding-agent providers on this host.

    Probes the IPC daemon's socket first, falling through to the bundled
    ``quse`` one-shot. JSON output is FLATTENED into per-provider NDJSON
    (quse owns the schema); ``--capture``/``--cached`` add the SWR cache.
    """
    special = _handle_special_modes(
        provider,
        no_daemon=no_daemon, capture=capture, cached=cached, reset_events=reset_events,
    )
    if _exit_special(ctx, special):
        return
    if _daemon_usage_exit(
        ctx, provider,
        json_output=json_output, no_daemon=no_daemon, no_cache=no_cache,
    ):
        return
    exit_code = _run_fallback(provider, json_output=json_output)
    if exit_code != 0:
        ctx.exit(exit_code)


def _fetch_usage_ndjson(
    provider: Optional[str],
    *,
    no_daemon: bool,
) -> tuple[Optional[str], str, int]:
    """Fetch live usage NDJSON for the cache capture.

    Returns ``(stdout, stderr, returncode)`` where ``stdout`` is the flattened
    per-provider NDJSON (or ``None`` when the bundled ``quse`` is missing).
    Mirrors the command's own daemon-then-subprocess fall-through so a
    scheduled ``--capture`` benefits from the daemon cache when one is live.
    """
    if not no_daemon:
        envelope = _try_daemon_usage_fetch(provider, no_cache=False)
        if envelope is not None:
            # Daemon envelope stdout is already-flattened NDJSON — use as-is.
            stdout = str(envelope.get("stdout") or "")
            stderr = str(envelope.get("stderr") or "")
            return stdout, stderr, int(envelope.get("returncode", 0))
    return _capture_via_quse(provider)


def _capture_usage(provider: Optional[str], *, no_daemon: bool) -> int:
    """Fetch usage live and persist the cache + history log, then report.

    Designed to run on a schedule. On a successful fetch it writes
    ``usage-latest.json`` and appends to ``usage-history.jsonl`` under
    ``$XDG_STATE_HOME/pocketshell/usage/`` and echoes the cache object so a
    cron/systemd log shows what landed. A failed fetch is NOT cached so a
    transient provider hiccup never pins a bad reading.
    """
    from pocketshell.usage import capture as _capture

    stdout, stderr, returncode = _fetch_usage_ndjson(provider, no_daemon=no_daemon)
    if returncode != 0 or stdout is None:
        if stderr:
            sys.stderr.write(stderr)
        return returncode if returncode != 0 else 1

    cache_obj = _capture.write_capture(stdout)
    sys.stdout.write(json.dumps(cache_obj, sort_keys=True) + "\n")
    return 0


def _emit_cached_usage() -> int:
    """Emit the last captured reading as a JSON document, or exit non-zero.

    Returns exit code 0 when a cache exists (its JSON document is written to
    stdout), or 3 with a friendly stderr note when no capture has run yet so
    the app can fall back to a pure live fetch.
    """
    from pocketshell.usage import capture as _capture

    document = _capture.cached_document()
    if document is None:
        sys.stderr.write(
            "pocketshell: no captured usage yet. "
            "Run `pocketshell usage --capture` (or wait for the scheduled "
            "capture) to populate the cache.\n"
        )
        return 3
    sys.stdout.write(document)
    return 0


def _emit_reset_events() -> int:
    """Emit recorded reset events (#690) as a JSON document.

    Always exits 0: the document is ``{"reset_events": [...]}`` (empty list
    when no resets have been detected/logged yet), so the app can read it
    unconditionally and surface "limits reset at <time>" when present.
    """
    from pocketshell.usage import reset as _reset

    sys.stdout.write(_reset.reset_events_document())
    return 0
