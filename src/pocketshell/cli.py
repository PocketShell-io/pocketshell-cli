"""Top-level Click dispatcher for the unified `pocketshell` CLI.

Skeleton landed in the first PR of issue
[#170](https://github.com/alexeygrigorev/pocketshell/issues/170). Follow-up
PRs add subgroups: `sessions` (#218),
`agent-log` (#217), `daemon` (#219), and `repos` (#220).
The foreground static server is `serve` (#2333).

Per the D22 locked principle (no backwards compatibility, hard cuts only)
the PocketShell Android app probes for this single binary instead of
`quse`: usage runs `pocketshell usage --json` (#231).
The cutover is complete; the app no longer probes the old binaries.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional, Sequence

import click

from pocketshell import __version__
from pocketshell.account.cli import login_command, logout_command, whoami_command
from pocketshell.gateway import gateway_group

if os.name != "nt":
    from pocketshell.agents.conversations.cli import agent_log_command
    from pocketshell.cards import register_push_card_commands
    from pocketshell.agents import agents_group
    from pocketshell.agents.launch.cli import agent_group
    from pocketshell.env import env_group
    from pocketshell.engines import engines_group
    from pocketshell.github import github_group
    from pocketshell.hooks import hooks_group
    from pocketshell.link.cli import link_group, relay_group
    from pocketshell.logs import logs_group
    from pocketshell.profiles import profiles_group
    from pocketshell.attachments import prune_attachments_command
    from pocketshell.push import push_group
    from pocketshell.repos import repos_group
    from pocketshell.sessions import sessions_group
    from pocketshell.serve import serve_command
    from pocketshell.tree import tree_group
    from pocketshell.tree.workspaces.cli import workspaces_group
    from pocketshell.usage import usage_command



@click.group(
    context_settings={"help_option_names": ["-h", "--help"]},
    help=(
        "Unified server-side helper for the PocketShell Android and desktop clients.\n\n"
        "Subcommands replace the separately-installed `quse` CLI. Today "
        "`usage`, `sessions`, "
        "`agent-log`, `repos`, `github`, `daemon`, and `serve` are wired "
        "up; more subcommands will land in follow-up rounds."
    ),
)
@click.version_option(__version__, "-V", "--version", prog_name="pocketshell")
def cli() -> None:
    """Top-level group. Each subcommand is registered below."""


if os.name != "nt":
    cli.add_command(usage_command, name="usage")
    cli.add_command(agent_group, name="agent")
    cli.add_command(agents_group, name="agents")
    cli.add_command(profiles_group, name="profiles")
    cli.add_command(engines_group, name="engines")
    cli.add_command(sessions_group, name="sessions")
    cli.add_command(tree_group, name="tree")
    cli.add_command(agent_log_command, name="agent-log")
    cli.add_command(repos_group, name="repos")
    cli.add_command(github_group, name="github")
    cli.add_command(env_group, name="env")
    cli.add_command(hooks_group, name="hooks")
    cli.add_command(logs_group, name="logs")
    cli.add_command(prune_attachments_command, name="prune-attachments")
    cli.add_command(push_group, name="push")
    # Generic typed-card feed verbs (epic #859) extend the same `push` group:
    # `push checklist|get|status|check`. Additive — the FCM `push` group stays the
    # single owner of the group object (see pocketshell.cards).
    register_push_card_commands(push_group)
    cli.add_command(serve_command, name="serve")
    cli.add_command(link_group, name="link")
    cli.add_command(relay_group, name="relay")
    # `gateway` wraps the Go `pocketshell-link` host agent (reverse-tunnel
    # transport, per-device enrolled keys). Deliberately separate from the
    # legacy shared-token `link`/`relay` commands above — the two protocols
    # are not interoperable and must not be cross-routed.
    cli.add_command(gateway_group, name="gateway")
    cli.add_command(workspaces_group, name="workspaces")
else:
    # These groups load Unix locks/PTY/daemon modules. Do not fake those APIs
    # or let their import failure disable the independent account/gateway CLI.
    def _unsupported_windows(ctx: click.Context) -> None:
        raise click.ClickException(
            f"{ctx.command.name} is not supported on Windows by this CLI; "
            "use login/logout/whoami or gateway."
        )

    for _name in (
        "usage", "agent", "agents", "profiles", "engines", "sessions", "tree",
        "agent-log", "repos", "github", "env", "hooks", "logs", "prune-attachments",
        "push", "serve", "link", "relay", "workspaces",
    ):
        cli.add_command(click.Command(
            _name, callback=click.pass_context(_unsupported_windows),
            context_settings={"ignore_unknown_options": True, "allow_extra_args": True},
        ))
    cli.add_command(gateway_group, name="gateway")

# Account device-flow login (docs/account.md). The stored CLI session only
# ever leaves this machine to mint short-lived gateway tokens.
cli.add_command(login_command, name="login")
cli.add_command(logout_command, name="logout")
cli.add_command(whoami_command, name="whoami")
# Device-password SSH key vault (docs/keys.md), used by `gateway ssh --key`.
# Imported here rather than in the import block above so this registration
# stays one self-contained hunk.
from pocketshell.keys import keys_group  # noqa: E402

cli.add_command(keys_group, name="keys")


# ---------------------------------------------------------------------------
# `pocketshell daemon` subgroup — IPC daemon lifecycle
# ---------------------------------------------------------------------------


@cli.group(
    name="daemon",
    context_settings={"help_option_names": ["-h", "--help"]},
    help=(
        "Manage the PocketShell IPC daemon (Unix-socket JSON-RPC server).\n\n"
        "The daemon is a performance optimisation: subcommands probe for it "
        "and fall through to one-shot subprocess calls when it is absent. "
        "Use `start` to launch it explicitly, `stop` to shut it down, and "
        "`status` to inspect the live socket. See issue #219."
    ),
)
def daemon_group() -> None:
    """Daemon lifecycle subgroup."""
    if os.name == "nt":
        raise click.ClickException("The Unix-socket daemon is not supported on Windows.")


def _serve_foreground(
    ctx: click.Context,
    socket_path: Path,
    idle_timeout: Optional[float],
) -> None:
    """Run the daemon in this process; propagate a non-zero exit code."""
    from pocketshell import daemon as _daemon

    exit_code = _daemon.serve_foreground(
        socket_path=socket_path,
        idle_timeout=idle_timeout,
    )
    if exit_code != 0:
        ctx.exit(exit_code)


def _spawn_and_wait(
    ctx: click.Context,
    socket_path: Path,
    idle_timeout: Optional[float],
) -> None:
    """Spawn the detached daemon and wait for its socket; exit 1 on timeout."""
    from pocketshell import daemon as _daemon

    pid = _daemon.spawn_detached(
        socket_path=socket_path,
        idle_timeout=idle_timeout,
    )
    if not _daemon.wait_until_ready(socket_path=socket_path):
        click.echo(
            f"daemon spawn ({pid}) did not become ready within 5 s",
            err=True,
        )
        ctx.exit(1)
    click.echo(f"started (pid: {pid}, socket: {socket_path})")


@daemon_group.command("start")
@click.option(
    "--foreground",
    "-f",
    is_flag=True,
    help="Run the daemon in the foreground (do not detach).",
)
@click.option(
    "--idle-timeout",
    type=float,
    default=None,
    help=(
        "Override the 120 s idle-shutdown window. Pass 0 to disable "
        "auto-shutdown (used by future systemd Type=simple mode)."
    ),
)
@click.pass_context
def daemon_start(
    ctx: click.Context,
    foreground: bool,
    idle_timeout: Optional[float],
) -> None:
    """Start the IPC daemon.

    Default behaviour spawns a detached child via the gpg-agent
    pattern (one fork + ``setsid``) and waits for the socket to come
    up before returning. ``--foreground`` skips the fork — useful for
    debugging or for a future systemd ``Type=simple`` unit.
    """
    # Lazy import to keep the CLI import cost low for callers that
    # never touch the daemon path.
    from pocketshell import daemon as _daemon

    socket_path = _daemon.resolve_socket_path()
    if _daemon.is_daemon_running(socket_path):
        click.echo(f"already running (socket: {socket_path})")
        return
    if foreground:
        _serve_foreground(ctx, socket_path, idle_timeout)
        return
    _spawn_and_wait(ctx, socket_path, idle_timeout)


@daemon_group.command("stop")
@click.pass_context
def daemon_stop(ctx: click.Context) -> None:
    """Stop the IPC daemon and clean up its socket.

    Sends SIGTERM via the PID file when available, falls back to the
    ``daemon.shutdown`` RPC method otherwise. Idempotent: exits 0 even
    when no daemon was running, matching ``systemctl stop`` semantics.
    """
    from pocketshell import daemon as _daemon

    was_running = _daemon.stop_daemon()
    if was_running:
        click.echo("stopped")
    else:
        click.echo("not running")


@daemon_group.command("status")
@click.pass_context
def daemon_status(ctx: click.Context) -> None:
    """Report daemon liveness and socket path.

    Exit code semantics mirror ``systemctl is-active``:

    - 0 -> daemon is alive and answering ``daemon.ping``
    - 3 -> daemon is NOT running (no socket or stale socket)
    """
    from pocketshell import daemon as _daemon

    socket_path = _daemon.resolve_socket_path()
    pid = _daemon.read_pid()
    if _daemon.is_daemon_running(socket_path):
        if pid is not None:
            click.echo(f"running (pid: {pid}, socket: {socket_path})")
        else:
            click.echo(f"running (socket: {socket_path})")
        return
    click.echo(f"not running (socket: {socket_path})")
    ctx.exit(3)


@daemon_group.command(
    "_serve",
    hidden=True,
    help="Internal foreground entrypoint used by `daemon start` lazy-spawn.",
)
def daemon_serve_internal() -> None:
    """Foreground serve loop invoked by :func:`pocketshell.daemon.spawn_detached`.

    Hidden because it is not part of the user-facing surface; the
    public way to launch the daemon is ``pocketshell daemon start``.
    The internal entrypoint exists so the lazy-spawn ``Popen`` has a
    stable argv that does NOT re-trigger the detach logic (which
    would fork again).
    """
    from pocketshell import daemon as _daemon

    socket_env = os.environ.get("POCKETSHELL_DAEMON_SOCKET")
    socket_path = _daemon.resolve_socket_path() if socket_env is None else Path(socket_env)
    _daemon.serve_foreground(socket_path=socket_path)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Entrypoint for both the console-script and `python -m pocketshell`.

    Returns an integer exit code rather than letting Click call
    `sys.exit` so the function is testable from the unit suite.

    Last-resort handling: Ctrl-C / :class:`click.Abort` exit 130 quietly; any
    other unexpected exception prints only its class name (a traceback could
    echo raw bytes from a broker, gateway or host — terminal escapes
    included) and exits 1. ``POCKETSHELL_DEBUG=1`` re-raises instead.
    """
    try:
        result = cli.main(args=list(argv) if argv is not None else None,
                          prog_name="pocketshell",
                          standalone_mode=False)
    except click.exceptions.Exit as exc:
        return int(exc.exit_code)
    except click.ClickException as exc:
        exc.show()
        return int(exc.exit_code)
    except (KeyboardInterrupt, click.Abort):
        return 130
    except Exception as exc:
        if os.environ.get("POCKETSHELL_DEBUG") == "1":
            raise
        sys.stderr.write(f"pocketshell: internal error ({type(exc).__name__})\n")
        return 1
    if result is None:
        return 0
    try:
        return int(result)
    except (TypeError, ValueError):
        return 0


if __name__ == "__main__":
    sys.exit(main())
