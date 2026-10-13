"""Click command line interface for `pocketshell tray`."""

from __future__ import annotations

import os
import sys
from typing import Optional

import click

from pocketshell.tray import autostart
from pocketshell.tray.single_instance import SingleInstance


def _check_dependencies() -> None:
    """Verify that optional tray dependencies are available."""
    missing = []
    try:
        import PIL  # noqa: F401
    except ImportError:
        missing.append("Pillow")

    try:
        import pystray  # noqa: F401
    except ImportError:
        missing.append("pystray")
    except Exception as exc:
        # e.g. Xlib error on headless Linux
        if sys.platform.startswith("linux") and not (
            os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")
        ):
            raise click.ClickException(
                "pocketshell tray requires an active graphical display ($DISPLAY or $WAYLAND_DISPLAY is unset)."
            ) from exc
        raise click.ClickException(f"Failed to initialize system tray backend: {exc}") from exc

    if missing:
        deps = " and ".join(missing)
        raise click.ClickException(
            f"pocketshell tray requires optional dependencies ({deps}).\n"
            "Install them with:\n"
            '  uv tool install "pocketshell[tray]"\n'
            "or:\n"
            '  pip install "pocketshell[tray]"'
        )

    if sys.platform.startswith("linux") and not (
        os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")
    ):
        raise click.ClickException(
            "pocketshell tray requires an active graphical display ($DISPLAY or $WAYLAND_DISPLAY is unset)."
        )


@click.command(
    name="tray",
    context_settings={"help_option_names": ["-h", "--help"]},
    help=(
        "PocketShell background system tray application.\n\n"
        "Displays gateway status (online, degraded, offline), active sessions, "
        "and connected clients with real-time notifications."
    ),
)
@click.option(
    "--install-autostart",
    is_flag=True,
    help="Configure the tray app to start automatically at user login.",
)
@click.option(
    "--remove-autostart",
    is_flag=True,
    help="Remove the tray app from user login autostart.",
)
@click.option(
    "--poll-interval",
    type=float,
    default=5.0,
    help="Status polling frequency in seconds (default: 5.0).",
)
@click.option(
    "--status-cmd",
    type=str,
    default=None,
    help="Custom status command to override `pocketshell gateway status --json`.",
)
def tray_command(
    install_autostart: bool,
    remove_autostart: bool,
    poll_interval: float,
    status_cmd: Optional[str],
) -> None:
    """Entry point for `pocketshell tray`."""
    if install_autostart and remove_autostart:
        raise click.UsageError("Cannot specify both --install-autostart and --remove-autostart.")

    if install_autostart:
        ok, msg = autostart.install_autostart()
        if not ok:
            raise click.ClickException(msg)
        click.echo(msg)
        return

    if remove_autostart:
        ok, msg = autostart.remove_autostart()
        if not ok:
            raise click.ClickException(msg)
        click.echo(msg)
        return

    # Check dependencies before starting GUI
    _check_dependencies()

    # Enforce single instance
    lock = SingleInstance()
    if not lock.acquire():
        click.echo("PocketShell tray is already running.", err=True)
        sys.exit(0)

    try:
        from pocketshell.tray.app import TrayApp
        from pocketshell.tray.status_client import GatewayStatusClient

        status_client = (
            GatewayStatusClient(status_command=status_cmd.split())
            if status_cmd
            else GatewayStatusClient()
        )
        app = TrayApp(status_client=status_client, poll_interval=poll_interval)
        app.run()
    finally:
        lock.release()
