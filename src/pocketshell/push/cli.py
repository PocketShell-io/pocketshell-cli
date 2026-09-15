"""The `pocketshell push` click command group."""
from __future__ import annotations
import click
from pocketshell.usage_capture import (
    resolve_paths,
)
# --- sibling modules ---
from pocketshell.push.store import register_token, token_file


@click.group(
    name="push",
    context_settings={"help_option_names": ["-h", "--help"]},
    help=(
        "Manage push (FCM) delivery for usage-reset events (issue #690).\n\n"
        "The Android app delivers its device token over a live SSH session "
        "with `push register-token <token>`; the hourly `usage --capture` then "
        "sends a data push for each newly-detected limit reset. Push delivery "
        "is fail-soft: until a Firebase service-account credential is placed on "
        "the host, sends no-op and the in-app reset banner remains the fallback."
    ),
)
def push_group() -> None:
    """Top-level group registered onto the root `pocketshell` CLI."""


@push_group.command("register-token")
@click.argument("token", required=True)
def push_register_token(token: str) -> None:
    """Persist the app's FCM device TOKEN for reset-push delivery.

    Atomic write, mode ``0600``, under the pocketshell usage state dir. The
    Android `FcmTokenRegistrar` invokes this over a live foreground SSH session
    (`pocketshell push register-token '<token>'`).
    """
    try:
        path = register_token(token)
    except ValueError as exc:
        raise click.ClickException(str(exc))
    click.echo(f"registered device token ({path})")


@push_group.command("token-path", hidden=True)
def push_token_path() -> None:
    """Print the resolved registered-token path (debug helper)."""
    click.echo(str(token_file(resolve_paths())))
