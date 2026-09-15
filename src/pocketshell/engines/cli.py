"""The `pocketshell engines` click command group."""
from __future__ import annotations
import click
# --- sibling modules ---
from pocketshell.engines.registry import json_payload, load_registry


@click.group(
    name="engines",
    context_settings={"help_option_names": ["-h", "--help"]},
    help=(
        "Inspect the host engine registry. The Android picker reads this "
        "same manifest before displaying create choices."
    ),
)
def engines_group() -> None:
    """Top-level registry inspection group."""


@engines_group.command("list")
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Emit the registry as JSON (the client uses this form).",
)
def engines_list(as_json: bool) -> None:
    """List configured engines and their current host availability."""
    registry = load_registry()
    if as_json:
        click.echo(json_payload(registry))
        return
    for item in registry:
        state = "enabled" if item.enabled else "disabled"
        if not item.available:
            state = f"{state}, unavailable"
        if item.force_available is not None:
            state = f"{state}, force_available={str(item.force_available).lower()}"
        if item.unavailable_reason:
            state = f"{state} ({item.unavailable_reason})"
        click.echo(f"{item.id}\t{item.label}\t{state}")
