"""The `pocketshell profiles` click command group."""
from __future__ import annotations
from typing import Optional
import click
# --- sibling modules ---
from pocketshell.profiles.model import yaml  # noqa: F401
# --- sibling modules ---
from pocketshell.profiles.model import PROFILE_ENGINES, _profile_payload
from pocketshell.profiles.resolve import load_profiles


@click.group(
    name="profiles",
    context_settings={"help_option_names": ["-h", "--help"]},
    help=(
        "Inspect the host's coding-agent profiles (claude / codex).\n\n"
        "Profiles are defined ONCE on the host — auto-discovered from "
        "conventional config dirs (~/.claude, ~/.zlaude, ~/.codex …) and an "
        "optional ~/.config/pocketshell/profiles.yaml — so the mobile "
        "client fetches them instead of storing them per-host. See #718."
    ),
)
def profiles_group() -> None:
    """Top-level `profiles` group registered onto the root CLI."""


@profiles_group.command("list")
@click.option(
    "--engine",
    type=click.Choice(PROFILE_ENGINES),
    default=None,
    help="Limit to one engine (claude / codex). Default: all engines.",
)
@click.option(
    "--json",
    "as_json",
    is_flag=True,
    help="Emit JSON instead of YAML (the client parses JSON today).",
)
def profiles_list(engine: Optional[str], as_json: bool) -> None:
    """List the host's agent profiles as YAML (default) or JSON.

    Each entry is ``{name, engine, config_dir, default}``. Never prints
    anything from inside a config dir (no keys / secrets).
    """
    profiles = load_profiles(engine=engine)
    payload = {"profiles": [_profile_payload(p) for p in profiles]}

    if as_json:
        import json

        click.echo(json.dumps(payload, indent=2, sort_keys=False))
        return

    if yaml is None:  # pragma: no cover - yaml is a hard dependency
        raise click.ClickException(
            "PyYAML is required for YAML output; pass --json instead."
        )
    text = yaml.safe_dump(payload, sort_keys=False, default_flow_style=False)
    click.echo(text.rstrip("\n"))
