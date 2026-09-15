"""The `pocketshell sessions` click command group."""
from __future__ import annotations
import click


@click.group(
    name="sessions",
    context_settings={"help_option_names": ["-h", "--help"]},
    help="List, create, attach to, and stop aplexer sessions on the host.",
)
def sessions_group() -> None:
    """Session lifecycle commands backed by aplexer."""
