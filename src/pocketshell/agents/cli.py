"""The `pocketshell agent` click command group."""
from __future__ import annotations
import click
from pocketshell.engines import engine_for, load_registry
# --- sibling modules ---
from pocketshell.agents.environment import AGENT_KINDS
from pocketshell.agents.launch import _make_agent_command
# __SIBLING_IMPORTS__


class _RegistryAgentGroup(click.Group):
    """Click group that resolves newly configured registry ids on demand."""

    def list_commands(self, ctx: click.Context) -> list[str]:
        names = set(super().list_commands(ctx))
        names.update(item.id for item in load_registry(probe=False))
        return sorted(names)

    def get_command(self, ctx: click.Context, name: str):
        command = super().get_command(ctx, name)
        if command is not None:
            return command
        try:
            engine_for(name, probe=False)
        except KeyError:
            return None
        return _make_agent_command(name)


@click.group(
    cls=_RegistryAgentGroup,
    name="agent",
    context_settings={"help_option_names": ["-h", "--help"]},
    help=(
        "Launch a coding-agent CLI in a folder, server-side.\n\n"
        "Replaces the giant inline `env -u … <agent>` line the app used to "
        "type into the pane. Merges the folder's `.env`/`.envrc`, strips "
        "provider API-key vars for every agent (subscription billing), and "
        "suppresses each agent's first-run modal (codex update check / "
        "claude folder-trust) so the agent is immediately usable. "
        "See issue #703."
    ),
)
def agent_group() -> None:
    """Top-level group registered onto the root `pocketshell` CLI."""


for _kind in AGENT_KINDS:
    agent_group.add_command(_make_agent_command(_kind))


for _kind in AGENT_KINDS:
    agent_group.add_command(_make_agent_command(_kind))
