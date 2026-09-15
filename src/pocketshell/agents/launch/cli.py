"""The `pocketshell agent` click command group."""
from __future__ import annotations
from typing import Optional
import click
from pocketshell.engines import engine_for, load_registry
# --- sibling modules ---
from pocketshell.agents.launch.environment import AGENT_KINDS
from pocketshell.agents.launch.run import _resolve_config_dir, launch_agent
# __SIBLING_IMPORTS__


_DIR_OPTION = click.option(
    "--dir",
    "directory",
    required=True,
    type=str,
    help="Folder to launch the agent in (its cwd).",
)
_SKIP_PERM_OPTION = click.option(
    "--skip-permissions/--no-skip-permissions",
    default=True,
    show_default=True,
    help=(
        "Launch with per-action approval prompts disabled "
        "(codex YOLO / claude bypass / grok --always-approve). "
        "No-op for opencode."
    ),
)
_CONFIG_DIR_OPTION = click.option(
    "--config-dir",
    "config_dir",
    default=None,
    type=str,
    help=(
        "Profile config dir: CODEX_HOME (codex) / CLAUDE_CONFIG_DIR "
        "(claude). Ignored for opencode. Mutually exclusive with "
        "--profile."
    ),
)
_PROFILE_OPTION = click.option(
    "--profile",
    "profile",
    default=None,
    type=str,
    help=(
        "Named host profile (see `pocketshell profiles list`); resolves "
        "to its config dir. Mutually exclusive with --config-dir."
    ),
)


def _make_agent_command(kind: str):
    """Build the Click command for one agent kind."""

    @_DIR_OPTION
    @_SKIP_PERM_OPTION
    @_CONFIG_DIR_OPTION
    @_PROFILE_OPTION
    @click.command(
        name=kind,
        context_settings={"help_option_names": ["-h", "--help"]},
        help=f"Launch `{kind}` in --dir with first-run prompts suppressed.",
    )
    @click.pass_context
    def _cmd(
        ctx: click.Context,
        directory: str,
        skip_permissions: bool,
        config_dir: Optional[str],
        profile: Optional[str],
    ) -> None:
        config_dir, extra_env = _resolve_config_dir(
            ctx, kind, config_dir, profile
        )
        launch_agent(
            ctx,
            kind,
            directory,
            skip_permissions=skip_permissions,
            config_dir=config_dir,
            extra_env=extra_env,
        )

    return _cmd


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
