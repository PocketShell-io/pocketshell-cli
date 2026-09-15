"""Agent launch domain: command construction, environment, and execution."""

from pocketshell.agents.launch.command import build_argv
from pocketshell.agents.launch.environment import (
    AGENT_KINDS,
    PROVIDER_ENV_UNSET_VARS,
    build_env,
)
from pocketshell.agents.launch.run import launch_agent, _resolve_config_dir
from pocketshell.agents.launch.spec import _aplexer_profile_id
from pocketshell.agents.launch.trust import claude_config_path, seed_claude_trust

__all__ = [
    "AGENT_KINDS",
    "PROVIDER_ENV_UNSET_VARS",
    "build_env",
    "build_argv",
    "claude_config_path",
    "seed_claude_trust",
    "launch_agent",
    "_aplexer_profile_id",
    "_resolve_config_dir",
]
