"""The built-in engine manifests compiled into PocketShell."""
from __future__ import annotations
# --- sibling modules ---
from pocketshell.engines.harness import _profile
from pocketshell.engines.spec import EngineManifest, LaunchSpec

# OpenCode's ``usage_provider`` names the quse provider whose quota belongs to
# this engine, and quse has no provider called "opencode" — the
# OpenCode-on-Go backend is reported as `go` (quse.opencode_go_quota). The old
# value would have made `pocketshell usage opencode` fail with
# "Unknown provider" (#2293).

_CLAUDE = EngineManifest(
    id="claude",
    family="claude",
    harness="claude",
    label="Claude",
    provider_mark="Anthropic",
    usage_provider="claude",
    launch=LaunchSpec(
        argv=("claude",),
        skip_permissions_argv=("--dangerously-skip-permissions",),
        profile_env="CLAUDE_CONFIG_DIR",
        profile=_profile(
            "CLAUDE_CONFIG_DIR",
            ".claude",
            (".claude.json", "settings.json"),
            ("claude", "laude"),
            "Claude",
        ),
    ),
)

_CODEX = EngineManifest(
    id="codex",
    family="codex",
    harness="codex",
    label="Codex",
    provider_mark="OpenAI",
    usage_provider="codex",
    launch=LaunchSpec(
        argv=("codex", "-c", "check_for_update_on_startup=false"),
        skip_permissions_argv=(
            "--dangerously-bypass-approvals-and-sandbox",
        ),
        profile_env="CODEX_HOME",
        profile=_profile(
            "CODEX_HOME",
            ".codex",
            ("config.toml", "auth.json"),
            ("codex", "odex"),
            "Codex",
        ),
    ),
)

_OPENCODE = EngineManifest(
    id="opencode",
    family="opencode",
    harness="opencode",
    label="OpenCode",
    provider_mark="OpenCode",
    usage_provider="go",
    launch=LaunchSpec(argv=("opencode",)),
)

_GROK = EngineManifest(
    id="grok",
    family="grok",
    harness="grok",
    label="Grok",
    provider_mark="xAI",
    usage_provider="grok",
    launch=LaunchSpec(
        argv=("grok",),
        skip_permissions_argv=("--always-approve",),
        profile_env="GROK_HOME",
    ),
)


def builtin_manifests() -> tuple[EngineManifest, ...]:
    """Return the shipped registry entries in the established picker order."""
    return (_CLAUDE, _CODEX, _OPENCODE, _GROK)


def builtin_engine_ids() -> tuple[str, ...]:
    return tuple(item.id for item in builtin_manifests())
