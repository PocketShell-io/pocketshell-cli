"""Agent launch environment construction and provider key stripping."""
from __future__ import annotations
import os
from typing import Any, Optional
from pocketshell.engines import builtin_engine_ids, engine_for
# __SIBLING_IMPORTS__


# ---------------------------------------------------------------------------
# Provider API-key env vars stripped for EVERY agent (subscription billing).
# ---------------------------------------------------------------------------
#
# CANONICAL SOURCE: the maintainer's dotfiles at
# ``config/opencode/env_unset.txt`` (installed as
# ``~/git/.claude/config/opencode/env_unset.txt``). This list is a verbatim
# copy of that file (71 entries). With these unset, an agent falls back to
# the maintainer's *subscription* auth instead of a per-token env API key
# (which bills per token). Keeping the list here makes the wrapper
# self-contained — it does not require the ``oc`` function or
# ``env_unset.txt`` to be present on the host.
#
# Maintainer decision (issue #703): strip these for ALL three agents
# (codex / claude / opencode), not opencode-only — subscription billing
# across the board.
#
# The Android picker (SessionTypePickerSheet.kt) used to carry an identical
# copy; with the wrapper owning the launch, the app no longer needs it.
PROVIDER_ENV_UNSET_VARS: tuple[str, ...] = (
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_PROFILE",
    "AWS_REGION",
    "AWS_BEARER_TOKEN_BEDROCK",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_ROLE_ARN",
    "OPENAI_API_KEY",
    "OPENAI_BASE_URL",
    "OPENAI_ORG_ID",
    "OPENAI_PROJECT_ID",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_BASE_URL",
    "ANTHROPIC_AUTH_TOKEN",
    "GROQ_API_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GOOGLE_CLOUD_PROJECT",
    "GOOGLE_API_KEY",
    "VERTEX_LOCATION",
    "VERTEX_AI_PROJECT",
    "DEEPSEEK_API_KEY",
    "XAI_API_KEY",
    "FIREWORKS_API_KEY",
    "CEREBRAS_API_KEY",
    "OPENROUTER_API_KEY",
    "TOGETHER_API_KEY",
    "TOGETHER_AI_API_KEY",
    "AZURE_API_KEY",
    "AZURE_RESOURCE_NAME",
    "AZURE_COGNITIVE_SERVICES_RESOURCE_NAME",
    "AZURE_OPENAI_API_KEY",
    "AZURE_OPENAI_ENDPOINT",
    "CLOUDFLARE_API_TOKEN",
    "CLOUDFLARE_ACCOUNT_ID",
    "CLOUDFLARE_GATEWAY_ID",
    "CLOUDFLARE_API_KEY",
    "HUGGING_FACE_API_KEY",
    "HF_TOKEN",
    "HF_API_TOKEN",
    "MOONSHOT_API_KEY",
    "MOONSHOTAI_API_KEY",
    "MINIMAX_API_KEY",
    "NEBIUS_API_KEY",
    "DEEPINFRA_API_KEY",
    "BASETEN_API_KEY",
    "VENICE_API_KEY",
    "SCALEWAY_API_KEY",
    "OVH_API_KEY",
    "CORTECS_API_KEY",
    "IONET_API_KEY",
    "VERCEL_API_KEY",
    "ZENMUX_API_KEY",
    "ZAI_API_KEY",
    "HELICONE_API_KEY",
    "OPENCODE_API_KEY",
    "OPENCODE_ZEN_API_KEY",
    "GITLAB_TOKEN",
    "GITLAB_INSTANCE_URL",
    "GITLAB_AI_GATEWAY_URL",
    "GITLAB_OAUTH_CLIENT_ID",
    "AICORE_SERVICE_KEY",
    "AICORE_DEPLOYMENT_ID",
    "AICORE_RESOURCE_GROUP",
    "OPENAI_COMPATIBLE_API_KEY",
    "LMSTUDIO_API_KEY",
    "OLLAMA_API_KEY",
    "302AI_API_KEY",
    "FIRMWARE_API_KEY",
    "2AI_API_KEY",
    "GEMINI_API_KEY",
)


# Recognised agent kinds. Order is the picker's order (claude, codex,
# opencode) but the wrapper is keyed by name, not ordinal.
AGENT_KINDS: tuple[str, ...] = builtin_engine_ids()


def _layered_env(
    base_env: dict[str, str],
    folder_exports: dict[str, str],
    manifest: Any,
    extra_env: Optional[dict[str, str]],
) -> dict[str, str]:
    """Layer folder exports + profile env + launch env_set, then strip keys.

    A profile's ``env:`` block (profiles.yaml, issue #732) layers on top of
    the folder exports, BEFORE the provider strip, so the strip still wins
    for provider keys — a profile can set arbitrary non-provider vars but
    cannot re-inject a stripped API key. The strip (issue #703 —
    subscription billing across the board) runs last so it overrides any
    provider key from base/folder/profile env.
    """
    env = dict(base_env)
    env.update(folder_exports)
    if extra_env:
        env.update(extra_env)
    for name, value in manifest.launch.env_set:
        env[name] = value
    for name in manifest.launch.env_unset:
        env.pop(name, None)
    return env


def build_env(
    kind: str,
    base_env: dict[str, str],
    folder_exports: dict[str, str],
    *,
    config_dir: Optional[str] = None,
    extra_env: Optional[dict[str, str]] = None,
) -> dict[str, str]:
    """Return the environment to exec the agent with.

    Layers ``base_env`` + the folder's merged exports + the profile's
    ``extra_env`` + the manifest's ``env_set``, then strips every
    :data:`PROVIDER_ENV_UNSET_VARS` var so the agent uses its subscription
    auth (see :func:`_layered_env`). With ``config_dir``, sets the agent's
    config-dir env var (``CODEX_HOME``/``CLAUDE_CONFIG_DIR``); ignored for
    opencode (no profile env var).
    """
    try:
        manifest = engine_for(kind)
    except KeyError as exc:
        raise ValueError(f"unknown agent kind: {kind!r}") from exc

    env = _layered_env(base_env, folder_exports, manifest, extra_env)

    if config_dir:
        env_name = manifest.launch.profile_env
        if env_name:
            env[env_name] = config_dir

    return env


def _ordered_env_unset(*groups: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(
        dict.fromkeys(
            name for group in groups for name in group if str(name).strip()
        )
    )


def _spec_unset(spec: dict) -> tuple[str, ...]:
    """The spec's ``env_unset`` names; non-list shapes yield nothing."""
    raw_unset = spec.get("env_unset")
    if isinstance(raw_unset, list):
        return tuple(str(name) for name in raw_unset)
    return ()


def _env_from_launch_spec(
    spec: dict,
    *,
    folder_exports: dict[str, str],
    extra_env: Optional[dict[str, str]],
    config_dir: Optional[str],
    profile_env: Optional[str],
) -> dict[str, str]:
    """Layer PocketShell env on top of a launch-spec, then strip keys.

    Always unions the host-wide provider strip with ``spec.env_unset`` so a
    partial/mutant spec cannot leave subscription keys in the child env.
    """
    env = dict(os.environ)
    env.update(folder_exports)
    if extra_env:
        env.update(extra_env)
    env_set = spec.get("env_set")
    if isinstance(env_set, dict):
        env.update({str(k): str(v) for k, v in env_set.items()})
    if config_dir and profile_env:
        env[profile_env] = config_dir
    for name in _ordered_env_unset(PROVIDER_ENV_UNSET_VARS, _spec_unset(spec)):
        env.pop(name, None)
    return env
