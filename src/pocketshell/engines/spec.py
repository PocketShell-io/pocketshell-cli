"""Launch/manifest dataclasses and availability reasoning."""
from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Optional


# The provider strip is launch policy, not an app-side engine list.  Keeping
# it in the registry makes custom engines inherit the same billing safeguard.
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


@dataclass(frozen=True)
class ProfileSpec:
    """Declarative profile discovery and launch environment metadata."""

    env_var: str
    default_dirname: str
    markers: tuple[str, ...] = ()
    name_hints: tuple[str, ...] = ()
    default_label: str = ""


def _ordered_env_unset_union(*groups: tuple[str, ...]) -> tuple[str, ...]:
    """Keep the built-in provider strip when config adds custom variables."""
    return tuple(
        dict.fromkeys(
            name
            for group in groups
            for name in group
            if name.strip()
        )
    )


@dataclass(frozen=True)
class LaunchSpec:
    """Declarative launch argv/env/profile behavior for one engine."""

    argv: tuple[str, ...]
    skip_permissions_argv: tuple[str, ...] = ()
    env_unset: tuple[str, ...] = PROVIDER_ENV_UNSET_VARS
    env_set: tuple[tuple[str, str], ...] = ()
    profile_env: Optional[str] = None
    profile: Optional[ProfileSpec] = None

    def __post_init__(self) -> None:
        # A custom registry entry may add launch.env.unset entries, but it can
        # never opt out of the host-wide subscription/API-key safety policy.
        object.__setattr__(
            self,
            "env_unset",
            _ordered_env_unset_union(PROVIDER_ENV_UNSET_VARS, self.env_unset),
        )

    @property
    def supports_skip_permissions(self) -> bool:
        return bool(self.skip_permissions_argv)


@dataclass(frozen=True)
class EngineManifest:
    """One host registry entry, including current availability/config state.

    ``available`` is an OBSERVATION (see :func:`resolve_harnesses`), never an
    input the config can go stale on.  ``force_available`` is the deliberate
    escape hatch: an ``engines.yaml`` entry may set it to pin availability on
    a host whose layout the resolver cannot anticipate.  ``force_available``
    is deliberately a different key from the ``available`` output field so a
    copied/stale manifest row can never be mistaken for that intent.
    """

    id: str
    family: str
    harness: str
    label: str
    provider_mark: str
    launch: LaunchSpec
    usage_provider: Optional[str] = None
    enabled: bool = True
    available: bool = True
    unavailable_reason: Optional[str] = None
    # Explicit `force_available:` from engines.yaml. None = probe decides.
    force_available: Optional[bool] = None
    # Explicit `unavailable_reason:` from engines.yaml, kept so the probe
    # cannot silently discard a host-authored explanation.
    configured_unavailable_reason: Optional[str] = None

    @property
    def available_for_create(self) -> bool:
        return self.enabled and self.available

    def _launch_payload(self) -> dict[str, object]:
        """Render the launch spec, including the profile when configured."""
        launch: dict[str, object] = {
            "argv": list(self.launch.argv),
            "skip_permissions_argv": list(self.launch.skip_permissions_argv),
            "supports_skip_permissions": self.launch.supports_skip_permissions,
            "env": {
                "set": dict(self.launch.env_set),
                "unset": list(self.launch.env_unset),
            },
            "profile_env": self.launch.profile_env,
        }
        if self.launch.profile is not None:
            launch["profile"] = _profile_payload(self.launch.profile)
        return launch

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.id,
            "family": self.family,
            "harness": self.harness,
            "label": self.label,
            "provider_mark": self.provider_mark,
            "usage_provider": self.usage_provider,
            "enabled": self.enabled,
            "available": self.available,
            "available_for_create": self.available_for_create,
            "unavailable_reason": self.unavailable_reason,
            "force_available": self.force_available,
            "launch": self._launch_payload(),
        }


def _profile_payload(profile: ProfileSpec) -> dict[str, object]:
    return {
        "env_var": profile.env_var,
        "default_dirname": profile.default_dirname,
        "markers": list(profile.markers),
        "name_hints": list(profile.name_hints),
        "default_label": profile.default_label,
    }


_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
DISABLED_ENGINE_REASON = "disabled in the host registry"
FORCED_UNAVAILABLE_REASON = "pinned unavailable by `force_available: false`"


def _missing_harness_reason(item: EngineManifest) -> str:
    return f"`{item.harness}` is not installed on this host (not on PATH)."


def _availability_reason(item: EngineManifest, available: bool) -> Optional[str]:
    """Derive the user-facing reason for a non-createable engine.

    A disabled engine whose harness is ALSO missing used to report only the
    disablement, which silently lost the more actionable half of the state.
    Both halves are reported when both apply.
    """
    if item.enabled and available:
        return None
    if not available and item.force_available is False:
        return FORCED_UNAVAILABLE_REASON
    if not available and not item.enabled:
        return (
            f"`{item.harness}` is not installed on this host (not on PATH) "
            f"and is {DISABLED_ENGINE_REASON}."
        )
    if not available:
        return _missing_harness_reason(item)
    return DISABLED_ENGINE_REASON


def _effective_reason(item: EngineManifest, available: bool) -> Optional[str]:
    """Prefer a host-authored reason over the derived one when unavailable."""
    if item.enabled and available:
        return None
    if item.configured_unavailable_reason:
        return item.configured_unavailable_reason
    return _availability_reason(item, available)