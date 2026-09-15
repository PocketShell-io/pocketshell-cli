"""Host-side declarative registry for coding-agent engines.

The registry is the single source for the engine id used by the wrapper and
the metadata sent to the Android picker.  Built-in entries provide the
existing engines; ``~/.config/pocketshell/engines.yaml`` can add, override,
enable, or disable entries without a Kotlin change.

Registry ids are intentionally open.  ``family`` is the closed detection
projection used by the client (for example, ``godex`` can use the ``codex``
family), while ``id`` is the durable value recorded as ``@ps_agent_kind``.

Availability (issue #2276) is an observation this module makes at manifest
build time, never a config bit: see :func:`resolve_harnesses`.  The single
deliberate escape hatch is ``force_available:`` in ``engines.yaml``.
"""
from __future__ import annotations

from pocketshell.engines.builtin import (
    builtin_manifests,
    builtin_engine_ids,
)
from pocketshell.engines.cli import (
    engines_group,
)
from pocketshell.engines.harness import (
    LOGIN_SHELL_PATH_TIMEOUT_S,
    LOGIN_SHELL_PROBE_KILL,
    clear_resolution_cache,
    resolve_harnesses,
)
from pocketshell.engines.registry import (
    registry_config_path,
    load_registry,
    registry_payload,
    engine_for,
    createable_registry,
    json_payload,
)
from pocketshell.engines.spec import (
    ProfileSpec,
    LaunchSpec,
    EngineManifest,
    PROVIDER_ENV_UNSET_VARS,
    DISABLED_ENGINE_REASON,
    FORCED_UNAVAILABLE_REASON,
)

__all__ = [
    "ProfileSpec",
    "LaunchSpec",
    "EngineManifest",
    "PROVIDER_ENV_UNSET_VARS",
    "DISABLED_ENGINE_REASON",
    "FORCED_UNAVAILABLE_REASON",
    "LOGIN_SHELL_PATH_TIMEOUT_S",
    "LOGIN_SHELL_PROBE_KILL",
    "clear_resolution_cache",
    "resolve_harnesses",
    "builtin_manifests",
    "builtin_engine_ids",
    "registry_config_path",
    "load_registry",
    "registry_payload",
    "engine_for",
    "createable_registry",
    "json_payload",
    "engines_group",
]
