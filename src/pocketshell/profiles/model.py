"""Profile dataclass, naming, and divergence diagnostics."""
from __future__ import annotations
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


try:  # pragma: no cover - import guard
    import yaml
except ImportError:  # pragma: no cover - yaml is a hard dep, guard is defensive
    yaml = None  # type: ignore[assignment]


# Engines that support a profile config dir. opencode has no profile env var.
PROFILE_ENGINES: tuple[str, ...] = ("claude", "codex")


# Engines that support a profile config dir. opencode has no profile env var.
PROFILE_ENGINES: tuple[str, ...] = ("claude", "codex")


# Per-engine discovery rules: the default top-level dir name and the marker
# files that prove a directory is that engine's config dir.
_ENGINE_DEFAULT_DIRNAME: dict[str, str] = {
    "claude": ".claude",
    "codex": ".codex",
}


# Per-engine discovery rules: the default top-level dir name and the marker
# files that prove a directory is that engine's config dir.
_ENGINE_DEFAULT_DIRNAME: dict[str, str] = {
    "claude": ".claude",
    "codex": ".codex",
}


_ENGINE_MARKERS: dict[str, tuple[str, ...]] = {
    "claude": (".claude.json", "settings.json"),
    "codex": ("config.toml", "auth.json"),
}


_ENGINE_MARKERS: dict[str, tuple[str, ...]] = {
    "claude": (".claude.json", "settings.json"),
    "codex": ("config.toml", "auth.json"),
}


# Sibling-dir name substrings that flag a non-default profile for an engine.
# A top-level ``~/.<name>`` dir whose stem contains ANY of these (and isn't
# the default dir) is a candidate profile for that engine. The suffix hints
# (``laude`` / ``odex``) catch the maintainer's single-leading-letter swaps
# like ``zlaude`` (Z.AI) where ``claude`` itself isn't a substring.
_ENGINE_NAME_HINTS: dict[str, tuple[str, ...]] = {
    "claude": ("claude", "laude"),
    "codex": ("codex", "odex"),
}


# Sibling-dir name substrings that flag a non-default profile for an engine.
# A top-level ``~/.<name>`` dir whose stem contains ANY of these (and isn't
# the default dir) is a candidate profile for that engine. The suffix hints
# (``laude`` / ``odex``) catch the maintainer's single-leading-letter swaps
# like ``zlaude`` (Z.AI) where ``claude`` itself isn't a substring.
_ENGINE_NAME_HINTS: dict[str, tuple[str, ...]] = {
    "claude": ("claude", "laude"),
    "codex": ("codex", "odex"),
}


# Display name for the engine's default profile (sorted first, pre-selected).
_ENGINE_DEFAULT_DISPLAY: dict[str, str] = {
    "claude": "Claude",
    "codex": "Codex",
}


# Display name for the engine's default profile (sorted first, pre-selected).
_ENGINE_DEFAULT_DISPLAY: dict[str, str] = {
    "claude": "Claude",
    "codex": "Codex",
}


# Known dir-stem → display-name aliases for non-default profiles. The
# maintainer's ``~/.zlaude`` is the Z.AI-routed Claude profile.
_KNOWN_ALIASES: dict[str, str] = {
    "zlaude": "Claude (Z.AI)",
}


# Known dir-stem → display-name aliases for non-default profiles. The
# maintainer's ``~/.zlaude`` is the Z.AI-routed Claude profile.
_KNOWN_ALIASES: dict[str, str] = {
    "zlaude": "Claude (Z.AI)",
}


# Aplexer Phase A (#2341): prefer `a profiles --json` siblings when the
# probe succeeds. Kill switches: POCKETSHELL_APLEXER=0 /
# POCKETSHELL_APLEXER_PROFILES=0. See docs/aplexer-integration.md.
_LOG = logging.getLogger("pocketshell.profiles")


@dataclass(frozen=True)
class Profile:
    """A named agent profile resolving to a config dir for one engine.

    ``config_dir`` is ``None`` for the engine's built-in default (which maps
    to an empty ``--config-dir`` at launch — the agent uses its own default
    location). ``default`` flags the engine's default profile, which the
    picker pre-selects. ``env`` carries optional extra environment from the
    explicit config file (server-side only; never secrets via the wire).
    """

    name: str
    engine: str
    config_dir: Optional[str] = None
    default: bool = False
    env: dict[str, str] = field(default_factory=dict)


def _humanise_stem(stem: str) -> str:
    """Turn a dir stem like ``zlaude`` into a display name ``Zlaude``."""
    cleaned = stem.lstrip(".").replace("-", " ").replace("_", " ").strip()
    if not cleaned:
        return stem
    return " ".join(part.capitalize() for part in cleaned.split())


def _display_name_for_sibling(engine: str, stem: str) -> str:
    """Display name for a non-default sibling dir of ``engine``."""
    key = stem.lstrip(".")
    if key in _KNOWN_ALIASES:
        return _KNOWN_ALIASES[key]
    return _humanise_stem(stem)


def _profile_key(profile: Profile) -> tuple[str, Optional[str]]:
    """Compare native vs aplexer siblings by engine + config_dir."""
    path = profile.config_dir
    if path is None:
        return (profile.engine, None)
    try:
        return (profile.engine, str(Path(path).resolve()))
    except OSError:
        return (profile.engine, path)


def _log_profile_divergence(native: list[Profile], aplexer: list[Profile]) -> None:
    """Log missing/extra/differing siblings; defaults are native-only."""
    native_siblings = [p for p in native if not p.default]
    aplexer_by_key = {_profile_key(p): p for p in aplexer}
    native_by_key = {_profile_key(p): p for p in native_siblings}
    missing = sorted(set(native_by_key) - set(aplexer_by_key))
    extra = sorted(set(aplexer_by_key) - set(native_by_key))
    differing = []
    for key, native_profile in native_by_key.items():
        other = aplexer_by_key.get(key)
        if other is not None and other.name != native_profile.name:
            differing.append((native_profile.name, other.name, key))
    if not missing and not extra and not differing:
        return
    _LOG.warning(
        "aplexer profile shadow divergence: missing=%s extra=%s differing=%s",
        [native_by_key[k].name for k in missing],
        [aplexer_by_key[k].name for k in extra],
        [f"{old}->{new}" for old, new, _ in differing],
    )


def _profile_payload(profile: Profile) -> dict[str, object]:
    """Serialisable, secret-free dict for one profile."""
    return {
        "name": profile.name,
        "engine": profile.engine,
        "config_dir": profile.config_dir,
        "default": profile.default,
    }
