"""Merge native + aplexer profiles and resolve launch args."""
from __future__ import annotations
import os
from pathlib import Path
from typing import Optional
from pocketshell import aplexer
# --- sibling modules ---
from pocketshell.profiles.model import yaml  # noqa: F401
# --- sibling modules ---
from pocketshell.profiles.discovery import _config_file_path, _home_dir, discover_profiles
from pocketshell.profiles.model import PROFILE_ENGINES, Profile, _ENGINE_DEFAULT_DISPLAY, _display_name_for_sibling


def _stem_matching_id(payload: dict, name: str) -> Optional[str]:
    """Case-insensitive match of ``name`` against aplexer profile ids."""
    lowered = name.strip().lower()
    for stem in payload:
        if isinstance(stem, str) and stem.lower() == lowered:
            return stem
    return None


def _stem_matching_display(
    payload: dict, engine: str, name: str
) -> Optional[str]:
    """Aplexer id whose display name for ``engine`` matches ``name``."""
    lowered = name.strip().lower()
    for stem, entry in payload.items():
        if not isinstance(entry, dict) or entry.get("engine") != engine:
            continue
        if _display_name_for_sibling(engine, str(stem)).lower() == lowered:
            return str(stem)
    return None


def resolve_aplexer_profile_arg(
    name: str,
    engine: Optional[str] = None,
    env: Optional[dict[str, str]] = None,
) -> Optional[str]:
    """Map a client-facing profile name onto the ``a start --profile`` value.

    Resolution order (#2661): case-insensitive aplexer-id match; a
    display-name match for ``engine``; the engine's default display name
    → ``None`` (the caller must drop ``--profile``); anything else →
    ``name`` unchanged so aplexer produces its authoritative error. Probe
    failure or kill switches also return ``name`` unchanged.
    """
    payload = aplexer.run_json(["profiles"], env=env, feature="profiles")
    if not isinstance(payload, dict):
        return name
    stem = _stem_matching_id(payload, name)
    if stem is not None:
        return stem
    if engine:
        stem = _stem_matching_display(payload, engine, name)
        if stem is not None:
            return stem
        if _ENGINE_DEFAULT_DISPLAY.get(engine, "").lower() == name.strip().lower():
            return None
    return name


def _expand_config_dir(raw: Optional[str], env: Optional[dict[str, str]]) -> Optional[str]:
    """Expand ``~`` / ``$VAR`` in a config-file ``config_dir`` to an abspath."""
    if raw is None:
        return None
    text = str(raw).strip()
    if not text:
        return None
    home = str(_home_dir(env))
    if text == "~":
        return home
    if text.startswith("~/"):
        text = home + text[1:]
    text = os.path.expandvars(text)
    return str(Path(text))


def _config_entries(env: Optional[dict[str, str]]) -> list:
    """Raw ``profiles:`` entries from profiles.yaml; ``[]`` when unreadable."""
    path = _config_file_path(env)
    if not path.is_file():
        return []
    if yaml is None:  # pragma: no cover - yaml is a hard dependency
        return []
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):  # type: ignore[union-attr]
        return []
    if not isinstance(raw, dict):
        return []
    entries = raw.get("profiles")
    return entries if isinstance(entries, list) else []


def _profile_from_config_entry(
    entry, env: Optional[dict[str, str]]
) -> Optional[Profile]:
    """Map one profiles.yaml entry; ``None`` when malformed/unknown engine."""
    if not isinstance(entry, dict):
        return None
    name = entry.get("name")
    engine = entry.get("engine")
    if not isinstance(name, str) or not name.strip():
        return None
    if engine not in PROFILE_ENGINES:
        return None
    config_dir = _expand_config_dir(entry.get("config_dir"), env)
    extra_env = entry.get("env")
    env_map: dict[str, str] = {}
    if isinstance(extra_env, dict):
        env_map = {str(k): str(v) for k, v in extra_env.items()}
    return Profile(
        name=name.strip(),
        engine=engine,
        config_dir=config_dir,
        default=(config_dir is None),
        env=env_map,
    )


def load_config_profiles(
    env: Optional[dict[str, str]] = None,
) -> list[Profile]:
    """Load explicit profiles from ``~/.config/pocketshell/profiles.yaml``.

    Returns ``[]`` when the file is absent or empty. Malformed entries
    (missing ``name`` / unknown ``engine``) are skipped quietly so a
    typo never breaks discovery — the conventional-dir path still works.
    """
    out: list[Profile] = []
    for entry in _config_entries(env):
        profile = _profile_from_config_entry(entry, env)
        if profile is not None:
            out.append(profile)
    return out


def _claim(profile: Profile, names: set, dirs: set) -> None:
    """Record a profile's name and ``(engine, dir)`` as taken."""
    names.add(profile.name)
    dirs.add((profile.engine, profile.config_dir))


def _merge_profiles(
    config_profiles: list[Profile], discovered: list[Profile]
) -> list[Profile]:
    """Config profiles win; discovered ones join if name and dir are free."""
    taken_names: set[str] = set()
    taken_dirs: set[tuple[str, Optional[str]]] = set()
    merged: list[Profile] = []

    for profile in config_profiles:
        _claim(profile, taken_names, taken_dirs)
        merged.append(profile)

    for profile in discovered:
        if profile.name in taken_names:
            continue
        if (profile.engine, profile.config_dir) in taken_dirs:
            continue
        _claim(profile, taken_names, taken_dirs)
        merged.append(profile)
    return merged


def _sort_profiles(merged: list[Profile]) -> list[Profile]:
    """Engine order, default first, otherwise keep insertion order."""
    engine_rank = {eng: i for i, eng in enumerate(PROFILE_ENGINES)}
    indexed = list(enumerate(merged))
    indexed.sort(
        key=lambda pair: (
            engine_rank.get(pair[1].engine, len(PROFILE_ENGINES)),
            0 if pair[1].default else 1,
            pair[0],
        )
    )
    return [profile for _, profile in indexed]


def load_profiles(
    env: Optional[dict[str, str]] = None,
    *,
    engine: Optional[str] = None,
) -> list[Profile]:
    """Merge explicit-config + discovered profiles into the final list.

    Resolution: explicit config-file profiles first (they win on a ``name``
    collision and claim their ``(engine, config_dir)`` so discovery won't
    duplicate), then discovered profiles whose name and ``(engine, dir)``
    aren't already taken. Within each engine the default profile sorts
    first, then config-file order, then discovery order. ``engine`` filters
    the result to a single engine.
    """
    merged = _merge_profiles(load_config_profiles(env), discover_profiles(env))
    if engine is not None:
        merged = [p for p in merged if p.engine == engine]
    return _sort_profiles(merged)


def resolve_profile(
    name: str,
    engine: str,
    env: Optional[dict[str, str]] = None,
) -> Profile:
    """Resolve a profile ``name`` for ``engine`` to its :class:`Profile`.

    Raises :class:`KeyError` when no profile of that name exists for the
    engine (the CLI turns this into a clear error). Matching is exact on
    the display ``name`` first; if that misses, a case-insensitive match is
    attempted so a client can pass either ``"Claude (Z.AI)"`` or a slug.
    """
    profiles = load_profiles(env, engine=engine)
    for profile in profiles:
        if profile.name == name:
            return profile
    lowered = name.strip().lower()
    for profile in profiles:
        if profile.name.lower() == lowered:
            return profile
    raise KeyError(name)
