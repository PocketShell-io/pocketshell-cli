"""Discover per-engine config-dir profiles on the host."""
from __future__ import annotations
import os
from pathlib import Path
from typing import Any, Optional
from pocketshell.runtime import aplexer
# --- sibling modules ---
from pocketshell.profiles.model import PROFILE_ENGINES, Profile, _ENGINE_DEFAULT_DIRNAME, _ENGINE_DEFAULT_DISPLAY, _ENGINE_MARKERS, _ENGINE_NAME_HINTS, _display_name_for_sibling, _log_profile_divergence


_APLEXER_CONFIG_DIR_ENV = {
    "claude": "CLAUDE_CONFIG_DIR",
    "codex": "CODEX_HOME",
}


def _home_dir(env: Optional[dict[str, str]] = None) -> Path:
    """Resolve ``$HOME`` (honouring an injected env for tests)."""
    source = env if env is not None else os.environ
    home = source.get("HOME")
    if home:
        return Path(home)
    return Path(os.path.expanduser("~"))


def _has_marker(directory: Path, markers: tuple[str, ...]) -> bool:
    """True if ``directory`` is a dir carrying one of ``markers``."""
    if not directory.is_dir():
        return False
    return any((directory / marker).is_file() for marker in markers)


def _config_file_path(env: Optional[dict[str, str]] = None) -> Path:
    """Path to the optional ``profiles.yaml`` (XDG_CONFIG_HOME honoured)."""
    source = env if env is not None else os.environ
    xdg = source.get("XDG_CONFIG_HOME")
    if xdg:
        base = Path(xdg)
    else:
        base = _home_dir(source) / ".config"
    return base / "pocketshell" / "profiles.yaml"


def _env_map(env: Optional[dict[str, str]] = None) -> dict[str, str]:
    """Process env overlaid with an optional injected map (tests pass HOME)."""
    merged = dict(os.environ)
    if env:
        merged.update(env)
    return merged


def _profiles_from_aplexer_json(payload: Any) -> Optional[list[Profile]]:
    """Map ``a profiles --json`` onto PocketShell ``Profile`` objects.

    Aplexer emits an object keyed by dir stem. Listings never carry
    ``env``. Default-dir profiles are not in this payload (aplexer omits
    ``~/.claude`` / ``~/.codex``); callers keep synthesizing those natively.
    """
    if not isinstance(payload, dict):
        return None
    out: list[Profile] = []
    for stem, entry in payload.items():
        if not isinstance(stem, str) or not isinstance(entry, dict):
            continue
        engine = entry.get("engine")
        if engine not in PROFILE_ENGINES:
            continue
        env_block = entry.get("env") if isinstance(entry.get("env"), dict) else {}
        env_key = _APLEXER_CONFIG_DIR_ENV.get(str(engine))
        raw_dir = env_block.get(env_key) if env_key else None
        config_dir = str(raw_dir) if raw_dir else None
        out.append(
            Profile(
                name=_display_name_for_sibling(str(engine), stem),
                engine=str(engine),
                config_dir=config_dir,
                default=False,
                env={},
            )
        )
    return out


def _aplexer_profiles(
    env: Optional[dict[str, str]] = None,
) -> Optional[list[Profile]]:
    """Run ``a profiles --json``. None on skip or any failure."""
    payload = aplexer.run_json(["profiles"], env=env, feature="profiles")
    if payload is None:
        return None
    return _profiles_from_aplexer_json(payload)


def _default_profile(home: Path, engine: str) -> Optional[Profile]:
    """The engine-default profile when ``~/.<dirname>`` carries a marker."""
    markers = _ENGINE_MARKERS[engine]
    if not _has_marker(home / _ENGINE_DEFAULT_DIRNAME[engine], markers):
        return None
    return Profile(
        name=_ENGINE_DEFAULT_DISPLAY[engine],
        engine=engine,
        config_dir=None,
        default=True,
    )


def _is_sibling_dir(
    entry: Path,
    *,
    default_dirname: str,
    hints: Any,
    markers: Any,
) -> bool:
    """A non-default dot-dir matching one of the engine's name hints and
    carrying one of its markers."""
    stem = entry.name
    if not stem.startswith(".") or stem == default_dirname:
        return False
    if not any(hint in stem.lower() for hint in hints):
        return False
    return _has_marker(entry, markers)


def _sibling_profiles(home: Path, engine: str) -> list[Profile]:
    """Non-default ``~/.<name>`` siblings for ``engine``, sorted.

    A sibling must be a dot-dir carrying a marker, matching one of the
    engine's name hints, and not be the default dir itself.
    """
    siblings: list[Profile] = []
    try:
        entries = sorted(home.iterdir())
    except OSError:
        entries = []
    for entry in entries:
        if _is_sibling_dir(
            entry,
            default_dirname=_ENGINE_DEFAULT_DIRNAME[engine],
            hints=_ENGINE_NAME_HINTS[engine],
            markers=_ENGINE_MARKERS[engine],
        ):
            siblings.append(
                Profile(
                    name=_display_name_for_sibling(engine, entry.name),
                    engine=engine,
                    config_dir=str(entry),
                    default=False,
                )
            )
    return siblings


def _native_profiles(home: Path) -> list[Profile]:
    """Conventional config-dir profiles for every engine, in engine order."""
    out: list[Profile] = []
    for engine in PROFILE_ENGINES:
        default = _default_profile(home, engine)
        if default is not None:
            out.append(default)
        out.extend(_sibling_profiles(home, engine))
    return out


def discover_profiles(
    env: Optional[dict[str, str]] = None,
) -> list[Profile]:
    """Auto-discover conventional config-dir profiles per engine.

    Conservative: only top-level ``~/.<name>`` dirs carrying a real marker
    file (see module docstring). The default dir → the engine default
    profile (``config_dir=None``, ``default=True``); matching sibling dirs →
    non-default profiles with their absolute ``config_dir``.

    When ``a`` is available, prefers sibling profiles from ``a profiles --json``
    and keeps native engine defaults. Probe failure / kill switch returns this
    native result unchanged.
    """
    out = _native_profiles(_home_dir(env))

    mapped = _aplexer_profiles(env)
    if mapped is None:
        return out
    _log_profile_divergence(out, mapped)
    defaults = [profile for profile in out if profile.default]
    return defaults + mapped
