"""User registry config loading, overlays, and lookup."""
from __future__ import annotations
import json
import os
from dataclasses import replace
from pathlib import Path
from typing import Mapping, Optional
from pocketshell import aplexer
# --- sibling modules ---
from pocketshell.engines.builtin import builtin_manifests
from pocketshell.engines.harness import resolve_harnesses
from pocketshell.engines.spec import EngineManifest, LaunchSpec, ProfileSpec, _ID_RE, _effective_reason


try:  # pragma: no cover - import guard
    import yaml
except ImportError:  # pragma: no cover - yaml is a hard dependency
    yaml = None  # type: ignore[assignment]


def registry_config_path(env: Optional[Mapping[str, str]] = None) -> Path:
    source = os.environ if env is None else env
    xdg = source.get("XDG_CONFIG_HOME")
    if xdg:
        base = Path(xdg)
    else:
        home = source.get("HOME") or os.path.expanduser("~")
        base = Path(home) / ".config"
    return base / "pocketshell" / "engines.yaml"


def _read_config(env: Optional[Mapping[str, str]]) -> list[Mapping[str, object]]:
    path = registry_config_path(env)
    if not path.is_file() or yaml is None:
        return []
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):  # type: ignore[union-attr]
        return []
    if not isinstance(raw, Mapping):
        return []
    entries = raw.get("engines")
    if not isinstance(entries, list):
        return []
    return [entry for entry in entries if isinstance(entry, Mapping)]


def _string_tuple(raw: object, default: tuple[str, ...] = ()) -> tuple[str, ...]:
    if not isinstance(raw, (list, tuple)):
        return default
    return tuple(str(item) for item in raw if str(item).strip())


def _profile_from_mapping(
    raw: object,
    base: Optional[ProfileSpec],
) -> Optional[ProfileSpec]:
    if raw is None:
        return base
    if not isinstance(raw, Mapping):
        return base
    return ProfileSpec(
        env_var=str(raw.get("env_var", base.env_var if base else "")),
        default_dirname=str(
            raw.get("default_dirname", base.default_dirname if base else "")
        ),
        markers=_string_tuple(raw.get("markers"), base.markers if base else ()),
        name_hints=_string_tuple(
            raw.get("name_hints"), base.name_hints if base else ()
        ),
        default_label=str(
            raw.get("default_label", base.default_label if base else "")
        ),
    )


def _env_fields_from_mapping(
    env_raw: object,
    base: LaunchSpec,
) -> tuple[tuple[tuple[str, str], ...], tuple[str, ...]]:
    """Read ``env: {set, unset}`` onto the base launch's env fields."""
    if not isinstance(env_raw, Mapping):
        return base.env_set, base.env_unset
    set_raw = env_raw.get("set")
    env_set = (
        tuple((str(key), str(value)) for key, value in set_raw.items())
        if isinstance(set_raw, Mapping)
        else base.env_set
    )
    env_unset = _string_tuple(env_raw.get("unset"), base.env_unset)
    return env_set, env_unset


def _launch_from_mapping(
    raw: object,
    base: LaunchSpec,
) -> LaunchSpec:
    if not isinstance(raw, Mapping):
        return base
    env_set, env_unset = _env_fields_from_mapping(raw.get("env"), base)
    return LaunchSpec(
        argv=_string_tuple(raw.get("argv"), base.argv),
        skip_permissions_argv=_string_tuple(
            raw.get("skip_permissions_argv"), base.skip_permissions_argv
        ),
        env_unset=env_unset,
        env_set=env_set,
        profile_env=(
            str(raw["profile_env"])
            if "profile_env" in raw and raw["profile_env"] is not None
            else base.profile_env
        ),
        profile=_profile_from_mapping(raw.get("profile", base.profile), base.profile),
    )


def _force_available(
    raw: Mapping[str, object],
    base: Optional[EngineManifest],
) -> Optional[bool]:
    """Read the explicit `force_available:` escape hatch (booleans only).

    The `available:` key is NOT accepted as an override: it is an output field
    of `pocketshell engines list --json`, so honouring it as input made a
    stale/copied value hide an installed engine forever (#2276 round 3).
    """
    value = raw.get("force_available")
    if isinstance(value, bool):
        return value
    return base.force_available if base is not None else None


def _configured_reason(
    raw: Mapping[str, object],
    base: Optional[EngineManifest],
) -> Optional[str]:
    if raw.get("unavailable_reason") is not None:
        return str(raw["unavailable_reason"])
    return base.configured_unavailable_reason if base is not None else None


def _validated_engine_id(raw: Mapping[str, object]) -> Optional[str]:
    """Normalise the ``id`` field; ``None`` when absent or malformed."""
    raw_id = raw.get("id")
    if not isinstance(raw_id, str):
        return None
    engine_id = raw_id.strip().lower()
    if not _ID_RE.fullmatch(engine_id):
        return None
    return engine_id


def _optional_str(raw: Mapping[str, object], key: str) -> Optional[str]:
    """``raw[key]`` as a string, or ``None`` when absent / explicitly null."""
    value = raw.get(key)
    return str(value) if value is not None else None


def _fresh_manifest(
    raw: Mapping[str, object],
    engine_id: str,
) -> EngineManifest:
    """Build a brand-new manifest for an id no built-in provides."""
    launch = _launch_from_mapping(
        raw.get("launch"),
        LaunchSpec(argv=(str(raw.get("harness", engine_id)),)),
    )
    return EngineManifest(
        id=engine_id,
        family=str(raw.get("family", engine_id)),
        harness=str(raw.get("harness", engine_id)),
        label=str(raw.get("label", engine_id)),
        provider_mark=str(raw.get("provider_mark", "")),
        usage_provider=_optional_str(raw, "usage_provider"),
        launch=launch,
        enabled=bool(raw.get("enabled", True)),
        available=bool(raw.get("available", True)),
        unavailable_reason=_optional_str(raw, "unavailable_reason"),
        force_available=_force_available(raw, None),
        configured_unavailable_reason=_configured_reason(raw, None),
    )


def _overridden_manifest(
    raw: Mapping[str, object],
    base: EngineManifest,
) -> EngineManifest:
    """Apply engines.yaml overrides onto an existing manifest."""
    return replace(
        base,
        family=str(raw.get("family", base.family)),
        harness=str(raw.get("harness", base.harness)),
        label=str(raw.get("label", base.label)),
        provider_mark=str(raw.get("provider_mark", base.provider_mark)),
        usage_provider=(
            str(raw["usage_provider"])
            if raw.get("usage_provider") is not None
            else base.usage_provider
        ),
        launch=_launch_from_mapping(raw.get("launch"), base.launch),
        enabled=bool(raw.get("enabled", base.enabled)),
        available=bool(raw.get("available", base.available)),
        unavailable_reason=(
            str(raw["unavailable_reason"])
            if raw.get("unavailable_reason") is not None
            else base.unavailable_reason
        ),
        force_available=_force_available(raw, base),
        configured_unavailable_reason=_configured_reason(raw, base),
    )


def _manifest_from_mapping(
    raw: Mapping[str, object],
    base: Optional[EngineManifest],
) -> Optional[EngineManifest]:
    """Registry entry for one engines.yaml mapping, or ``None`` if invalid."""
    engine_id = _validated_engine_id(raw)
    if engine_id is None:
        return None
    if base is None:
        return _fresh_manifest(raw, engine_id)
    return _overridden_manifest(raw, base)


# Engines aplexer lists that must not appear in the PocketShell agent picker.
_HIDDEN_APLEXER_ENGINES = frozenset({"shell"})


def _aplexer_engine_rows(
    env: Optional[Mapping[str, str]] = None,
) -> Optional[list[Mapping[str, object]]]:
    payload = aplexer.run_json(["engines"], env=env, feature="engines")
    if not isinstance(payload, list):
        return None
    return [row for row in payload if isinstance(row, Mapping)]


def _aplexer_launch_for(
    item: EngineManifest,
    row: Mapping[str, object],
) -> LaunchSpec:
    """Overlay aplexer's argv / env_unset onto the manifest's launch spec."""
    command = row.get("command")
    argv = (
        tuple(str(part) for part in command if str(part).strip())
        if isinstance(command, list) and command
        else item.launch.argv
    )
    unset = row.get("env_unset")
    env_unset = (
        tuple(str(part) for part in unset if str(part).strip())
        if isinstance(unset, list)
        else item.launch.env_unset
    )
    return LaunchSpec(
        argv=argv,
        skip_permissions_argv=item.launch.skip_permissions_argv,
        env_unset=env_unset,
        env_set=item.launch.env_set,
        profile_env=item.launch.profile_env,
        profile=item.launch.profile,
    )


def _overlay_aplexer_engines(
    manifests: dict[str, EngineManifest],
    env: Optional[Mapping[str, str]] = None,
) -> None:
    """Overlay argv / env_unset from ``a engines --json``.

    Presentation fields (label, family, provider_mark, skip_permissions_argv)
    stay PocketShell's. Unknown aplexer engines are not added, and aplexer's
    own ``available`` bit is deliberately NOT read: availability is this
    host's own harness resolution (:func:`resolve_harnesses`) — inheriting a
    second tool's cached answer is what hid an installed engine in #2276.
    """
    rows = _aplexer_engine_rows(env)
    if rows is None:
        return
    for row in rows:
        name = row.get("name")
        if not isinstance(name, str) or name in _HIDDEN_APLEXER_ENGINES:
            continue
        item = manifests.get(name)
        if item is None:
            continue
        manifests[name] = replace(item, launch=_aplexer_launch_for(item, row))


def _apply_config_entries(
    manifests: dict[str, EngineManifest],
    order: list[str],
    env: Optional[Mapping[str, str]],
) -> None:
    """Fold engines.yaml entries over the built-ins, keeping first-seen order."""
    for raw in _read_config(env):
        item = _manifest_from_mapping(
            raw, manifests.get(str(raw.get("id", "")).lower())
        )
        if item is None:
            continue
        if item.id not in manifests:
            order.append(item.id)
        manifests[item.id] = item


def _apply_availability(
    item: EngineManifest,
    resolved: dict[str, Optional[str]],
    probe: bool,
) -> EngineManifest:
    """Pick ``available`` from force_available > host probe > configured bit."""
    if item.force_available is not None:
        available: bool = item.force_available
    elif probe:
        available = resolved.get(item.harness) is not None
    else:
        available = item.available
    return replace(
        item,
        available=available,
        unavailable_reason=_effective_reason(item, available),
    )


def _resolved_harnesses(
    items: list[EngineManifest],
    env: Optional[Mapping[str, str]],
    *,
    probe: bool,
) -> dict[str, Optional[str]]:
    """Resolve every harness once (exec PATH, then login shell, then known
    install locations); empty when probing is off."""
    if not probe:
        return {}
    source = os.environ if env is None else env
    return resolve_harnesses(tuple(item.harness for item in items), source)


def load_registry(
    env: Optional[Mapping[str, str]] = None,
    *,
    probe: bool = True,
) -> list[EngineManifest]:
    """Load built-ins plus declarative overrides/additions.

    Availability is a host observation, not config state: when probing is
    enabled every configured harness is resolved once and stale configured
    or aplexer bits cannot override it. The one deliberate override is an
    explicit ``force_available:`` boolean in ``engines.yaml``. The CLI emits
    the full registry, including disabled/unavailable entries, so the picker
    hides only non-createable engines while existing sessions still render
    from their recorded identity. When ``a`` is present, argv/env_unset for
    known ids come from ``a engines --json``; ``engines.yaml`` still wins on
    presentation and can add engines aplexer does not know.
    """
    manifests: dict[str, EngineManifest] = {
        item.id: item for item in builtin_manifests()
    }
    order = list(manifests)
    # Aplexer supplies argv/env_unset for known ids; user yaml still wins
    # if it then overrides the same id.
    _overlay_aplexer_engines(manifests, env)
    _apply_config_entries(manifests, order, env)

    items = [manifests[engine_id] for engine_id in order]
    resolved = _resolved_harnesses(items, env, probe=probe)
    return [_apply_availability(item, resolved, probe) for item in items]


def registry_payload(registry: list[EngineManifest]) -> dict[str, object]:
    return {"engines": [item.to_payload() for item in registry]}


def engine_for(
    engine_id: str,
    env: Optional[Mapping[str, str]] = None,
    *,
    probe: bool = False,
) -> EngineManifest:
    wanted = engine_id.strip().lower()
    for item in load_registry(env, probe=probe):
        if item.id == wanted:
            return item
    raise KeyError(engine_id)


def createable_registry(
    env: Optional[Mapping[str, str]] = None,
) -> list[EngineManifest]:
    return [item for item in load_registry(env) if item.available_for_create]


def json_payload(registry: list[EngineManifest]) -> str:
    return json.dumps(registry_payload(registry), indent=2, sort_keys=False)
