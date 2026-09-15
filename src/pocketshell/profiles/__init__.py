"""Server-side agent profile discovery + the `pocketshell profiles` group.

Issue [#718](https://github.com/alexeygrigorev/pocketshell/issues/718),
slice 1 (server). Profiles are defined **once on the host** — never edited
on the mobile client — so the client can fetch them with
``pocketshell profiles list`` and feed its picker.

A *profile* names a coding-agent config dir:

- **claude** → ``CLAUDE_CONFIG_DIR``
- **codex** → ``CODEX_HOME``

(opencode has no profile env var, so it is out of scope — see
``build_env`` in :mod:`pocketshell.agents`.)

Two complementary sources are merged (the explicit config file wins on a
name collision):

1. **Conventional-dir auto-discovery** (the zero-config path). For each
   engine, scan the top level of ``$HOME`` for config dirs that carry a
   real *marker* file:

   - claude marker: ``.claude.json`` **or** ``settings.json``
   - codex marker: ``config.toml`` **or** ``auth.json``

   The engine's **default** dir (``~/.claude`` / ``~/.codex``) becomes the
   default profile, named after the engine ("Claude" / "Codex") and sorted
   first; the picker pre-selects it. Any *sibling* dir that matches the
   engine's name pattern and carries a marker becomes a non-default profile
   (e.g. ``~/.zlaude`` → "Claude (Z.AI)" via a small known-alias map, with
   a humanised dir-stem fallback). Discovery is deliberately conservative:
   top-level ``~/.<name>`` dirs only, a real marker file required, never
   recursive, so a stray empty dir never becomes a phantom profile.

2. **Optional explicit config** ``~/.config/pocketshell/profiles.yaml``
   (``XDG_CONFIG_HOME`` honoured). A list of
   ``{name, engine, config_dir, env?}`` entries. It augments and overrides
   discovery: an explicit profile wins on a ``name`` collision, and its
   ``config_dir`` claims that ``(engine, dir)`` so discovery won't add a
   duplicate.

Security: a profile references **config_dirs only, never keys**. Discovery
stats a handful of dirs and reads marker *names* — it never reads inside a
config dir (those hold ``auth.json`` / ``.env``). ``profiles list`` emits
``{name, engine, config_dir, default}`` and nothing else.

Aplexer integration (Phase A, #2341): when the ``a`` binary is on PATH,
``discover_profiles`` probes ``a profiles --json`` and **prefers** those
sibling profiles, keeping native ``Claude``/``Codex`` defaults. Native
discovery is the fallback when ``a`` is missing, the probe fails, or
``POCKETSHELL_APLEXER=0`` / ``POCKETSHELL_APLEXER_PROFILES=0`` is set.
See ``docs/aplexer-integration.md``.
"""
from __future__ import annotations

from pocketshell.profiles.cli import (
    profiles_group,
)
from pocketshell.profiles.discovery import (
    _profiles_from_aplexer_json,
    _aplexer_profiles,
    discover_profiles,
)
from pocketshell.profiles.model import (
    Profile,
)
from pocketshell.profiles.resolve import (
    load_profiles,
    load_config_profiles,
    resolve_profile,
    resolve_aplexer_profile_arg,
)

__all__ = [
    "Profile",
    "_profiles_from_aplexer_json",
    "_aplexer_profiles",
    "_profiles_from_aplexer_json",
    "_aplexer_profiles",
    "discover_profiles",
    "load_profiles",
    "load_config_profiles",
    "resolve_profile",
    "resolve_aplexer_profile_arg",
    "profiles_group",
]
