"""Generic per-session typed-card store — the agent→app "push feed" (epic #859).

A running agent (Claude/Codex on the host) pushes a **typed card** to the
PocketShell app, scoped to the **current aplexer session**; the app renders each
card by its type and writes interaction state back. This module is the host
side of that channel: a **generic** typed-card store keyed by session,
with a **type registry**. v1 registers ONE card type — ``checklist`` — but the
store + registry are deliberately type-agnostic so adding ``note`` (mark-as-read)
or ``choice``/``approval`` later is just a new schema + handler, no new
transport (issue #859, Phase 1; the maintainer's "generic channel, checklist
FIRST" refinement).

Card model (generic, unchanged across types)::

    {
      "id":         "<card id>",          # stable per card
      "type":       "checklist",          # registry key
      "created_at": "<iso8601 utc>",
      "updated_at": "<iso8601 utc>",
      "title":      "<human title>",      # optional, per type
      "body":       {...},                # type-specific payload
      "state":      {...},                # type-specific interaction state
    }

For the ``checklist`` type:

- ``body  = {"items": [{"id": "<item id>", "text": "<item text>"}, ...]}``
- ``state = {"checked": ["<item id>", ...]}``

Storage
-------

One YAML document per session under ``~/.pocketshell/cards/<session>.yaml``
(mirrors the ``reviews/`` inbox convention #714 — but two-way), holding the
session's list of cards. The app reads it over the warm session (D21, no new
connection) via ``pocketshell push get --json`` and writes interaction state
back via ``pocketshell push check``. Persisted with the atomic temp-file +
``os.replace`` private-write pattern (mode 0600, dir 0700) copied from
:mod:`pocketshell.tree`, so a concurrent reader never sees a half-written file.

The state is durable (survives a CLI process restart and a reconnect) because
it lives host-side, keyed by the session the agent is running in.

Why a TYPE REGISTRY (not an ``if card["type"] == "checklist"`` ladder)
----------------------------------------------------------------------

Each card type is a :class:`CardType` registered in :data:`REGISTRY`. A type
owns: building its ``body`` from CLI input, its initial ``state``, applying an
interaction (e.g. tick an item), and summarising itself for the human/YAML
output. Adding ``note`` later = register one more :class:`CardType` — the store,
the CLI verbs, and the persistence are unchanged. The :func:`register_card_type`
seam is exercised by a unit test with a stub second type so this extensibility
is proven, not merely asserted in a docstring.
"""
from __future__ import annotations

from pocketshell.cards.types.checklist import (
    DEFAULT_CHECKLIST_ID,
    parse_checklist_markdown,
)
from pocketshell.cards.cli import (
    register_push_card_commands,
)
from pocketshell.cards.types.note import (
    DEFAULT_NOTE_ID,
)
from pocketshell.cards.paths import (
    CardPaths,
    CARDS_DIR_ENV,
    resolve_paths,
    detect_session,
)
from pocketshell.cards.storage import (
    NEW_FILE_MODE,
    _write_private,
    _session_lock,
)
from pocketshell.cards.store import (
    read_cards,
    write_cards,
    build_card,
    upsert_card,
    apply_interaction,
)
from pocketshell.cards.types.registry import (
    CardType,
    REGISTRY,
    register_card_type,
    get_card_type,
)

__all__ = [
    "NEW_FILE_MODE",
    "CardPaths",
    "CARDS_DIR_ENV",
    "resolve_paths",
    "detect_session",
    "CardType",
    "REGISTRY",
    "register_card_type",
    "get_card_type",
    "DEFAULT_CHECKLIST_ID",
    "parse_checklist_markdown",
    "DEFAULT_NOTE_ID",
    "read_cards",
    "write_cards",
    "build_card",
    "upsert_card",
    "apply_interaction",
    "register_push_card_commands",
    "_write_private",
    "_session_lock",
]
