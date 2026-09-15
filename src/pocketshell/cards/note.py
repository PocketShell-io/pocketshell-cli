"""The built-in note card type."""
from __future__ import annotations
from typing import Any, Mapping
# --- sibling modules ---
from pocketshell.cards.store import _now_iso
from pocketshell.cards.types import CardType, register_card_type


# Default note card id used when ``--id`` is omitted (one default note per
# session unless the agent names them — mirrors DEFAULT_CHECKLIST_ID).
DEFAULT_NOTE_ID = "note"


def _note_build_body(*, text: str, **_: Any) -> dict[str, Any]:
    """Build the note ``body`` — ``{"text": <message>}``."""
    return {"text": text}


def _note_initial_state(_body: dict[str, Any]) -> dict[str, Any]:
    """A fresh note is unread."""
    return {"read": False, "read_at": None}


def _note_apply_interaction(
    body: dict[str, Any],
    state: dict[str, Any],
    interaction: Mapping[str, Any],
) -> dict[str, Any]:
    """Mark a note read/unread.

    ``interaction = {"read": bool}``. ``read`` defaults to True (mark read).
    ``read_at`` records when it was first read (cleared on unread) so the agent
    can see acknowledgement timing via ``push status``.
    """
    read = bool(interaction.get("read", True))
    return {"read": read, "read_at": _now_iso() if read else None}


def _note_summarise(body: dict[str, Any], state: dict[str, Any]) -> str:
    return "note: read" if state.get("read") else "note: unread"


register_card_type(
    CardType(
        name="note",
        build_body=_note_build_body,
        initial_state=_note_initial_state,
        apply_interaction=_note_apply_interaction,
        summarise=_note_summarise,
    )
)
