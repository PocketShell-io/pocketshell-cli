"""The built-in checklist card type."""
from __future__ import annotations
import re
from typing import Any, Mapping
# --- sibling modules ---
from pocketshell.cards.types import CardType, register_card_type


# Default checklist card id used when ``--id`` is omitted: a session has exactly
# one "default" checklist unless the agent names them, which keeps the common
# ``push checklist`` → ``push check`` flow free of id juggling.
DEFAULT_CHECKLIST_ID = "checklist"


def _slug(text: str) -> str:
    """Lowercase ASCII slug of ``text`` for a stable, readable item id."""
    cleaned = re.sub(r"[^a-z0-9]+", "-", text.strip().lower()).strip("-")
    return cleaned[:48]


# A markdown checklist item line: `- [ ] text` or `- [x] text` (also `* ` / `+ `).
_CHECKLIST_LINE = re.compile(r"^\s*[-*+]\s*\[(?P<mark>[ xX])\]\s*(?P<text>.+?)\s*$")


def parse_checklist_markdown(markdown: str) -> list[dict[str, Any]]:
    """Parse ``- [ ] item`` / ``- [x] item`` markdown lines into items.

    Returns ``[{"id", "text", "preset_done"}]`` in source order. Lines that do
    not match a checklist bullet are ignored, so an agent can pipe a section of
    a larger doc. Item ids are a readable slug of the text plus an index to
    keep them unique even when two items share text.
    """
    items: list[dict[str, Any]] = []
    for index, line in enumerate(markdown.splitlines()):
        match = _CHECKLIST_LINE.match(line)
        if match is None:
            continue
        text = match.group("text").strip()
        if not text:
            continue
        preset_done = match.group("mark").lower() == "x"
        slug = _slug(text) or "item"
        item_id = f"{slug}-{index}"
        items.append({"id": item_id, "text": text, "preset_done": preset_done})
    return items


def _checklist_build_body(*, items: list[dict[str, Any]], **_: Any) -> dict[str, Any]:
    """Build the checklist ``body`` — ``{"items": [{id, text}]}``."""
    return {"items": [{"id": it["id"], "text": it["text"]} for it in items]}


def _checklist_initial_state(body: dict[str, Any]) -> dict[str, Any]:
    """Initial checked set — honour any ``- [x]`` presets if carried on items."""
    # ``body`` only carries id+text; presets ride on the build-time item list,
    # so initial state starts empty and presets are applied by the builder via
    # ``preset_checked`` (see :func:`build_card`).
    return {"checked": []}


def _checklist_apply_interaction(
    body: dict[str, Any],
    state: dict[str, Any],
    interaction: Mapping[str, Any],
) -> dict[str, Any]:
    """Tick/untick one item.

    ``interaction = {"item": "<item id>", "done": bool}``. ``done`` defaults to
    True (tick). Raises :class:`ValueError` if the item id is unknown so the CLI
    surfaces a clear error rather than silently no-opping.
    """
    item_id = interaction.get("item")
    if not isinstance(item_id, str) or not item_id:
        raise ValueError("checklist: `item` (item id) is required")
    known = {it.get("id") for it in body.get("items", []) if isinstance(it, Mapping)}
    if item_id not in known:
        raise ValueError(f"checklist: unknown item id {item_id!r}")
    done = bool(interaction.get("done", True))
    checked = [c for c in state.get("checked", []) if isinstance(c, str)]
    if done and item_id not in checked:
        checked.append(item_id)
    elif not done and item_id in checked:
        checked = [c for c in checked if c != item_id]
    return {"checked": checked}


def _checklist_summarise(body: dict[str, Any], state: dict[str, Any]) -> str:
    items = body.get("items", [])
    checked = state.get("checked", [])
    total = len(items) if isinstance(items, list) else 0
    done = len(checked) if isinstance(checked, list) else 0
    return f"checklist {done}/{total} checked"


register_card_type(
    CardType(
        name="checklist",
        build_body=_checklist_build_body,
        initial_state=_checklist_initial_state,
        apply_interaction=_checklist_apply_interaction,
        summarise=_checklist_summarise,
    )
)
