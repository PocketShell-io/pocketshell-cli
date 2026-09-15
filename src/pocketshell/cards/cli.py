"""Registration of the push-card click commands."""
from __future__ import annotations
import sys
from pathlib import Path
from typing import Any, Mapping, Optional
import click
# --- sibling modules ---
from pocketshell.cards.checklist import DEFAULT_CHECKLIST_ID, _slug, parse_checklist_markdown
from pocketshell.cards.note import DEFAULT_NOTE_ID
from pocketshell.cards.paths import resolve_paths
from pocketshell.cards.store import _import_yaml, _notify_card_pushed_best_effort, _require_session, apply_interaction, build_card, read_cards, upsert_card
from pocketshell.cards.types import get_card_type


def _stdin_text() -> str:
    """Read piped stdin; a TTY (or closed stdin) means "no input"."""
    if sys.stdin is None or sys.stdin.isatty():
        return ""
    return sys.stdin.read()


def _summary_line(card: Mapping[str, Any], unknown_fallback: str) -> str:
    """Render the type-specific one-line summary for a card."""
    handler = get_card_type(card.get("type", ""))
    body = card.get("body", {}) if isinstance(card.get("body"), Mapping) else {}
    state = card.get("state", {}) if isinstance(card.get("state"), Mapping) else {}
    return handler.summarise(dict(body), dict(state)) if handler else unknown_fallback


def _apply_interaction_or_fail(session: str, card_id: str, interaction: dict[str, Any]):
    """Apply an app-side interaction, mapping ValueError to a usage error."""
    try:
        return apply_interaction(session, card_id, interaction, paths=resolve_paths())
    except ValueError as exc:
        raise click.ClickException(str(exc))


def _checklist_payload(items: tuple[str, ...]) -> list[dict[str, Any]]:
    """Build item dicts from repeated ``--item`` flags."""
    parsed: list[dict[str, Any]] = []
    for index, raw in enumerate(items):
        text = raw.strip()
        if not text:
            continue
        slug = _slug(text) or "item"
        parsed.append({"id": f"{slug}-{index}", "text": text, "preset_done": False})
    return parsed


def _checklist_items(items: tuple[str, ...]) -> list[dict[str, Any]]:
    """The parsed item list: ``--item`` flags win over piped markdown."""
    if items:
        return _checklist_payload(items)
    return parse_checklist_markdown(_stdin_text())


def _upsert_and_notify(target: str, card: dict[str, Any]) -> Path:
    """Persist ``card``, then fire the best-effort FCM heads-up push.

    Every agent-facing card upsert notifies (#859 checklists, #1446 notes):
    the phone surfaces a notification opening this session's card feed.
    """
    card_paths = resolve_paths()
    path = upsert_card(target, card, paths=card_paths)
    _notify_card_pushed_best_effort(target, card, card_paths=card_paths)
    return path


@click.command("checklist")
@click.option("--title", "title", default=None, help="Human title for the checklist card.")
@click.option(
    "--id",
    "card_id",
    default=DEFAULT_CHECKLIST_ID,
    help=f"Card id (default {DEFAULT_CHECKLIST_ID!r}; one default checklist per session).",
)
@click.option(
    "--item",
    "items",
    multiple=True,
    help="A checklist item (repeatable). Alternative to piping markdown on stdin.",
)
@click.option("--session", "session", default=None, help="Override the auto-detected session.")
def push_checklist(
    title: Optional[str],
    card_id: str,
    items: tuple[str, ...],
    session: Optional[str],
) -> None:
    """Create/replace the session's checklist card from stdin markdown or --item.

    Reads ``- [ ] item`` markdown on stdin, OR takes repeated ``--item``
    flags. The session is auto-detected from ``$POCKETSHELL_SESSION`` (override with
    ``--session``). A re-push fully replaces the card of that id.
    """
    target = _require_session(session)
    parsed = _checklist_items(items)
    if not parsed:
        raise click.ClickException(
            "no checklist items: pipe `- [ ]` markdown on stdin or pass --item."
        )
    preset_checked = [it["id"] for it in parsed if it.get("preset_done")]
    card = build_card(
        card_type="checklist",
        card_id=card_id,
        title=title,
        build_kwargs={"items": parsed},
        preset_checked=preset_checked,
    )
    path = _upsert_and_notify(target, card)
    click.echo(
        f"checklist {card_id!r} ({len(parsed)} items) -> session {target!r} ({path})"
    )


@click.command("get")
@click.option("--json", "as_json", is_flag=True, help="Emit the cards as a JSON array (for the app).")
@click.option("--session", "session", default=None, help="Override the auto-detected session.")
def push_get(as_json: bool, session: Optional[str]) -> None:
    """Return the session's cards (human/YAML by default, --json for the app)."""
    # No notify (#1446 audit): read-only query, upserts no card. The app is
    # the caller here; there is nothing new to surface.
    import json

    target = _require_session(session)
    cards = read_cards(target, paths=resolve_paths())
    if as_json:
        click.echo(json.dumps({"session": target, "cards": cards}))
        return
    if not cards:
        click.echo(f"(no cards for session {target!r})")
        return
    yaml = _import_yaml()
    click.echo(
        yaml.safe_dump(
            {"session": target, "cards": cards},
            sort_keys=False,
            default_flow_style=False,
        ).rstrip("\n")
    )


def _status_rows(cards: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Reduce cards to id/type/state rows for ``push status``."""
    return [
        {
            "id": card.get("id"),
            "type": card.get("type"),
            "state": card.get("state", {}),
        }
        for card in cards
    ]


@click.command("status")
@click.option("--id", "card_id", default=None, help="Limit to one card id.")
@click.option("--json", "as_json", is_flag=True, help="Emit interaction state as JSON.")
@click.option("--session", "session", default=None, help="Override the auto-detected session.")
def push_status(card_id: Optional[str], as_json: bool, session: Optional[str]) -> None:
    """Report interaction state — which checklist items the human has ticked."""
    # No notify (#1446 audit): read-only query, upserts no card.
    import json

    target = _require_session(session)
    cards = read_cards(target, paths=resolve_paths())
    if card_id is not None:
        cards = [c for c in cards if c.get("id") == card_id]
    statuses = _status_rows(cards)
    if as_json:
        click.echo(json.dumps({"session": target, "status": statuses}))
        return
    if not statuses:
        click.echo(f"(no cards for session {target!r})")
        return
    for card in cards:
        summary = _summary_line(card, unknown_fallback="(unknown type)")
        click.echo(f"{card.get('id')}: {summary}")


@click.command("check")
@click.option("--id", "card_id", required=True, help="The checklist card id.")
@click.option("--item", "item_id", required=True, help="The item id to (un)check.")
@click.option("--done/--undone", "done", default=True, help="Tick (default) or untick the item.")
@click.option("--session", "session", default=None, help="Override the auto-detected session.")
def push_check(card_id: str, item_id: str, done: bool, session: Optional[str]) -> None:
    """Set a checklist item's checked state (this is what the app's tick calls)."""
    # No notify (#1446 audit): this is the APP writing back the human's tick,
    # not an agent pushing a new card. Notifying would push the phone about
    # its own action (and could loop). It mutates state, never upserts a card.
    target = _require_session(session)
    card = _apply_interaction_or_fail(target, card_id, {"item": item_id, "done": done})
    click.echo(f"{card_id}: {_summary_line(card, unknown_fallback='')}")


@click.command("note")
@click.option("--title", "title", default=None, help="Human title for the note card.")
@click.option(
    "--id",
    "card_id",
    default=DEFAULT_NOTE_ID,
    help=f"Card id (default {DEFAULT_NOTE_ID!r}; one default note per session).",
)
@click.option(
    "--text",
    "text",
    default=None,
    help="The note body. Alternative to piping the message on stdin.",
)
@click.option("--session", "session", default=None, help="Override the auto-detected session.")
def push_note(
    title: Optional[str],
    card_id: str,
    text: Optional[str],
    session: Optional[str],
) -> None:
    """Create/replace the session's note card from --text or piped stdin.

    A note is a non-interactive message the human marks read (``push read``).
    The session is auto-detected from ``$POCKETSHELL_SESSION`` (override with ``--session``).
    A re-push fully replaces the card of that id (hard-cut, D22).
    """
    target = _require_session(session)
    body_text = text.strip() if text is not None and text.strip() else _stdin_text().strip()
    if not body_text:
        raise click.ClickException(
            "empty note: pass --text or pipe the message on stdin."
        )
    card = build_card(
        card_type="note",
        card_id=card_id,
        title=title,
        build_kwargs={"text": body_text},
    )
    path = _upsert_and_notify(target, card)
    click.echo(f"note {card_id!r} -> session {target!r} ({path})")


@click.command("read")
@click.option("--id", "card_id", required=True, help="The note card id.")
@click.option("--read/--unread", "read", default=True, help="Mark read (default) or unread.")
@click.option("--session", "session", default=None, help="Override the auto-detected session.")
def push_read(card_id: str, read: bool, session: Optional[str]) -> None:
    """Set a note's read state (this is what the app's "mark read" calls)."""
    # No notify (#1446 audit): this is the APP writing back "human read it",
    # not an agent pushing a new card. Same rationale as `push check`.
    target = _require_session(session)
    card = _apply_interaction_or_fail(target, card_id, {"read": read})
    click.echo(f"{card_id}: {_summary_line(card, unknown_fallback='')}")


def register_push_card_commands(push_group: click.Group) -> None:
    """Register the typed-card verbs onto the existing ``push`` click group.

    Called from :mod:`pocketshell.cli`. Kept as a function (not module-level
    decorators) so the FCM ``push`` group stays the single owner of the group
    object and this module only *extends* it — minimal, additive (#859 scope:
    keep shared registration minimal).
    """
    for command in (
        push_checklist,
        push_get,
        push_status,
        push_check,
        push_note,
        push_read,
    ):
        push_group.add_command(command)
