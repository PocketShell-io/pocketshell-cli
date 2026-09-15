"""Read/write/mutate the per-session cards document."""
from __future__ import annotations
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Optional
import click
# --- sibling modules ---
from pocketshell.cards.paths import CardPaths, detect_session
from pocketshell.cards.storage import _session_lock, _write_private
from pocketshell.cards.types import get_card_type


def _now_iso() -> str:
    """Current UTC time as an ISO-8601 string (stable, second precision)."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _import_yaml() -> Any:
    import yaml  # PyYAML is a hard dependency (pyproject); import here for clarity.

    return yaml


def _read_cards_file(path: Path, session: str) -> list[dict[str, Any]]:
    try:
        raw = path.read_text(encoding="utf-8")
    except (FileNotFoundError, IsADirectoryError, PermissionError):
        return []
    if not raw.strip():
        return []
    yaml = _import_yaml()
    try:
        doc = yaml.safe_load(raw)
    except yaml.YAMLError:
        return []
    if not isinstance(doc, Mapping):
        return []
    if doc.get("session") != session:
        return []
    cards = doc.get("cards")
    if not isinstance(cards, list):
        return []
    return [dict(c) for c in cards if isinstance(c, Mapping)]


def read_cards(session: str, *, paths: CardPaths) -> list[dict[str, Any]]:
    """Return the session's list of cards (empty when none / unreadable)."""
    return _read_cards_file(paths.session_file(session), session)


def write_cards(session: str, cards: list[dict[str, Any]], *, paths: CardPaths) -> Path:
    """Atomically persist the session's card list as YAML. Returns the path."""
    path = paths.session_file(session)
    with _session_lock(path):
        _write_cards_file(path, session, cards)
    return path


def _write_cards_file(path: Path, session: str, cards: list[dict[str, Any]]) -> None:
    yaml = _import_yaml()
    doc = {
        "schema": 1,
        "session": session,
        "updated_at": _now_iso(),
        "cards": cards,
    }
    text = yaml.safe_dump(doc, sort_keys=False, default_flow_style=False)
    _write_private(path, text)


def _mutate_cards(
    session: str,
    *,
    paths: CardPaths,
    mutation: Callable[[list[dict[str, Any]]], Any],
) -> tuple[Path, Any]:
    """Apply one read-modify-write transaction under the session lock."""
    path = paths.session_file(session)
    with _session_lock(path):
        cards = _read_cards_file(path, session)
        result = mutation(cards)
        _write_cards_file(path, session, cards)
    return path, result


def _preset_checked_state(
    state: dict[str, Any],
    preset_checked: Optional[list[str]],
) -> dict[str, Any]:
    """Seed ``state["checked"]`` from the parser's ``- [x]`` lines.

    Generic seam: a type whose state has a ``checked`` list honours presets;
    other types ignore an irrelevant preset.
    """
    if preset_checked and isinstance(state.get("checked"), list):
        state["checked"] = list(dict.fromkeys(preset_checked))
    return state


def build_card(
    *,
    card_type: str,
    card_id: str,
    title: Optional[str],
    build_kwargs: dict[str, Any],
    preset_checked: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Construct a fresh card of ``card_type`` via the registry.

    Raises :class:`ValueError` for an unregistered type. ``preset_checked``
    seeds initial state (the checklist parser's ``- [x]`` lines).
    """
    handler = get_card_type(card_type)
    if handler is None:
        raise ValueError(f"unknown card type {card_type!r}")
    now = _now_iso()
    body = handler.build_body(**build_kwargs)
    state = _preset_checked_state(handler.initial_state(body), preset_checked)
    card: dict[str, Any] = {
        "id": card_id,
        "type": card_type,
        "created_at": now,
        "updated_at": now,
        "body": body,
        "state": state,
    }
    if title:
        card["title"] = title
    return card


def upsert_card(session: str, card: dict[str, Any], *, paths: CardPaths) -> Path:
    """Insert or replace ``card`` (matched by ``id``) in the session's list.

    Replace preserves nothing of the old card — a re-push of a checklist by the
    agent is a full replace (hard-cut semantics; the new list is authoritative).
    """
    def mutate(cards: list[dict[str, Any]]) -> None:
        card_id = card["id"]
        cards[:] = [c for c in cards if c.get("id") != card_id]
        cards.append(card)

    path, _ = _mutate_cards(session, paths=paths, mutation=mutate)
    return path


def apply_interaction(
    session: str,
    card_id: str,
    interaction: Mapping[str, Any],
    *,
    paths: CardPaths,
) -> dict[str, Any]:
    """Apply an interaction (e.g. tick) to one card; persist; return the card.

    Raises :class:`ValueError` when the card id is not found in the session, or
    when the type's :meth:`apply_interaction` rejects the interaction.
    """
    def mutate(cards: list[dict[str, Any]]) -> dict[str, Any]:
        target = next((card for card in cards if card.get("id") == card_id), None)
        if target is None:
            raise ValueError(f"no card with id {card_id!r} in session {session!r}")
        handler = get_card_type(target.get("type", ""))
        if handler is None:
            raise ValueError(f"card {card_id!r} has unknown type {target.get('type')!r}")
        body = target.get("body", {}) if isinstance(target.get("body"), Mapping) else {}
        state = target.get("state", {}) if isinstance(target.get("state"), Mapping) else {}
        target["state"] = handler.apply_interaction(dict(body), dict(state), interaction)
        target["updated_at"] = _now_iso()
        return target

    _, target = _mutate_cards(session, paths=paths, mutation=mutate)
    return target


def _require_session(explicit: Optional[str]) -> str:
    session = detect_session(explicit=explicit)
    if session is None:
        raise click.ClickException(
            "could not determine the session: pass --session or set "
            "POCKETSHELL_SESSION in the workload environment."
        )
    return session


def _notify_card_pushed_best_effort(
    session: str, card: dict[str, Any], *, card_paths: CardPaths
) -> None:
    """Fire a best-effort FCM push for a freshly upserted card (#859 Slice D/2).

    The single notification path shared by EVERY card-creating ``push`` verb
    (``checklist``, ``note``, and any future card type). Centralising it here is
    the durable class fix for #1446: a new ``push <cardtype>`` verb that upserts
    a card just calls this one helper, so it can't silently forget to notify the
    phone the way ``push note`` originally did.

    Fail-soft — the push deps are imported lazily so a host without them still
    pushes the card, and any failure is swallowed so a card write never wedges
    the CLI. De-dup + configuration guards live in :func:`notify_card_pushed`.
    """
    try:
        from pocketshell.cards.push import notify_card_pushed

        notify_card_pushed(session, card, card_paths=card_paths)
    except Exception:
        pass
