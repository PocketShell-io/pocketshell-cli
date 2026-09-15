"""Card type registry: checklist, note, and user registrations."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional


@dataclass(frozen=True)
class CardType:
    """One registered card type and its behaviour.

    - ``name`` — the registry key (the card's ``type`` field).
    - ``build_body`` — turn type-specific CLI input (a kwargs dict) into the
      persisted ``body`` payload.
    - ``initial_state`` — the ``state`` payload for a freshly-built card.
    - ``apply_interaction`` — mutate ``state`` in place for an interaction (e.g.
      tick an item / mark a note read). Returns the (possibly new) state dict.
    - ``summarise`` — a short one-line human description for ``push get`` /
      ``push status`` text output.
    """

    name: str
    build_body: Callable[..., dict[str, Any]]
    initial_state: Callable[[dict[str, Any]], dict[str, Any]]
    apply_interaction: Callable[[dict[str, Any], dict[str, Any], Mapping[str, Any]], dict[str, Any]]
    summarise: Callable[[dict[str, Any], dict[str, Any]], str]


REGISTRY: dict[str, CardType] = {}


def register_card_type(card_type: CardType) -> None:
    """Register a :class:`CardType`. Adding a new type is exactly this call."""
    REGISTRY[card_type.name] = card_type


def get_card_type(name: str) -> Optional[CardType]:
    return REGISTRY.get(name)
