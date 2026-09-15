"""Card type registry public surface.

Concrete built-in types live beside the registry and are imported explicitly
by :mod:`pocketshell.cards` so registration remains visible at composition
time without making this package recursively import the card façade.
"""

from pocketshell.cards.types.registry import (
    CardType,
    REGISTRY,
    get_card_type,
    register_card_type,
)

__all__ = [
    "CardType",
    "REGISTRY",
    "get_card_type",
    "register_card_type",
]
