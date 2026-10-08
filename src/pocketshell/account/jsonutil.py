"""Strict JSON decoding for broker responses and the credentials file.

Rejects: invalid UTF-8, a BOM, duplicate object keys (two parsers could
disagree on which value wins), NaN/Infinity, and absurd nesting.
"""

from __future__ import annotations

import json


class StrictJSONError(ValueError):
    """The document is not strict JSON. The message never contains the input."""


_MAX_DEPTH = 32


def _no_duplicates(pairs: list[tuple[str, object]]) -> dict:
    out: dict = {}
    for key, value in pairs:
        if key in out:
            raise StrictJSONError("duplicate key")
        out[key] = value
    return out


def _reject_constant(_name: str) -> object:
    raise StrictJSONError("non-finite number")


def _depth_ok(value: object, depth: int = 0) -> bool:
    if depth > _MAX_DEPTH:
        return False
    if isinstance(value, dict):
        return all(_depth_ok(v, depth + 1) for v in value.values())
    if isinstance(value, list):
        return all(_depth_ok(v, depth + 1) for v in value)
    return True


def loads_strict(raw: bytes) -> object:
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise StrictJSONError("not UTF-8") from None
    if text.startswith("﻿"):
        raise StrictJSONError("byte-order mark")
    try:
        value = json.loads(
            text, object_pairs_hook=_no_duplicates, parse_constant=_reject_constant
        )
    except StrictJSONError:
        raise
    except (ValueError, RecursionError):
        raise StrictJSONError("malformed JSON") from None
    if not _depth_ok(value):
        raise StrictJSONError("too deeply nested")
    return value
