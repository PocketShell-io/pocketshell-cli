"""Normalise provider JSONL rows into HandoffMessage lists."""
from __future__ import annotations
import json
import re
from dataclasses import dataclass
from typing import Any, Iterable, List, Optional


@dataclass(frozen=True)
class HandoffMessage:
    """A compact transcript message for cross-agent handoff output."""

    role: str
    text: str


_CLAUDE_SYSTEM_NOTE_TAGS = [
    "system-reminder",
    "command-name",
    "command-args",
    "command-message",
    "command-stdout",
    "local-command-stdout",
]


def _parse_json_line(line: str) -> Optional[dict[str, Any]]:
    """Parse one JSONL row, returning ``None`` for malformed/partial rows."""
    try:
        value = json.loads(line)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def _normalise_text(text: str) -> str:
    """Trim surrounding whitespace and drop blank transcript fragments."""
    return text.strip()


def _text_from_scalar(value: Any) -> Optional[str]:
    if isinstance(value, str):
        text = _normalise_text(value)
        return text if text else None
    return None


def _text_parts_from_content(value: Any, allowed_types: set[str]) -> List[str]:
    """Extract plain text content blocks without tool-call/tool-result blocks."""
    if isinstance(value, str):
        text = _normalise_text(value)
        return [text] if text else []
    if isinstance(value, dict):
        block_type = value.get("type")
        if isinstance(block_type, str) and block_type not in allowed_types:
            return []
        text = _text_from_scalar(value.get("text"))
        if text is not None:
            return [text]
        return _text_parts_from_content(value.get("content"), allowed_types)
    if isinstance(value, list):
        parts: List[str] = []
        for item in value:
            parts.extend(_text_parts_from_content(item, allowed_types))
        return parts
    return []


def _strip_claude_system_notes(text: str) -> str:
    """Remove Claude XML-style system-note blocks from otherwise-human text."""
    cleaned = text
    for tag in _CLAUDE_SYSTEM_NOTE_TAGS:
        cleaned = re.sub(
            rf"(?is)<{re.escape(tag)}(?:\s[^>]*)?>.*?</{re.escape(tag)}>",
            "",
            cleaned,
        )
    return _normalise_text(cleaned)


def _claude_messages_from_row(row: dict[str, Any]) -> List[HandoffMessage]:
    message = row.get("message") if isinstance(row.get("message"), dict) else None
    role = row.get("role") or (message or {}).get("role") or row.get("type")
    if role not in {"user", "assistant"}:
        return []

    content = (message or {}).get("content") if message is not None else row.get("content")
    fragments = _text_parts_from_content(content, {"text"})
    messages: List[HandoffMessage] = []
    for fragment in fragments:
        text = _strip_claude_system_notes(fragment)
        if text:
            messages.append(HandoffMessage(role=role, text=text))
    return messages


def _codex_message_text(item: dict[str, Any]) -> Optional[str]:
    for key in ("message", "text"):
        text = _text_from_scalar(item.get(key))
        if text is not None:
            return text
    parts = _text_parts_from_content(item.get("content"), {"input_text", "output_text", "text"})
    return "\n\n".join(parts).strip() if parts else None


def _codex_messages_from_row(row: dict[str, Any]) -> List[HandoffMessage]:
    item = row.get("payload") if isinstance(row.get("payload"), dict) else None
    if item is None:
        item = row.get("item") if isinstance(row.get("item"), dict) else row

    item_type = item.get("type") or row.get("type")
    if item_type == "message":
        role = item.get("role")
        if role not in {"user", "assistant"}:
            return []
    elif item_type == "user_message":
        role = "user"
    elif item_type in {"assistant_message", "agent_message"}:
        role = "assistant"
    else:
        return []

    text = _codex_message_text(item)
    return [HandoffMessage(role=role, text=text)] if text else []


def _json_object_from_string(value: Any) -> Optional[dict[str, Any]]:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _opencode_role(row: dict[str, Any], message_data: Optional[dict[str, Any]]) -> Optional[str]:
    role = row.get("message_role") or row.get("messageRole") or row.get("role")
    if role is None and message_data is not None:
        role = message_data.get("role")
    return role if role in {"user", "assistant"} else None


def _opencode_part_text(part: Optional[dict[str, Any]]) -> Optional[str]:
    if part is None:
        return None
    part_type = part.get("type")
    if part_type in {"tool_use", "tool", "tool_result", "function_call_output", "reasoning"}:
        return None
    if isinstance(part_type, str) and part_type not in {"input_text", "output_text", "text"}:
        return None
    parts = _text_parts_from_content(part, {"input_text", "output_text", "text"})
    return "\n\n".join(parts).strip() if parts else None


def _opencode_messages_from_row(row: dict[str, Any]) -> List[HandoffMessage]:
    message_data = _json_object_from_string(
        row.get("message_data") or row.get("messageData") or row.get("msg_data")
    )
    role = _opencode_role(row, message_data)
    if role is None:
        return []

    part_data = _json_object_from_string(row.get("part_data") or row.get("partData"))
    part_text = _opencode_part_text(part_data)
    if part_text:
        return [HandoffMessage(role=role, text=part_text)]

    fallback = (
        _text_from_scalar(row.get("message_content"))
        or _text_from_scalar(row.get("messageContent"))
        or _text_from_scalar(row.get("content"))
        or _text_from_scalar(row.get("text"))
        or _opencode_part_text(message_data)
    )
    return [HandoffMessage(role=role, text=fallback)] if fallback else []


def _grok_content_text(update: dict[str, Any]) -> Optional[str]:
    content = update.get("content")
    if isinstance(content, dict):
        return _text_from_scalar(content.get("text"))
    return _text_from_scalar(content)


def _grok_messages_from_row(row: dict[str, Any]) -> List[HandoffMessage]:
    params = row.get("params") if isinstance(row.get("params"), dict) else {}
    update = params.get("update") if isinstance(params.get("update"), dict) else {}
    kind = update.get("sessionUpdate")
    if kind == "user_message_chunk":
        text = _grok_content_text(update)
        return [HandoffMessage(role="user", text=text)] if text else []
    if kind == "agent_message_chunk":
        text = _grok_content_text(update)
        return [HandoffMessage(role="assistant", text=text)] if text else []
    return []


def _handoff_messages_from_row(engine: str, row: dict[str, Any]) -> List[HandoffMessage]:
    """Dispatch one parsed JSONL row to its per-engine message extractor."""
    if engine == "claude":
        return _claude_messages_from_row(row)
    if engine == "codex":
        return _codex_messages_from_row(row)
    if engine == "opencode":
        return _opencode_messages_from_row(row)
    if engine == "grok":
        return _grok_messages_from_row(row)
    return []


def _handoff_messages_from_lines(engine: str, lines: Iterable[str]) -> List[HandoffMessage]:
    """Extract user/assistant prose from raw agent JSONL rows."""
    messages: List[HandoffMessage] = []
    for line in lines:
        row = _parse_json_line(line)
        if row is None:
            continue
        messages.extend(_handoff_messages_from_row(engine, row))
    return messages
