"""Bound, render, and write handoff transcripts."""
from __future__ import annotations
import sys
from pathlib import Path
from typing import List, Optional
# --- sibling modules ---
from pocketshell.agent_log.messages import HandoffMessage


_DEFAULT_HANDOFF_MAX_TURNS = 30


_DEFAULT_HANDOFF_MAX_CHARS = 20_000


_HANDOFF_PROMPT = (
    "Read this previous agent conversation and continue from the current state. "
    "Use only the user and assistant messages below as context; tool calls and "
    "tool results were omitted. Ask for clarification only if critical context "
    "is missing."
)


def _bound_handoff_messages(
    messages: List[HandoffMessage],
    max_turns: int,
) -> tuple[List[HandoffMessage], int]:
    if max_turns <= 0 or max_turns >= len(messages):
        return list(messages), 0
    omitted = len(messages) - max_turns
    return messages[-max_turns:], omitted


def _render_message(message: HandoffMessage) -> str:
    title = "User" if message.role == "user" else "Assistant"
    return f"### {title}\n\n{message.text}\n"


def _source_lines(
    engine: str,
    session_name: str,
    messages: List[HandoffMessage],
    max_turns: int,
    max_chars: int,
) -> List[str]:
    """The ``## Source`` metadata block of the handoff header."""
    return [
        "## Source",
        "",
        f"- Engine: {engine}",
        f"- Session: {session_name}",
        f"- Messages included: {len(messages)}",
        f"- Max turns: {max_turns}",
        f"- Max chars: {max_chars}",
        "- Omitted by default: tool calls, tool results, command output, reasoning, and system notes",
    ]


def _render_header(
    *,
    engine: str,
    session: str,
    messages: List[HandoffMessage],
    omitted_for_turns: int,
    max_turns: int,
    max_chars: int,
) -> str:
    """The prompt + source-metadata header, with the omission banner."""
    session_name = session.removesuffix(".jsonl")
    header_parts = [
        "# Agent Handoff",
        "",
        "## Ready Prompt",
        "",
        _HANDOFF_PROMPT,
        "",
        *_source_lines(engine, session_name, messages, max_turns, max_chars),
        "",
        "## Conversation",
        "",
    ]
    if omitted_for_turns:
        header_parts.extend([f"[{omitted_for_turns} earlier message(s) omitted by --max-turns.]", ""])
    return "\n".join(header_parts)


def _fit_output(header: str, body: str, max_chars: int) -> str:
    """Bound ``header + body`` to ``max_chars``, trimming the body first."""
    output = header + body
    if len(output) <= max_chars:
        return output

    marker = "[Earlier conversation text omitted to fit --max-chars.]\n\n"
    budget = max_chars - len(header) - len(marker)
    if budget > 0:
        output = header + marker + body[-budget:].lstrip()
    if len(output) <= max_chars:
        return output

    # Extremely small limits cannot fit the complete header. Keep the ready
    # prompt at the front and hard-bound the artifact.
    truncated = output[:max_chars].rstrip()
    return truncated + "\n" if len(truncated) < max_chars else truncated


def _render_handoff_markdown(
    *,
    engine: str,
    session: str,
    messages: List[HandoffMessage],
    omitted_for_turns: int,
    max_turns: int,
    max_chars: int,
) -> str:
    """Render the bounded conversation as a handoff Markdown artifact."""
    header = _render_header(
        engine=engine,
        session=session,
        messages=messages,
        omitted_for_turns=omitted_for_turns,
        max_turns=max_turns,
        max_chars=max_chars,
    )
    body = "\n".join(_render_message(message) for message in messages)
    return _fit_output(header, body, max_chars)


def _write_handoff_output(text: str, out: Optional[Path]) -> None:
    if out is None:
        sys.stdout.write(text)
        if not text.endswith("\n"):
            sys.stdout.write("\n")
        return
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
