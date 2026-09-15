"""The `pocketshell agent-log` click command group."""
from __future__ import annotations
import json
import os
import sys
from pathlib import Path
from typing import List, Optional
import click
# --- sibling modules ---
from pocketshell.agent_log.handoff import _DEFAULT_HANDOFF_MAX_CHARS, _DEFAULT_HANDOFF_MAX_TURNS, _bound_handoff_messages, _render_handoff_markdown, _write_handoff_output
from pocketshell.agent_log.messages import _handoff_messages_from_lines
from pocketshell.agent_log.readers import _clamp_line_bytes, _read_lines, _tail
from pocketshell.agent_log.resolve import _resolve_log_path
from pocketshell.agent_log.roots import _claude_projects_root, _codex_sessions_root, _grok_sessions_root, _opencode_root


# Sentinel exit codes (mirrors the convention used by ``usage`` / ``jobs``):
#
# - 0   -> success; lines were read (possibly zero) and written out.
# - 2   -> bad invocation (e.g. unknown engine). Click handles this for
#          us via its ``BadParameter`` path; we only set it explicitly
#          when we need to bail out after Click validation.
# - 66  -> ``EX_NOINPUT`` from <sysexits.h>: the resolved log path does
#          not exist. Distinct from "command not found" (127) so a
#          daemon consumer can tell "session id is wrong" apart from
#          "binary is missing".
_EXIT_LOG_NOT_FOUND = 66


def _emit_text(lines: List[str]) -> None:
    """Write each line followed by a newline to stdout.

    The output is byte-identical to ``tail -n N <path>`` for the same N
    (modulo a trailing newline on the last line, which ``tail``
    preserves and we re-add unconditionally). Downstream consumers that
    already parse JSONL line-by-line keep working.
    """
    for line in lines:
        sys.stdout.write(line)
        sys.stdout.write("\n")


def _emit_json(
    engine: str,
    session: str,
    path: Path,
    lines: List[str],
) -> None:
    """Emit a JSON envelope ``{engine, session, path, count, lines}``.

    ``lines`` holds the raw JSONL strings verbatim (NOT pre-parsed JSON
    objects). The Kotlin parsers stay authoritative for the structural
    contract; this envelope only proves provenance.
    """
    envelope = {
        "engine": engine,
        "session": session.removesuffix(".jsonl"),
        "path": str(path),
        "count": len(lines),
        "lines": lines,
    }
    # ``indent=None`` keeps the envelope on one line so a daemon
    # consumer can stream events without a multi-line parser. Sorted
    # keys make the output deterministic for golden-file tests.
    json.dump(envelope, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")


def _require_log_options(
    session: Optional[str],
    engine: Optional[str],
) -> tuple[str, str]:
    """Validate the two required options; return ``(engine, session)`` normalised.

    Both options are declared optional because the group must also accept
    bare ``agent-log handoff ...`` invocations without them.
    """
    if session is None:
        raise click.UsageError("Missing option '--session' / '-s'.")
    if engine is None:
        raise click.UsageError("Missing option '--engine' / '-e'.")
    return engine.lower(), session


def _bail_log_not_found(engine: str, session: str) -> None:
    """Print the friendly search-miss message and exit ``EX_NOINPUT`` (66).

    Shared by ``agent-log`` and ``agent-log handoff``; mirrors the
    install-hint style used by ``usage`` / ``jobs`` for missing binaries.
    """
    click.echo(
        (
            f"pocketshell: no {engine} session log found for "
            f"`{session}`. Looked under "
            f"{_search_root_for(engine)} "
            f"(use --cwd for Claude if the session was launched from a "
            f"specific project directory)."
        ),
        err=True,
    )
    raise click.exceptions.Exit(_EXIT_LOG_NOT_FOUND)


def _handoff_transcript(
    *,
    engine: str,
    session: str,
    path: Path,
    max_turns: int,
    max_chars: int,
) -> str:
    """Filter the raw log to user/assistant turns and render the artifact."""
    messages = _handoff_messages_from_lines(engine, _read_lines(path))
    bounded_messages, omitted_for_turns = _bound_handoff_messages(messages, max_turns)
    return _render_handoff_markdown(
        engine=engine,
        session=session,
        messages=bounded_messages,
        omitted_for_turns=omitted_for_turns,
        max_turns=max_turns,
        max_chars=max_chars,
    )


@click.group(
    "agent-log",
    invoke_without_command=True,
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.option(
    "--session",
    "-s",
    "session",
    required=False,
    type=str,
    help=(
        "Session id — usually the JSONL file's basename. Accepts both "
        "`abc123` and `abc123.jsonl`."
    ),
)
@click.option(
    "--engine",
    "-e",
    "engine",
    required=False,
    type=click.Choice(["claude", "codex", "opencode", "grok"], case_sensitive=False),
    help="Which agent CLI's log to read.",
)
@click.option(
    "--cwd",
    "cwd",
    type=str,
    default=None,
    help=(
        "Working directory the agent was launched from. Used for "
        "Claude Code and Grok Build (to pick the right encoded-cwd "
        "subdirectory). Ignored for codex and opencode."
    ),
)
@click.option(
    "--tail",
    "-n",
    "tail_count",
    type=click.IntRange(min=0),
    default=None,
    help="Emit only the last N events. Default: emit the whole file.",
)
@click.option(
    "--json",
    "json_output",
    is_flag=True,
    help="Emit a JSON envelope (`{engine, session, path, count, lines}`) instead of raw JSONL.",
)
@click.option(
    "--max-line-bytes",
    "max_line_bytes",
    type=click.IntRange(min=0),
    default=None,
    help=(
        "Replace any single log line longer than N bytes with a compact "
        "truncation marker, server-side, so one multi-megabyte line (a pasted "
        "image / huge tool result) cannot balloon the read into the client's "
        "heap. Default: no clamp (emit lines verbatim)."
    ),
)
@click.pass_context
def agent_log_command(
    ctx: click.Context,
    session: Optional[str],
    engine: Optional[str],
    cwd: Optional[str],
    tail_count: Optional[int],
    json_output: bool,
    max_line_bytes: Optional[int],
) -> None:
    """Print an agent JSONL conversation log.

    Emits the canonical per-engine JSONL as raw lines (default) or inside a
    JSON envelope (``--json``). ``--tail N`` bounds output to the last N
    events; ``--max-line-bytes N`` degrades one pathological line to a
    truncation marker (#1225/#1267). Exit codes: 0 ok; 66 log not found;
    2 bad invocation (handled by Click).
    """
    if ctx.invoked_subcommand is not None:
        return
    engine_normalised, session_id = _require_log_options(session, engine)
    path = _resolve_log_path(engine_normalised, session_id, cwd)
    if path is None:
        _bail_log_not_found(engine_normalised, session_id)

    lines = _clamp_line_bytes(_tail(_read_lines(path), tail_count), max_line_bytes)
    if json_output:
        _emit_json(engine_normalised, session_id, path, lines)
    else:
        _emit_text(lines)


@agent_log_command.command(
    "handoff",
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.option(
    "--session",
    "-s",
    "session",
    required=True,
    type=str,
    help=(
        "Session id — usually the JSONL file's basename. Accepts both "
        "`abc123` and `abc123.jsonl`."
    ),
)
@click.option(
    "--engine",
    "-e",
    "engine",
    required=True,
    type=click.Choice(["claude", "codex", "opencode", "grok"], case_sensitive=False),
    help="Which agent CLI's log to export.",
)
@click.option(
    "--cwd",
    "cwd",
    type=str,
    default=None,
    help=(
        "Working directory the agent was launched from. Used for "
        "Claude Code and Grok Build; ignored for codex and opencode."
    ),
)
@click.option(
    "--max-turns",
    "max_turns",
    type=click.IntRange(min=0),
    default=_DEFAULT_HANDOFF_MAX_TURNS,
    show_default=True,
    help=(
        "Include at most the last N user/assistant messages after filtering. "
        "Use 0 for all filtered messages."
    ),
)
@click.option(
    "--max-chars",
    "max_chars",
    type=click.IntRange(min=500),
    default=_DEFAULT_HANDOFF_MAX_CHARS,
    show_default=True,
    help="Hard cap for the rendered Markdown artifact.",
)
@click.option(
    "--out",
    "out",
    type=click.Path(dir_okay=False, path_type=Path),
    default=None,
    help="Write the Markdown artifact to this file. Default: stdout.",
)
def handoff_command(
    session: str,
    engine: str,
    cwd: Optional[str],
    max_turns: int,
    max_chars: int,
    out: Optional[Path],
) -> None:
    """Export a compact user/assistant transcript for another agent.

    The handoff artifact is Markdown/plain text with a ready-to-paste
    continuation prompt. Tool calls, tool results, reasoning, command
    output, and system-note records are excluded by default.
    """
    engine_normalised = engine.lower()
    path = _resolve_log_path(engine_normalised, session, cwd)
    if path is None:
        _bail_log_not_found(engine_normalised, session)
    output = _handoff_transcript(
        engine=engine_normalised,
        session=session,
        path=path,
        max_turns=max_turns,
        max_chars=max_chars,
    )
    _write_handoff_output(output, out)


def _search_root_for(engine: str) -> str:
    """Human-friendly description of where ``engine`` logs live.

    Used only inside the error message when the resolver returns
    ``None``. Pulled out for readability and so the test suite can
    reuse it via the public ``_resolve_*_path`` helpers without
    re-deriving the paths.
    """
    if engine == "claude":
        return str(_claude_projects_root()) + os.sep + "<encoded-cwd>" + os.sep
    if engine == "codex":
        return str(_codex_sessions_root()) + os.sep + "<YYYY>/<MM>/<DD>" + os.sep
    if engine == "opencode":
        return str(_opencode_root()) + os.sep
    if engine == "grok":
        return str(_grok_sessions_root()) + os.sep + "<urlencoded-cwd>" + os.sep
    return "(unknown engine)"
