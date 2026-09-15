"""Create or reuse a detached aplexer session."""
from __future__ import annotations
import json
import os
import subprocess
from typing import Any, Mapping, Optional, Sequence
from uuid import uuid4
import click
from pocketshell.runtime import aplexer as _aplexer
from pocketshell.runtime import memcap as _memcap
from pocketshell import profiles as _profiles
from pocketshell.runtime import sessions as _session_enum
# --- sibling modules ---
from pocketshell.sessions.cli import sessions_group


CREATE_SCHEMA_VERSION = _session_enum.SCHEMA_VERSION


_APLEXER_START_TIMEOUT_S = 20.0


class _CreateError(Exception):
    """A create failure with the exit code the CLI should return."""

    def __init__(self, message: str, *, exit_code: int = 1) -> None:
        super().__init__(message)
        self.message = message
        self.exit_code = exit_code


def _resolve_aplexer() -> "_aplexer.AplexerResolution":
    """Resolve the bundled ``a`` executable once for an operation."""
    return _aplexer.resolve_a()


def _aplexer_unresolved_message(
    resolution: "_aplexer.AplexerResolution", *, action: str
) -> str:
    return (
        "pocketshell: could not resolve the bundled `a` (aplexer) binary; "
        f"{action}. Reinstall the pocketshell CLI "
        "(`uv tool install --force pocketshell`) or set APLEXER_BIN. "
        "Tried: " + "; ".join(resolution.tried)
    )


def _run_aplexer(argv: Sequence[str]) -> tuple[int, str, str]:
    """Run one aplexer command and retain its diagnostic output."""
    try:
        completed = subprocess.run(
            list(argv),
            check=False,
            capture_output=True,
            text=True,
            timeout=_APLEXER_START_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        return 124, "", f"`{' '.join(argv)}` timed out"
    except OSError as exc:
        return 127, "", str(exc)
    return completed.returncode, completed.stdout, completed.stderr


def _aplexer_snapshot() -> Any:
    payload = _aplexer.run_json(["snapshot"], feature="sessions")
    if payload is None:
        payload = _aplexer.run_json(["list"], feature="sessions")
    return payload


def _aplexer_records_holding(
    payload: Any, *, workspace: str, tag: str
) -> list[Mapping[str, Any]]:
    """Return snapshot records matching the requested workspace and tag."""
    if not isinstance(payload, list):
        return []
    target = os.path.realpath(workspace)
    records: list[Mapping[str, Any]] = []
    for raw in payload:
        if not isinstance(raw, Mapping):
            continue
        if str(raw.get("tag") or "") != tag:
            continue
        raw_workspace = raw.get("workspace") or raw.get("cwd") or ""
        if os.path.realpath(str(raw_workspace)) == target:
            records.append(raw)
    return records


def _aplexer_existing_record(
    payload: Any, *, workspace: str, tag: str
) -> Optional[Mapping[str, Any]]:
    """Return the live aplexer record for a workspace and tag, if any."""
    for raw in _aplexer_records_holding(payload, workspace=workspace, tag=tag):
        if _session_enum.aplexer_record_is_alive(raw):
            return raw
    return None


def _systemd_scope_argv(argv: list[str], memory_bytes: int) -> list[str]:
    """Wrap a start in ``systemd-run --user --scope --collect``.

    From a bare SSH session the common ancestor of aplexer's worker and
    the capped workload scope is root-owned, so every capped create died
    with ``spawn workload: Permission denied`` (#2625); inside a
    user-manager scope the ancestor is the user-owned ``app.slice``.
    """
    return [
        "systemd-run", "--user", "--scope",
        "--unit", f"aplexer-launch-{uuid4().hex}",
        "--collect", "--",
    ] + argv + ["--memory", str(memory_bytes)]


def aplexer_start_argv(
    *,
    aplexer_path: str,
    workspace: str,
    tag: str,
    engine: Optional[str],
    profile: Optional[str],
    memory_bytes: Optional[int],
) -> list[str]:
    """Build the detached ``a --json start`` invocation.

    A capped start is wrapped in a systemd user scope (see
    :func:`_systemd_scope_argv`); only capped starts wrap — an uncapped
    start must keep working on hosts with no user manager at all.
    """
    argv = [aplexer_path, "--json", "start", "--workspace", workspace, "--tag", tag]
    if engine:
        argv.extend(["--engine", engine])
    if profile:
        argv.extend(["--profile", profile])
    if memory_bytes is None:
        return argv
    return _systemd_scope_argv(argv, memory_bytes)


def _cap_unenforceable_hint(memory_bytes: Optional[int], detail: str) -> str:
    if memory_bytes is None:
        return ""
    lowered = detail.lower()
    if "fail closed" not in lowered and "delegate" not in lowered:
        return ""
    return (
        f" This host could not enforce the {memory_bytes}-byte session memory "
        "cap. Fix the host's systemd --user setup, or create the session "
        "explicitly uncapped with `--mem none`."
    )


def _aplexer_path_or_error() -> str:
    """Resolve the bundled ``a`` binary, raising a 127 create error if absent."""
    resolution = _resolve_aplexer()
    if resolution.path is None:
        raise _CreateError(
            _aplexer_unresolved_message(
                resolution, action="sessions create requires aplexer"
            ),
            exit_code=127,
        )
    return resolution.path


def _memory_bytes_or_error(name: str, workspace: str, mem: Optional[str]) -> int:
    """Resolve the session memory cap, mapping config errors to exit 2."""
    try:
        return _memcap.resolve_session_mem_bytes(flag=mem, workspace=workspace)
    except _memcap.MemCapError as exc:
        raise _CreateError(
            f"pocketshell: cannot create {name!r} in {workspace!r}: {exc}",
            exit_code=2,
        ) from exc


def _reused_record_payload(
    snapshot: Any, name: str, workspace: str
) -> Optional[dict[str, Any]]:
    """Return the "already exists" envelope when workspace+tag is live."""
    existing = _aplexer_existing_record(snapshot, workspace=workspace, tag=name)
    if existing is None:
        return None
    return {
        "name": _session_enum.aplexer_display_name(existing) or name,
        "id": str(existing.get("id") or "") or None,
        "created": False,
    }


def _start_argv(
    aplexer_path: str,
    workspace: str,
    tag: str,
    engine: Optional[str],
    profile: Optional[str],
    memory_bytes: int,
) -> list[str]:
    """Build the ``a start`` argv, resolving the profile for the engine."""
    return aplexer_start_argv(
        aplexer_path=aplexer_path,
        workspace=workspace,
        tag=tag,
        engine=engine,
        profile=(
            _profiles.resolve_aplexer_profile_arg(profile, engine=engine)
            if profile
            else profile
        ),
        memory_bytes=memory_bytes,
    )


def _start_failure(
    *,
    code: int,
    stdout: str,
    stderr: str,
    name: str,
    memory_bytes: int,
) -> _CreateError:
    """Map a non-zero ``a start`` exit to the right create error."""
    detail = stderr.strip() or stdout.strip() or "no output"
    return _CreateError(
        f"pocketshell: `a start --tag {name}` exited {code}: {detail}"
        + _cap_unenforceable_hint(memory_bytes, detail),
        exit_code=code,
    )


def _parse_start_record(stdout: str) -> Mapping[str, Any]:
    """Parse ``a --json start`` stdout into a session record mapping."""
    try:
        record = json.loads(stdout)
    except ValueError as exc:
        raise _CreateError(
            f"pocketshell: `a --json start` returned unreadable JSON: {exc}"
        ) from exc
    if not isinstance(record, Mapping):
        raise _CreateError(
            "pocketshell: `a --json start` returned "
            f"{type(record).__name__}, expected a session record"
        )
    return record


def _created_record_payload(record: Mapping[str, Any], name: str) -> dict[str, Any]:
    """Build the "created" envelope from a fresh aplexer session record."""
    return {
        "name": _session_enum.aplexer_display_name(record) or name,
        "id": str(record.get("id") or "") or None,
        "created": True,
    }


def _start_new_record(
    *,
    aplexer_path: str,
    name: str,
    workspace: str,
    engine: Optional[str],
    profile: Optional[str],
    memory_bytes: int,
) -> dict[str, Any]:
    """Run ``a start`` and return the created-record envelope."""
    argv = _start_argv(
        aplexer_path, workspace, name, engine, profile, memory_bytes
    )
    code, stdout, stderr = _run_aplexer(argv)
    if code != 0:
        raise _start_failure(
            code=code, stdout=stdout, stderr=stderr,
            name=name, memory_bytes=memory_bytes,
        )
    record = _parse_start_record(stdout)
    return _created_record_payload(record, name)


def _create_on_aplexer(
    *, name: str, cwd: Optional[str], mem: Optional[str],
    engine: Optional[str], profile: Optional[str],
) -> dict[str, Any]:
    """Create or reuse the aplexer record for ``workspace + tag``."""
    aplexer_path = _aplexer_path_or_error()
    workspace = cwd or os.getcwd()
    memory_bytes = _memory_bytes_or_error(name, workspace, mem)
    snapshot = _aplexer_snapshot()

    reused = _reused_record_payload(snapshot, name, workspace)
    if reused is not None:
        return reused

    return _start_new_record(
        aplexer_path=aplexer_path,
        name=name,
        workspace=workspace,
        engine=engine,
        profile=profile,
        memory_bytes=memory_bytes,
    )


def _emit_create_failure(
    ctx: click.Context, message: str, *, exit_code: int, as_json: bool
) -> None:
    if as_json:
        click.echo(json.dumps({"schema": CREATE_SCHEMA_VERSION, "error": message}, indent=2))
    else:
        click.echo(message, err=True)
    ctx.exit(exit_code or 1)


@sessions_group.command("create", context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("name")
@click.option(
    "--cwd", "-c", default=None,
    help="Working directory for the new detached aplexer session.",
)
@click.option(
    "--mem", default=None,
    help="Memory cap override, for example 24G; use `none` only explicitly.",
)
@click.option(
    "--engine", default=None,
    help="Start a coding agent in the new session.",
)
@click.option(
    "--profile", default=None,
    help="Named host profile for --engine.",
)
@click.option(
    "--json", "as_json", is_flag=True, default=False,
    help="Emit the schema-3 create envelope.",
)
@click.pass_context
def sessions_create(
    ctx: click.Context,
    name: str,
    cwd: Optional[str],
    mem: Optional[str],
    engine: Optional[str],
    profile: Optional[str],
    as_json: bool,
) -> None:
    """Create a detached aplexer session, idempotently."""
    try:
        result = _create_on_aplexer(
            name=name, cwd=cwd, mem=mem, engine=engine, profile=profile
        )
    except _CreateError as exc:
        _emit_create_failure(ctx, exc.message, exit_code=exc.exit_code, as_json=as_json)
        return
    if as_json:
        click.echo(json.dumps({"schema": CREATE_SCHEMA_VERSION, **result}, indent=2))
