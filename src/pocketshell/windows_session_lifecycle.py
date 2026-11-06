"""Windows lifecycle adapter for the measured bundled aplexer backend."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from uuid import UUID

import click

from pocketshell.runtime import aplexer, memcap, sessions, windows_job


class SessionError(RuntimeError):
    def __init__(self, message, code=1, *, uncertain=False):
        super().__init__(message)
        self.code, self.uncertain = code, uncertain


def _uuid(value):
    if not isinstance(value, str):
        raise SessionError("The backend returned a missing session UUID.")
    try:
        parsed = str(UUID(value))
    except ValueError:
        raise SessionError("The backend returned an invalid session UUID.") from None
    if parsed != value:
        raise SessionError("The backend returned a noncanonical session UUID.")
    return parsed


def workspace_path(value, *, existing=False):
    value = str(value)
    if re.match(r"^/[A-Za-z]:[/\\]", value):
        value = value[1:]
    elif re.match(r"^/[A-Za-z]/", value):
        value = value[1] + ":/" + value[3:]
    path = Path(value).expanduser()
    try:
        if not re.match(r"^[A-Za-z]:[/\\]", str(path)) or any(x in value for x in ("\0", "\r", "\n")):
            raise ValueError("expected a drive-absolute Windows path")
        path = path.resolve(strict=existing)
        if existing and not path.is_dir():
            raise ValueError("not a directory")
    except (ValueError, OSError) as error:
        raise SessionError(f"The Windows workspace is unavailable: {error}", 2) from None
    return str(path)


def _same_workspace(left, right):
    return os.path.normcase(workspace_path(left)) == os.path.normcase(workspace_path(right))


def backend():
    resolved = aplexer.resolve_a()
    expected = Path(sys.executable).parent / "a.exe"
    worker = expected.with_name("aplexer.exe")
    if not resolved.path or not resolved.worker or Path(resolved.path).resolve() != expected.resolve() \
            or Path(resolved.worker).resolve() != worker.resolve():
        raise SessionError("The packaged Windows aplexer CLI/worker pair is unavailable.", 127)
    try:
        def digest(path):
            with path.open("rb") as stream:
                return hashlib.file_digest(stream, "sha256").digest()
        if digest(expected) != digest(worker):
            raise OSError("paired binary digests differ")
    except OSError:
        raise SessionError("The packaged Windows aplexer CLI/worker pair does not verify.", 127) from None
    return str(expected)


def _json(binary, args, *, creating=False):
    try:
        result = subprocess.run([binary, "--json", *args], capture_output=True, text=True,
                                timeout=20 if creating else 8, creationflags=0x08000000)
    except subprocess.TimeoutExpired:
        raise SessionError("The session operation timed out. Refresh sessions before retrying; no UUID was guessed.",
                           124, uncertain=creating) from None
    except OSError:
        raise SessionError("The bundled session backend could not be started.", 127) from None
    if result.returncode:
        raise SessionError("The session backend refused the operation: " + (result.stderr or "").strip()[:1200],
                           result.returncode, uncertain=creating)
    try:
        return json.loads(result.stdout)
    except (ValueError, TypeError):
        raise SessionError("The session result is malformed. Refresh sessions before retrying; no UUID was guessed.",
                           uncertain=creating) from None


def snapshot(binary):
    rows = _json(binary, ["snapshot"])
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise SessionError("The session backend returned a malformed registry.")
    ids = [_uuid(row.get("id")) for row in rows]
    if len(ids) != len(set(ids)):
        raise SessionError("The session registry contains duplicate identities.")
    return rows


def _verify_record(row, requested=None):
    ident = _uuid(row.get("id"))
    pid = row.get("workload_pid")
    limits = row.get("limits")
    limit = limits.get("memory_bytes") if isinstance(limits, dict) else None
    if not sessions.aplexer_record_is_alive(row) or not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0 \
            or not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0:
        raise SessionError("The live session identity or memory limit is not verified.")
    try:
        bound = windows_job.verify(ident, pid, requested)
    except windows_job.JobError as error:
        raise SessionError(str(error)) from None
    if bound["memory_limit_bytes"] != limit:
        raise SessionError("The session registry and actual Windows job memory limit disagree.")
    return bound


def create(name, cwd=None, mem=None, engine=None, profile=None):
    if not name or len(name) > 128 or name.strip() != name or any(ord(x) < 32 or x in "/\\:" for x in name):
        raise SessionError("A session name must be 1-128 characters without control characters or path separators.", 2)
    workspace = workspace_path(cwd or os.getcwd(), existing=True)
    try:
        memory = memcap.resolve_session_mem_bytes(flag=mem, workspace=workspace)
    except memcap.MemCapError as error:
        raise SessionError(str(error), 2) from None
    if memory is None:
        raise SessionError("Windows session creation requires an explicit or default memory limit.", 2)
    binary = backend()
    before = snapshot(binary)
    matching = [row for row in before if row.get("tag") == name and row.get("workspace")
                and _same_workspace(row["workspace"], workspace) and sessions.aplexer_record_is_alive(row)]
    if len(matching) > 1:
        raise SessionError("The workspace/session name is ambiguous.", 4)
    if matching:
        row = matching[0]
        bound = _verify_record(row, memory)
        return {"name": sessions.aplexer_display_name(row), "id": row["id"], "created": False,
                "memory_enforcement": bound}
    args = ["start", "--workspace", workspace, "--cwd", workspace, "--tag", name, "--memory", str(memory)]
    if engine:
        args += ["--engine", engine]
    if profile:
        args += ["--profile", profile]
    record = _json(binary, args, creating=True)
    if not isinstance(record, dict):
        raise SessionError("The create result is not a session record; refresh sessions before retrying.", uncertain=True)
    try:
        ident = _uuid(record.get("id"))
        if ident in {row["id"] for row in before} or record.get("tag") != name \
                or not _same_workspace(record.get("workspace", ""), workspace):
            raise SessionError("The create result does not identify this new workspace/session.")
        after = [row for row in snapshot(binary) if row["id"] == ident]
        if len(after) != 1 or after[0].get("tag") != name or not _same_workspace(after[0].get("workspace", ""), workspace):
            raise SessionError("The created session could not be verified in the registry.")
        row = after[0]
        bound = _verify_record(row, memory)
    except SessionError as error:
        raise SessionError(str(error) + " A session may have been created; refresh sessions before retrying.",
                           error.code, uncertain=True) from None
    return {"name": sessions.aplexer_display_name(row), "id": ident, "created": True,
            "memory_enforcement": bound}


def _record(binary, selector):
    try:
        ident = _uuid(selector)
    except SessionError:
        raise SessionError("A full immutable session UUID is required.", 2) from None
    matches = [row for row in snapshot(binary) if row["id"] == ident]
    if len(matches) != 1:
        raise SessionError("Session not found.", 3)
    return matches[0]


def resolve(binary, selector):
    row = _record(binary, selector)
    if not sessions.aplexer_record_is_alive(row):
        raise SessionError("Session not found.", 3)
    _verify_record(row)
    return row


def _ended_identity(row):
    phase = row.get("phase")
    if phase not in ("exited", "failed") or row.get("state") != phase \
            or row.get("worker_alive") is not False or row.get("containment_empty") is not True:
        raise SessionError("The finished session's state and empty containment are not verified.")
    return tuple(row.get(key) for key in
                 ("id", "phase", "state", "worker_alive", "containment_empty", "worker_pid", "workload_pid"))


def attach(selector):
    binary = backend()
    row = resolve(binary, selector)
    # Windows execv does not replace the parent. Wait with inherited terminal
    # streams; never hide a system shell or interpolate a command string.
    flags = 0 if sys.stdin.isatty() or sys.stdout.isatty() else 0x08000000
    return subprocess.call([binary, "attach", "--no-status", row["id"]],
                           stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr, creationflags=flags)


def kill(selector):
    binary = backend()
    row = _record(binary, selector)
    if sessions.aplexer_record_is_alive(row) and row.get("phase") not in ("exited", "failed"):
        if row.get("phase") != row.get("state") or row.get("phase") not in sessions.APLEXER_LIVE_STATES:
            raise SessionError("The session's live state is not verified.")
        _verify_record(row)
    else:
        identity = _ended_identity(row)
        try:
            windows_job.verify_finished(row["id"], row.get("worker_pid"), row.get("workload_pid"))
        except windows_job.JobError as error:
            raise SessionError(str(error)) from None
        # This explicit invocation may remove an ended record. Never turn a
        # previous unconfirmed live kill into an automatic postmortem deletion.
        if _ended_identity(_record(binary, row["id"])) != identity:
            raise SessionError("The finished session's identity changed before removal.")
    answer = _json(binary, ["kill", row["id"], "--grace-ms", "1000"])
    if not isinstance(answer, dict) or answer.get("id") != row["id"] or answer.get("record_removed") is not True:
        raise SessionError("Session termination/removal was not confirmed; refresh sessions before retrying.")
    if any(item["id"] == row["id"] for item in snapshot(binary)):
        raise SessionError("The stopped session still appears in the registry.")
    return {"name": sessions.aplexer_display_name(row), "id": row["id"], "killed": True, "reaped": True}


def _fail(ctx, error, as_json):
    if as_json:
        click.echo(json.dumps({"schema": 3, "error": str(error), "uncertain": error.uncertain}))
    else:
        click.echo(str(error), err=True)
    ctx.exit(error.code)


def install(group):
    @group.command("create")
    @click.argument("name", required=False)
    @click.option("--name", "named", default=None)
    @click.option("--cwd", "-c", default=None)
    @click.option("--mem", default=None)
    @click.option("--engine", default=None)
    @click.option("--profile", default=None)
    @click.option("--json", "as_json", is_flag=True)
    @click.pass_context
    def create_command(ctx, name, named, cwd, mem, engine, profile, as_json):
        try:
            if name is not None and named is not None:
                raise SessionError("Supply the session name once, positionally or with --name.", 2)
            result = create(named if named is not None else name, cwd, mem, engine, profile)
        except SessionError as error:
            _fail(ctx, error, as_json)
            return
        if as_json:
            click.echo(json.dumps({"schema": 3, **result}))

    @group.command("attach")
    @click.argument("selector")
    @click.pass_context
    def attach_command(ctx, selector):
        try:
            ctx.exit(attach(selector))
        except SessionError as error:
            _fail(ctx, error, False)

    @group.command("kill")
    @click.argument("selector")
    @click.option("--json", "as_json", is_flag=True)
    @click.pass_context
    def kill_command(ctx, selector, as_json):
        try:
            result = kill(selector)
        except SessionError as error:
            _fail(ctx, error, as_json)
            return
        if as_json:
            click.echo(json.dumps({"schema": 3, **result}))
