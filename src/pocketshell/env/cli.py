"""The `pocketshell env` click command group."""
from __future__ import annotations
import json
import os
import sys
from pathlib import Path
import click
# --- sibling modules ---
from pocketshell.env.parse import ENV_FILE, ENV_FILENAMES, _is_valid_key
from pocketshell.env.store import copy_keys, get_values, list_keys, render_export, unset_keys, write_keys


def _resolve_dir(ctx: click.Context, directory: str) -> Path:
    """Expand ``directory`` and require it to be an existing folder.

    Exits with code 2 if the folder is missing. A fresh ``.env`` / ``.envrc``
    is created inside an already-existing folder, so the directory itself must
    be present for both read and write paths.
    """
    path = Path(os.path.expanduser(directory))
    if not path.is_dir():
        click.echo(f"pocketshell env: directory does not exist: {path}", err=True)
        ctx.exit(2)
    return path


@click.group(
    name="env",
    context_settings={"help_option_names": ["-h", "--help"]},
    help=(
        "Read and write a folder's `.env` / `.envrc` files server-side.\n\n"
        "Values are written via stdin JSON (never argv) so secrets do not "
        "leak into `ps` or scrollback. `list` returns key names only; use "
        "`get` to reveal values. `.env` keys are bare `KEY=value`; `.envrc` "
        "keys get the `export ` prefix. See D24 in docs/decisions.md."
    ),
)
def env_group() -> None:
    """Top-level group registered onto the root `pocketshell` CLI."""


@env_group.command(
    "list",
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.option("--dir", "directory", required=True, type=str, help="Folder to inspect.")
@click.option(
    "--json",
    "json_output",
    is_flag=True,
    help="Emit a JSON array of {key, file, has_value} objects.",
)
@click.pass_context
def env_list(ctx: click.Context, directory: str, json_output: bool) -> None:
    """List key names + file + has_value across `.env` and `.envrc`.

    Never prints values (write-only default, D24).
    """
    path = _resolve_dir(ctx, directory)
    keys = list_keys(path)
    if json_output:
        payload = [
            {"key": k.key, "file": k.file, "has_value": k.has_value} for k in keys
        ]
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
        return
    for k in keys:
        flag = "set" if k.has_value else "empty"
        click.echo(f"{k.key}\t{k.file}\t{flag}")


@env_group.command(
    "get",
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.option("--dir", "directory", required=True, type=str, help="Folder to read.")
@click.option(
    "--key",
    "keys",
    multiple=True,
    required=True,
    type=str,
    help="Key to reveal (may be repeated).",
)
@click.option(
    "--json",
    "json_output",
    is_flag=True,
    help="Emit a JSON object mapping key -> value for keys that exist.",
)
@click.pass_context
def env_get(
    ctx: click.Context,
    directory: str,
    keys: tuple[str, ...],
    json_output: bool,
) -> None:
    """Reveal the value(s) of the requested key(s).

    Missing keys are simply absent from the output; only a hard error
    (e.g. missing directory) is non-zero.
    """
    path = _resolve_dir(ctx, directory)
    values = get_values(path, list(keys))
    if json_output:
        click.echo(json.dumps(values, indent=2, sort_keys=True))
        return
    for key in keys:
        if key in values:
            click.echo(f"{key}={values[key]}")


@env_group.command(
    "set",
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.option("--dir", "directory", required=True, type=str, help="Folder to write into.")
@click.option(
    "--file",
    "file_name",
    type=click.Choice(ENV_FILENAMES),
    default=ENV_FILE,
    show_default=True,
    help="Which file to write (.env has no prefix, .envrc gets `export `).",
)
@click.pass_context
def env_set(ctx: click.Context, directory: str, file_name: str) -> None:
    """Create/update keys from a `{"KEY":"value"}` JSON object on stdin.

    Values come from stdin (never argv) so secrets do not leak into
    `ps`/scrollback. Comments, ordering, and untouched keys are
    preserved (surgical rewrite).
    """
    path = _resolve_dir(ctx, directory)
    raw = sys.stdin.read()
    if not raw.strip():
        click.echo("pocketshell env set: no JSON on stdin", err=True)
        ctx.exit(2)
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        click.echo(f"pocketshell env set: invalid JSON on stdin: {exc}", err=True)
        ctx.exit(2)
    if not isinstance(payload, dict):
        click.echo("pocketshell env set: stdin JSON must be an object", err=True)
        ctx.exit(2)
    updates: dict[str, str] = {}
    for key, value in payload.items():
        if not isinstance(key, str) or not _is_valid_key(key):
            click.echo(f"pocketshell env set: invalid key: {key!r}", err=True)
            ctx.exit(2)
        updates[key] = "" if value is None else str(value)
    write_keys(path, file_name, updates)


@env_group.command(
    "unset",
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.option("--dir", "directory", required=True, type=str, help="Folder to edit.")
@click.option(
    "--key",
    "keys",
    multiple=True,
    required=True,
    type=str,
    help="Key to delete (may be repeated).",
)
@click.pass_context
def env_unset(ctx: click.Context, directory: str, keys: tuple[str, ...]) -> None:
    """Delete the named key(s) from both files, leaving the rest intact."""
    path = _resolve_dir(ctx, directory)
    unset_keys(path, list(keys))


@env_group.command(
    "copy",
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.option("--from", "src_dir", required=True, type=str, help="Source folder.")
@click.option("--to", "dst_dir", required=True, type=str, help="Destination folder.")
@click.option(
    "--key",
    "keys",
    multiple=True,
    required=True,
    type=str,
    help="Key to copy (may be repeated).",
)
@click.option(
    "--file",
    "file_name",
    type=click.Choice(ENV_FILENAMES),
    default=ENV_FILE,
    show_default=True,
    help="Which destination file to write the copied keys into.",
)
@click.pass_context
def env_copy(
    ctx: click.Context,
    src_dir: str,
    dst_dir: str,
    keys: tuple[str, ...],
    file_name: str,
) -> None:
    """Copy named keys' values from source folder into the destination."""
    src = _resolve_dir(ctx, src_dir)
    dst = _resolve_dir(ctx, dst_dir)
    copy_keys(src, dst, list(keys), dst_file=file_name)


@env_group.command(
    "export",
    context_settings={"help_option_names": ["-h", "--help"]},
)
@click.option("--dir", "directory", required=True, type=str, help="Folder to export.")
@click.pass_context
def env_export(ctx: click.Context, directory: str) -> None:
    """Emit an `eval`-safe `export KEY=value` block merging both files."""
    path = _resolve_dir(ctx, directory)
    rendered = render_export(path)
    if rendered:
        sys.stdout.write(rendered)
