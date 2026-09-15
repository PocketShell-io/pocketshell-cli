"""`pocketshell env` subcommand group.

Read and write ``.env`` / ``.envrc`` files on the remote host so the
PocketShell Android app can manage a folder's environment without
launching an agent. **Server-side only** — the phone holds no secrets;
all file I/O happens on the dev box. This mirrors D19/D23's
"zero provider credentials on the phone" stance.

File formats (locked as D24)
----------------------------

- ``.env`` — ``KEY=value`` lines, no prefix.
- ``.envrc`` — ``export KEY=value`` lines (direnv style).

When both files exist in a folder they are *both* managed; every key is
tagged with the file it lives in. New keys default to ``.env`` unless the
caller picks ``--file .envrc``.

Subcommands
-----------

- ``env list --dir <path> [--json]`` — list key names + file +
  ``has_value`` (never values).
- ``env get --dir <path> --key FOO [--key BAR] [--json]`` — return
  value(s). Plain reveal; phone-side gating dropped.
- ``env set --dir <path> --file .env|.envrc`` — read ``{"KEY":"value"}``
  JSON from **stdin** and create/update keys. Surgical line rewrite:
  comments, ordering, and untouched keys are preserved.
- ``env unset --dir <path> --key FOO [--key BAR]`` — delete keys.
- ``env copy --from <src> --to <dst> --key FOO [...] [--file .env|.envrc]``
  — copy specific keys' values from the source folder into the
  destination.
- ``env export --dir <path>`` — emit a shell-eval-able block merging both
  files as ``export KEY=value`` lines, with shell-quoted values.

Why stdin for ``set`` (D24)
---------------------------

Secret values never appear in argv: ``ps`` or shell history.
scrollback would otherwise leak them. The caller pipes a JSON object on
stdin instead. ``export`` shell-quotes values so the emitted block is
safe to ``eval`` in the launch hook (#263).

New files are created mode ``0600``; existing files keep their perms.
"""
from __future__ import annotations

from pocketshell.env.cli import (
    env_group,
)
from pocketshell.env.parse import (
    ENV_FILE,
    ENVRC_FILE,
    parse_assignment,
    parse_env_file,
)
from pocketshell.env.store import (
    NEW_FILE_MODE,
    EnvKey,
    env_files_in,
    list_keys,
    get_values,
    merged_exports,
    write_keys,
    unset_keys,
    copy_keys,
    render_export,
)

__all__ = [
    "ENV_FILE",
    "ENVRC_FILE",
    "NEW_FILE_MODE",
    "parse_assignment",
    "parse_env_file",
    "EnvKey",
    "env_files_in",
    "list_keys",
    "get_values",
    "merged_exports",
    "write_keys",
    "unset_keys",
    "copy_keys",
    "render_export",
    "env_group",
]
