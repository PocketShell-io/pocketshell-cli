"""`pocketshell prune-attachments` — server-side attachment retention backstop.

The PocketShell Android composer uploads each prompt attachment to the
remote host under ``~/.pocketshell/attachments/<host-scope>/`` (see
``PromptAttachmentStager.REMOTE_DIRECTORY`` on the client). Nothing on the
host ever removes those files, so the directory grows unbounded on every
host the user attaches to (issue #547).

The client already prunes the *active* scope dir on a fresh upload
(``RemoteAttachmentPruner`` — option 1 in #547). This command is the
**server-side backstop** (option 2): it runs ON the host, over the whole
``~/.pocketshell/attachments/`` tree, so even hosts the user stopped
attaching to are eventually trimmed. It is meant to be invoked by the normal
``pocketshell`` plumbing (e.g. on connect / during usage probes) or from a
maintainer's cron.

Safety bounds (deny-by-default — this deletes files):

- **Scoped to one directory.** Only files directly under
  ``~/.pocketshell/attachments/<scope>/`` (depth-2 from the root) are ever
  considered. The root and the per-scope directories themselves are never
  deleted; the user's own files outside the attachments tree are never
  touched. The resolved root must stay inside ``$HOME`` or the command
  refuses to run.
- **Regular files only.** Symlinks, directories, sockets, and anything
  that is not a plain regular file is skipped — a symlink inside the
  attachments dir can never be used to delete a file elsewhere.
- **Age bound (TTL).** A file is a deletion candidate only when its mtime
  is strictly older than ``DEFAULT_TTL_DAYS`` (14 days).
- **Size cap.** After the TTL pass, if the *surviving* attachments still
  exceed ``DEFAULT_MAX_TOTAL_BYTES`` (256 MiB), the oldest survivors are
  deleted (oldest-first) until the tree is back under the cap. Files
  younger than ``PROTECT_NEWEST_HOURS`` (24h) are never deleted by the
  size cap so an active session's just-uploaded files are spared even
  during a big backlog clear.
- **Dry-run default off, but ``--dry-run`` reports without deleting.**

The command is best-effort and never raises on a per-file delete error
(permissions, races) — it logs the failure into the result summary and
continues, so a single bad file can't wedge the whole prune.

Modules
-------

- :mod:`pocketshell.attachments.prune` — the retention passes and
  their result summary (importable without Click).
- :mod:`pocketshell.attachments.cli` — the Click command and its
  output rendering.
"""
from __future__ import annotations

from pocketshell.attachments.prune import (
    ATTACHMENTS_RELATIVE_ROOT,
    DEFAULT_MAX_TOTAL_BYTES,
    DEFAULT_TTL_DAYS,
    PROTECT_NEWEST_HOURS,
    DeletedFile,
    PruneResult,
    prune_attachments,
    resolve_attachments_root,
)
from pocketshell.attachments.cli import prune_attachments_command

__all__ = [
    "DEFAULT_TTL_DAYS",
    "DEFAULT_MAX_TOTAL_BYTES",
    "PROTECT_NEWEST_HOURS",
    "ATTACHMENTS_RELATIVE_ROOT",
    "DeletedFile",
    "PruneResult",
    "resolve_attachments_root",
    "prune_attachments",
    "prune_attachments_command",
]
