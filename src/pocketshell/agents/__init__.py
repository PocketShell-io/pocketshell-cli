"""`pocketshell agent <kind> --dir <dir>` subcommand.

Launch a coding-agent CLI (``codex`` / ``claude`` / ``opencode`` / ``grok``) in a
folder, server-side, replacing the giant inline ``env -u VAR1 -u VAR2 …``
line the Android app used to type into a new session (issue #703).

Why this exists
---------------

The app previously reconstructed the *entire* launch chain inline:

```
eval "$(pocketshell env export --dir '<dir>')"; env -u VAR1 … (71 vars) … codex --dangerously-bypass-approvals-and-sandbox
```

That is ~1500 characters of brittle shell typed into the pane. Worse, the
agent then **parked on a first-run modal prompt** the user never knew to
dismiss:

- ``codex 0.137.0`` halts on *"Update available 0.137.0 → 0.139.0 — Press
  enter to continue"*.
- ``claude`` in a fresh folder halts on *"Is this a project you trust?
  1. Yes / 2. No"*.

So the agent *appeared* but never actually became usable. This wrapper
replaces the whole inline chain with one short line —
``pocketshell agent <kind> --dir <dir> [--skip-permissions]
[--config-dir <dir>]`` — and **suppresses those first-run prompts** so the
agent UI is immediately usable.

What it does
------------

1. ``cd <dir>`` (validated, like ``env``'s ``_resolve_dir``).
2. Merge the folder's ``.env`` / ``.envrc`` into the environment
   (reuses :func:`pocketshell.env.merged_exports`) — this replaces the
   ``eval "$(pocketshell env export …)"`` prelude.
3. Apply the env-strip **for every agent kind** (see below).
4. Suppress the agent's first-run prompt.
5. ``os.execvpe`` the agent so it replaces the wrapper process and owns the
   pty cleanly.

Env-strip scope (issue #703 — maintainer decision: ALL three agents)
--------------------------------------------------------------------

Maintainer decision (2026-06-11, issue #703): strip the provider API-key
vars for **all three** agents — ``codex``, ``claude``, and ``opencode`` —
so each falls back to its *subscription* auth instead of a per-token env
API key (which bills per token). Subscription billing across the board.

This matches the old app behaviour (which stripped for all three) but now
lives in the concise ``pocketshell agent`` wrapper instead of being
reconstructed inline by the app. The 71-var list is
:data:`PROVIDER_ENV_UNSET_VARS`.

Prompt suppression (the part that fixes "the agent doesn't start")
------------------------------------------------------------------

- **codex** — ``-c check_for_update_on_startup=false`` disables the
  startup update check, so codex never parks on the
  "Update available … Press enter to continue" modal. The project-trust
  prompt does not appear in codex 0.137.0 (verified), so no extra trust
  seeding is needed.
- **claude** — the workspace-trust dialog is gated by
  ``hasTrustDialogAccepted`` per project in ``~/.claude.json``. Even
  ``--dangerously-skip-permissions`` does NOT skip it (issue #703). The
  wrapper pre-seeds ``projects.<dir>.hasTrustDialogAccepted = true`` before
  exec, so claude starts straight into the usable agent prompt.
- **opencode** — config-driven; no first-run modal to suppress.
- **grok** — no first-run trust modal. ``--always-approve`` is the
  skip-permissions flag. Session logs live under ``$GROK_HOME/sessions``
  (default ``~/.grok``).
"""
from __future__ import annotations

from pocketshell.agents.cli import (
    agent_group,
)
from pocketshell.agents.command import (
    build_argv,
)
from pocketshell.agents.environment import (
    AGENT_KINDS,
    PROVIDER_ENV_UNSET_VARS,
    build_env,
)
from pocketshell.agents.launch import (
    launch_agent,
    _resolve_config_dir,
)
from pocketshell.agents.record import (
    record_agent_kind,
    record_agent_source,
)
from pocketshell.agents.spec import (
    _aplexer_profile_id,
)
from pocketshell.agents.trust import (
    claude_config_path,
    seed_claude_trust,
)
import os  # noqa: F401  (tests patch agents.os.execvpe)
import shutil  # noqa: F401  (tests patch agents.shutil.which)

__all__ = [
    "AGENT_KINDS",
    "PROVIDER_ENV_UNSET_VARS",
    "build_env",
    "build_argv",
    "claude_config_path",
    "seed_claude_trust",
    "launch_agent",
    "record_agent_kind",
    "record_agent_source",
    "_aplexer_profile_id",
    "_resolve_config_dir",
    "agent_group",
]
