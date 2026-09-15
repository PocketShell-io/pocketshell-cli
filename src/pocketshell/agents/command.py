"""Argv construction for each agent kind."""
from __future__ import annotations
from pocketshell.engines import engine_for
# __SIBLING_IMPORTS__


def build_argv(kind: str, *, skip_permissions: bool) -> list[str]:
    """Return the argv (program + args) used to exec the agent.

    The argv carries the per-agent first-run-prompt suppression and the
    skip-permissions flag:

    - **codex** — ``-c check_for_update_on_startup=false`` suppresses the
      startup update-check modal (issue #703).
      ``--dangerously-bypass-approvals-and-sandbox`` when
      ``skip_permissions`` (the maintainer's ``cy`` alias).
    - **claude** — ``--dangerously-skip-permissions`` when
      ``skip_permissions`` (the ``csp`` alias). The trust dialog is
      suppressed out-of-band by pre-seeding ``~/.claude.json`` (see
      :func:`seed_claude_trust`), not via argv.
    - **opencode** — no skip flag (permissions are config-driven in
      ``opencode.json``); the billing fix is the env strip, not a flag.
    """
    try:
        manifest = engine_for(kind)
    except KeyError as exc:
        raise ValueError(f"unknown agent kind: {kind!r}") from exc
    argv = list(manifest.launch.argv)
    if skip_permissions:
        argv.extend(manifest.launch.skip_permissions_argv)
    return argv


def _agent_missing_message(kind: str) -> str:
    """Friendly install hint shown when the agent CLI is not on PATH.

    Mirrors the missing-binary wording used by ``pocketshell.sessions`` /
    ``pocketshell.usage`` / ``pocketshell.sessions`` so the user sees a
    consistent ``127`` + install-hint message whichever subcommand
    surfaces the failure first, instead of a raw ``FileNotFoundError``
    traceback from ``os.execvpe``.
    """
    return (
        f"pocketshell: `{kind}` is not installed on this host (not on PATH). "
        f"Install the {kind} CLI and re-run."
    )
