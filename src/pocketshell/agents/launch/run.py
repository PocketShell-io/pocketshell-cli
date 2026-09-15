"""The launch_agent entry point and config-dir resolution."""
from __future__ import annotations
import os
import shutil
from pathlib import Path
from typing import Any, Mapping, Optional
import click
from pocketshell.engines import EngineManifest, engine_for
from pocketshell.env import merged_exports
# --- sibling modules ---
from pocketshell.agents.launch.command import _agent_missing_message, build_argv
from pocketshell.agents.launch.environment import _env_from_launch_spec, build_env
from pocketshell.agents.launch.spec import _aplexer_launch_spec
from pocketshell.agents.launch.trust import claude_config_path, seed_claude_trust


def _resolve_dir(ctx: click.Context, directory: str) -> Path:
    """Expand ``directory`` and require it to be an existing folder."""
    path = Path(os.path.expanduser(directory))
    if not path.is_dir():
        click.echo(
            f"pocketshell agent: directory does not exist: {path}", err=True
        )
        ctx.exit(2)
    return path


def _resolve_manifest(ctx: click.Context, kind: str) -> EngineManifest:
    """Look up the engine manifest; unknown or disabled ids exit."""
    try:
        manifest = engine_for(kind, probe=True)
    except KeyError:
        click.echo(f"pocketshell agent: unknown engine id: {kind!r}", err=True)
        ctx.exit(2)
    if not manifest.enabled:
        click.echo(
            f"pocketshell agent: engine {kind!r} is disabled in the host registry",
            err=True,
        )
        ctx.exit(126)
    return manifest


def _env_from_spec(
    spec: Mapping[str, Any],
    folder_exports: dict[str, str],
    extra_env: Optional[dict[str, str]],
    config_dir: Optional[str],
    profile_env: str,
) -> dict[str, str]:
    """Build the launch env from an engine's declarative launch spec."""
    return _env_from_launch_spec(
        spec,
        folder_exports=folder_exports,
        extra_env=extra_env,
        config_dir=config_dir,
        profile_env=profile_env,
    )


def _build_launch(
    kind: str,
    resolved_dir: str,
    *,
    skip_permissions: bool,
    config_dir: Optional[str],
    extra_env: Optional[dict[str, str]],
    manifest: EngineManifest,
) -> tuple[list[str], dict[str, str]]:
    """Resolve argv + env for the launch, preferring a declarative spec."""
    folder_exports = merged_exports(Path(resolved_dir))
    spec = _aplexer_launch_spec(
        kind, resolved_dir,
        skip_permissions=skip_permissions, config_dir=config_dir,
    )
    if spec is not None:
        argv = [str(part) for part in spec["argv"]]
        env = _env_from_spec(
            spec, folder_exports, extra_env, config_dir,
            manifest.launch.profile_env,
        )
    else:
        env = build_env(
            kind, dict(os.environ), folder_exports,
            config_dir=config_dir, extra_env=extra_env,
        )
        argv = build_argv(kind, skip_permissions=skip_permissions)
    return argv, env


def _preflight_binary(ctx: click.Context, kind: str, argv: list[str]) -> None:
    """Confirm the agent CLI is on PATH *before* os.chdir + exec.

    Without this, a missing `claude`/`codex`/`opencode` makes os.execvpe
    raise FileNotFoundError and dump a raw Python traceback to the SSH
    client. Emit the same friendly 127 + install hint every other
    subcommand uses instead (#774 §3).
    """
    if shutil.which(argv[0]) is None:
        click.echo(_agent_missing_message(kind), err=True)
        ctx.exit(127)


def _seed_trust_if_needed(kind: str, env: dict[str, str], resolved_dir: str) -> None:
    """Claude only: mark the launch directory trusted in its config."""
    if kind == "claude":
        seed_claude_trust(claude_config_path(env), resolved_dir)


def _prepare_launch(
    ctx: click.Context,
    kind: str,
    directory: str,
    *,
    skip_permissions: bool,
    config_dir: Optional[str],
    extra_env: Optional[dict[str, str]],
) -> tuple[dict[str, str], list[str]]:
    """Resolve engine + dir, build argv/env, preflight, chdir, seed trust."""
    manifest = _resolve_manifest(ctx, kind)
    resolved_dir = str(_resolve_dir(ctx, directory))
    argv, env = _build_launch(
        kind, resolved_dir,
        skip_permissions=skip_permissions,
        config_dir=config_dir, extra_env=extra_env, manifest=manifest,
    )
    _preflight_binary(ctx, kind, argv)
    # Run from the folder so the agent's cwd is correct.
    os.chdir(resolved_dir)
    _seed_trust_if_needed(kind, env, resolved_dir)
    return env, argv


def launch_agent(
    ctx: click.Context, kind: str, directory: str, *, skip_permissions: bool,
    config_dir: Optional[str], extra_env: Optional[dict[str, str]] = None,
    execvpe=None,
) -> None:
    """Resolve the dir, build env+argv, suppress prompts, exec the agent.

    ``extra_env`` layers the selected profile's ``env:`` block (#732) under
    the #703 provider strip. ``execvpe`` is a test injection point; production
    resolves :func:`os.execvpe` *at call time* so a monkeypatch on
    ``agents.os.execvpe`` is honoured (a default argument would bind the
    original at def-time and bypass the patch). Never returns.
    """
    execvpe = execvpe or os.execvpe
    env, argv = _prepare_launch(
        ctx, kind, directory,
        skip_permissions=skip_permissions,
        config_dir=config_dir, extra_env=extra_env,
    )
    # Replace this process with the agent so it owns the pty cleanly.
    execvpe(argv[0], argv, env)


def _resolve_named_profile(ctx: click.Context, kind: str, profile: str):
    """Resolve ``--profile`` via the profiles registry; unknown is an error."""
    # Lazy import keeps the agent launch path from importing yaml unless a
    # profile is actually requested.
    from pocketshell.profiles import resolve_profile

    try:
        return resolve_profile(profile, kind)
    except KeyError:
        click.echo(
            f"pocketshell agent: unknown {kind} profile: {profile!r} "
            f"(see `pocketshell profiles list --engine {kind}`)",
            err=True,
        )
        ctx.exit(2)


def _resolve_config_dir(
    ctx: click.Context,
    kind: str,
    config_dir: Optional[str],
    profile: Optional[str],
) -> tuple[Optional[str], dict[str, str]]:
    """Resolve config dir and extra env from the launch flags.

    Returns ``(config_dir, extra_env)``. ``--config-dir`` and
    ``--profile`` are mutually exclusive. ``--profile`` resolves the named
    host profile to its ``config_dir`` and ``env:`` block (#732). Session
    metadata is recorded by aplexer from the launched process, so the wrapper
    does not maintain a second host-side metadata source.
    """
    if config_dir is not None and profile is not None:
        click.echo(
            "pocketshell agent: --config-dir and --profile are mutually "
            "exclusive",
            err=True,
        )
        ctx.exit(2)
    if profile is None:
        return config_dir, {}
    resolved = _resolve_named_profile(ctx, kind, profile)
    return resolved.config_dir, dict(resolved.env)
