"""Harness binary discovery via login-shell PATH probes."""
from __future__ import annotations
import os
import shutil
import signal
import subprocess
from glob import glob
from typing import Mapping, Optional
# --- sibling modules ---
from pocketshell.engines.spec import ProfileSpec


LOGIN_SHELL_PATH_TIMEOUT_S = 5.0


# Kill switch for hosts where spawning a login shell is undesirable.
LOGIN_SHELL_PROBE_KILL = "POCKETSHELL_ENGINE_LOGIN_SHELL_PROBE"


#: How the login shell is asked for its PATH, most portable form first.
#: `printenv PATH` is shell-agnostic; fish, for example, expands `"$PATH"` to a
#: SPACE-separated list, so the POSIX `printf` form is only the fallback for a
#: host without `printenv`.
LOGIN_SHELL_PATH_COMMANDS: tuple[str, ...] = (
    "printenv PATH",
    'printf %s "$PATH"',
)


#: Absolute install locations probed when neither the exec `PATH` nor the
#: login shell resolves a harness.  Globs are expanded (newest match first);
#: `$HOME`-relative patterns are skipped when the environment has no `HOME`.
LAUNCH_PATH_PATTERNS: tuple[str, ...] = (
    # Plain per-user/system bin dirs (mirrors PocketshellCommand.PATH_PREFIX_DIRS).
    "$HOME/.local/bin",
    "$HOME/bin",
    "$HOME/.cargo/bin",
    "$HOME/.pixi/bin",
    "/usr/local/bin",
    "/opt/homebrew/bin",
    # Node version managers — every agent harness in the registry today ships
    # as an npm package, so this is where they usually land.
    "$HOME/.nvm/versions/node/*/bin",
    "$HOME/.local/share/fnm/node-versions/*/installation/bin",
    "$HOME/.volta/bin",
    "$HOME/.bun/bin",
    "$HOME/.deno/bin",
    "$HOME/.npm-global/bin",
    "$HOME/.npm-packages/bin",
    "$HOME/.yarn/bin",
    "$HOME/.config/yarn/global/node_modules/.bin",
    # Generic language/tool version managers.
    "$HOME/.asdf/shims",
    "$HOME/.asdf/installs/*/*/bin",
    "$HOME/.local/share/mise/shims",
    "$HOME/.rye/shims",
    "$HOME/go/bin",
)


_LOGIN_SHELL_PATH_CACHE: dict[tuple[str, str, str], tuple[str, ...]] = {}


# Snapshot Popen (same rationale as aplexer._Popen): helper tests that patch
# ``subprocess.Popen`` to block a launched child must not swallow — or crash —
# this read-only PATH observation.
_Popen = subprocess.Popen


_TimeoutExpired = subprocess.TimeoutExpired


def _run_capture(argv: list[str], env: dict[str, str]) -> Optional[str]:
    """Run ``argv`` and return stdout, or None on any failure/timeout."""
    try:
        proc = _Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            env=env,
            start_new_session=True,
        )
        try:
            stdout, _stderr = proc.communicate(timeout=LOGIN_SHELL_PATH_TIMEOUT_S)
        except _TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                proc.kill()
            proc.communicate()
            return None
    except (OSError, ValueError):
        return None
    if proc.returncode != 0:
        return None
    return stdout


def clear_resolution_cache() -> None:
    """Drop the memoised login-shell PATH (used by tests and long-lived procs)."""
    _LOGIN_SHELL_PATH_CACHE.clear()


def _parse_path_entries(stdout: str) -> tuple[str, ...]:
    """Split captured PATH output into unique non-empty entries."""
    return tuple(
        dict.fromkeys(
            entry for entry in stdout.strip().split(os.pathsep) if entry.strip()
        )
    )


def _probe_shell_paths(
    shells: tuple[str, ...],
    env: dict[str, str],
) -> tuple[str, ...]:
    """Ask each login shell for its PATH; the first non-empty answer wins."""
    for shell in shells:
        for command in LOGIN_SHELL_PATH_COMMANDS:
            stdout = _run_capture([shell, "-lc", command], env)
            if stdout is None:
                continue
            dirs = _parse_path_entries(stdout)
            if dirs:
                return dirs
    return ()


def _login_shell_dirs(source: Mapping[str, str]) -> tuple[str, ...]:
    """Return the PATH entries a LOGIN shell exports, memoised per environment.

    This is the environment the harness is actually launched in (the session
    user's shell as a login shell, and the create flow `send-keys`-types the
    wrapper into that pane).  Failures are silent: the caller still has the
    absolute-candidate ladder below.
    """
    if source.get(LOGIN_SHELL_PROBE_KILL) == "0":
        return ()
    shells = tuple(
        dict.fromkeys(shell for shell in (source.get("SHELL"), "/bin/sh") if shell)
    )
    key = (shells[0], source.get("HOME", ""), source.get("PATH", ""))
    cached = _LOGIN_SHELL_PATH_CACHE.get(key)
    if cached is not None:
        return cached
    env = {str(name): str(value) for name, value in source.items()}
    dirs = _probe_shell_paths(shells, env)
    _LOGIN_SHELL_PATH_CACHE[key] = dirs
    return dirs


def _launch_candidate_dirs(source: Mapping[str, str]) -> tuple[str, ...]:
    """Expand :data:`LAUNCH_PATH_PATTERNS` to existing directories."""
    home = source.get("HOME")
    found: list[str] = []
    for pattern in LAUNCH_PATH_PATTERNS:
        expanded = pattern
        if expanded.startswith("$HOME"):
            if not home:
                continue
            expanded = f"{home}{expanded[len('$HOME'):]}"
        if any(ch in expanded for ch in "*?["):
            # Newest version directory first for `.../node/*/bin`-style layouts.
            matches = sorted(glob(expanded), reverse=True)
        else:
            matches = [expanded]
        found.extend(match for match in matches if os.path.isdir(match))
    return tuple(dict.fromkeys(found))


def resolve_harnesses(
    harnesses: tuple[str, ...],
    source: Mapping[str, str],
) -> dict[str, Optional[str]]:
    """Resolve every harness the way it will be LAUNCHED, not merely exec'd.

    Returns ``{harness: absolute path or None}``.  The ladder is
    ``PATH`` -> login-shell ``PATH`` -> absolute candidate directories, and
    each rung only runs for the harnesses still unresolved, so a host whose
    engines are all on ``PATH`` spawns no subprocess at all.
    """
    ordered = tuple(dict.fromkeys(harnesses))
    resolved: dict[str, Optional[str]] = {
        name: shutil.which(name, path=source.get("PATH")) for name in ordered
    }
    missing = [name for name in ordered if resolved[name] is None]
    if not missing:
        return resolved
    for extra_dirs in (_login_shell_dirs(source), _launch_candidate_dirs(source)):
        if not extra_dirs:
            continue
        search = os.pathsep.join(extra_dirs)
        for name in tuple(missing):
            found = shutil.which(name, path=search)
            if found is not None:
                resolved[name] = found
        missing = [name for name in missing if resolved[name] is None]
        if not missing:
            break
    return resolved


def _profile(
    env_var: str,
    default_dirname: str,
    markers: tuple[str, ...],
    name_hints: tuple[str, ...],
    default_label: str,
) -> ProfileSpec:
    return ProfileSpec(
        env_var=env_var,
        default_dirname=default_dirname,
        markers=markers,
        name_hints=name_hints,
        default_label=default_label,
    )
