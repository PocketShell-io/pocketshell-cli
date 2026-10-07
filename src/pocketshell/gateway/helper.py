"""Resolution and exec boundary for the Go `pocketshell-link` host helper.

The `pocketshell gateway` commands are thin wrappers: they never implement
tunnel, enrollment, or SSH logic themselves, they build an argv for the
installed Go helper and replace this process with it (``os.execv``). That
boundary is what makes the wrappers faithful:

- **stdin** — the enroll token arrives piped to stdin and flows straight to
  the helper through the inherited descriptor. Python never reads it, so it
  cannot end up in a log, an exception message, or the wrapper's output.
- **signals** — the interpreter image is replaced, so SIGINT/SIGTERM reach
  the helper's own ``signal.NotifyContext`` handlers exactly as if the user
  had run `pocketshell-link` directly.
- **exit code** — the helper's status IS the command's status; nothing
  re-maps it.

The helper is resolved from trusted locations only:
``POCKETSHELL_GATEWAY_HELPER`` (explicit operator pin, validated — a bad
value errors instead of silently falling back to PATH) or a
`pocketshell-link` found on PATH. It is never downloaded and never bundled:
build it from the private ``pocketshell-gateway`` repository
(https://github.com/PocketShell-io/pocketshell-gateway) with Go (the
missing-helper error says exactly that). The planned distribution route —
platform wheels carrying the prebuilt helper, built and published by the
private repo's own CI, checksum-verified, no silent downloads — is specified
in ``docs/gateway-distribution.md``; until that lands, this resolution
contract is the whole story.

**Version/protocol honesty:** the wrapper performs NO version or protocol
negotiation today. The current helper's `version` subcommand reports the
literal string ``pocketshell-link dev (protocol pocketshell-tunnel-v1)`` —
a hardcoded ``dev``, not a release version — so any "check" against it
would be theater, not compatibility proof. A runtime version/protocol
metadata request is filed with the Go runtime owner; once the helper
reports real metadata, a check can be added and must compare the protocol
tag (``pocketshell-tunnel-v1``), not parse the version as a compatibility
guarantee.

"""

from __future__ import annotations

import os
import shutil
from typing import NoReturn, Optional

HELPER_NAME = "pocketshell-link"
HELPER_ENV_VAR = "POCKETSHELL_GATEWAY_HELPER"

# Kept in sync with the helper contract (cmd/pocketshell-link/main.go in the
# pocketshell-gateway repo). These are the
# subcommands the wrapper forwards; anything else the helper grows stays
# opt-in on the helper's own CLI until a wrapper lands for it.
SUBCOMMANDS = ("enroll", "run", "show")


class HelperNotFoundError(Exception):
    """The Go `pocketshell-link` helper could not be resolved.

    The message is operator-facing: it names the env var, the PATH lookup,
    and the build command. The CLI layer prints it verbatim and exits 127.
    """


def resolve_helper() -> str:
    """Return the executable path of the Go `pocketshell-link` helper.

    Resolution order:

    1. ``$POCKETSHELL_GATEWAY_HELPER`` — an explicit pin to a trusted
       binary. When set but not an executable file this raises instead of
       falling back: an operator who pinned a path must never be silently
       served by a different binary off PATH.
    2. `pocketshell-link` on PATH.

    Raises :class:`HelperNotFoundError` with an actionable message
    otherwise.
    """
    pinned = os.environ.get(HELPER_ENV_VAR)
    if pinned:
        if os.path.isfile(pinned) and os.access(pinned, os.X_OK):
            return pinned
        raise HelperNotFoundError(
            f"{HELPER_ENV_VAR} is set to {pinned!r} but that is not an "
            "executable file. Fix the variable or unset it to look for "
            f"`{HELPER_NAME}` on PATH instead."
        )
    found = shutil.which(HELPER_NAME)
    if found:
        return found
    raise HelperNotFoundError(
        f"the PocketShell gateway helper `{HELPER_NAME}` was not found.\n"
        "\n"
        "`pocketshell gateway` execs the Go helper; it does not bundle or "
        "download it. Build\nit from a checkout of the private "
        "pocketshell-gateway repository\n"
        "(https://github.com/PocketShell-io/pocketshell-gateway):\n"
        "\n"
        "  cd /path/to/pocketshell-gateway\n"
        "  go build -o \"$HOME/.local/bin/pocketshell-link\" ./cmd/pocketshell-link\n"
        "\n"
        f"Or point {HELPER_ENV_VAR} at an existing `{HELPER_NAME}` binary."
    )


def build_helper_argv(
    subcommand: str,
    *,
    server: Optional[str] = None,
    config_dir: Optional[str] = None,
    insecure_dev: bool = False,
    verbose: bool = False,
    token_stdin: bool = False,
    device_id: Optional[str] = None,
    ssh_host: Optional[str] = None,
    expect_host_key: Optional[str] = None,
    dev_broker_issuer: Optional[str] = None,
    re_enroll: bool = False,
) -> list[str]:
    """Build the helper argv for one subcommand.

    Only options the caller actually received are forwarded: the Go helper
    owns the defaults (`--server` -> ``wss://gateway.pocketshell.io``,
    `--config-dir` -> ``${XDG_CONFIG_HOME:-$HOME/.config}/pocketshell-link``,
    `--ssh-host` -> ``127.0.0.1:22``), so a wrapper-supplied default would
    be a second source of truth that drifts. Boolean flags are forwarded
    only when set — `--insecure-dev` in particular is never defaulted on.

    `--dev-broker-issuer` and `--re-enroll` exist on `enroll` only; passing
    them for `run`/`show` is a programming error and raises here rather
    than building an argv the helper would reject at flag-parse time. (The
    CLI layer additionally refuses `--dev-broker-issuer` without
    `--insecure-dev` and an explicit lab `--server`; see
    `pocketshell.gateway.cli._preflight_dev_broker_issuer`.)

    Values are returned as individual argv elements verbatim; values with
    spaces (a host-key line, a config dir under a spaced path) stay single
    elements. Nothing here is ever interpolated through a shell: the argv
    goes to :func:`os.execv` directly.
    """
    if subcommand not in SUBCOMMANDS:
        raise ValueError(f"unsupported helper subcommand: {subcommand!r}")
    if subcommand != "enroll":
        enroll_only = [
            name
            for name, passed in (
                ("token_stdin", token_stdin),
                ("device_id", device_id is not None),
                ("ssh_host", ssh_host is not None),
                ("expect_host_key", expect_host_key is not None),
                ("dev_broker_issuer", dev_broker_issuer is not None),
                ("re_enroll", re_enroll),
            )
            if passed
        ]
        if enroll_only:
            raise ValueError(
                f"enroll-only option(s) {enroll_only} passed for helper "
                f"subcommand {subcommand!r}"
            )
    argv = [subcommand]
    if token_stdin:
        argv.append("--token-stdin")
    if server is not None:
        argv.extend(["--server", server])
    if config_dir is not None:
        argv.extend(["--config-dir", config_dir])
    if device_id is not None:
        argv.extend(["--device-id", device_id])
    if ssh_host is not None:
        argv.extend(["--ssh-host", ssh_host])
    if expect_host_key is not None:
        argv.extend(["--expect-host-key", expect_host_key])
    if re_enroll:
        argv.append("--re-enroll")
    if dev_broker_issuer is not None:
        argv.extend(["--dev-broker-issuer", dev_broker_issuer])
    if insecure_dev:
        argv.append("--insecure-dev")
    if verbose:
        argv.append("--verbose")
    return argv


def exec_helper(helper: str, argv: list[str]) -> NoReturn:
    """Replace this process with the helper (never returns).

    ``os.execv`` keeps the inherited file descriptors, controlling
    terminal, and PID, which is exactly the preservation contract:
    the token on stdin, Ctrl+C / SIGTERM delivery, and the helper's exit
    code all pass through without this wrapper in the loop. POSIX only —
    same assumption the bundled aplexer dependency already makes.
    """
    os.execv(helper, [helper, *argv])
