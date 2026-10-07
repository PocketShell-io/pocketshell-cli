"""Resolution, protocol verification, and exec boundary for the Go
`pocketshell-link` host helper.

The `pocketshell gateway` commands are thin wrappers: they never implement
tunnel, enrollment, or SSH logic themselves, they build an argv for the
installed Go helper, verify it identifies as protocol-compatible, and then
replace this process with it (``os.execv``). That boundary is what makes
the wrappers faithful:

- **stdin** — the enroll token arrives piped to stdin and flows straight to
  the helper through the inherited descriptor. Python never reads it (the
  metadata probe below runs with stdin detached), so it cannot end up in a
  log, an exception message, or the wrapper's output.
- **signals** — the interpreter image is replaced, so SIGINT/SIGTERM reach
  the helper's own ``signal.NotifyContext`` handlers exactly as if the user
  had run `pocketshell-link` directly.
- **exit code** — the helper's status IS the command's status; nothing
  re-maps it.

The helper is resolved from trusted locations only, in this order:

1. ``POCKETSHELL_GATEWAY_HELPER`` — an explicit operator pin, validated (a
   bad value errors instead of silently falling back).
2. the binary inside an installed ``pocketshell-gateway-link`` platform
   wheel (built by the private pocketshell-gateway repo's own delivery
   pipeline). A selected-but-broken install — binary missing, not
   executable, built for a different platform — is a hard error, never a
   silent fallback to PATH.
3. a `pocketshell-link` found on PATH.

Nothing is ever downloaded at runtime and nothing is bundled: the binary
reaches the machine only through an install the user consented to — the
checksum-verified private-beta wheel (see ``docs/gateway-distribution.md``)
or a build from the private ``pocketshell-gateway`` repository
(https://github.com/PocketShell-io/pocketshell-gateway).

**Protocol metadata gate:** before every exec, the chosen helper must
answer ``version --json`` with exactly one JSON object
``{"version": …, "protocol": "pocketshell-tunnel-v1", "commit": …}`` (the
helper's frozen additive contract). The probe is bounded — wall-clock
timeout, output-size cap, stdin detached — and any failure (stale or
unknown protocol tag, missing/mistyped/empty fields, malformed JSON,
duplicate keys, nonzero exit, timeout, excess output) refuses the helper
with a concise compatibility error before the real subcommand can run.
The protocol tag is the compatibility contract; ``version``/``commit``
are provenance information only. An un-injected source build honestly
reports ``devel``/``unknown`` and passes the gate because it speaks the
right protocol — that is useful for local testing, and it is never
mistaken for a verified release anywhere. The metadata output itself is
never echoed, never logged, and never reused as trust or authentication
proof: it decides pass/fail locally, nothing more. (One bounded
diagnostic exception: a wrong ``protocol`` tag is quoted into the refusal
ASCII-escaped and truncated to 100 characters — see
:func:`_validate_metadata_fields`.)

"""

from __future__ import annotations

import json
import os
import platform
import selectors
import shutil
import subprocess
import sys
import time
from importlib import metadata
from typing import NoReturn, Optional

HELPER_NAME = "pocketshell-link"
HELPER_ENV_VAR = "POCKETSHELL_GATEWAY_HELPER"

# The installed-wheel route: the delivery pipeline packages the built
# helper as platform wheels carrying ONLY the binary at this in-package
# path (aplexer precedent: `aplexer_cli/bin/…`). The wrapper never
# downloads or installs it — the user's explicit, checksum-verified
# `pip install` does (private beta; docs/gateway-distribution.md).
WHEEL_DIST_NAME = "pocketshell-gateway-link"
WHEEL_BIN_RELATIVE = "pocketshell_gateway_link/bin/pocketshell-link"

# The compatibility contract between this wrapper and the helper
# (`protocolVersionTag` beside cmd/pocketshell-link/main.go in the
# pocketshell-gateway repo): bumped only on wire-INCOMPATIBLE helper
# changes, kept on additive ones.
EXPECTED_PROTOCOL = "pocketshell-tunnel-v1"

# Bounds for the `version --json` metadata probe. One small JSON line is
# the entire expected answer; anything near these bounds is already a
# misbehaving helper and fails closed.
METADATA_TIMEOUT_SECONDS = 10.0
METADATA_MAX_OUTPUT_BYTES = 4096
# Upper I/O chunk only: each os.read is clamped to the remaining output
# budget (+1), so no transient read ever allocates beyond the contract.
_METADATA_READ_CHUNK = 65536

# The wheel platform tag each host can accept, mirroring the delivery
# build matrix (delivery owns packaging and provenance; this is the
# consumer-side check that an installed wheel was actually built for THIS
# platform, so a foreign wheel is refused instead of exec'ing an
# architecture mismatch). Keys use the normalized machine spelling;
# platform spellings amd64/aarch64 normalize below.
_HOST_WHEEL_TAGS = {
    ("linux", "x86_64"): "manylinux_2_28_x86_64",
    ("linux", "arm64"): "manylinux_2_28_aarch64",
    ("darwin", "x86_64"): "macosx_11_0_x86_64",
    ("darwin", "arm64"): "macosx_11_0_arm64",
}

# Kept in sync with the helper contract (cmd/pocketshell-link/main.go in the
# pocketshell-gateway repo). These are the
# subcommands the wrapper forwards; anything else the helper grows stays
# opt-in on the helper's own CLI until a wrapper lands for it.
SUBCOMMANDS = ("enroll", "run", "show")


class HelperNotFoundError(Exception):
    """The Go `pocketshell-link` helper could not be resolved.

    The message is operator-facing: it names the env var, the wheel and
    PATH lookups, and the build command. The CLI layer prints it verbatim
    and exits 127.
    """


class HelperIncompatibleError(Exception):
    """A resolved helper refused to identify as protocol-compatible.

    Raised by :func:`verify_helper` when the bounded ``version --json``
    probe fails: wrong protocol tag, malformed or mistyped metadata,
    non-JSON constants, unparseable nesting, nonzero exit, timeout, or
    excess output. The message is concise by contract — the helper's own
    output is never echoed (single bounded exception: the ASCII-escaped,
    truncated protocol tag of a stale-protocol refusal) — and the CLI
    prints it verbatim and exits 126.
    """


def _incompatible(helper: str, reason: str) -> HelperIncompatibleError:
    """Compose the one-line compatibility error.

    The helper path is ``ascii()``-escaped so an exotic local filename
    (newlines, quotes, control bytes) cannot break the one-line promise;
    for ordinary paths the escaped form contains the path verbatim.
    """
    return HelperIncompatibleError(
        f"the gateway helper at {ascii(helper)} is not compatible with "
        f"this CLI: {reason}. Install the {WHEEL_DIST_NAME} wheel built "
        f"for this platform or point {HELPER_ENV_VAR} at a compatible "
        "binary."
    )


def _installed_wheel_distribution():
    """The installed ``pocketshell-gateway-link`` distribution, or None.

    Small indirection so tests can fake broken/foreign installs without
    touching the real environment. A distribution whose metadata cannot be
    read at all is a selected-but-broken install: hard error, no fallback.
    """
    try:
        return metadata.distribution(WHEEL_DIST_NAME)
    except metadata.PackageNotFoundError:
        return None
    except Exception as exc:
        raise HelperNotFoundError(
            f"the installed {WHEEL_DIST_NAME} package could not be read "
            f"({exc!r}); reinstall it. The wrapper does not fall back to a "
            "different helper while a broken install is selected."
        ) from exc


def _host_wheel_tag() -> str:
    """The delivery-matrix wheel platform tag this machine can run."""
    system = platform.system().lower()
    machine = platform.machine().lower()
    if machine in ("amd64", "x86_64"):
        machine = "x86_64"
    elif machine in ("arm64", "aarch64"):
        machine = "arm64"
    tag = _HOST_WHEEL_TAGS.get((system, machine))
    if tag is None:
        raise HelperNotFoundError(
            f"no {WHEEL_DIST_NAME} wheel exists for this platform "
            f"({system} {platform.machine()}); the delivery matrix covers "
            "linux amd64/arm64 and darwin amd64/arm64 only. Build the "
            f"helper from source and pin it via {HELPER_ENV_VAR}."
        )
    return tag


def _resolve_wheel_helper() -> Optional[str]:
    """The wheel-installed helper binary, or None when no wheel is installed.

    An installed wheel is a selection: if it is broken — the binary is
    missing or not executable, the wheel was built for a different
    platform, or its metadata is unreadable (missing, mangled, or not
    valid UTF-8) — this raises instead of returning None, so the wrapper
    never quietly continues on PATH as if the package were not there.
    """
    dist = _installed_wheel_distribution()
    if dist is None:
        return None
    expected_tag = _host_wheel_tag()
    try:
        wheel_text = dist.read_text("WHEEL")
        binary = dist.locate_file(WHEEL_BIN_RELATIVE)
    except Exception as exc:
        raise HelperNotFoundError(
            f"the installed {WHEEL_DIST_NAME} package metadata could not "
            f"be read ({exc!r}); reinstall it. The wrapper does not fall "
            "back to a different helper while a broken install is selected."
        ) from exc
    if not wheel_text:
        raise HelperNotFoundError(
            f"the installed {WHEEL_DIST_NAME} package has no readable "
            "wheel metadata (dist-info/WHEEL missing); reinstall it. The "
            "wrapper does not fall back to a different helper while a "
            "broken install is selected."
        )
    tags = [
        line.split(":", 1)[1].strip()
        for line in wheel_text.splitlines()
        if line.startswith("Tag:")
    ]
    if not any(tag and tag.split("-")[-1] == expected_tag for tag in tags):
        raise HelperNotFoundError(
            f"the installed {WHEEL_DIST_NAME} wheel is built for platform "
            f"tag(s) {tags}, which do not match this host (expects "
            f"{expected_tag}); install the wheel built for this platform. "
            "The wrapper does not fall back to a different helper while a "
            "mismatched install is selected."
        )
    if not os.path.isfile(binary):
        raise HelperNotFoundError(
            f"the installed {WHEEL_DIST_NAME} wheel does not contain an "
            f"executable at {WHEEL_BIN_RELATIVE} "
            f"(looked at {binary}); reinstall it. The wrapper does not "
            "fall back to a different helper while a broken install is "
            "selected."
        )
    if not os.access(binary, os.X_OK):
        raise HelperNotFoundError(
            f"the helper installed by {WHEEL_DIST_NAME} at {binary} is "
            "not executable; reinstall the wheel. The wrapper does not "
            "fall back to a different helper while a broken install is "
            "selected."
        )
    return str(binary)


def resolve_helper() -> str:
    """Return the executable path of the Go `pocketshell-link` helper.

    Resolution order:

    1. ``$POCKETSHELL_GATEWAY_HELPER`` — an explicit pin to a trusted
       binary. When set but not an executable file this raises instead of
       falling back: an operator who pinned a path must never be silently
       served by a different binary off PATH.
    2. the binary inside an installed ``pocketshell-gateway-link`` wheel —
       preferred over PATH so an explicit package install is not shadowed
       by a stray binary. A broken or foreign-platform install raises
       instead of falling back (see :func:`_resolve_wheel_helper`).
    3. `pocketshell-link` on PATH.

    Raises :class:`HelperNotFoundError` with an actionable message
    otherwise. The selection is normalized ONCE to a single absolute
    path: both the protocol probe (:func:`verify_helper`, a ``Popen``
    that would otherwise PATH-search a bare name) and the final
    :func:`exec_helper` (``os.execv``, which would resolve that same bare
    name against the working directory) use that identical file.
    Whatever it is still has to pass :func:`verify_helper` before
    anything is exec'd.
    """
    if sys.platform == "win32":
        raise HelperNotFoundError(
            "pocketshell gateway does not support Windows: the exec "
            "boundary is the POSIX os.execv, and the "
            f"{WHEEL_DIST_NAME} wheels ship for linux amd64/arm64 and "
            "darwin amd64/arm64 only."
        )
    pinned = os.environ.get(HELPER_ENV_VAR)
    if pinned:
        if os.path.isfile(pinned) and os.access(pinned, os.X_OK):
            return os.path.abspath(pinned)
        raise HelperNotFoundError(
            f"{HELPER_ENV_VAR} is set to {pinned!r} but that is not an "
            "executable file. Fix the variable or unset it to look for "
            f"`{HELPER_NAME}` on PATH instead."
        )
    wheel_binary = _resolve_wheel_helper()
    if wheel_binary:
        return os.path.abspath(wheel_binary)
    found = shutil.which(HELPER_NAME)
    if found:
        return os.path.abspath(found)
    raise HelperNotFoundError(
        f"the PocketShell gateway helper `{HELPER_NAME}` was not found.\n"
        "\n"
        "`pocketshell gateway` execs the Go helper; it does not bundle or "
        "download it. Install\nthe private-beta platform wheel (verify "
        "its checksum against the channel's published\ndigest first — see "
        "docs/gateway-distribution.md):\n"
        "\n"
        "  pip install --no-index --no-deps \\\n"
        "      /verified/path/pocketshell_gateway_link-<version>-<platform>.whl\n"
        "\n"
        "Or build it from a checkout of the private pocketshell-gateway "
        "repository\n"
        "(https://github.com/PocketShell-io/pocketshell-gateway):\n"
        "\n"
        "  cd /path/to/pocketshell-gateway\n"
        "  go build -o \"$HOME/.local/bin/pocketshell-link\" ./cmd/pocketshell-link\n"
        "\n"
        f"Or point {HELPER_ENV_VAR} at an existing `{HELPER_NAME}` binary."
    )


def _probe_version_json(helper: str) -> tuple[int, bytes]:
    """Run ``helper version --json`` under hard bounds and capture the answer.

    stdin is detached (``DEVNULL``) so the probe can never consume the
    piped enrollment token that must remain untouched on this process's
    stdin for the later :func:`exec_helper`. One monotonic deadline
    (:data:`METADATA_TIMEOUT_SECONDS`) governs ACCEPTANCE: output is read
    through a selector against it, each read is clamped to the remaining
    output budget (so no transient over-sized buffer), and after stdout
    EOF the child must still be done within what remains of that same
    deadline — closing stdout early buys no extra answer time. Only the
    kill/reap CLEANUP may outlive the deadline. Output exceeding
    :data:`METADATA_MAX_OUTPUT_BYTES` is refused the moment it happens, so
    nothing the helper writes is ever captured unboundedly. The probe
    child is always reaped; a misbehaving one is killed.
    """
    deadline = time.monotonic() + METADATA_TIMEOUT_SECONDS
    try:
        proc = subprocess.Popen(
            [helper, "version", "--json"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError as exc:
        raise _incompatible(
            helper, f"cannot be executed ({exc.strerror or exc})"
        ) from None
    chunks: list[bytes] = []
    total = 0
    timed_out = False
    returncode: Optional[int] = None
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    timed_out = True
                    break
                # Never read more than the remaining budget (+1 to detect
                # the overflow): the allocation stays bounded by the
                # contract, not by a chunk constant.
                chunk = os.read(
                    proc.stdout.fileno(),
                    min(_METADATA_READ_CHUNK, METADATA_MAX_OUTPUT_BYTES - total + 1),
                )
                if not chunk:
                    break
                total += len(chunk)
                if total > METADATA_MAX_OUTPUT_BYTES:
                    raise _incompatible(
                        helper,
                        f"wrote more than the "
                        f"{METADATA_MAX_OUTPUT_BYTES}-byte version-metadata "
                        "budget",
                    )
                chunks.append(chunk)
        if not timed_out:
            # Acceptance, not cleanup: the child must be FINISHED within
            # the original monotonic budget even though it already closed
            # stdout; cleanup below may take longer but never extends the
            # answer window.
            try:
                returncode = proc.wait(
                    timeout=max(deadline - time.monotonic(), 0.0)
                )
            except subprocess.TimeoutExpired:
                timed_out = True
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        proc.stdout.close()
    if timed_out:
        raise _incompatible(
            helper,
            f"did not answer `version --json` within "
            f"{METADATA_TIMEOUT_SECONDS:g}s",
        )
    assert returncode is not None  # only reachable when wait() succeeded
    return returncode, b"".join(chunks)


class _NonJsonConstantError(ValueError):
    """NaN/Infinity/-Infinity: a Python json extension, never valid JSON."""


def _reject_non_json_constant(token: str) -> None:
    """``parse_constant`` hook keeping the metadata gate strict-JSON."""
    raise _NonJsonConstantError(token)


def _no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    """``object_pairs_hook`` rejecting repeated JSON keys (conflicting
    metadata must not silently resolve to whichever key came last)."""
    seen: dict = {}
    for key, value in pairs:
        if key in seen:
            raise ValueError(f"duplicate key {key!r}")
        seen[key] = value
    return seen


def _parse_version_metadata(output: bytes) -> None:
    """Strictly validate the probe output as the frozen one-line contract.

    Exactly one JSON object on a single line; ``version``/``commit`` must
    be nonempty strings; ``protocol`` must equal
    :data:`EXPECTED_PROTOCOL`. Extra top-level fields are accepted (the
    contract is additive), everything else fails closed: non-JSON
    constants (``NaN``/``Infinity``/``-Infinity``) are rejected even in
    additive fields, and nesting deep enough to exhaust the parser's
    recursion is contained as the concise refusal instead of leaking a
    ``RecursionError`` traceback. Raises
    :class:`HelperIncompatibleError` with a reason-only message; the
    caller composes the full error. Field values are never quoted into
    error text (except the ASCII-escaped protocol tag) so a hostile
    helper cannot forge log lines.
    """
    reason: str
    if b"\x00" in output:
        reason = "metadata contains NUL bytes"
    else:
        try:
            text = output.decode("utf-8")
        except UnicodeDecodeError:
            reason = "metadata is not UTF-8 text"
        else:
            if text.endswith("\n"):
                text = text[:-1]
            if not text or "\n" in text:
                reason = "expected exactly one JSON line, got several"
            else:
                try:
                    fields = json.loads(
                        text,
                        object_pairs_hook=_no_duplicate_keys,
                        parse_constant=_reject_non_json_constant,
                    )
                except _NonJsonConstantError:
                    reason = (
                        "metadata contains NaN/Infinity, which are not "
                        "valid JSON"
                    )
                except RecursionError:
                    reason = "metadata nests too deeply to parse"
                except ValueError:
                    reason = "metadata is not a single JSON object"
                else:
                    if not isinstance(fields, dict):
                        reason = "metadata is not a JSON object"
                    else:
                        _validate_metadata_fields(fields)
                        return
    raise HelperIncompatibleError(reason)


def _validate_metadata_fields(fields: dict) -> None:
    missing = object()
    for name in ("version", "protocol", "commit"):
        value = fields.get(name, missing)
        if value is missing:
            raise HelperIncompatibleError(
                f"metadata field {name!r} is missing"
            )
        if not isinstance(value, str):  # includes JSON null/true/numbers
            raise HelperIncompatibleError(
                f"metadata field {name!r} is not a string"
            )
        if not value.strip():
            raise HelperIncompatibleError(
                f"metadata field {name!r} is empty"
            )
    if fields["protocol"] != EXPECTED_PROTOCOL:
        raise HelperIncompatibleError(
            f"protocol {ascii(fields['protocol'])[:100]} is not "
            f"{EXPECTED_PROTOCOL!r} (helper from a different or stale "
            "protocol generation)"
        )


def verify_helper(helper: str) -> None:
    """Refuse a helper that does not identify as protocol-compatible.

    Runs the bounded ``version --json`` probe (see
    :func:`_probe_version_json`) and fails closed — before any real
    subcommand could run — unless the helper answers with the exact
    one-line metadata contract. This is a local pass/fail gate only: the
    metadata output is never echoed and never treated as a release,
    version, or trust statement. An un-injected source build honestly
    reporting ``devel``/``unknown`` passes because it speaks
    :data:`EXPECTED_PROTOCOL`; it is provenance "unverified", by design.
    """
    returncode, output = _probe_version_json(helper)
    if returncode != 0:
        raise _incompatible(
            helper,
            f"`version --json` exited with status {returncode} instead of "
            "reporting version metadata",
        )
    try:
        _parse_version_metadata(output)
    except HelperIncompatibleError as exc:
        raise _incompatible(helper, str(exc)) from None


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
