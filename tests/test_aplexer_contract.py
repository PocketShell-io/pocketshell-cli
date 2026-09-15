"""Behavioural contract of the BUNDLED aplexer binary (issue #2543).

``test_aplexer_resolution.py`` proves *which* ``a`` we run. This file proves
*what that ``a`` does* — and it exists because the version string provably
cannot answer that question.

Why a version check is not enough
---------------------------------

While #2543 was in review, aplexer's ``main`` sat 143 commits past the
``v0.1.1`` tag while STILL self-reporting ``a --version`` -> ``0.1.1``. The
published 0.1.1 wheel and the build every PocketShell host actually ran were
therefore indistinguishable by version, and pinning 0.1.1 under the D22 hard
cut (the bundled copy is the ONLY copy) would have silently DOWNGRADED every
host. Two post-0.1.1 fixes the real create-agent path depends on were missing:

* ``ee4b957`` — profile ``executable`` override (argv[0]) for Codex variants.
  0.1.1 accepts the key and then IGNORES it, so
  ``[profiles.zcodex] engine="codex", executable="zcodex"`` resolved argv[0]
  to ``codex`` and ``pocketshell sessions create --backend aplexer --engine
  codex --profile zcodex`` died with
  ``a: command is not executable or was not found in PATH: codex``.
* ``d13ecb2`` — preserve the provider environment for plain ``shell``
  launches. 0.1.1 stripped 71 provider vars from every shell session.

The 0.1.3 bump proved the point a second time, from the other direction: a
version comparison would have called it a patch release, while what it
actually fixes is the phone's session tree going blank whenever a session is
being created (see the ``aplexer#2 / #3`` block below).

So these tests pin BEHAVIOUR, against the real bundled binary, with their own
config, state and runtime fixtures (``APLEXER_CONFIG`` /
``APLEXER_STATE_DIR`` / ``APLEXER_RUNTIME_DIR``) — never the maintainer's
personal ``~/.config/aplexer/config.toml`` or the live sessions in
``~/.local/state/aplexer``, which would make them pass on exactly one machine
and disturb real work while doing it. Every assertion here was verified to
fail on the previous published wheel and pass on the pinned one (0.1.1 -> 0.1.2
for the ``executable`` / shell-env pair, 0.1.2 -> 0.1.3 for the registry-scan
trio, 0.1.3 -> 0.1.4 for the ``agent`` field); a future pin that regresses
fails loudly instead of shipping a silent downgrade.

They run in the ``Python utility tests`` job (``tests.yml``), on Linux, with
no Docker service or fixture port — the same gate the rest of this suite uses.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import tomllib
import uuid
from pathlib import Path
from typing import Any, Optional, Sequence

import pytest

from pocketshell.runtime import aplexer as _aplexer
from pocketshell.runtime import sessions as _session_enum
from pocketshell import sessions as _sessions

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="aplexer publishes Linux wheels only; the pin is marked sys_platform=='linux'",
)

# Exactly the `a` surface pocketshell drives, read off the call sites:
#   sessions.aplexer_start_argv / _create_on_aplexer  -> start
#   sessions._aplexer_snapshot / session_enum         -> snapshot, list
#   engines.py / profiles.py                          -> engines, profiles
#   agents.py::launch_agent shim                      -> launch-spec
#   sessions.py attach / kill                         -> attach, kill
# A future pin that drops any of these (or renames a flag) breaks the CLI at
# runtime with no compile-time signal, so assert the surface exists.
REQUIRED_SURFACE: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("start", ("--workspace", "--tag", "--engine", "--profile")),
    ("snapshot", ()),
    ("list", ()),
    ("engines", ()),
    ("profiles", ()),
    ("launch-spec", ("--engine", "--cwd", "--profile", "--no-skip-permissions")),
    ("attach", ("--workspace", "--tag")),
    ("kill", ("--workspace", "--tag")),
)


def bundled_a() -> str:
    """The pinned, bundled ``a`` — never a host copy, never PATH.

    Fails (does not skip) when it is missing: on Linux an absent bundled
    console-script is a packaging-integrity error, which is exactly the class
    of problem #2543 is about.
    """
    report = _aplexer.resolve_a({"PATH": ""})
    if report.path is None:
        pytest.fail(
            "no bundled aplexer console-script next to the interpreter; "
            f"tried {report.tried}"
        )
    expected = str(Path(sys.executable).parent / "a")
    assert report.path == expected, (
        "the binary under contract test must be the BUNDLED one "
        f"({expected}), got {report.path} via {report.source}"
    )
    return report.path


def _pinned_version() -> str:
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    reqs = [
        r
        for r in data["project"]["dependencies"]
        if r.split(";")[0].strip().startswith("aplexer")
    ]
    assert len(reqs) == 1, f"expected exactly one aplexer requirement, got {reqs}"
    return reqs[0].split(";")[0].strip().split("==", 1)[1]


def _short_runtime_root() -> str:
    """A throwaway ``APLEXER_RUNTIME_DIR`` short enough for AF_UNIX.

    aplexer binds ``<runtime_root>/sessions/<uuid>/control.sock`` — 59 bytes
    of suffix — and ``sun_path`` is capped at 108, so the runtime root cannot
    be a deep pytest ``tmp_path``. That is why the fixture below could not
    simply reuse ``tmp_path`` for it: with the pytest root the worker dies
    with ``path must be shorter than SUN_LEN`` for reasons that have nothing
    to do with the contract under test (observed while writing this file).

    Prefer the platform temp dir; fall back to ``/dev/shm`` when ``TMPDIR``
    is itself too deep. Fail loudly rather than silently producing a
    mysterious worker-startup error.
    """
    suffix = len("/sessions/") + 36 + len("/control.sock")
    for base in (tempfile.gettempdir(), "/dev/shm"):
        if not os.path.isdir(base):
            continue
        root = tempfile.mkdtemp(prefix="ps-aplx-", dir=base)
        if len(root) + suffix < 108:
            return root
        os.rmdir(root)
    raise AssertionError(
        "no temp base short enough for an AF_UNIX control socket; "
        f"tried {tempfile.gettempdir()!r} and '/dev/shm'"
    )


@pytest.fixture(autouse=True)
def _no_host_aplexer_override(monkeypatch: pytest.MonkeyPatch) -> None:
    """Hermeticity: a developer-shell APLEXER_BIN must not leak in.

    The contract below exercises the BUNDLED ``a`` (and, via conftest's
    ``install_fake_a``, an explicit stub when a test asks for one); a real
    override exported in the maintainer's shell would silently answer for
    both, so it is scrubbed up front.
    """
    monkeypatch.delenv("APLEXER_BIN", raising=False)


@pytest.fixture
def aplexer_fixture(tmp_path: Path):
    """A throwaway aplexer config + state + runtime, and an env that uses them.

    ``APLEXER_CONFIG`` / ``APLEXER_STATE_DIR`` / ``APLEXER_RUNTIME_DIR`` are
    aplexer's own explicit overrides (``aplexer/src/lib.rs::Paths::discover``),
    so the contract is asserted against OUR fixture profiles and OUR session
    registry — never whatever the developer has in ``~/.config/aplexer`` or
    the live sessions in ``~/.local/state/aplexer``. The registry override
    matters as much as the config one now that this file exercises the
    session-listing path: a test that scanned the real registry would both
    read the maintainer's live sessions and be at the mercy of them.

    ``PATH`` holds the system dirs only — no ``a``, no ``aplexer`` — so a host
    copy cannot answer for the bundled one, and ``XDG_RUNTIME_DIR`` is
    deliberately absent: the autouse conftest fixture points it deep under the
    pytest tmp root, and aplexer's ``$XDG_RUNTIME_DIR/aplexer/sessions/<uuid>/
    control.sock`` then exceeds the 108-byte AF_UNIX limit, killing the worker
    for reasons unrelated to this contract.
    """

    class Fixture:
        def __init__(self) -> None:
            self.binary = bundled_a()
            self.config = tmp_path / "aplexer-config.toml"
            self.home = tmp_path / "aplexer-home"
            self.workspace = tmp_path / "ws"
            self.state_dir = tmp_path / "aplexer-state"
            for directory in (self.home, self.workspace, self.state_dir):
                directory.mkdir(exist_ok=True)
            self.runtime_dir = _short_runtime_root()
            self.env = {
                "PATH": "/usr/bin:/bin",
                "HOME": str(self.home),
                "TERM": "dumb",
                "APLEXER_CONFIG": str(self.config),
                "APLEXER_STATE_DIR": str(self.state_dir),
                "APLEXER_RUNTIME_DIR": self.runtime_dir,
                # conftest's autouse isolation sets POCKETSHELL_APLEXER=0 so
                # that helper tests can never be answered by a host `a`. The
                # tests here that drive the PRODUCTION probes
                # (session_enum._probe_aplexer, sessions._aplexer_snapshot)
                # must opt back in, or `run_json` short-circuits to None
                # before running anything — a red that proves the kill switch
                # works, not that the pin is wrong.
                "POCKETSHELL_APLEXER": "1",
            }

        @property
        def sessions_root(self) -> Path:
            """``<state>/sessions`` — the directory ``list_records`` scans."""
            return self.state_dir / "sessions"

        def make_record_less_session_dir(self) -> Path:
            """The exact on-disk shape a concurrent ``a start`` leaves behind.

            ``start_session`` creates ``<state>/sessions/<uuid>/`` and only
            then writes ``session.json`` into it (26-43 ms later, measured),
            both under the registry lock. Every reader that does NOT take that
            lock — which is every ``a list`` / ``a snapshot`` / ``a watch``,
            i.e. everything PocketShell drives — can observe the gap.
            """
            directory = self.sessions_root / str(uuid.uuid4())
            directory.mkdir(parents=True)
            assert not (directory / "session.json").exists()
            return directory

        def write_config(self, body: str) -> None:
            self.config.write_text(body, encoding="utf-8")

        def run(self, args: Sequence[str], *, timeout: float = 60) -> Any:
            if not self.config.exists():
                self.write_config("version = 1\n")
            return subprocess.run(
                [self.binary, *args],
                capture_output=True,
                text=True,
                env=dict(self.env),
                cwd=str(self.workspace),
                timeout=timeout,
            )

        def json(self, args: Sequence[str], *, timeout: float = 60) -> Any:
            completed = self.run(["--json", *args], timeout=timeout)
            assert completed.returncode == 0, (
                f"`a --json {' '.join(args)}` exited {completed.returncode}: "
                f"{completed.stderr or completed.stdout}"
            )
            return json.loads(completed.stdout)

    fixture = Fixture()
    try:
        yield fixture
    finally:
        # The runtime root lives outside ``tmp_path`` (AF_UNIX length), so
        # pytest's own tmp retention does not clean it up.
        shutil.rmtree(fixture.runtime_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# issue #9 — `a rename` behind `pocketshell sessions rename`
# ---------------------------------------------------------------------------


def test_bundled_aplexer_rename_rekeys_the_live_row(aplexer_fixture) -> None:
    """Real transport: create, rename, and confirm the row re-keys attachable.

    The unit tests pin the argv; this pins the RUNTIME half of the verb —
    the renamed session survives as a live, attachable row under its new
    name, and the old name is gone.
    """
    tag = f"ps9-{uuid.uuid4().hex[:8]}"
    new_tag = f"{tag}-r"
    started = aplexer_fixture.run(
        [
            "--json", "start",
            "--workspace", str(aplexer_fixture.workspace),
            "--tag", tag,
        ]
    )
    assert started.returncode == 0, started.stderr.strip()

    def running_row() -> Optional[dict[str, Any]]:
        matches = [
            row for row in aplexer_fixture.json(["list"]) if row["tag"] == tag
        ]
        if len(matches) == 1 and matches[0].get("state") == "running":
            return matches[0]
        return None

    try:
        row = _poll(running_row, lambda value: value is not None)
        assert row is not None, f"session {tag} never reached state=running"
        # Rename by record id (the dir-stem id #2661 established): aplexer's
        # bare-tag selector does not resolve a tag from the cwd alone here.
        renamed = aplexer_fixture.run(
            ["--json", "rename", str(row["id"]), "--tag", new_tag]
        )
        assert renamed.returncode == 0, renamed.stderr.strip()
        record = json.loads(renamed.stdout)
        assert record["tag"] == new_tag

        rows, errors = _session_enum.enumerate_live_sessions(env=aplexer_fixture.env)
        assert errors == [], errors
        renamed_rows = [row for row in rows if row.tag == new_tag]
        assert len(renamed_rows) == 1, f"renamed row missing from the live set: {rows}"
        assert renamed_rows[0].alive is True, "the renamed session must stay attachable"
        assert renamed_rows[0].aplexer_id == record.get("id"), (
            "the rename must not re-issue a session id"
        )
        assert renamed_rows[0].name == f"{aplexer_fixture.workspace.name}:{new_tag}"
        assert all(row.tag != tag for row in rows), "the old name must be gone"
    finally:
        aplexer_fixture.run(
            ["kill", "--workspace", str(aplexer_fixture.workspace), "--tag", new_tag]
        )


# ---------------------------------------------------------------------------
# ee4b957 — the profile `executable` override (the reviewer's blocker)
# ---------------------------------------------------------------------------


def test_bundled_aplexer_honours_the_profile_executable_override(aplexer_fixture) -> None:
    """argv[0] comes from the profile's ``executable``, engine args survive.

    Fixture shape of the maintainer's real ``[profiles.zcodex]``: the builtin
    ``codex`` engine plus an ``executable`` override. Published 0.1.1 resolves
    argv[0] to ``codex`` here (verified); 0.1.2 resolves the override.
    """
    aplexer_fixture.write_config(
        "version = 1\n"
        "[profiles.ps2543codex]\n"
        'engine = "codex"\n'
        'executable = "ps2543-codex-variant"\n'
    )

    spec = aplexer_fixture.json(
        ["launch-spec", "--engine", "codex", "--profile", "ps2543codex"]
    )

    argv = spec["argv"]
    assert argv[0] == "ps2543-codex-variant", (
        "the bundled aplexer ignored the profile `executable` override — this "
        "is aplexer ee4b957, missing from published 0.1.1, and it breaks "
        "`sessions create --engine codex --profile <codex-variant>` with "
        "\"command is not executable or was not found in PATH: codex\". "
        f"Full argv: {argv}"
    )
    assert "-c" in argv and "check_for_update_on_startup=false" in argv, (
        "`executable` overrides ONLY argv[0]; the engine's own default "
        f"arguments must survive. Full argv: {argv}"
    )
    assert "--dangerously-bypass-approvals-and-sandbox" in argv, (
        "the engine's skip-permissions argv must still be appended by default"
    )


def test_bundled_aplexer_profiles_json_exposes_the_executable_field(
    aplexer_fixture,
) -> None:
    """``a --json profiles`` reports ``executable``, so the field is real.

    Published 0.1.1 omits the key entirely from every profile record, which is
    what made the downgrade invisible: the config parses, the profile lists,
    and only the resolved argv is wrong.
    """
    aplexer_fixture.write_config(
        "version = 1\n"
        "[profiles.ps2543codex]\n"
        'engine = "codex"\n'
        'executable = "ps2543-codex-variant"\n'
    )

    profiles = aplexer_fixture.json(["profiles"])

    assert "ps2543codex" in profiles, profiles
    record = profiles["ps2543codex"]
    assert "executable" in record, (
        "`a --json profiles` does not expose `executable`; the bundled build "
        f"predates aplexer ee4b957. Record: {record}"
    )
    assert record["executable"] == "ps2543-codex-variant"


def test_bundled_aplexer_start_launches_the_profile_executable(aplexer_fixture) -> None:
    """End-to-end: a real ``a start`` runs the OVERRIDE, not the engine default.

    The reviewer's blocker manifested at ``a start``, not at ``launch-spec``,
    so reproduce it there on the real binaries. The fixture engine's own
    command is a binary that deliberately does not exist, so a build without
    ee4b957 fails with the maintainer's exact error shape
    (``a: command is not executable or was not found in PATH: …``) — verified
    against published 0.1.1 — while a correct build runs the override and
    leaves a marker file behind.
    """
    marker = aplexer_fixture.workspace.parent / "ps2543-executable-ran"
    shim = aplexer_fixture.workspace.parent / "ps2543-shim"
    shim.write_text(
        "#!/bin/sh\n"
        f'echo ran > "{marker}"\n'
        "exec sleep 60\n",
        encoding="utf-8",
    )
    shim.chmod(0o755)
    aplexer_fixture.write_config(
        "version = 1\n"
        "[engines.ps2543engine]\n"
        'command = ["ps2543-engine-default-absent"]\n'
        "[profiles.ps2543profile]\n"
        'engine = "ps2543engine"\n'
        f'executable = "{shim}"\n'
    )
    tag = f"ps2543c-{uuid.uuid4().hex[:8]}"

    started = aplexer_fixture.run(
        [
            "--json", "start",
            "--workspace", str(aplexer_fixture.workspace),
            "--tag", tag,
            "--engine", "ps2543engine",
            "--profile", "ps2543profile",
        ]
    )
    try:
        assert started.returncode == 0, (
            "`a start` refused the profile `executable` override: "
            f"{started.stderr.strip() or started.stdout.strip()}"
        )
        record = json.loads(started.stdout)
        assert record.get("command") == [str(shim)], (
            "the started session's command must be the profile override, not "
            f"the engine default: {record.get('command')}"
        )
        assert record.get("phase") == "running", (
            f"the worker did not come up: {record.get('phase')} / {record.get('error')}"
        )
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and not marker.exists():
            time.sleep(0.1)
        assert marker.exists(), (
            "the overridden executable never ran — `a start` reported success "
            "without launching the profile's binary"
        )
    finally:
        aplexer_fixture.run(
            ["kill", "--workspace", str(aplexer_fixture.workspace), "--tag", tag]
        )


# ---------------------------------------------------------------------------
# aplexer#2 / #3 — a session being created must not erase the session list
# ---------------------------------------------------------------------------
#
# The 0.1.3 pin exists for this. `list_records` treated a session directory
# with no `session.json` in it as a CORRUPT REGISTRY and failed the whole
# scan:
#
#     a: load session registry entry <dir>: read <dir>/session.json:
#     No such file or directory (os error 2)                        exit=1
#
# But `start_session` creates that directory 26-43 ms BEFORE it writes the
# record, on every single `a start`. So the window is not exotic — it is on
# the normal create path, and any reader that does not hold the registry lock
# can land in it. `a watch` polls forever and died on it (1 run in 60 on an
# idle box); `a list` was bricked outright for the duration.
#
# That reaches the phone directly. `session_enum._probe_aplexer` and
# `sessions._aplexer_snapshot` are the two production probes, and BOTH try
# `a --json snapshot` then fall back to `a --json list` — the fallback cannot
# help here, because the failure is in the shared registry scan underneath
# both. `aplexer.run_json` then collapses the failure to `None`, so the
# session tree loses every aplexer row while a session is being created.
#
# Worse, and found while writing these tests: a record-less directory that
# OUTLIVES the window (a killed/crashed `a start`) bricks the registry
# permanently on 0.1.2 — including `a start` itself, which scans the registry
# under the lock. The host can then never create or list an aplexer session
# again without manual `rmdir`.


def test_bundled_aplexer_lists_through_a_session_being_created(
    aplexer_fixture,
) -> None:
    """A record-less session dir must not fail the scan — it is skipped.

    The narrow, worker-free half of the regression: the registry contains
    exactly the directory `start_session` has just created and not yet
    written into. Published 0.1.2 exits 1 here (verified); 0.1.3 returns
    `[]`.
    """
    aplexer_fixture.write_config("version = 1\n")
    incomplete = aplexer_fixture.make_record_less_session_dir()

    completed = aplexer_fixture.run(["--json", "list"])

    assert completed.returncode == 0, (
        "the bundled aplexer failed the whole registry scan because a session "
        "was mid-creation; this is aplexer#3, missing from published 0.1.2, "
        "and it blanks the phone's session tree. "
        f"exit={completed.returncode} stderr={completed.stderr.strip()!r}"
    )
    assert json.loads(completed.stdout) == [], completed.stdout
    assert incomplete.exists(), "the fixture directory should not be consumed"


def test_probe_aplexer_survives_a_session_being_created(aplexer_fixture) -> None:
    """`session_enum._probe_aplexer` returns a LIST, never `None` + an error.

    This is the production probe the session tree calls. On 0.1.2 it comes
    back `(None, "…both failed or returned unreadable JSON…")`, which is the
    aplexer-shaped hole the phone showed.
    """
    aplexer_fixture.write_config("version = 1\n")
    aplexer_fixture.make_record_less_session_dir()

    payload, error = _session_enum._probe_aplexer(aplexer_fixture.env)

    assert error is None, (
        "the production aplexer probe reported a failure for a session that "
        f"was merely being created: {error}"
    )
    assert payload == [], payload


def test_session_being_created_does_not_erase_live_aplexer_sessions(
    aplexer_fixture, monkeypatch
) -> None:
    """End-to-end: a REAL running session stays listed, and `start` still works.

    The narrow test above passes on an empty registry, which cannot show the
    user-visible damage. This one starts a real session through a real
    worker, then drops the record-less directory next to it and asserts that
    BOTH production probes still see it. Verified against published 0.1.2:
    the live session vanishes from both (`_probe_aplexer` -> `(None, error)`,
    `sessions._aplexer_snapshot` -> `None`) and a second `a start` fails
    outright.
    """
    shim = aplexer_fixture.workspace.parent / "aplx-regression-shim"
    shim.write_text("#!/bin/sh\nexec sleep 60\n", encoding="utf-8")
    shim.chmod(0o755)
    aplexer_fixture.write_config(
        "version = 1\n"
        "[engines.aplxregression]\n"
        f'command = ["{shim}"]\n'
    )
    for key, value in aplexer_fixture.env.items():
        monkeypatch.setenv(key, value)

    started_records: dict[str, dict[str, Any]] = {}

    def start(tag: str) -> subprocess.CompletedProcess:
        completed = aplexer_fixture.run(
            [
                "--json", "start",
                "--workspace", str(aplexer_fixture.workspace),
                "--tag", tag,
                "--engine", "aplxregression",
            ]
        )
        if completed.returncode == 0:
            started_records[tag] = json.loads(completed.stdout)
        return completed

    def kill(tag: str) -> None:
        """`a kill`, with a pid-based fallback so the RED path self-cleans.

        On a broken registry (exactly what this test simulates for the
        0.1.2 red baseline) `a kill` fails the same registry scan `list`
        does, so a cleanup that only runs `a kill` leaves the fixture's
        `sleep 60` behind on every red-baseline run. The `start` record
        names the pids, so kill those process groups directly when `a
        kill` reports failure — best-effort, CI only ever runs 0.1.3+
        where the primary path succeeds.
        """
        completed = aplexer_fixture.run(
            ["kill", "--workspace", str(aplexer_fixture.workspace), "--tag", tag]
        )
        if completed.returncode == 0:
            return
        record = started_records.get(tag)
        for key in ("worker_pid", "workload_pid"):
            pid = (record or {}).get(key)
            if not pid:
                continue
            try:
                os.killpg(int(pid), signal.SIGKILL)
            except (OSError, ValueError):
                pass

    live_tag = f"aplx-live-{uuid.uuid4().hex[:8]}"
    second_tag = f"aplx-second-{uuid.uuid4().hex[:8]}"
    started = start(live_tag)
    try:
        assert started.returncode == 0, (
            f"could not start the fixture session: {started.stderr.strip()}"
        )
        assert json.loads(started.stdout)["phase"] == "running", started.stdout
        assert [
            row["tag"] for row in _session_enum._probe_aplexer(aplexer_fixture.env)[0]
        ] == [live_tag], "precondition: the live session must be listed"

        # …and now a concurrent `a start` is mid-flight.
        aplexer_fixture.make_record_less_session_dir()

        payload, error = _session_enum._probe_aplexer(aplexer_fixture.env)
        assert error is None, (
            "a session being created blanked the aplexer half of the session "
            f"tree: {error}"
        )
        assert [row["tag"] for row in payload] == [live_tag], (
            "the LIVE session disappeared from the listing because an "
            f"unrelated session was being created: {payload}"
        )

        snapshot = _sessions._aplexer_snapshot()
        assert snapshot is not None, (
            "`sessions._aplexer_snapshot` returned None — `aplexer.run_json` "
            "collapses this failure silently, which is why the phone showed "
            "an empty tree with no error"
        )
        assert [row["tag"] for row in snapshot] == [live_tag], snapshot

        # The same scan runs under the registry lock inside `start_session`,
        # so 0.1.2 could not even create a session while one was pending.
        second = start(second_tag)
        assert second.returncode == 0, (
            "`a start` itself failed while another session was mid-creation; "
            "`pocketshell sessions create --backend aplexer` breaks with it. "
            f"stderr={second.stderr.strip()!r}"
        )
        tags = {
            row["tag"] for row in _session_enum._probe_aplexer(aplexer_fixture.env)[0]
        }
        assert tags == {live_tag, second_tag}, tags
    finally:
        kill(live_tag)
        kill(second_tag)


# ---------------------------------------------------------------------------
# issue #4 — the skip is narrow: a GENUINELY corrupt record still hard-fails
# ---------------------------------------------------------------------------
#
# 0.1.3 stopped failing the whole scan on a record-less directory because
# `start_session` legitimately creates that state for 26-43 ms on every `a
# start`. The trio above pins that narrow skip. Nothing pins the NEGATIVE
# side: a future aplexer bump that broadened the skip into "swallow all
# registry-load errors" would pass everything above silently and re-create
# the same invisible blanking through a different door — real corruption
# reported to the phone as an empty session list. Verified by hand against
# 0.1.2 and 0.1.3 during the #2547 review (garbage rc=1, wrong schema rc=1);
# these two tests turn that verification into a pin.


def test_bundled_aplexer_hard_fails_on_an_unparseable_record(aplexer_fixture) -> None:
    """`session.json` that is not JSON at all must fail the scan, not skip."""
    aplexer_fixture.write_config("version = 1\n")
    corrupt = aplexer_fixture.sessions_root / str(uuid.uuid4())
    corrupt.mkdir(parents=True)
    (corrupt / "session.json").write_text("not json at all {{{", encoding="utf-8")

    completed = aplexer_fixture.run(["--json", "list"])

    assert completed.returncode != 0, (
        "the bundled aplexer silently skipped a session record that is not "
        "parseable JSON; a genuinely corrupt registry must hard-fail, or real "
        "corruption reaches the phone as an empty session list (issue #4). "
        f"exit={completed.returncode} stdout={completed.stdout!r}"
    )
    assert corrupt.exists(), "the fixture record must not be consumed"


def test_bundled_aplexer_hard_fails_on_an_unsupported_schema_version(
    aplexer_fixture,
) -> None:
    """Valid JSON, well-formed record, wrong `schema_version` -> hard fail.

    Every field aplexer's own `SessionRecord` requires is present (the
    defaults `read_record` honours are omitted), so serde parses the record
    and the failure comes from the schema check itself — the exact branch a
    broadened skip would have to swallow to regress.
    """
    aplexer_fixture.write_config("version = 1\n")
    corrupt = aplexer_fixture.sessions_root / str(uuid.uuid4())
    corrupt.mkdir(parents=True)
    record = {
        "schema_version": 424242,
        "id": str(corrupt.name),
        "workspace": "/tmp/ps4-ws",
        "tag": "ps4-schema",
        "engine": "shell",
        "command": ["/bin/true"],
        "cwd": "/tmp/ps4-ws",
        "history_bytes": 0,
        "created_at_ms": 0,
        "updated_at_ms": 0,
        "phase": "running",
        "socket_path": "/tmp/ps4-sock",
        "history_path": "/tmp/ps4-hist",
    }
    (corrupt / "session.json").write_text(json.dumps(record), encoding="utf-8")

    completed = aplexer_fixture.run(["--json", "list"])

    assert completed.returncode != 0, (
        "the bundled aplexer accepted a record with an unsupported "
        "`schema_version`; a future-schema record must hard-fail so a "
        "downgraded CLI cannot quietly drop sessions it cannot understand "
        f"(issue #4). exit={completed.returncode} stdout={completed.stdout!r}"
    )
    assert corrupt.exists(), "the fixture record must not be consumed"


# ---------------------------------------------------------------------------
# issue #7 — `state`: aplexer's OWN liveness answer, consumed verbatim
# ---------------------------------------------------------------------------
#
# Three rounds of #2554 re-derived liveness from `phase` + `worker_alive` and
# got it wrong three times; aplexer 355db6e (first released in 0.1.4) answers
# the question itself with `observed_state()`, on every list/snapshot row.
# pocketshell now consumes `state` verbatim (runtime/sessions.py) and the
# local derivation is deleted — D22, no fallback branch. These pins are the
# other half of that cut: the field must EXIST, its vocabulary must be the
# documented one, and the "broken" crashed-start answer must be real, or a
# future aplexer bump silently breaks the contract the session tree now
# leans on.

APLEXER_STATE_VOCABULARY = frozenset(
    {"starting", "running", "exiting", "exited", "failed", "broken"}
)


def test_bundled_aplexer_reports_state_on_a_live_session(aplexer_fixture) -> None:
    """A real session's row carries `state`, inside the documented vocabulary."""
    tag = f"ps7-{uuid.uuid4().hex[:8]}"

    def listed() -> dict[str, Any]:
        rows = [
            row for row in aplexer_fixture.json(["list"]) if row["tag"] == tag
        ]
        assert len(rows) == 1, f"expected exactly one `{tag}` row, got {rows}"
        return rows[0]

    started = aplexer_fixture.run(
        [
            "--json", "start",
            "--workspace", str(aplexer_fixture.workspace),
            "--tag", tag,
        ]
    )
    assert started.returncode == 0, started.stderr.strip()

    try:
        started_row = listed()
        assert "state" in started_row, (
            "the bundled aplexer emitted no `state` field; pocketshell's "
            "liveness answer IS this field since issue #7 — a bump that "
            f"drops it silently dead-ends the whole session tree. Keys: "
            f"{sorted(started_row)}"
        )
        row = _poll(listed, lambda r: r.get("state") == "running")
        # Vocabulary pin: whatever aplexer prints must be a name pocketshell
        # knows, or the fail-closed consume in runtime/sessions.py would
        # classify real sessions as dead. Unknown names fail HERE.
        assert row["state"] in APLEXER_STATE_VOCABULARY, (
            f"unknown `state` vocabulary: {row['state']!r}; known: "
            f"{sorted(APLEXER_STATE_VOCABULARY)}"
        )
        assert row["state"] == "running"
    finally:
        aplexer_fixture.run(
            ["kill", "--workspace", str(aplexer_fixture.workspace), "--tag", tag]
        )


def test_bundled_aplexer_calls_a_dead_worker_broken(aplexer_fixture) -> None:
    """SIGKILL the worker: the running-phase record must read `broken`.

    This is the exact crashed-start-adjacent shape #2554 round 4 found: a
    record whose worker died without writing an exit, stuck at `phase:
    running`. aplexer's `observed_state()` folds it to `broken` — the answer
    the local predicate kept reconstructing wrong — and the second half of
    this test proves pocketshell consumes it: the row must leave the
    attachable set the moment aplexer says broken.
    """
    tag = f"ps7-{uuid.uuid4().hex[:8]}"

    def listed() -> dict[str, Any]:
        rows = [
            row for row in aplexer_fixture.json(["list"]) if row["tag"] == tag
        ]
        assert len(rows) == 1, f"expected exactly one `{tag}` row, got {rows}"
        return rows[0]

    started = aplexer_fixture.run(
        [
            "--json", "start",
            "--workspace", str(aplexer_fixture.workspace),
            "--tag", tag,
        ]
    )
    assert started.returncode == 0, started.stderr.strip()

    try:
        row = _poll(listed, lambda r: r.get("state") == "running")
        worker_pid = row.get("worker_pid")
        assert worker_pid, f"no worker pid on the running row: {row}"

        os.kill(int(worker_pid), signal.SIGKILL)

        row = _poll(listed, lambda r: r.get("state") == "broken")
        assert row["phase"] == "running", (
            "the fixture must reproduce the stale-running-record shape; "
            f"phase moved to {row['phase']!r} on its own"
        )
        assert row["state"] == "broken", (
            "a worker killed without an exit must surface as `broken`, not "
            f"{row['state']!r} — this is the classification #2554 got wrong "
            "three times, now consumed verbatim"
        )

        # The consumer half: `state` alone decides attachability.
        payload = aplexer_fixture.json(["snapshot"])
        live = _session_enum.sessions_from_aplexer_snapshot(payload)
        dead = _session_enum.dead_sessions_from_aplexer_snapshot(payload)
        assert all(session.tag != tag for session in live)
        assert any(
            session.tag == tag and session.alive is False for session in dead
        )
    finally:
        completed = aplexer_fixture.run(
            ["kill", "--workspace", str(aplexer_fixture.workspace), "--tag", tag]
        )
        if completed.returncode != 0:
            # The worker is already dead; the record's own pid is the
            # self-cleaning fallback (the record IS the evidence).
            try:
                os.killpg(int(worker_pid), signal.SIGKILL)
            except (OSError, NameError, ValueError):
                pass


# ---------------------------------------------------------------------------
# 0.1.4 — the snapshot names WHICH agent is running inside the session
# ---------------------------------------------------------------------------
#
# `engine` cannot answer that. Every session PocketShell creates is
# `engine: "shell"` with the agent started by hand inside it, so on 0.1.3 a
# tree of claude/codex/opencode sessions was indistinguishable from a tree of
# bare shells. 0.1.4 derives an `agent` field at QUERY time from the
# workload's descendant process tree (aplexer ca56fa5, spec.md section 18)
# and puts it on every `a list --json` / `a snapshot` row.
#
# Version-trap rule (AGENTS.md): pin the BEHAVIOUR, never the string. So this
# drives the bundled binary through a real session whose workload shell spawns
# a real process named `claude`, and follows it all the way out to the
# schema-2 payload the phone reads.


def _poll(read, predicate, *, timeout: float = 30.0, interval: float = 0.2):
    """Poll ``read()`` until ``predicate`` holds; return the last value seen.

    Detection is a live ``/proc`` walk, so the answer changes a few hundred ms
    after the process tree does. Polling with a deadline is the honest way to
    observe that; a fixed sleep would be either flaky or slow.
    """
    deadline = time.monotonic() + timeout
    value = read()
    while not predicate(value) and time.monotonic() < deadline:
        time.sleep(interval)
        value = read()
    return value


def test_bundled_aplexer_names_the_agent_running_inside_a_session(
    aplexer_fixture, monkeypatch
) -> None:
    """A real session: no agent -> `claude` -> no agent again, on the real `a`.

    The workload is a plain shell (the production shape); the "agent" is a
    symlink to ``sleep`` whose FILENAME is the agent's command token, exactly
    how detection is supposed to recognise a hand-launched agent. Nothing in
    the shell's own argv names an agent, so the null bookends are real
    evidence and not an accident of the temp path.

    Published 0.1.3 has no `agent` key at all — the first assertion below
    fails on it — while 0.1.4 tracks the process tree in both directions.
    Both ends of the wire are checked: the raw `a --json list`/`snapshot`
    rows, and the schema-2 payload `pocketshell sessions list --json` emits
    after `session_enum._probe_aplexer` has driven the same binary.
    """
    agent_bin = aplexer_fixture.workspace.parent / "ps2581-bin"
    agent_bin.mkdir()
    # `sleep` under an agent's name: `comm` and argv[0] both become the token
    # detection looks for, with no coding agent installed anywhere.
    (agent_bin / "claude").symlink_to("/bin/sleep")
    go_marker = aplexer_fixture.workspace.parent / "ps2581-go"
    pid_file = aplexer_fixture.workspace.parent / "ps2581-agent-pid"
    runner = aplexer_fixture.workspace.parent / "ps2581-session-runner.sh"
    # The paths live in the SCRIPT, never in the shell's argv, so the parent
    # process cannot itself be mistaken for the agent.
    runner.write_text(
        "#!/bin/sh\n"
        f'while [ ! -e "{go_marker}" ]; do sleep 0.05; done\n'
        f'"{agent_bin}/claude" 3600 &\n'
        f'echo $! > "{pid_file}"\n'
        "wait\n"
        "exec sleep 300\n",
        encoding="utf-8",
    )
    runner.chmod(0o755)
    # Deliberately the literal `shell` engine, overridden to run the fixture
    # runner: that is the shape EVERY PocketShell session has, and the shape
    # in which `engine` is null on the wire and therefore cannot name the
    # agent. Anything else would prove the field works on a session type the
    # product never creates.
    aplexer_fixture.write_config(
        "version = 1\n"
        "[engines.shell]\n"
        f'command = ["/bin/sh", "{runner}"]\n'
    )
    for key, value in aplexer_fixture.env.items():
        monkeypatch.setenv(key, value)
    tag = f"ps2581-{uuid.uuid4().hex[:8]}"

    def listed(subcommand: str = "list") -> dict[str, Any]:
        rows = [
            row for row in aplexer_fixture.json([subcommand]) if row["tag"] == tag
        ]
        assert len(rows) == 1, f"expected exactly one `{tag}` row, got {rows}"
        return rows[0]

    def probed_payload() -> dict[str, Any]:
        payload, error = _session_enum._probe_aplexer(aplexer_fixture.env)
        assert error is None, error
        rows = _session_enum.sessions_from_aplexer_snapshot(payload)
        row = next(r for r in rows if r.tag == tag)
        return row.to_payload(schema=2)

    started = aplexer_fixture.run(
        [
            "--json", "start",
            "--workspace", str(aplexer_fixture.workspace),
            "--tag", tag,
            "--engine", "shell",
        ]
    )
    try:
        assert started.returncode == 0, (
            f"could not start the fixture session: {started.stderr.strip()}"
        )
        assert json.loads(started.stdout)["command"] == ["/bin/sh", str(runner)], (
            "the fixture must own the workload; the config override did not "
            f"take: {started.stdout}"
        )

        # 1. The key exists at all. This is what 0.1.3 cannot do.
        row = listed()
        assert "agent" in row, (
            "the bundled aplexer emits no `agent` field; this is aplexer "
            "ca56fa5, missing from published 0.1.3, and without it the "
            "session tree cannot say which agent a session is running "
            f"(engine is {row.get('engine')!r} for every PocketShell "
            f"session). Row keys: {sorted(row)}"
        )
        # 2. ...and it is honest before anything agent-shaped is running.
        assert row["agent"] is None, (
            "an idle shell session reported an agent; the workload's own argv "
            f"({row.get('command')}) must not name one. Row: {row}"
        )
        assert probed_payload()["agent"] is None

        # 3. Launch the agent inside the session; detection follows the tree.
        go_marker.touch()
        row = _poll(listed, lambda r: r.get("agent") is not None)
        assert row["agent"] == "claude", (
            "the bundled aplexer did not detect a live `claude` process in "
            f"the session's own descendant tree. Row: {row}"
        )
        # `a snapshot` is the probe pocketshell tries FIRST; the two commands
        # must not disagree.
        assert listed("snapshot")["agent"] == "claude"
        # ...and it survives the whole host path out to the wire.
        payload = probed_payload()
        assert payload["agent"] == "claude", payload
        assert payload["engine"] is None, (
            "precondition for the whole feature: this row's engine says "
            f"nothing about the agent. Payload: {payload}"
        )

        # 4. The agent exits; the session stays. Nothing may be sticky —
        #    detection is per-query and must never be persisted.
        os.kill(int(pid_file.read_text().strip()), 15)
        row = _poll(listed, lambda r: r.get("agent") is None)
        assert row["agent"] is None, (
            "the agent exited but the row still names it, so the value is "
            f"cached or persisted rather than derived per query. Row: {row}"
        )
        assert row["phase"] == "running", (
            f"the session itself must still be alive: {row}"
        )
        assert probed_payload()["agent"] is None
    finally:
        aplexer_fixture.run(
            ["kill", "--workspace", str(aplexer_fixture.workspace), "--tag", tag]
        )


# ---------------------------------------------------------------------------
# d13ecb2 — provider environment preserved for plain shell launches
# ---------------------------------------------------------------------------


def test_bundled_aplexer_preserves_provider_env_for_shell_launches(
    aplexer_fixture,
) -> None:
    """A plain ``shell`` session keeps its ambient/provider environment.

    Published 0.1.1 unset 71 provider vars for the literal ``shell`` engine
    (verified), so every non-agent session created through a 0.1.1 bundle
    would silently lose them.
    """
    spec = aplexer_fixture.json(["launch-spec", "--engine", "shell"])

    assert spec["env_unset"] == [], (
        "the bundled aplexer strips the provider environment from plain "
        "`shell` launches; this is aplexer d13ecb2, missing from published "
        f"0.1.1. Stripped: {spec['env_unset']}"
    )


def test_bundled_aplexer_still_strips_provider_env_for_agent_engines(
    aplexer_fixture,
) -> None:
    """…and the strip policy still applies to agent engines (no over-correction)."""
    spec = aplexer_fixture.json(["launch-spec", "--engine", "codex"])

    unset = set(spec["env_unset"])
    assert {"OPENAI_API_KEY", "ANTHROPIC_API_KEY"} <= unset, (
        "agent engines must still drop provider API keys so subscription auth "
        f"is used; unset only {sorted(unset)}"
    )


# ---------------------------------------------------------------------------
# The `a` surface pocketshell actually drives
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("subcommand,flags", REQUIRED_SURFACE)
def test_bundled_aplexer_exposes_the_surface_pocketshell_drives(
    aplexer_fixture, subcommand: str, flags: tuple[str, ...]
) -> None:
    """Every subcommand + flag the CLI invokes exists in the bundled build.

    ``launch-spec`` is hidden from ``a --help`` (it is aplexer's integration
    point for this CLI), so probe each subcommand directly rather than
    scraping the top-level command list.
    """
    completed = aplexer_fixture.run([subcommand, "--help"])

    assert completed.returncode == 0, (
        f"the bundled aplexer has no `a {subcommand}`; pocketshell calls it. "
        f"{completed.stderr or completed.stdout}"
    )
    help_text = completed.stdout
    missing = [flag for flag in flags if flag not in help_text]
    assert not missing, (
        f"`a {subcommand}` no longer accepts {missing}; pocketshell passes "
        f"them. Help:\n{help_text}"
    )


def test_bundled_aplexer_reports_the_pinned_version(aplexer_fixture) -> None:
    """Sanity only: the bundled binary IS the pinned wheel.

    Deliberately last and deliberately weak — the whole reason this file
    exists is that this assertion passed for a build missing the two fixes
    above. It guards "did the wheel install at all", nothing more; the
    behavioural tests are the contract.
    """
    completed = aplexer_fixture.run(["--version"])

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.split() == ["a", _pinned_version()], (
        f"bundled `a --version` is {completed.stdout.strip()!r}, pyproject "
        f"pins {_pinned_version()}"
    )


def test_contract_env_never_reads_the_developers_aplexer_config(
    aplexer_fixture,
) -> None:
    """The fixture config is authoritative — not ``~/.config/aplexer``.

    A contract test that silently fell back to the maintainer's own profiles
    would pass on exactly one machine, which is what the reviewer warned
    against.
    """
    aplexer_fixture.write_config("version = 1\n")

    profiles = aplexer_fixture.json(["profiles"])

    assert profiles == {}, (
        "the bundled `a` read profiles from somewhere other than "
        f"APLEXER_CONFIG: {profiles}"
    )
    assert aplexer_fixture.env["HOME"] != os.path.expanduser("~")
