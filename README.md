# pocketshell

Unified server-side Python utility for the [PocketShell](https://github.com/PocketShell-io/pocketshell)
Android client. This is the host-side companion CLI, maintained in its own
repo with an independent release cycle; before v0.5.5 it lived at
`tools/pocketshell/` in the [monorepo](https://github.com/PocketShell-io/pocketshell)
(versioning was coupled to the app tag there — see [Release flow](#release-flow)). The app probes for this single helper on each remote
host and uses its subcommands for usage, aplexer session lifecycle, agent
conversations, QR host setup, repository discovery, environment files, hooks,
logs, and daemon lifecycle checks.

## Durable workspaces

The Quiet workspace-first client uses the host-side workspace membership
contract before it has any live session to enumerate:

```text
pocketshell workspaces list --host <host> --json
pocketshell workspaces add <path> --host <host> --json
pocketshell workspaces remove <path> --host <host> --json
```

Membership is stored in the existing private tree registry. Each entry has a
canonical absolute `path` for identity and a separate `display_path` for the
path spelling shown in the UI. Adding or removing the same path repeatedly is
safe, and `list` retains empty workspaces.

## Install

The recommended path is `uv tool install`, which lands the binary on PATH
under `~/.local/bin/`:

```bash
uv tool install pocketshell
```

For local development from a clone:

```bash
cd pocketshell-cli
uv venv
uv pip install -e .
pocketshell --help
```

`pipx install pocketshell` works the same way for users who prefer
pipx. Both install paths produce a `pocketshell` binary that the
PocketShell app's bootstrap probe detects.

### Optional extras

`pocketshell qr-share` requires the `qrcode[pil]` package (Pillow) to
render QR images. Because Pillow is heavy and not needed by any other
subcommand, it ships behind an optional `qr` extra:

```bash
uv tool install pocketshell --with qrcode[pil]
# or
pip install pocketshell[qr]
```

Without the extra, every other subcommand keeps working; only
`pocketshell qr-share` exits 127 with a friendly install hint.

## Usage

Top-level commands in the current helper:

```text
pocketshell usage [provider] [--json]       # provider quota / usage
pocketshell sessions list --json           # schema-3 aplexer session rows
pocketshell sessions create NAME --json      # create or reuse a session
pocketshell sessions attach NAME             # attach to a live session
pocketshell sessions kill NAME --json        # stop and reap a session
pocketshell agent-log ...                   # agent conversation logs
pocketshell repos list ...                  # local / GitHub repositories
pocketshell github status [--json]          # gh install / auth state
pocketshell env ...                         # .env / .envrc management
pocketshell hooks ...                       # Claude/Codex/OpenCode hooks
pocketshell logs ...                        # server-side trace sink
pocketshell daemon ...                      # IPC daemon lifecycle
pocketshell serve --dir PATH [--port N]     # foreground static HTTP server
pocketshell qr-share ...                    # SSH host QR import payloads
```

Run `pocketshell --help` or `pocketshell <command> --help` for the live
flag set. Some parity subcommands still proxy through the existing host
tools internally so their output remains byte-identical to what the app
already parses.

### `pocketshell sessions`

The session group is deliberately aplexer-only. `list`, `create`, `attach`, and
`kill` all use the bundled `a` executable resolved next to the installed
PocketShell interpreter; a missing or unusable aplexer is reported as an error
instead of an empty session list.

```bash
pocketshell sessions list --json
pocketshell sessions create my-session --cwd ~/git/project --mem none --json
pocketshell sessions attach my-session
pocketshell sessions kill my-session --json
```

The list and lifecycle responses use schema 3. Rows carry the aplexer id,
workspace, tag, phase, attachment state, and agent metadata; there is no
backend discriminator or legacy session socket. Create is idempotent for the
same workspace and tag. Kill stops the workload and reaps the aplexer record
before returning its JSON result.

### `pocketshell usage`

```text
pocketshell usage           # human-readable lines, one per provider
pocketshell usage --json    # machine-readable JSON (consumed by the app)
pocketshell usage codex     # filter to a single provider
```

The output shape is byte-identical to `quse [provider] [--json]`. When
the IPC daemon is running, `usage --json` dispatches `usage.fetch` over
the daemon socket and uses the daemon's short TTL cache; otherwise an
absent/unavailable daemon or explicitly supported method skew falls through
to the one-shot subprocess path. Timeout, malformed-response, and
daemon-internal failures are surfaced instead of being retried locally.

All daemon-backed wrappers (`usage`, `repos`, `tree`, `sessions`, and
`agents kind`) use one typed fallback boundary. It emits the safe
`pocketshell.daemon_call` event with `reason`, `method`, `phase`, RPC code, and
available CLI/daemon versions. It never logs RPC parameters or command output.

If `quse` is not installed, `pocketshell usage` exits with code 127 and
prints an install hint to stderr.

### `pocketshell repos list`

Enumerate git repositories — either cloned on this host (`--local`) or
owned by the authenticated GitHub user (`--remote`). The two modes
share one unified JSON schema so a future merged view can interleave
them transparently.

```bash
pocketshell repos list --local            # scan ~/git for clones (human)
pocketshell repos list --local --json     # same, JSON output
pocketshell repos list --remote --json    # via owner-only `gh api user/repos`
pocketshell repos list --remote --limit 20
```

Schema (every entry):

```json
{
  "owner": "alexeygrigorev",          // null when remote URL is non-GitHub
  "name": "pocketshell",              // local dir basename, or GH repo name
  "full_name": "PocketShell-io/pocketshell",  // null when owner unknown
  "local": {                          // populated by --local scans
    "path": "/home/alexey/git/pocketshell",
    "head": "main"
  },
  "remote": {                         // populated by --remote scans
    "default_branch": "main",
    "html_url": "https://github.com/PocketShell-io/pocketshell",
    "ssh_url": "git@github.com:PocketShell-io/pocketshell.git",
    "updated_at": "2026-05-27T12:00:00Z"
  }
}
```

`--local` scans `~/git` by default (override with one or more `--root`
flags or the colon-separated `POCKETSHELL_REPOS_ROOTS` env var) and
populates `local` for every entry. `owner` and `full_name` are
best-effort from the parsed `remote.origin.url`; non-GitHub remotes
leave them `null`.

`--remote` delegates to `gh api 'user/repos?affiliation=owner&sort=updated' --paginate --slurp`.
Requires `gh` on PATH (`apt install gh` on Debian/Ubuntu,
`brew install gh` on macOS) authenticated via
`gh auth login -s repo:read`. Sorted by `updated_at` descending so the
picker shows the most-recently-touched repos first. Missing `gh` exits
127 with an install hint; a non-zero `gh` exit (auth missing,
rate-limit, etc.) propagates the exit code and stderr verbatim.

With neither flag, defaults to `--local` and prints a one-line
discoverability hint mentioning `--remote`.

Daemon mode caches `repos.list_local` for 10 s and `repos.list_remote`
for 5 min. `--no-daemon` forces the in-process path; `--no-cache`
forces the daemon to re-run upstream on the next call.

### `pocketshell github status`

Reports whether the GitHub CLI (`gh`) is installed and authenticated, as
structured JSON the app consumes to gate GitHub features and prompt the
user to configure `gh` when it is missing (epic #644, slice #645).

```bash
pocketshell github status          # human-readable summary
pocketshell github status --json   # machine-readable JSON (consumed by the app)
```

Schema:

```json
{
  "installed": true,             // shutil.which("gh") found the binary
  "authenticated": true,         // `gh auth status` exited 0
  "account": "alexeygrigorev",   // logged-in username, or null
  "hint": null                   // actionable hint when something is missing
}
```

The command always exits 0 — "gh missing" and "not authenticated" are
normal, reportable states (not probe failures), so the app can poll the
status without treating it as an error. When `gh` is absent the `hint` tells
the user to install it and run `gh auth login`; when present but
unauthenticated the `hint` tells them to run `gh auth login`. The only
network access is whatever `gh auth status` itself performs (a token-validity
check); the command does NOT call the GitHub API.

### `pocketshell serve`

Serve a folder over HTTP for a client-owned SSH port forward:

```bash
pocketshell serve --dir /path/to/site
pocketshell serve --dir /path/to/site --port 8080 --bind 127.0.0.1
```

The server binds `127.0.0.1` by default. Omitting `--port` (or passing
`--port 0`) lets the OS select a free port; after binding, stdout contains
exactly one stable JSON line with the selected port:

```json
{"port":43123}
```

The process stays in the foreground so the caller owns its lifetime: keep the
SSH exec channel alive while the site is needed and terminate that process
when the view closes or the connection is lost. There is no detached server
registry or `--stop` command in this contract. HTTP access logs and errors go
to stderr, keeping stdout parseable.

Requests serve static files with stdlib MIME detection. A directory resolves
to its `index.html` when present; paths are resolved before the containment
check, so parent traversal and symlinks that leave the selected directory are
rejected rather than served.

### `pocketshell qr-share`

Builds a `pocketshell.ssh-import.v1` payload from an `~/.ssh/config`
alias (resolved via `ssh -G`) or from explicit flags, wraps it in one or
more `pocketshell.qr.v1` chunked envelopes (matching the Kotlin
`QrChunkCodec` byte-for-byte), and emits QR codes for the phone-side
scanner to consume (issue #129).

```bash
pocketshell qr-share prod                           # ssh-config alias
pocketshell qr-share --host h --user u --key ~/.ssh/id_ed25519 --name h
pocketshell qr-share prod --png --out-dir /tmp/qr   # write PNGs
pocketshell qr-share prod --print-only --id deadbeef  # debug envelopes
```

When stdout is a TTY the QRs are drawn inline as Unicode blocks; between
multi-part transmissions the command pauses on "Press Enter for next
QR" so the user can scan each in turn. When stdout is not a TTY (or
`--png` is passed) a numbered PNG sequence (`qr-share-01.png`,
`qr-share-02.png`, ...) is written to `--out-dir`.

Requires the optional `qr` extra (see [Optional extras](#optional-extras)).
Without it, the command exits 127 with the install hint and every other
subcommand keeps working.

#### Running from a repo clone (no install)

To run `qr-share` straight from a checkout without installing the tool,
use `uv run` from the repo root and include the `qr` extra:

```bash
cd pocketshell-cli
uv run --extra qr pocketshell qr-share prod
```

The first run creates `.venv` and installs the QR dependency; later runs
are instant. Run it in an interactive terminal so stdout is a TTY and the
QR renders inline — otherwise it falls back to writing PNGs (add
`--png --out-dir ./qr` to force PNGs). Omitting `--extra qr` makes the
command exit 127 with the install hint.

### `pocketshell hooks`

Installs agent **stop / idle-detection** hooks across Claude Code,
Codex, and OpenCode and normalizes their events into a single
append-only JSONL bus the app can read back. Server-side only;
integration only — no "tell the agent to continue" action yet (deferred;
see issue #267 and locked decision **D26** in `docs/decisions.md`).

```bash
pocketshell hooks install [--engine claude|codex|opencode|all]   # default: all
pocketshell hooks status  [--engine ...] [--json] [--last N]
pocketshell hooks events  [--since ISO8601] [--limit N] [--json]
pocketshell hooks uninstall [--engine ...]
```

`install` is **non-destructive — it merges, it never clobbers**:

- **Claude Code** — adds a `{type: "command", command: "python3 <handler>"}`
  entry under the `Stop`, `SubagentStop`, and `Notification` hook events
  in `~/.claude/settings.json`, only when absent. All other top-level
  keys and any pre-existing user hooks are preserved.
- **Codex** — sets the top-level `notify` program in `~/.codex/config.toml`
  to our handler (Codex hooks do not fire under `codex exec`, so `notify`
  is the headless-safe signal). If `notify` is already set to something
  else, it warns and **skips** rather than overwriting. The rest of the
  TOML is preserved.
- **OpenCode** — drops a `pocketshell-idle-signal.js` plugin into
  `~/.config/opencode/plugin/` without disturbing other plugins.

`install` is idempotent (running twice adds nothing new). Generated handler
scripts and `.installed` ownership metadata are durable data under
`$XDG_DATA_HOME/pocketshell/hooks/` (default
`~/.local/share/pocketshell/hooks/`). The volatile event bus stays at
`$XDG_CACHE_HOME/pocketshell/hooks/events.jsonl` (default
`~/.cache/pocketshell/hooks/events.jsonl`). A routine cache cleanup therefore
starts a fresh bus without breaking the absolute commands retained by Claude or
Codex; the next event recreates the cache directory and bus.

Path overrides are intentionally separate:

- `$POCKETSHELL_HOOKS_HANDLER_DIR` overrides the durable generated-handler dir.
- `$POCKETSHELL_HOOKS_EVENTS_FILE` overrides the event bus file.
- The historical `$POCKETSHELL_HOOKS_DIR` remains an alias for the **handler
  directory only** when the new handler variable is unset. It no longer moves
  the bus. Use both new variables and rerun `hooks install` when both paths need
  customization.

Each generated handler embeds the resolved bus path and appends a normalized
record `{ts, engine, state, source, session_id, cwd, ...}` there. `install`
also migrates PocketShell-owned Claude/Codex commands from the old cache path to
the durable path even when cache cleanup already removed the old scripts;
foreign hooks and foreign Codex `notify` programs remain untouched.

**Per-engine uninstall** (`pocketshell hooks uninstall`) removes only what
we added and is idempotent:

- **Claude Code** — drops our command group from each hook event; an
  event key (and the top-level `hooks` object) is deleted only if we
  created it and it ends up empty. A user's pre-existing hooks always
  survive, so a pre-populated `settings.json` comes back
  byte-equivalent for the unrelated parts.
- **Codex** — removes the top-level `notify` line only when it still
  points at our handler. A `notify` the user pointed elsewhere is left
  alone.
- **OpenCode** — deletes our plugin file; other plugins and the dir
  itself are left in place.

The event bus (`events.jsonl`) is preserved on uninstall so already-emitted
records stay readable; only PocketShell-owned current/legacy config entries,
generated executables, and durable ownership metadata are cleaned up.

## Development

```bash
cd pocketshell-cli
uv venv
uv pip install -e ".[dev]"
uv run pytest
```

Or via the dependency-group:

```bash
uv sync --group dev
uv run pytest
```

The tests stub subprocess boundaries and the bundled aplexer resolver so
they run in seconds without invoking a real host session.

## Release flow

`pocketshell` is released from THIS repo on its own cycle, independent of the
Android app (extraction: PocketShell-io/pocketshell#2643). The `version` in
`pyproject.toml` is the single source of truth:

1. Bump `version` in `pyproject.toml` (one small commit — the release
   declaration; org convention, cf. PocketShell-io/quse).
2. Tag that commit `vX.Y.Z` — the tag MUST equal the pyproject version — and
   push the tag. `.github/workflows/publish.yml` builds the sdist + wheel,
   refuses to publish if `dist/` does not carry exactly the tagged version,
   and publishes to PyPI.
3. Hosts pick it up with `uv tool upgrade pocketshell`.

CI (`.github/workflows/ci.yml`) runs the pytest suite plus the packaging and
frozen-lock guards on every PR and every push to `main`. The first
self-governed release is **0.5.5**, continuing from the last app-coupled
release 0.5.4 so `uv tool upgrade` stays monotonic.

### PyPI publish setup (one-time)

The `publish-pypi` job publishes with a PyPI API token stored as the
`PYPI_API_TOKEN` secret on this repo (same mechanism as
[PocketShell-io/quse](https://github.com/PocketShell-io/quse)):

1. On pypi.org, create an API token scoped to the `pocketshell` project (or
   reuse the existing project-scoped token from the monorepo era).
2. On GitHub: this repo → Settings → Secrets and variables → Actions →
   New repository secret → name `PYPI_API_TOKEN`. The `pypi` environment
   already exists; the publish job runs inside it.

If a publish fails after the tag is pushed, fix the cause and re-run
`publish.yml` from the Actions tab (it has a `workflow_dispatch` trigger) —
the tag does not need to move.

Manual escape hatch (maintainer account, only when CI publishing is
unavailable):

```bash
uv build
uv run --with twine twine upload dist/*
```

## Why a unified CLI?

The PocketShell app previously depended on multiple host-side tools.
That meant separate installs to keep up to date, separate probes to
surface failures from, and multiple PATH-discovery edge cases. A single
`pocketshell` binary collapses that app-facing contract into one install,
one probe, and one bootstrap row. The Android bootstrap probe now derives
PATH from the user's shell rc and prepends `$HOME/.local/bin`,
`$HOME/bin`, and `$HOME/.cargo/bin` before probing, so cloned-repo or
venv installs can be discovered without a manual app-side PATH field.
