# Distributing the `pocketshell-link` helper — contract and plan

`pocketshell gateway …` execs the Go helper **`pocketshell-link`** (repo
`PocketShell-io/pocketshell-gateway`, private). This doc states the
distribution contract that exists today — private-beta platform wheels plus
the build-it-yourself route — the wrapper-side protocol gate, and the honest
limits of both. It is owned with the gateway CLI wrapper; the helper source,
artifacts, checksums and CI belong to the pocketshell-gateway Go runtime and
delivery workers.

## 1. The contract today (three-step resolution, no network)

`pocketshell gateway` resolves the helper from trusted locations only, in
this order:

1. `POCKETSHELL_GATEWAY_HELPER` — an explicit operator pin. A pin that is
   missing or not executable is a hard error; the wrapper never falls back
   to a different binary silently. This is how a lab tests a locally built
   helper against a wheel-installed CLI.
2. the binary inside an **installed `pocketshell-gateway-link` wheel**
   (`pocketshell_gateway_link/bin/pocketshell-link`, aplexer precedent).
   The wheel step is a selection, not a hint: an installed-but-broken
   wheel — binary missing or not executable, wheel built for a different
   platform/arch, unreadable dist-info — is a hard error, **never** a
   silent fallback to PATH. Wheels exist for linux amd64/arm64 and darwin
   amd64/arm64 (`manylinux_2_28` floor, macOS 11+); anything else —
   Windows included — is refused with the platform named.
3. `pocketshell-link` on `PATH`.

With none of the three, every `gateway` subcommand exits **127** with both
actionable routes (wheel install below, or `go build` from the private
repo). A helper that IS found but fails the protocol gate (§2) exits
**126** with a concise compatibility error.

The wrapper **never downloads** anything, **never bundles** a copy, and
accepts no credentials for fetching one. The binary reaches the machine
only through an install the user consented to. **Platforms:** the exec
boundary is `os.execv` — POSIX only (Linux, macOS). Windows is unsupported.
Musl/Alpine and BSDs have no wheels and are untested; build from source at
your own risk or don't.

## 2. Private beta: getting and installing the wheel (no public channel yet)

During the private beta there is **no public package**. What exists today is
the implemented *packaging route*: the private repo's delivery pipeline
builds the platform wheels as CI artifacts, and people with repo access
retrieve them from a CI run by hand. A standing authenticated distribution
channel and the release-versioned artifact set are still pending (§4), so
"get the wheel" currently means exactly this manual retrieval. The install
is three explicit steps — retrieve, verify, install offline:

```bash
# 1. Retrieve from the PRIVATE CI (manual, per run; you need repo access):
#    pocketshell-gateway repo → CI "packaging" run for commit <sha> →
#    download the wheel matching your platform, e.g.
#    pocketshell_gateway_link-<version>-py3-none-manylinux_2_28_x86_64.whl
#    (linux amd64; the aarch64/darwin tags map the same way)

# 2. Verify the digest. A sha256 sidecar or SHA256SUMS from the SAME CI
#    run is an integrity check WITHIN that channel — it catches a
#    truncated/corrupted download, not a compromised run — it is not an
#    independent trust source merely because it is a separate file. Only a
#    digest obtained genuinely out-of-band (a maintainer, a different
#    channel) anchors trust independently. Fail closed: no matching
#    digest, no install.
sha256sum pocketshell_gateway_link-*.whl
#    …compare with the expected digest, and check the run's PROVENANCE
#    (source commit, toolchain) matches what you expect…

# 3. Install offline, into the same environment as the pocketshell CLI:
pip install --no-index --no-deps /verified/path/pocketshell_gateway_link-*.whl
```

`--no-index --no-deps` is the point, not ceremony: the wheel is
dependency-free and self-contained, and offline installation guarantees
nothing is fetched from any index at install time either. There is
deliberately **no `pocketshell` extra / public version pin yet** — adding
one would reference an unpublished version, so it waits until a real
publish channel exists (§4). The `PATH`/`POCKETSHELL_GATEWAY_HELPER`
routes stay first-class; a manual or PATH helper is equally valid, as long
as it passes the metadata gate in §3.

## 3. The protocol metadata gate (implemented)

Since pocketshell-gateway `1d2248e`, the helper has real build metadata:
`pocketshell-link version --json` prints exactly one JSON line
`{"version": …, "protocol": "pocketshell-tunnel-v1", "commit": …}` (a
frozen additive contract; extra appended fields must be tolerated). The
wrapper verifies this **before every exec of every chosen helper** — pin,
wheel, or PATH alike — under hard bounds:

- bounded wall-clock timeout and a small output cap (a misbehaving helper
  is killed, nothing is captured unboundedly), stdin detached so the
  piped enrollment token cannot be consumed by the probe;
- strict parse: exactly one JSON object, nonempty string
  `version`/`commit`, `protocol` exactly `pocketshell-tunnel-v1`;
- any deviation — stale or unknown protocol tag, missing/mistyped/empty
  fields, malformed or duplicated keys, non-JSON constants
  (`NaN`/`Infinity`), unparseable nesting, nonzero exit, timeout, excess
  output — refuses the helper with exit **126** and a concise one-line
  compatibility error. The helper's own output is never echoed and never
  logged, with one bounded diagnostic exception: a wrong `protocol` tag
  is quoted ASCII-escaped and truncated, so a stale generation is still
  recognizable without letting a hostile helper forge error lines. The
  helper path in refusals is escaped the same way.

**Honesty rules.** The protocol tag is the compatibility contract; the
version and commit are provenance, never a compatibility proof and never
trust or authentication evidence. An un-injected source build honestly
reports `devel`/`unknown` and passes the gate — it speaks the right
protocol — but it is an *unverified, unreleased* build: useful for local
testing, and nowhere presented as a release. Release artifacts carry
injected `-X main.version/-X main.commit` values: those strings identify
the *claimed* build (and must match what the delivery channel says you
should have), but they are self-reported labels — they cannot by
themselves prove provenance, which is what the out-of-band digest and
the run's recorded provenance are for.

## 4. What remains (sequencing)

1. ~~Go runtime worker: real version + stable protocol metadata~~ — done
   (pocketshell-gateway `1d2248e`; frozen additive `version --json`).
2. **Delivery worker:** the build matrix, per-artifact sha256 sidecars,
   SHA256SUMS and build provenance exist in the delivery pipeline; what
   remains theirs is the *publication* decision (private channel first,
   and eventually a public index) and the release-versioned, checksummed
   artifact set. The CLI wrapper consumes wheels; it never publishes and
   never downloads.
3. **This repo, after a real published version exists:** add the
   `pocketshell` optional extra pinning that version (until then,
   deliberately absent — a pin against an unpublished version would be
   broken on install), and keep this doc's platform statements in sync
   with the delivery matrix. The resolver, the protocol gate, and the
   fail-closed wheel semantics are already in place, so that step is a
   one-line dependency plus docs.
