# Distributing the `pocketshell-link` helper — contract and plan

`pocketshell gateway …` execs the Go helper **`pocketshell-link`** (repo
`PocketShell-io/pocketshell-gateway`, private). This doc states the
distribution contract that exists today, the platform-wheel plan that will
replace "build it yourself", and the honest limits of both. It is owned with
the gateway CLI wrapper; the helper source, artifacts and CI belong to the
pocketshell-gateway Go runtime and delivery workers.

## 1. The contract today (safe wrapper, no network)

1. `POCKETSHELL_GATEWAY_HELPER` — an explicit operator pin. A pin that is
   missing or not executable is a hard error; the wrapper never falls back
   to a different binary silently.
2. `pocketshell-link` on `PATH`.
3. Otherwise every `gateway` subcommand exits **127** with exact build
   instructions (clone the private repo, `go build -o … ./cmd/pocketshell-link`).

The wrapper **never downloads** anything, **never bundles** a copy, and
accepts no credentials for fetching one. There is no silent autodownload of
unverified binaries — not now, and not planned: even once wheels exist, the
binary reaches the machine only through an explicit package-manager install
the user consented to.

**Platforms:** the exec boundary is `os.execv` — POSIX only (Linux, macOS).
Windows is unsupported. Musl/Alpine and BSDs are untested and unsupported
until someone runs the suites there; say so rather than assuming.

## 2. Honest gap: version/protocol metadata does not exist yet

A compatibility check needs metadata to check against. The current helper's
`version` subcommand prints the literal string
`pocketshell-link dev (protocol pocketshell-tunnel-v1)` — a hardcoded
`dev`, not a release version. Therefore:

- The wrapper performs **no version or protocol check today**. Comparing
  against `dev` would be theater, and pretending that "the helper accepts
  the flags" proves version compatibility would be worse. It proves only
  that the argv contract did not drift at that moment.
- The *protocol tag* `pocketshell-tunnel-v1` in that line is the real
  compatibility contract between wrapper and helper. A runtime
  version/protocol metadata request (real build version via link flags or
  embedded build info, stable machine-readable protocol tag, bump policy)
  is filed with the Go runtime owner. Once it lands, the wrapper can check
  the protocol tag — and must still treat the version as information, not
  as a compatibility proof.

## 3. The plan: platform wheels, after the bundled-aplexer precedent

The CLI already ships one native dependency this way: **aplexer** publishes
platform-tagged, non-purelib wheels (`py3-none-manylinux_2_28_x86_64`, …)
that carry the compiled binaries inside the wheel (`aplexer_cli/bin/…`),
installed by the ordinary package manager, pinned exactly
(`aplexer==0.1.8; sys_platform == 'linux'`). The same shape works for the
gateway helper, while preserving the private Go source:

1. **Who builds:** the private `pocketshell-gateway` repo's CI — the only
   place with source access — cross-builds `pocketshell-link`
   (`CGO_ENABLED=0`, static) from a tagged commit for linux
   x86_64+aarch64 (glibc baseline stated by delivery, mirroring the
   `manylinux_2_28` floor) and macOS arm64+x86_64.
2. **What is published:** one PyPI distribution, e.g.
   `pocketshell-gateway-link`, versioned in lock-step with the helper's
   real version metadata (§2 is a hard prerequisite — a pin against `dev`
   pins nothing). Wheels only, platform-tagged, binaries under
   `pocketshell_gateway_link/bin/pocketshell-link`, `Root-Is-Purelib:
   false`. The PyPI upload itself is the verified channel: wheels carry
   RECORD hashes, the delivery pipeline additionally publishes `sha256`
   sidecars for every raw artifact it ships outside wheels. **Source is
   never published** — the wheels contain binaries built by the private
   repo's own CI.
3. **How the wrapper consumes it:** a `pocketshell` optional extra —
   `gateway = ["pocketshell-gateway-link==<pinned>; sys_platform in …"]` —
   an extra, not a hard dependency: hosts that enroll via the env pin/PATH
   contract must keep working, and a hard dependency would hard-cut
   platforms no wheel exists for (the aplexer hard cut is precedent for
   *that* choice, not this one). Resolution order becomes:
   `POCKETSHELL_GATEWAY_HELPER` pin → bundled wheel binary → `PATH`. The
   operator pin still wins, so a lab can always test a locally built
   helper against a wheel-installed CLI.
4. **Verification:** no new installer, no download-at-runtime, no private
   repo credentials in the wheel. Everything the binary needs travels
   inside the wheel the user chose to install; integrity is the wheel's
   (RECORD + the package index), plus published checksum sidecars for the
   delivery pipeline's raw artifacts.

An authenticated, verified installer route (e.g. the delivery pipeline's
hash-pinned installer for managed fleets) remains the alternative for
non-PyPI hosts and is owned by the delivery worker; this repo adds none of
it.

## 4. Sequencing (what blocks what)

1. **Go runtime worker:** real version + stable protocol metadata on the
   `version` subcommand (request filed; no wrapper-side ETA).
2. **Delivery worker:** build matrix + checksum sidecars + publish channel
   (handoff filed: current gap is ARM64-only artifacts with no checksums).
3. **This repo (only after 1–2):** add the extra with a real pinned
   version, extend resolution with the bundled step, add a protocol-tag
   check, and document the supported platform set that actually has wheels.
   Doing any of this against `dev` metadata would fake step 1 — so it is
   deliberately not done here.
