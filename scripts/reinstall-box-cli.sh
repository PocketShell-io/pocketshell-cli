#!/usr/bin/env bash
# Reinstall THIS box's own pocketshell CLI at a just-tagged release and
# smoke-check the result (issue #15).
#
# This box is both the development environment and the LIVE server the
# maintainer's phone talks to over SSH. Tagging a release does not update
# the installed CLI by itself; shipping without reinstalling it leaves the
# phone silently calling commands that do not exist on this host — the
# 2026-09-10 `workspaces` outage. Run this as the post-tag step of the
# release flow (README.md, "Release flow", step 4).
set -euo pipefail

usage() { echo "usage: $0 vX.Y.Z" >&2; exit 2; }
[ $# -eq 1 ] || usage
version="${1#v}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || usage

# The maintainer's global uv config carries a rolling `exclude-newer`
# cutoff (7 days) for lock reproducibility; a release published minutes
# ago is INVISIBLE to it, which is exactly how the first manual fix
# failed before the cutoff was overridden. Relax it for this one install.
cutoff="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "reinstalling pocketshell==${version} (exclude-newer ${cutoff})"
uv tool install "pocketshell==${version}" --force --exclude-newer "${cutoff}"

# --force swaps the tool environment underneath the ~/.local/bin entry
# point; right after it returns the shim can still be mid-replacement, so
# resolve the binary explicitly, keep stderr VISIBLE (a silent 2>/dev/null
# is how the first run of this script reported an empty version and
# failed confusingly), and retry briefly before declaring failure.
installed=""
for attempt in 1 2 3 4 5; do
  bin="$(command -v pocketshell || true)"
  if [ -n "$bin" ]; then
    installed="$("$bin" --version || true)"
    if printf '%s' "$installed" | grep -q "version ${version}\$"; then
      break
    fi
  fi
  echo "attempt ${attempt}: pocketshell --version did not report ${version} (got: '${installed}')" >&2
  sleep 1
done
echo "installed: ${installed}"
if ! printf '%s' "$installed" | grep -q "version ${version}\$"; then
  echo "FAIL: the installed CLI does not report ${version}: '${installed}'" >&2
  exit 1
fi

# The bundled dependencies are the other half of the outage class: the
# phone's session tree is dead without `a`, usage without `quse`. They
# must be resolvable beside the reinstalled CLI (never PATH-shadowed).
for dep in a aplexer quse; do
  dep_bin="$(command -v "${dep}" || true)"
  if [ -z "$dep_bin" ] || [ ! -x "$dep_bin" ]; then
    echo "FAIL: bundled \`${dep}\` is missing after reinstall (packaging integrity)" >&2
    exit 1
  fi
  echo "bundled: ${dep} -> ${dep_bin}"
done

# The probe the phone actually makes (the `workspaces` command the 0.5.4
# outage was about): a valid envelope and exit 0, from the REINSTALLED
# binary on PATH — not the repo venv.
pocketshell workspaces list --host release-smoke --json >/dev/null

echo "OK: this box now runs pocketshell ${version}"
