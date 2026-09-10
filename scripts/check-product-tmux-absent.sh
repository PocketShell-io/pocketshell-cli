#!/usr/bin/env bash
# Aplexer-only product guard for the CLI tree (issue #2561; split out of the
# monorepo guard by PocketShell-io/pocketshell#2643).
#
# The product session runtime must not grow a tmux fallback or discriminator.
# The session path is aplexer-backed (`a` console-script, no PATH fallback).
# The monorepo keeps its own copy of this guard for the Android/Kotlin
# surface; this one covers the CLI only.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

scan_paths() {
  local -a paths=("$@")
  local path
  for path in "${paths[@]}"; do
    if [[ ! -e "$path" ]]; then
      echo "check-product-tmux-absent: FAIL — missing scan path: $path" >&2
      return 1
    fi
  done

  local matches
  if command -v rg >/dev/null 2>&1; then
    matches="$(rg -n -i 'tmux' "${paths[@]}" || true)"
  else
    matches="$(grep -RniE 'tmux' "${paths[@]}" || true)"
  fi
  if [[ -n "$matches" ]]; then
    echo "check-product-tmux-absent: FAIL — product session surface mentions tmux:" >&2
    printf '%s\n' "$matches" >&2
    return 1
  fi
}

self_test() {
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  printf 'runs sessions via aplexer\n' > "$tmp/clean.py"
  printf 'fallback to tmux if missing\n' > "$tmp/dirty.py"
  if scan_paths "$tmp/dirty.py" >/dev/null 2>&1; then
    echo "check-product-tmux-absent: FAIL — self-test dirty fixture passed" >&2
    return 1
  fi
  scan_paths "$tmp/clean.py"
}

cd "$REPO_ROOT"
if [[ "${1:-}" == "--self-test" ]]; then
  self_test
  echo "check-product-tmux-absent: self-test OK"
  exit 0
fi
if [[ "${1:-}" != "" ]]; then
  echo "Usage: scripts/check-product-tmux-absent.sh [--self-test]" >&2
  exit 2
fi

scan_paths src pyproject.toml
echo "check-product-tmux-absent: OK — product session paths are aplexer-only"
