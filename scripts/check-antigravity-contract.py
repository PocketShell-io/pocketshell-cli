#!/usr/bin/env python3
"""Validate local Antigravity aplexer builds before changing the bundled pin.

Run with the pocketshell development interpreter and an explicit reviewed `a`
binary. Uses isolated config/state/runtime directories and a stub agy; never
requires Google authentication or touches the maintainer's live sessions.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("aplexer", type=Path)
    args = parser.parse_args()
    binary = args.aplexer.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="ps-agy-") as scratch:
        root = Path(scratch)
        (root / "config.toml").write_text("")
        (root / "agy").write_text(
            "#!/bin/bash\n"
            'printf "%s\\n" "$@" > "$AGY_ARGS_FILE"\n'
            'test -z "${GEMINI_API_KEY+x}" && test -z "${GOOGLE_API_KEY+x}" || exit 19\n'
            "exec -a agy /bin/sleep 90\n"
        )
        (root / "agy").chmod(0o755)
        env = dict(os.environ)
        env.update(
            APLEXER_BIN=str(binary), APLEXER_CONFIG=str(root / "config.toml"),
            APLEXER_STATE_DIR=str(root / "state"), APLEXER_RUNTIME_DIR=str(root / "run"),
            PATH=str(root) + os.pathsep + env.get("PATH", ""),
            PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"),
            POCKETSHELL_APLEXER="1", AGY_ARGS_FILE=str(root / "args"),
            GEMINI_API_KEY="test-key", GOOGLE_API_KEY="test-key",
        )

        def run(argv):
            result = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=15)
            assert result.returncode == 0, result.stderr or result.stdout
            return json.loads(result.stdout)

        spec = run([str(binary), "--json", "launch-spec", "--engine", "antigravity"])
        assert spec["argv"] == ["agy", "--dangerously-skip-permissions"], spec
        assert {"GEMINI_API_KEY", "GOOGLE_API_KEY"}.issubset(spec["env_unset"]), spec
        plain = run([
            str(binary), "--json", "launch-spec", "--engine", "antigravity",
            "--no-skip-permissions",
        ])
        assert plain["argv"] == ["agy"], plain
        created = run([
            sys.executable, "-m", "pocketshell", "sessions", "create", "google",
            "--cwd", str(root), "--engine", "antigravity", "--mem", "none", "--json",
        ])
        session_id = created["id"]
        try:
            deadline = time.monotonic() + 8
            row = None
            while time.monotonic() < deadline:
                rows = run([str(binary), "--json", "snapshot"])
                row = next((r for r in rows if r.get("id") == session_id), None)
                if row and row.get("agent") == "antigravity" and (root / "args").exists():
                    break
                time.sleep(0.05)
            assert row and row.get("agent") == "antigravity", row
            assert (root / "args").read_text().splitlines() == ["--dangerously-skip-permissions"]
            print("PASS: helper create -> aplexer -> agy bypass; Google keys stripped; snapshot antigravity")
        finally:
            result = subprocess.run(
                [str(binary), "kill", session_id], env=env,
                capture_output=True, text=True, timeout=15,
            )
            assert result.returncode == 0, result.stderr


if __name__ == "__main__":
    main()
