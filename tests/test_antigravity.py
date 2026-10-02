"""Antigravity helper launch and host metadata contracts (#3015)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from pocketshell import agents, engines
from pocketshell.runtime import cgroups
from pocketshell.sessions.create import aplexer_start_argv


def test_antigravity_manifest_uses_real_binary_without_invented_quota():
    manifest = next(m for m in engines.builtin_manifests() if m.id == "antigravity")
    assert manifest.label == "Antigravity"
    assert manifest.provider_mark == "Google"
    assert manifest.harness == "agy"
    assert manifest.usage_provider is None
    assert agents.build_argv("antigravity", skip_permissions=True) == [
        "agy", "--dangerously-skip-permissions",
    ]
    assert agents.build_argv("antigravity", skip_permissions=False) == ["agy"]


@pytest.mark.parametrize("skip", [True, False])
def test_real_helper_process_execs_agy_and_strips_google_keys(tmp_path: Path, skip: bool):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    agy = bin_dir / "agy"
    agy.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\n"
        "print(json.dumps({'argv':sys.argv[1:], 'cwd':os.getcwd(), "
        "'keys':[k for k in ('GEMINI_API_KEY','GOOGLE_API_KEY') if k in os.environ]}))\n"
    )
    agy.chmod(0o755)
    env = dict(os.environ)
    env.update(
        PATH=str(bin_dir), HOME=str(tmp_path),
        PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"),
        APLEXER_BIN=str(tmp_path / "missing-a"),
        POCKETSHELL_ENGINE_LOGIN_SHELL_PROBE="0",
        GEMINI_API_KEY="test-key", GOOGLE_API_KEY="test-key",
    )
    argv = [sys.executable, "-m", "pocketshell", "agent", "antigravity", "--dir", str(tmp_path)]
    if not skip:
        argv.append("--no-skip-permissions")
    result = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload == {
        "argv": ["--dangerously-skip-permissions"] if skip else [],
        "cwd": str(tmp_path), "keys": [],
    }


@pytest.mark.parametrize("token", ["agy", "/home/u/.local/bin/agy --continue", "antigravity"])
def test_antigravity_process_tokens(token):
    assert cgroups.classify_token(token) == "antigravity"


@pytest.mark.parametrize("token", ["legacy", "agy-helper", "myantigravity", "/work/antigravity-project"])
def test_unrelated_process_tokens_are_not_antigravity(token):
    assert cgroups.classify_token(token) is None


def test_session_create_forwards_canonical_antigravity_engine():
    assert aplexer_start_argv(
        aplexer_path="/bundled/a", workspace="/work/project", tag="google",
        engine="antigravity", profile=None, memory_bytes=None,
    ) == [
        "/bundled/a", "--json", "start", "--workspace", "/work/project",
        "--tag", "google", "--engine", "antigravity",
    ]
