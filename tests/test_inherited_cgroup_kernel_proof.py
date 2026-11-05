"""Required CI proof in disposable Docker cgroups; no real host OOM workload."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import uuid

import pytest

REPO = Path(__file__).resolve().parents[1]
LABEL = "pocketshell-inherited-kernel-proof"


def run(*args, **kwargs):
    return subprocess.run(list(args), check=True, capture_output=True, text=True, timeout=300, **kwargs)


def test_real_kernel_bounds_normal_session_without_systemd(tmp_path):
    if os.environ.get("POCKETSHELL_INHERITED_CAP_PROOF") != "required":
        pytest.skip("dedicated inherited-memory CI job sets required; no ambient Docker work in the unit loop")
    assert shutil.which("docker"), "required kernel proof needs Docker"
    run("docker", "info", "--format", "{{.ServerVersion}}")
    fixture = REPO / "tests/docker/inherited-memory"
    for name in ("Dockerfile", "proof.py"):
        shutil.copyfile(fixture / name, tmp_path / name)
    requirements = run("uv", "export", "--frozen", "--no-dev", "--no-emit-project",
                       "--format", "requirements-txt", cwd=REPO).stdout
    (tmp_path / "requirements.txt").write_text(requirements)
    run("uv", "build", "--wheel", "--out-dir", str(tmp_path), cwd=REPO)
    image = "pocketshell-inherited-proof-" + uuid.uuid4().hex
    owned = []
    try:
        run("docker", "build", "--label", f"agent.session={LABEL}", "-t", image, str(tmp_path))
        cases = [("bounded", ["--memory", "384m", "--memory-swap", "384m"]),
                 ("too-small", ["--memory", "384m", "--memory-swap", "384m"]),
                 ("swap", ["--memory", "384m", "--memory-swap", "768m"]),
                 ("unbounded", [])]
        for mode, limits in cases:
            name = "ps-inherited-proof-" + uuid.uuid4().hex
            owned.append(name)
            result = run("docker", "run", "--rm", "--name", name, "--label", f"agent.session={LABEL}",
                         "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                         "--pids-limit", "96", "--cpus", "0.5", *limits, image, mode)
            assert ('"created": true' if mode == "bounded" else '"refused": true') in result.stdout
    finally:
        # Exact unique owned names, registered before launch, including failed starts.
        for name in owned:
            subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=30)
        subprocess.run(["docker", "image", "rm", image], capture_output=True, timeout=30)
