"""Helpers shared by the key vault tests (imported as a top-level module,
like tests/gateway/gateway_keyblobs.py)."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest


def keygen(path: Path, *extra: str, passphrase: str = "", key_type: str = "ed25519") -> Path:
    if not shutil.which("ssh-keygen"):
        pytest.skip("ssh-keygen unavailable")
    subprocess.run(
        ["ssh-keygen", "-q", "-t", key_type, "-N", passphrase, "-C", "test@key", "-f", str(path),
         *extra],
        check=True,
    )
    os.chmod(path, 0o600)
    return path
