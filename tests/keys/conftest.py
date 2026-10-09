"""Fixtures for the key vault tests.

- every test gets its own XDG_CONFIG_HOME (never the developer's vault);
- the KDF runs with few iterations unless a test asks for the real cost
  (``real_kdf``) — the envelope records its own count, so this changes
  speed only, not behaviour;
- ``passwords`` replaces the terminal prompt with a scripted queue and
  records every prompt shown (the CLI flows never touch a real TTY).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pocketshell.keys import crypto, prompt


def pytest_configure(config):
    config.addinivalue_line("markers", "real_kdf: run the vault KDF at full cost")


@pytest.fixture(autouse=True)
def xdg(tmp_path_factory, monkeypatch) -> Path:
    root = tmp_path_factory.mktemp("xdg")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(root))
    return root


@pytest.fixture(autouse=True)
def fast_kdf(request, monkeypatch):
    if request.node.get_closest_marker("real_kdf") is None:
        monkeypatch.setattr(crypto, "KDF_ITERATIONS", 1000)


class ScriptedPasswords:
    def __init__(self) -> None:
        self.queue: list[str] = []
        self.prompts: list[str] = []

    def push(self, *values: str) -> None:
        self.queue.extend(values)

    def __call__(self, text: str) -> str:
        self.prompts.append(text)
        if not self.queue:
            raise AssertionError(f"unexpected password prompt: {text!r}")
        return self.queue.pop(0)


@pytest.fixture
def passwords(monkeypatch) -> ScriptedPasswords:
    scripted = ScriptedPasswords()
    monkeypatch.setattr(prompt, "read_password", scripted)
    return scripted
