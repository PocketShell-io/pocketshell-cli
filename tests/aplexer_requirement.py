"""The aplexer dependency contract comes only from pyproject.toml."""
from pathlib import Path
import tomllib

from packaging.requirements import Requirement


def aplexer_requirement() -> Requirement:
    project = Path(__file__).resolve().parents[1] / "pyproject.toml"
    dependencies = tomllib.loads(project.read_text(encoding="utf-8"))["project"]["dependencies"]
    matches = [Requirement(value) for value in dependencies if Requirement(value).name == "aplexer"]
    assert len(matches) == 1, f"expected one aplexer requirement, got {matches}"
    return matches[0]
