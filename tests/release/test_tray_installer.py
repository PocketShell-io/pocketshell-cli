import importlib.util
from pathlib import Path

import pytest

spec = importlib.util.spec_from_file_location("tray_installer", Path(__file__).parents[2] / "scripts/release/build_tray_installer.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


def inventory(root):
    return [{"path": p.relative_to(root).as_posix(), "sha256": builder.digest(p)}
            for p in root.rglob("*") if p.is_file()]


def test_catalog_rejects_tampered_or_extra_payload(tmp_path):
    (tmp_path / "python").mkdir()
    for name in ("a.exe", "aplexer.exe"):
        (tmp_path / "python" / name).write_bytes(b"matching Windows aplexer worker")
    rows = inventory(tmp_path)
    builder.verify_inventory(tmp_path, rows)
    (tmp_path / "python/a.exe").write_bytes(b"corrupt")
    with pytest.raises(ValueError, match="differs"):
        builder.verify_inventory(tmp_path, rows)
    (tmp_path / "python/a.exe").write_bytes(b"matching Windows aplexer worker")
    (tmp_path / "unexpected.exe").write_bytes(b"extra")
    with pytest.raises(ValueError, match="differs"):
        builder.verify_inventory(tmp_path, rows)


def test_catalog_requires_complete_aplexer(tmp_path):
    (tmp_path / "python").mkdir()
    (tmp_path / "python/a.exe").write_bytes(b"CLI without worker")
    with pytest.raises(ValueError, match="worker"):
        builder.verify_inventory(tmp_path, inventory(tmp_path))


def test_zip_preserves_namespace_packages_and_reproducibility(tmp_path):
    import zipfile
    a, b = tmp_path / "a.zip", tmp_path / "b.zip"
    builder.write_zip(a, {"google/auth/__init__.py": b"# namespace", "six.py": b"# module"})
    builder.write_zip(b, {"six.py": b"# module", "google/auth/__init__.py": b"# namespace"})
    assert a.read_bytes() == b.read_bytes()
    with zipfile.ZipFile(a) as archive:
        assert "google/" in archive.namelist()
