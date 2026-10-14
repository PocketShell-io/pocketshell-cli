import sys
import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="native Windows file authority")


def test_large_private_manifest_can_shrink_without_relaxing_leaf_authority(tmp_path):
    from pocketshell import windows_security as ws
    root = tmp_path / "private"
    manifest = root / "manifest.json"
    ws.write_private(manifest, b"x" * (2 << 20))
    ws.write_private(manifest, b"{}")
    assert ws.read_private(manifest, 2) == b"{}"
    unsafe = root / "inherited.json"
    unsafe.write_bytes(b"old")
    with pytest.raises(ws.PrivateFileError):
        ws.write_private(unsafe, b"new")
    assert unsafe.read_bytes() == b"old"
