"""Native Windows: protocol reads re-validate the OPENED handle's full DACL (root F9).

`WindowsApi.read_private_file` checks the path first (guardian private role),
then opens the file with FILE_FLAG_OPEN_REPARSE_POINT. Between those two
steps the object could be swapped, so the HANDLE must be validated again with
the same private rules — owner AND the complete DACL — before any byte is
read. The swap is simulated by validating the path as "A" (path check
replaced by a recorder) while the object actually opened ("B") has the same
owner but a foreign allow ACE.
"""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="native Windows security descriptors")

from pocketshell.gateway import service_windows as win  # noqa: E402
from pocketshell.gateway.service_common import ServiceError  # noqa: E402

CREATE_NO_WINDOW = 0x08000000


def _icacls(*args):
    proc = subprocess.run(["icacls", *map(str, args)], capture_output=True, creationflags=CREATE_NO_WINDOW)
    assert proc.returncode == 0, proc.stdout + proc.stderr


@pytest.fixture
def private_file(tmp_path):
    api = win.WindowsApi()
    sid = api.current_sid()
    root = tmp_path / "priv"
    root.mkdir()
    _icacls(root, "/inheritance:r", "/grant:r", f"*{sid}:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F")
    target = root / "CURRENT.json"
    target.write_bytes(b'{"version":1}')
    _icacls(root, "/setowner", f"*{sid}", "/T", "/C", "/Q")
    return api, sid, str(target)


def test_private_file_reads(private_file):
    api, sid, path = private_file
    assert api.read_private_file(path, sid, 4096) == b'{"version":1}'


def test_opened_handle_with_a_foreign_dacl_is_refused_even_if_the_path_check_passed(private_file, monkeypatch):
    api, sid, path = private_file
    _icacls(path, "/grant", "*S-1-1-0:R")  # object "B": same owner, foreign Everyone read ACE
    checked = []
    monkeypatch.setattr(api, "path_authority", lambda *a, **k: checked.append(a))  # path "A" passed
    with pytest.raises(ServiceError, match="foreign|DACL"):
        api.read_private_file(path, sid, 4096)
    assert checked, "the path check must still run first"


def test_opened_handle_with_a_foreign_owner_is_refused(private_file, monkeypatch):
    api, sid, path = private_file
    _icacls(path, "/setowner", "*S-1-5-32-544")
    monkeypatch.setattr(api, "path_authority", lambda *a, **k: None)
    with pytest.raises(ServiceError, match="owned|owner"):
        api.read_private_file(path, sid, 4096)


def test_reparse_point_is_refused(tmp_path, private_file):
    api, sid, path = private_file
    link = os.path.join(os.path.dirname(path), "LINK.json")
    try:
        os.symlink(path, link)
    except OSError:
        pytest.skip("symlink creation not permitted on this runner")
    with pytest.raises(ServiceError):
        api.read_private_file(link, sid, 4096)
