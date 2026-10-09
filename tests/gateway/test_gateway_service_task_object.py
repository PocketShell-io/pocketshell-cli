# ruff: noqa: F811
"""Task Scheduler OBJECT security (contract ec8534aa) in install, readback and status.

Behavioural controls written against the fake Task Scheduler only (no import
of the validator module), so they are meaningful against the previous source
too: the previous service registered with `schtasks /Create /XML` (no explicit
task SD, folder created implicitly) and never read either security descriptor.
"""

from __future__ import annotations

import pytest

from pocketshell.gateway import service_windows as win
from pocketshell.gateway.service_common import ServiceError

from test_gateway_service import (  # noqa: F401
    USER_SID,
    WIN_CONFIG,
    WIN_HELPER,
    FakeApi,
    _task_verbs,
    _windows_cli,
    fake_windows,
)

FOREIGN_READ = "(A;;FR;;;WD)"
TRUSTED_TASK = f"O:{USER_SID}D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{USER_SID})(A;;FR;;;{USER_SID})"
PROTECTED_FOLDER = f"O:{USER_SID}D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{USER_SID})"


def _install(fake):
    plan = win.plan_install(WIN_HELPER, WIN_CONFIG, force=False, start=True, api=FakeApi())
    return win.apply_install(plan, api=FakeApi())


def test_registers_with_an_explicit_task_sd_into_a_protected_folder(fake_windows):
    _install(fake_windows)
    assert fake_windows.register_payloads, "the task must be registered through COM RegisterTask with an SD"
    p = fake_windows.register_payloads[-1]
    assert p["sddl"] == f"O:{USER_SID}D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{USER_SID})"
    assert p["user"] == USER_SID and p["logon"] == 2 and p["flags"] == 2
    assert fake_windows.folder_sddl == PROTECTED_FOLDER


@pytest.mark.parametrize(
    "mutate",
    [
        lambda sd: sd + FOREIGN_READ,
        lambda sd: sd.replace(f"O:{USER_SID}", "O:BA"),
        lambda sd: sd.replace("(A;;FA;;;SY)", ""),
        lambda sd: sd.replace("(A;;FA;;;SY)", "(A;ID;FA;;;SY)"),
        lambda sd: sd + f"(A;;FR;;;{USER_SID})",
        lambda sd: sd.replace("D:", "D:AI"),
    ],
    ids=["foreign-read", "owner-admins", "missing-system", "inherited", "second-principal-read", "auto-inherited"],
)
def test_registered_task_sd_outside_the_contract_is_refused_before_run(fake_windows, mutate):
    fake_windows.task_sddl_mutate = mutate
    with pytest.raises(ServiceError, match="does not match|task"):
        _install(fake_windows)
    assert ("/Run", "GatewayLink") not in _task_verbs(fake_windows)
    assert "GatewayLink" not in fake_windows.tasks  # rolled back


def test_existing_unprotected_task_folder_is_refused_before_registering(fake_windows):
    fake_windows.folder_sddl = fake_windows.unprotected_folder_sddl
    with pytest.raises(ServiceError, match="folder"):
        _install(fake_windows)
    assert not any(v[0] == "/Create" for v in _task_verbs(fake_windows))


def test_status_requires_the_task_object_contract(fake_windows, monkeypatch):
    _install(fake_windows)
    fake_windows.state = "Running"
    assert win.status(api=FakeApi()).exit_code == 0
    fake_windows.tasks["GatewayLink"]["sddl"] = TRUSTED_TASK + FOREIGN_READ
    st = win.status(api=FakeApi())
    assert st.exit_code == 3
    assert any("foreign trustee" in w for w in st.warnings)
