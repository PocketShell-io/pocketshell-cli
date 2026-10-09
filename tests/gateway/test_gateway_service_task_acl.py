"""Task-object SD validator = the native owner's frozen AssertTaskObjectAuthority (ec8534aa).

The cases and expected verdicts are exactly those of their
task-object-authority-controls.ps1 (receipt f1b3f2f5…, 20 expected outcomes),
built from the same SDDL strings, including the actual captured canonical
task descriptor (owner own, P dropped, SY/BA/own FA + own FR).
"""

from __future__ import annotations

import base64

import pytest

from pocketshell.gateway import service_task_acl as acl

OWN = "S-1-5-21-1846869698-1433458354-420588588-1001"
ACTUAL = base64.b64decode(
    "TzpTLTEtNS0yMS0xODQ2ODY5Njk4LTE0MzM0NTgzNTQtNDIwNTg4NTg4LTEwMDFHOlMtMS01LTIxLTE4NDY4Njk2OTgtMTQzMzQ1ODM1NC00"
    "MjA1ODg1ODgtNTEzRDooQTs7RkE7OztTWSkoQTs7RkE7OztCQSkoQTs7RkE7OztTLTEtNS0yMS0xODQ2ODY5Njk4LTE0MzM0NTgzNTQtNDIw"
    "NTg4NTg4LTEwMDEpKEE7O0ZSOzs7Uy0xLTUtMjEtMTg0Njg2OTY5OC0xNDMzNDU4MzU0LTQyMDU4ODU4OC0xMDAxKQ=="
).decode()
FOLDER = f"O:{OWN}D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{OWN})"
THREE = f"O:{OWN}D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{OWN})"

CASES = [
    ("Actual captured canonical task four ACEs", ACTUAL, FOLDER, True),
    ("Explicit task three FA no protected bit", THREE, FOLDER, True),
    ("Protected exact task three FA", THREE.replace("D:", "D:P"), FOLDER, True),
    ("Wrong task owner", THREE.replace("O:" + OWN, "O:SY"), FOLDER, False),
    ("Null task DACL", f"O:{OWN}D:NO_ACCESS_CONTROL", FOLDER, False),
    ("Empty task DACL", f"O:{OWN}D:", FOLDER, False),
    ("Missing required System grant", THREE.replace("(A;;FA;;;SY)", ""), FOLDER, False),
    ("Foreign read grant", THREE + "(A;;FR;;;WD)", FOLDER, False),
    ("Foreign write grant", THREE + "(A;;FW;;;WD)", FOLDER, False),
    ("Duplicate own full grant", THREE + f"(A;;FA;;;{OWN})", FOLDER, False),
    ("Duplicate own principal read grant", ACTUAL + f"(A;;FR;;;{OWN})", FOLDER, False),
    ("Wrong trusted mask", THREE.replace("(A;;FA;;;BA)", "(A;;FR;;;BA)"), FOLDER, False),
    ("Inherited task ACE", THREE.replace("(A;;FA;;;SY)", "(A;ID;FA;;;SY)"), FOLDER, False),
    ("Inherit only task ACE", THREE.replace("(A;;FA;;;SY)", "(A;IO;FA;;;SY)"), FOLDER, False),
    ("Object inherit task ACE", THREE.replace("(A;;FA;;;SY)", "(A;OI;FA;;;SY)"), FOLDER, False),
    ("Trusted deny ACE", THREE + f"(D;;FR;;;{OWN})", FOLDER, False),
    ("Unprotected task parent", THREE, f"O:{OWN}D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{OWN})", False),
    ("Foreign task parent authority", THREE, f"O:{OWN}D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{OWN})(A;;FR;;;WD)", False),
    ("Missing task parent grant", THREE, f"O:{OWN}D:P(A;;GA;;;SY)(A;;GA;;;{OWN})", False),
]


@pytest.mark.parametrize("name, task, folder, accepted", CASES, ids=[c[0] for c in CASES])
def test_matches_the_frozen_native_controls(name, task, folder, accepted):
    problems = acl.task_object_problems(task, folder, OWN)
    assert (problems == []) is accepted, problems


def test_defaulted_dacl_control_is_not_expressible_in_sddl():
    """Their 20th control sets SE_DACL_DEFAULTED via SetFlags; an SDDL string
    (what GetSecurityDescriptor returns) cannot carry it. Equivalent refusal of
    every OTHER control bit SDDL can express:"""
    for flags in ("AI", "AR", "PAI"):
        assert acl.task_object_problems(THREE.replace("D:", "D:" + flags), FOLDER, OWN)


def test_requested_descriptors():
    assert acl.task_sddl(OWN) == f"O:{OWN}D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{OWN})"
    assert acl.folder_sddl(OWN) == FOLDER
    assert acl.task_object_problems(acl.task_sddl(OWN), acl.folder_sddl(OWN), OWN) == []


@pytest.mark.parametrize("bad", ["", "garbage", f"O:{OWN}D:(A;;ZZ;;;SY)", f"O:{OWN}D:(XA;;FA;;;SY)",
                                 f"O:{OWN}D:(A;;FA;;;LA)", f"O:{OWN}D:(OA;;FA;guid;;SY)"])
def test_unparseable_or_exotic_descriptors_are_refused(bad):
    assert acl.task_object_problems(bad or None, FOLDER, OWN)
    assert acl.task_object_problems(THREE, bad or None, OWN)


def _struct(sddl, **overrides):
    d = acl.from_sddl(sddl)
    d.update(overrides)
    return d


def test_structured_descriptors_from_the_scheduler():
    """The real query emits RawSecurityDescriptor facts; a machine-relative
    alias such as LA is resolved there, and the DACL_DEFAULTED control (their
    20th control, not expressible in SDDL) is visible and refused."""
    task, folder = _struct(ACTUAL), _struct(FOLDER)
    assert acl.task_object_problems(task, folder, OWN) == []
    defaulted = _struct(THREE, control=0x800C)  # SELF_RELATIVE | DACL_PRESENT | DACL_DEFAULTED
    assert acl.task_object_problems(defaulted, folder, OWN)
    custom = _struct(THREE)
    custom["dacl"] = custom["dacl"] + [{"type": 0, "flags": 0, "mask": None, "sid": None, "common": False,
                                         "callback": False}]
    assert acl.task_object_problems(custom, folder, OWN)
    assert acl.task_object_problems({"owner": OWN}, folder, OWN)  # malformed


def test_divergence_d1_auto_inherited_protected_folder_only():
    """D1 (reported): the scheduler-created protected folder carries AI."""
    ai_folder = _struct(FOLDER, control=0x9404)
    assert acl.task_object_problems(THREE, ai_folder, OWN) == []
    assert acl.task_object_problems(THREE, _struct(FOLDER.replace("D:P", "D:"), control=0x8404), OWN)
    assert acl.task_object_problems(_struct(THREE, control=0x8404), FOLDER, OWN)  # never on the task
