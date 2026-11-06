"""A marker, empty file, arbitrary child death or weak cap cannot qualify OOM."""
import ast
import copy
import importlib.util
from pathlib import Path
from uuid import uuid4

import pytest


spec = importlib.util.spec_from_file_location("tray_memory_oracle", Path(__file__).with_name("tray_memory_oracle.py"))
subject = importlib.util.module_from_spec(spec)
spec.loader.exec_module(subject)
IDENT = str(uuid4())
LIMIT = 64 * 1024**2


def observation():
    return {"pid": 1234, "isolated": True, "childJobMember": True, "imageVerified": True, "kernelFlags": 0x2200,
            "kernelLimitBytes": LIMIT, "nativeExit": subject.OOM_EXIT,
            "allocation": {"bytes": 0, "value": None},
            "before": {"job": "aplexer-" + IDENT, "memory_limit_bytes": LIMIT, "oom_kill_count": 0},
            "after": {"job": "aplexer-" + IDENT, "memory_limit_bytes": LIMIT, "oom_kill_count": 1,
                      "peak_memory_bytes": 158773248}}


def test_native_oom_and_kernel_bound_are_required_not_peak_bookkeeping():
    value = observation()
    subject.validate(value, ident=IDENT, limit=LIMIT, allow=False)
    assert value["after"]["peak_memory_bytes"] > LIMIT  # raw counter retained, never used as allocation success


@pytest.mark.parametrize("changes", [
    {"nativeExit": 0}, {"nativeExit": 1}, {"nativeExit": 259}, {"nativeExit": False},
    {"childJobMember": False}, {"imageVerified": False}, {"isolated": False}, {"pid": True},
    {"kernelLimitBytes": LIMIT * 2}, {"kernelFlags": 0x2000}, {"kernelFlags": 0x2A00},
    {"allocation": {"value": {"allocated": True}}}, {"allocation": {"value": True}},
])
def test_incomplete_or_contradictory_proof_is_refused(changes):
    value = observation()
    value.update(changes)
    with pytest.raises(AssertionError):
        subject.validate(value, ident=IDENT, limit=LIMIT, allow=False)


@pytest.mark.parametrize("changes", [{"oom_kill_count": 0}, {"oom_kill_count": 2},
    {"oom_kill_count": True}, {"job": "aplexer-" + str(uuid4())}, {"memory_limit_bytes": LIMIT * 2}])
def test_empty_result_and_child_exit_cannot_replace_exact_oom_counter_and_job(changes):
    value = observation()
    value["after"].update(changes)
    with pytest.raises(AssertionError):
        subject.validate(value, ident=IDENT, limit=LIMIT, allow=False)


def test_same_positive_control_requires_successful_allocation_and_no_oom():
    value = observation()
    value["nativeExit"] = 0
    value["allocation"]["value"] = {"allocated": True, "lastError": 0}
    value["after"]["oom_kill_count"] = 0
    subject.validate(value, ident=IDENT, limit=LIMIT, allow=True)
    bad = copy.deepcopy(value)
    bad["allocation"]["value"] = {"allocated": False}
    with pytest.raises(AssertionError):
        subject.validate(bad, ident=IDENT, limit=LIMIT, allow=True)
    bad = copy.deepcopy(value)
    bad["after"]["oom_kill_count"] = 1
    with pytest.raises(AssertionError):
        subject.validate(bad, ident=IDENT, limit=LIMIT, allow=True)


def test_probe_code_compiles_with_quote_unicode_and_placeholder_text_as_data(tmp_path):
    path = tmp_path / "space ' Unicode-ä @LIMIT@"
    args = [path / name for name in ("oracle", "pid", "release", "finish", "result")]
    child = subject.child_code(10, 20, *args)
    assert "\n" not in child and "\r" not in child and "NATIVE43_30" not in child
    compile(child, "<same-child-probe>", "exec")
    observer = subject.observer_code(IDENT, *args[1:], path / "a.exe", path / "python.exe", "a" * 64, LIMIT, False)
    compile(observer, "<native-observer>", "exec")
    assert any(isinstance(node, ast.Constant) and isinstance(node.value, str)
               and node.value.startswith(str(path)) for node in ast.walk(ast.parse(observer)))
