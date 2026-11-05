"""Fail-closed inherited-bound discovery and actual session create routing."""
from __future__ import annotations

import json
import sys
from dataclasses import replace
from types import SimpleNamespace

import pytest
from click.testing import CliRunner

from pocketshell import sessions
from pocketshell.runtime import inherited_cgroup as inherited
from pocketshell.runtime.memcap import MemCapError
from pocketshell.sessions import create

MIB = 1024**2
MOUNT = '42 23 0:28 / /sys/fs/cgroup ro,nosuid,nodev,noexec - cgroup2 cgroup rw,nsdelegate\n'


class KernelFixture:
    def __init__(self, *, cgroup="0::/\n", mount=MOUNT, ram=f"{384*MIB}\n", swap="0\n", kind="domain\n"):
        self.cgroup, self.mount, self.ram, self.swap, self.kind = cgroup, mount, ram, swap, kind
        self.reads = []

    def proc(self, path):
        self.reads.append(path)
        return self.cgroup if path == "/proc/self/cgroup" else self.mount

    def limits(self, mount):
        assert mount.mount_id == 42
        return self.kind, self.ram, self.swap, 28, 100


@pytest.fixture(autouse=True)
def no_system_escape(monkeypatch):
    monkeypatch.delenv("APLEXER_LAUNCH_SYSTEM_SCOPE", raising=False)


def test_existing_stronger_domain_is_truthfully_shared_and_zero_swap():
    proof = inherited.discover(12*1024**3, kernel=KernelFixture())
    assert proof.memory_max_bytes == 384*MIB and proof.membership == "/"
    assert proof.public() == {"mode": "inherited_cgroup", "requested_bytes": 12*1024**3,
                              "memory_max_bytes": 384*MIB, "swap_max_bytes": 0, "shared": True}


@pytest.mark.parametrize("ram", ["max\n", "0\n", "-1\n", "123 456\n", "01\n", "1e9\n", "", "9223372036854775808\n"])
def test_unbounded_missing_or_malformed_ram_never_inherits(ram):
    with pytest.raises(MemCapError):
        inherited.discover(12*1024**3, kernel=KernelFixture(ram=ram))


@pytest.mark.parametrize("swap", ["max\n", "1\n", f"{384*MIB}\n", "", "-1\n"])
def test_zero_swap_policy_is_not_relaxed(swap):
    with pytest.raises(MemCapError):
        inherited.discover(12*1024**3, kernel=KernelFixture(swap=swap))


def test_requested_cap_smaller_than_outer_limit_is_denied():
    with pytest.raises(MemCapError, match="weaker than requested"):
        inherited.discover(128*MIB, kernel=KernelFixture())


@pytest.mark.parametrize("kind", ["threaded\n", "domain threaded\n", "domain invalid\n", ""])
def test_only_real_domain_type_is_supported(kind):
    with pytest.raises(MemCapError, match="not a domain"):
        inherited.discover(1024*MIB, kernel=KernelFixture(kind=kind))


@pytest.mark.parametrize("cgroup", ["", "0::/\n0::/\n", "0::/a/../b\n", "0::relative\n", "0::/a//b\n", "bad", "0::/a/./b\n"])
def test_ambiguous_or_escaping_membership_is_denied(cgroup):
    with pytest.raises(MemCapError):
        inherited.discover(1024*MIB, kernel=KernelFixture(cgroup=cgroup))


@pytest.mark.parametrize("mount", [MOUNT + MOUNT, MOUNT.replace(" ro,", " rw,"),
                                    MOUNT.replace(" / /sys", " /other /sys"),
                                    MOUNT.replace("/sys/fs/cgroup", "/sys/../cgroup"),
                                    "malformed\n", MOUNT.replace("cgroup2", "tmpfs")])
def test_mount_ambiguity_or_untrusted_path_is_denied(mount):
    with pytest.raises(MemCapError):
        inherited.discover(1024*MIB, kernel=KernelFixture(mount=mount))


def test_namespace_subtree_mapping_and_spaces_are_not_shell_interpreted():
    mount = MOUNT.replace(" / /sys/fs/cgroup ", " /tenant /safe\\040mount ")
    parsed = inherited.cgroup_mount(mount, inherited.membership("0::/tenant/current\n"))
    assert str(parsed.path) == "/safe mount" and str(parsed.relative) == "current"
    root = inherited.cgroup_mount(MOUNT, inherited.membership("0::/\n"))
    assert root.relative.parts == ()


def test_system_scope_escape_override_is_denied(monkeypatch):
    monkeypatch.setenv("APLEXER_LAUNCH_SYSTEM_SCOPE", "system")
    with pytest.raises(MemCapError, match="escape override"):
        inherited.discover(1024*MIB, kernel=KernelFixture())


def test_membership_change_during_probe_is_denied():
    kernel = KernelFixture()
    original = kernel.limits
    def change(mount):
        result = original(mount)
        kernel.cgroup = "0::/different\n"
        return result
    kernel.limits = change
    with pytest.raises(MemCapError, match="changed during verification"):
        inherited.discover(1024*MIB, kernel=kernel)


def test_no_cached_proof_if_bound_changes_before_spawn(monkeypatch):
    proof = inherited.discover(1024*MIB, kernel=KernelFixture())
    monkeypatch.setattr(inherited, "discover", lambda _: replace(proof, memory_max_bytes=proof.memory_max_bytes//2))
    with pytest.raises(MemCapError, match="changed before launch"):
        inherited.revalidate(proof)


def test_explicit_none_and_available_dedicated_scope_keep_existing_behavior(monkeypatch):
    monkeypatch.setattr(inherited, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(inherited, "dedicated_scope_available", lambda: True)
    monkeypatch.setattr(inherited, "discover", lambda _: pytest.fail("must not inspect ambient cap"))
    assert inherited.plan(None) is None and inherited.plan(1024*MIB) is None


def test_no_systemd_selects_only_verified_existing_boundary(monkeypatch):
    monkeypatch.setattr(inherited, "sys", SimpleNamespace(platform="linux"))
    monkeypatch.setattr(inherited, "dedicated_scope_available", lambda: False)
    proof = inherited.discover(1024*MIB, kernel=KernelFixture())
    monkeypatch.setattr(inherited, "discover", lambda _: proof)
    assert inherited.plan(1024*MIB) == proof


def test_normal_create_inherits_without_claiming_independent_requested_scope(monkeypatch, tmp_path):
    proof = inherited.discover(12*1024**3, kernel=KernelFixture())
    monkeypatch.setattr(create, "_resolve_aplexer", lambda: SimpleNamespace(path="/bundled/a"))
    monkeypatch.setattr(create, "_aplexer_snapshot", lambda: [])
    monkeypatch.setattr(inherited, "plan", lambda _: proof)
    checked = []
    monkeypatch.setattr(inherited, "revalidate", lambda p: checked.append(p))
    calls = []
    def run(argv):
        assert checked == [proof]
        calls.append(argv)
        return 0, json.dumps({"id": "fixture-id", "workspace": str(tmp_path), "tag": "shell"}), ""
    monkeypatch.setattr(create, "_run_aplexer", run)
    result = CliRunner().invoke(sessions.sessions_group, ["create", "shell", "--cwd", str(tmp_path), "--json"])
    assert result.exit_code == 0, result.output
    assert calls == [["/bundled/a", "--json", "start", "--workspace", str(tmp_path), "--tag", "shell"]]
    assert json.loads(result.output)["memory_enforcement"] == proof.public()


def test_invalid_kernel_proof_refuses_before_any_session_launch(monkeypatch, tmp_path):
    monkeypatch.setattr(create, "_resolve_aplexer", lambda: SimpleNamespace(path="/bundled/a"))
    monkeypatch.setattr(create, "_aplexer_snapshot", lambda: [])
    def denied(_):
        raise MemCapError("no verified kernel bound")
    monkeypatch.setattr(inherited, "plan", denied)
    monkeypatch.setattr(create, "_run_aplexer", lambda _: pytest.fail("must not launch"))
    result = CliRunner().invoke(sessions.sessions_group, ["create", "shell", "--cwd", str(tmp_path), "--json"])
    assert result.exit_code != 0 and "no verified kernel bound" in result.output


@pytest.mark.skipif(sys.platform != "linux", reason="Linux filesystem FD validation")
def test_regular_files_cannot_forge_proc_or_cgroup_filesystem_proof(tmp_path):
    data = tmp_path / "membership"
    data.write_text("0::/\n")
    with pytest.raises(MemCapError, match="expected filesystem"):
        inherited.Kernel().proc(str(data))
    mount = inherited.CgroupMount(42, inherited.PurePosixPath("/"), inherited.PurePosixPath(str(tmp_path)),
                                  inherited.PurePosixPath("."))
    with pytest.raises(MemCapError, match="directory identity"):
        inherited.Kernel().limits(mount)


@pytest.mark.skipif(sys.platform != "linux", reason="Linux O_NOFOLLOW validation")
def test_symlinked_kernel_file_and_directory_are_denied(tmp_path):
    data = tmp_path / "data"
    data.write_text("0::/\n")
    link = tmp_path / "link"
    link.symlink_to(data)
    with pytest.raises(OSError):
        inherited.Kernel().proc(str(link))
    directory_link = tmp_path / "directory"
    directory_link.symlink_to(tmp_path, target_is_directory=True)
    mount = inherited.CgroupMount(42, inherited.PurePosixPath("/"), inherited.PurePosixPath(str(directory_link)),
                                  inherited.PurePosixPath("."))
    with pytest.raises(OSError):
        inherited.Kernel().limits(mount)
