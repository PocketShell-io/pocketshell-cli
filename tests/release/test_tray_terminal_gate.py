"""The normal artifact route must retain the non-optional native gate."""
import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]


def public_copy_fixture(tmp_path):
    spec = importlib.util.spec_from_file_location("tray_terminal_fixture", ROOT / "tests/release/tray_terminal_fixture.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    payload = tmp_path / "payload"
    files = {"GatewayTray.exe": b"tray", "pocketshell.exe": b"cli",
             "endpoint/bin/sshd.exe": b"backend", "psc-ssh/ssh.exe": b"client",
             "python/app.zip": b"app", "shell/.measured-hidden": b"public hidden file"}
    for name, data in files.items():
        path = payload / "runtime" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    (payload / "psc-ssh").mkdir()
    (payload / "psc-ssh/ssh.exe").write_bytes(files["psc-ssh/ssh.exe"])
    backend = {"source": "backend-source", "files": {"sshd.exe": module.digest(payload / "runtime/endpoint/bin/sshd.exe")}}
    backend_path = payload / "private-endpoint-build-receipt.json"
    backend_path.write_text(json.dumps(backend))
    catalog = {"source": "fixture-source", "files": [
        {"path": name, "sha256": module.digest(payload / "runtime" / name)} for name in files]}
    catalog_path = payload / "host-runtime-catalog.json"
    catalog_path.write_text(json.dumps(catalog))
    receipt = {"source": "fixture-source", "files": len(files), "catalogSHA256": module.digest(catalog_path),
               "privateEndpoint": {**backend, "receiptSHA256": module.digest(backend_path)},
               "launcherSHA256": module.digest(payload / "runtime/GatewayTray.exe"),
               "cliLauncher": {"sha256": module.digest(payload / "runtime/pocketshell.exe")}}
    return module, payload, receipt


def test_public_copy_inventory_keeps_exact_catalog_backend_client_and_hidden_files(tmp_path):
    module, payload, receipt = public_copy_fixture(tmp_path)
    measured = module.verified_public_files(payload, receipt)
    assert len(measured) == receipt["files"] + 3
    assert "runtime/shell/.measured-hidden" in measured
    assert measured["psc-ssh/ssh.exe"] == measured["runtime/psc-ssh/ssh.exe"]


def test_normal_installer_sidecar_is_never_enumerated_read_or_selected(tmp_path, monkeypatch):
    module, payload, receipt = public_copy_fixture(tmp_path)
    expected = module.verified_public_files(payload, receipt)
    sidecar = payload / "psc-package"
    sidecar.mkdir()
    (sidecar / "not-a-terminal-input.exe").write_bytes(b"synthetic optional installer client")
    original_digest, original_rglob = module.digest, Path.rglob
    def measured_digest(path):
        assert not path.is_relative_to(sidecar)
        return original_digest(path)
    def measured_rglob(path, *args, **kwargs):
        assert not path.is_relative_to(sidecar)
        return original_rglob(path, *args, **kwargs)
    monkeypatch.setattr(module, "digest", measured_digest)
    monkeypatch.setattr(Path, "rglob", measured_rglob)
    assert module.verified_public_files(payload, receipt) == expected
    assert not any(path.startswith("psc-package/") for path in expected)


@pytest.mark.parametrize("mutation", ["unknown-root", "sidecar-file", "sidecar-reparse"])
def test_public_copy_keeps_top_level_and_sidecar_boundary_strict(tmp_path, monkeypatch, mutation):
    module, payload, receipt = public_copy_fixture(tmp_path)
    if mutation == "unknown-root":
        (payload / "unmeasured-extra").mkdir()
    elif mutation == "sidecar-file":
        (payload / "psc-package").write_bytes(b"wrong object type")
    else:
        sidecar = payload / "psc-package"
        sidecar.mkdir()
        original = Path.is_symlink
        monkeypatch.setattr(Path, "is_symlink", lambda self: self == sidecar or original(self))
    with pytest.raises(AssertionError):
        module.verified_public_files(payload, receipt)


@pytest.mark.parametrize("mutation", ["extra", "runtime", "client", "catalog", "backend", "hardlink"])
def test_public_copy_refuses_unmeasured_or_changed_bytes_before_copy(tmp_path, mutation):
    module, payload, receipt = public_copy_fixture(tmp_path)
    target = payload / {"extra": "personal-credentials.json", "runtime": "runtime/python/app.zip",
                        "client": "psc-ssh/ssh.exe", "catalog": "host-runtime-catalog.json",
                        "backend": "private-endpoint-build-receipt.json", "hardlink": "runtime/python/app.zip"}[mutation]
    if mutation == "hardlink":
        (tmp_path / "alias").hardlink_to(target)
    else:
        target.write_bytes(b"untrusted")
    with pytest.raises(AssertionError):
        module.verified_public_files(payload, receipt)


@pytest.mark.parametrize("path", ["../outside", "/absolute", "C:/drive", "bad\\path"])
def test_public_copy_refuses_unsafe_catalog_names(tmp_path, path):
    module, payload, receipt = public_copy_fixture(tmp_path)
    catalog_path = payload / "host-runtime-catalog.json"
    catalog = json.loads(catalog_path.read_bytes())
    catalog["files"][0]["path"] = path
    catalog_path.write_text(json.dumps(catalog))
    receipt["catalogSHA256"] = module.digest(catalog_path)
    with pytest.raises(AssertionError):
        module.verified_public_files(payload, receipt)


def test_public_copy_refuses_reparse_ancestry_before_reading(tmp_path, monkeypatch):
    module, payload, receipt = public_copy_fixture(tmp_path)
    original = Path.is_symlink
    monkeypatch.setattr(Path, "is_symlink", lambda self: self == payload.parent or original(self))
    with pytest.raises(AssertionError):
        module.verified_public_files(payload, receipt)


def test_normal_release_requires_exact_native_inventory_before_upload():
    workflow = (ROOT / ".github/workflows/windows-tray-release.yml").read_text()
    gate = workflow.index("uv run --frozen python scripts/ci/tray_terminal_gate.py")
    assert workflow.index("Assemble installer from verified inputs") < gate
    assert gate < workflow.index("- name: Upload installer artifacts")
    assert "if ($LASTEXITCODE -ne 0) { throw 'Packaged terminal lifecycle" in workflow
    spec = importlib.util.spec_from_file_location("tray_terminal_gate", ROOT / "scripts/ci/tray_terminal_gate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.CASES == {
        "test_fresh_create_pty_reconnect_and_owned_kill",
        "test_project_cap_is_kernel_enforced_not_only_reported",
        "test_invalid_caps_and_mutable_selectors_fail_closed",
        "test_private_pty_encoder_preserves_one_exact_windows_operand",
        "test_private_profile_preserves_complete_scripts_and_interactive_shell",
        "test_packaged_launchers_preserve_console_and_quiet_stdio",
    }
    native = (ROOT / "tests/release/test_windows_tray_terminal_native.py").read_text()
    encoder = (ROOT / "tests/release/test_private_pty_argv_native.py").read_text()
    assert {line.split("(")[0][4:] for line in (native + encoder).splitlines() if line.startswith("def test_")} == module.CASES
    assert 'os.environ["POCKETSHELL_TRAY_TERMINAL_PAYLOAD"]' in native


def test_inventory_rejects_skip_and_teardown_failure():
    from types import SimpleNamespace
    spec = importlib.util.spec_from_file_location("tray_terminal_gate", ROOT / "scripts/ci/tray_terminal_gate.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    inventory = module.Inventory()
    for report in (
        SimpleNamespace(skipped=True, failed=False, when="setup", passed=False, nodeid="native::skip"),
        SimpleNamespace(skipped=False, failed=True, when="teardown", passed=False, nodeid="native::cleanup"),
    ):
        inventory.pytest_runtest_logreport(report)
    assert inventory.rejected == ["native::skip", "native::cleanup"]


def test_prompt_readiness_accepts_conhost_cursor_space_without_weakening_io():
    spec = importlib.util.spec_from_file_location("tray_terminal_fixture", ROOT / "tests/release/tray_terminal_fixture.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # Synthetic terminal painting: a trailing space need not be a literal byte.
    painted = b"\x1b[Hbash-9.9$\x1b[K\r\n\x1b[1;11H\x1b[?25h\x1b[1C"
    assert b"$ " not in painted and b"# " not in painted  # old readiness was RED
    for output in (painted, b"bash-9.9$ ", b"bash-9.9# ", b"bash-9.9$"):
        assert module.shell_prompt_seen(output)
    for output in (b"", b"Starting worker", b"cash$100", b"bash-9.9$unfinished", b"some $ output", b"# ",
                   b"echo bash-9.9$ ", b"echo \x1b[Hbash-9.9$ "):
        assert not module.shell_prompt_seen(output)
    source = (ROOT / "tests/release/tray_terminal_fixture.py").read_text()
    assert 'expected.encode() in b"".join(chunks) and oracle.exists()' in source
    assert 'assert oracle.read_text().strip() == expected' in source


def test_failed_diagnostics_bind_fixed_public_inputs_without_bypassing_gate():
    workflow = (ROOT / ".github/workflows/windows-tray-release.yml").read_text()
    start = workflow.index("      - name: Bind failed payload diagnostics")
    end = workflow.index("      - name: Fetch the previous release installer", start)
    diagnostic = workflow[start:end]
    assert "always() && steps.assemble.outcome == 'success' && steps.terminal_gate.outcome != 'success'" in diagnostic
    assert "always() && steps.diagnostic_manifest.outcome == 'success'" in diagnostic
    assert "acceptanceQualified = $false" in diagnostic
    assert "include-hidden-files: true" in diagnostic
    assert workflow.count("include-hidden-files: true") == 1
    assert "$receipt.source -ne $head -or $receipt.sourceDirty -or $catalog.source -ne $head" in diagnostic
    assert "$receipt.catalogSHA256" in diagnostic
    assert "verify_inventory(payload/'runtime', rows)" in diagnostic
    assert "assert expected and actual==expected" in diagnostic
    assert "$receipt.privateEndpoint.receiptSHA256" in diagnostic
    upload = diagnostic.split("          path: |", 1)[1].split("          if-no-files-found:", 1)[0]
    assert len([line for line in upload.splitlines() if line.strip()]) == 6
    assert "*" not in upload and "USERPROFILE" not in upload
    assert "Setup-x64.exe" not in upload and "psc-package" not in upload
    assert "payload\\runtime" in upload and "payload\\psc-ssh" in upload
    assert "continue-on-error" not in workflow
    # The accepted installer artifact remains downstream of the mandatory gate.
    assert workflow.index("- name: Upload installer artifacts") > end


def test_interrupt_wait_ignores_stale_prompt_and_requires_new_output():
    from types import SimpleNamespace
    spec = importlib.util.spec_from_file_location("tray_terminal_fixture", ROOT / "tests/release/tray_terminal_fixture.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for new_output, expected in ((b"", False), (b"still sleeping", False), (b"\r\nbash-9.9$\x1b[1C", True)):
        chunks = [b"bash-9.9$ ", b"computed-workload-ready\r\n"]
        sent = []
        def write(value):
            sent.append(value)
        def flush():
            assert sent == [b"\x03"]
            chunks.append(new_output)
        def wait(predicate, timeout):
            assert timeout == 10
            return predicate()
        process = SimpleNamespace(stdin=SimpleNamespace(write=write, flush=flush))
        assert module.interrupt_to_fresh_prompt(process, chunks, wait) is expected


def test_native_gate_keeps_exact_memory_observer_and_explicit_postmortem_proofs():
    gate = (ROOT / "scripts/ci/tray_terminal_gate.py").read_text()
    assert 'observations = proof["memoryObservations"]' in gate and "len(observations) == 2" in gate
    assert 'bounded["nativeExit"] == 0xC000012D' in gate
    assert 'bounded["kernelLimitBytes"] == 64 * 1024**2' in gate
    assert 'bounded["after"]["oom_kill_count"] == bounded["before"]["oom_kill_count"] + 1' in gate
    assert 'preserved["preservedBeforeExplicitCleanup"] is True' in gate
    assert 'explicit[0]["ownedProcessesGone"] == preserved["absence"]["ownedPIDsUnallocated"]' in gate
    native = (ROOT / "tests/release/test_windows_tray_terminal_native.py").read_text()
    assert 'host.kill(target["id"], after_oom=True)' in native
