"""The normal artifact route must retain the non-optional native gate."""
import importlib.util
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


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
