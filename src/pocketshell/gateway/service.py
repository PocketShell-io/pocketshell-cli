"""``pocketshell gateway service install|uninstall|status``.

The supported way to start an ENROLLED gateway host agent durably and
invisibly:

- **Linux** — a systemd ``--user`` unit
  (``~/.config/systemd/user/pocketshell-gateway.service``) whose
  ``ExecStart`` is the absolute, protocol-verified helper
  ``run --config-dir DIR`` (see :mod:`pocketshell.gateway.service_linux`).
- **Windows** — ONE per-user scheduled task ``\\PocketShell\\GatewayLink``
  (S4U, LeastPrivilege, session 0, boot + 5-minute watchdog) that launches
  the reviewed native helper directly (see
  :mod:`pocketshell.gateway.service_windows`).

Never enrolls, re-enrolls, or touches the enrolled state: ``install``
requires an existing enrollment (the helper's own non-secret ``show`` must
accept the config dir) and ``uninstall`` removes only the unit/task.
"""

from __future__ import annotations

import json
import sys
from typing import Optional

import click

from pocketshell.gateway import service_common as common
from pocketshell.gateway.service_common import ServiceError, sanitize


def _platform() -> str:
    if sys.platform == "win32":
        return "windows"
    if sys.platform.startswith("linux"):
        return "linux"
    raise ServiceError(
        "`gateway service` supports Linux (systemd --user) and Windows (Task "
        "Scheduler) only; run `pocketshell gateway run` under your own supervisor"
    )


def _guard(fn):
    """Operator-facing errors only: no tracebacks, sanitized text."""
    import functools

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except ServiceError as exc:
            click.echo(f"error: {exc}", err=True)
            sys.exit(exc.exit_code)
        except OSError as exc:
            click.echo(
                f"error: {sanitize(exc.strerror or type(exc).__name__)}", err=True
            )
            sys.exit(1)

    return wrapper


@click.group(
    name="service",
    context_settings={"help_option_names": ["-h", "--help"]},
    help=(
        "Start the enrolled host agent durably and invisibly: a systemd "
        "--user unit on Linux, one per-user scheduled task (S4U, session 0, "
        "no window) on Windows. Requires `pocketshell gateway enroll` first; "
        "never touches the enrollment."
    ),
)
def service_group() -> None:
    """Durable start of the gateway host agent."""


_CONFIG_DIR_HELP = (
    "Enrolled agent state directory (default: the helper's default, "
    "~/.config/pocketshell-link; %USERPROFILE%\\.config\\pocketshell-link on Windows). "
    "Passed to the helper explicitly."
)


@service_group.command("install")
@click.option("--config-dir", default=None, metavar="DIR", help=_CONFIG_DIR_HELP)
@click.option(
    "--helper",
    default=None,
    metavar="PATH",
    help=(
        "Absolute path of pocketshell-link. Linux default: the usual helper "
        "resolution. Windows: required (or POCKETSHELL_GATEWAY_HELPER); its "
        "sha256 must be a reviewed build."
    ),
)
@click.option(
    "--with-endpoint",
    "endpoint_manifest",
    default=None,
    metavar="MANIFEST",
    help=(
        "Windows only: also own the private loopback SSH endpoint: a second task "
        "(\\PocketShell\\GatewayEndpoint) launching the reviewed guardian with this "
        "reviewed guardian manifest, confirmed READY (exact enrolled host key) before "
        "the link is registered."
    ),
)
@click.option(
    "--endpoint-only",
    is_flag=True,
    help="With --with-endpoint: register only the endpoint task, never the link task.",
)
@click.option(
    "--instance",
    default=None,
    metavar="NAME",
    help=(
        "With --endpoint-only: an ISOLATED qualification endpoint task "
        "(GatewayEndpointQ<NAME>) on a non-production port."
    ),
)
@click.option("--dry-run", is_flag=True, help="Print the exact unit/task and commands; change nothing.")
@click.option("--force", is_flag=True, help="Replace an existing unit/task.")
@click.option(
    "--no-start",
    is_flag=True,
    help=(
        "Do not start it now. Linux: enable only (starts at next boot/login). "
        "Windows: register the task DISABLED (the watchdog would otherwise start "
        "it within 5 minutes); `install --force` later enables and starts it."
    ),
)
@_guard
def install(
    config_dir: Optional[str],
    helper: Optional[str],
    endpoint_manifest: Optional[str],
    endpoint_only: bool,
    instance: Optional[str],
    dry_run: bool,
    force: bool,
    no_start: bool,
) -> None:
    """Install (and start) the durable host agent for an enrolled config dir.

    Exit status: 0 installed and started (or registered with --no-start),
    5 installed but NOT started (start failed or not confirmed; the
    unit/task is kept), 1 refused or failed (nothing started).
    """
    platform = _platform()
    config_dir = config_dir or common.default_config_dir()
    if platform == "linux":
        from pocketshell.gateway import service_linux as backend

        if endpoint_manifest or endpoint_only or instance:
            raise ServiceError(
                "--with-endpoint is Windows-only; on Linux the local sshd is already a "
                "durable system or user service"
            )
        plan = backend.plan_install(helper, config_dir, force=force, start=not no_start)
        device = common.parse_show(plan.show).get("device id", "?")
        if dry_run:
            click.echo(f"# dry run: nothing written. Enrolled device: {device}")
            click.echo(f"# would write {plan.unit_path} (0644):")
            click.echo(plan.unit_text, nl=False)
            click.echo("# then run:")
            for argv in plan.commands:
                click.echo("  " + " ".join(argv))
            click.echo("# the unit's process argv:")
            click.echo("  " + json.dumps([plan.helper, "run", "--config-dir", plan.config_dir]))
            return
        warnings = backend.apply_install(plan)
        click.echo(f"installed {plan.unit_path} for device {device}"
                   + ("" if no_start else " (enabled and started)"))
    else:
        from pocketshell.gateway import service_windows as backend

        plan = backend.plan_install(
            helper, config_dir, force=force, start=not no_start,
            endpoint_manifest=endpoint_manifest, endpoint_only=endpoint_only, instance=instance,
        )
        device = common.parse_show(plan.show).get("device id", "?")
        if dry_run:
            click.echo(f"# dry run: nothing registered or written. Enrolled device: {device}")
            if plan.endpoint is not None:
                m = plan.endpoint.manifest
                click.echo(
                    f"# endpoint task {plan.endpoint.name} (127.0.0.1:{m.port}, enrolled host key "
                    f"{plan.endpoint.host_key.fingerprint}, manifest sha256 {m.sha256}); "
                    "definition (UTF-16):"
                )
                click.echo(plan.endpoint.xml, nl=False)
                click.echo("# the endpoint task's process argv (direct, no shell):")
                click.echo("  " + json.dumps([m.python, m.guardian, "--manifest", m.path]))
            if not plan.include_link:
                click.echo("# then run (CREATE_NO_WINDOW):")
                for argv in plan.commands():
                    click.echo("  " + json.dumps(argv))
                return
            click.echo(f"# task {backend.TASK_NAME}, principal {plan.user_sid}; definition (UTF-16):")
            click.echo(plan.xml, nl=False)
            click.echo("# then run (CREATE_NO_WINDOW):")
            for argv in plan.commands():
                click.echo("  " + json.dumps(argv))
            click.echo("# the task's process argv (direct, no shell):")
            click.echo("  " + json.dumps(plan.action_argv))
            return
        warnings = backend.apply_install(plan)
        if plan.endpoint is not None:
            click.echo(
                f"registered {plan.endpoint.name} (127.0.0.1:{plan.endpoint.manifest.port})"
                + (" (registered DISABLED)" if no_start
                   else " (started; guardian READY, held daemon alive, enrolled host key proven)")
            )
        if plan.include_link:
            click.echo(f"registered {backend.TASK_NAME} for device {device} as {plan.user_sid}"
                       + (" (registered DISABLED; `install --force` enables and starts it)"
                          if no_start else " (started)"))
    for warning in warnings:
        click.echo(f"warning: {warning}", err=True)


@service_group.command("uninstall")
@click.option(
    "--force",
    is_flag=True,
    help=(
        "Also remove a pocketshell-gateway.service unit / \\PocketShell\\GatewayLink "
        "task this command did not write (no 'Managed by' marker)."
    ),
)
@click.option("--instance", default=None, metavar="NAME", help="Windows: the qualification endpoint task.")
@_guard
def uninstall(force: bool, instance: Optional[str]) -> None:
    """Stop and remove only the unit/task (never the config dir, key or registration).

    Windows endpoint task: disabled first, then stopped through the guardian's
    STOP protocol (exact held daemon identity, never a kill), then deleted.
    """
    if _platform() == "linux":
        from pocketshell.gateway import service_linux as backend

        if instance:
            raise ServiceError("--instance is Windows-only")
        click.echo(backend.uninstall(force=force))
    else:
        from pocketshell.gateway import service_windows as backend

        click.echo(backend.uninstall(force=force, instance=instance))


@service_group.command("status")
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output.")
@click.option("--instance", default=None, metavar="NAME", help="Windows: the qualification endpoint task.")
@_guard
def status(as_json: bool, instance: Optional[str]) -> None:
    """Unit/task state, helper, config dir and enrolled `show` output.

    Exit status: 0 running, 3 installed but not running, 4 not installed.
    """
    if _platform() == "linux":
        from pocketshell.gateway import service_linux as backend

        if instance:
            raise ServiceError("--instance is Windows-only")
        st = backend.status()
    else:
        from pocketshell.gateway import service_windows as backend

        st = backend.status(instance=instance)
    if as_json:
        click.echo(json.dumps(st.as_dict(), indent=2))
    else:
        click.echo(f"{st.name}: " + (
            "not installed" if not st.installed
            else ("running" if st.running else "installed, not running")
        ) + (f" [{st.state}]" if st.installed else ""))
        if st.installed:
            rows = [
                ("definition", st.definition_path),
                ("managed", "yes" if st.managed else "no (not written by this command)"),
                ("helper", st.helper),
                ("helper sha256", st.helper_sha256),
            ]
            if st.helper_allowed is not None:
                rows.append(("reviewed build", "yes" if st.helper_allowed else "NO"))
            rows.append(("config dir", st.config_dir))
            for key in ("user_id", "logon_type", "run_level", "direct_launch"):
                if key in st.details:
                    rows.append((key.replace("_", " "), str(st.details[key])))
            procs = ", ".join(
                f"pid {p['pid']}" + (f" session {p['session_id']}" if p.get("session_id") is not None else "")
                for p in st.processes
            )
            rows.append(("processes", procs or "none"))
            for name, value in rows:
                click.echo(f"  {name + ':':<16}{value if value is not None else '-'}")
            if st.show:
                click.echo("  enrolled state (helper show):")
                for line in st.show.splitlines():
                    click.echo("    " + line)
            if st.show_error:
                click.echo(f"  show: {st.show_error}")
        for warning in st.warnings:
            click.echo(f"warning: {warning}", err=True)
    sys.exit(st.exit_code)
