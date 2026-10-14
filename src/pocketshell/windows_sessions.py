"""Portable aplexer session listing for gateway clients on Windows.

The Unix command group imports locks, PTYs and the Unix socket daemon. Keep
this Windows surface independent, using the same schema and live-session
enumerator as the tray and Unix listing command.
"""
import json
import click
from pocketshell.runtime import sessions as runtime


@click.group(name="sessions")
def sessions_group():
    """Inspect this Windows user's aplexer sessions."""


@sessions_group.command(name="list")
@click.option("--json", "json_output", is_flag=True)
@click.pass_context
def list_sessions(ctx, json_output):
    """List live sessions, including sessions created by an installed a CLI."""
    rows, errors = runtime.enumerate_live_sessions()
    if json_output:
        click.echo(json.dumps(runtime.json_payload(rows, errors)))
    else:
        click.echo(runtime.format_aplexer_table(rows), nl=False)
        for error in errors:
            click.echo(error["message"], err=True)
    if errors:
        ctx.exit(1)


sessions_group.add_command(list_sessions, name="ls")
