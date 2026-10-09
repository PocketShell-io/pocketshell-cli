"""CI-only harness: `python agent_harness.py <seams.json> <cli args...>`.

Applies TEST-ONLY allow-list seams (the fake helper / manifest / guardian
sources the native test builds) in this process, then runs the real CLI.
Never product code; the product has no runtime override of the reviewed lists.
"""

import json
import sys

from pocketshell.gateway import service_endpoint as ep
from pocketshell.gateway import service_windows as win

seams = json.load(open(sys.argv[1], encoding="utf-8"))
win.ALLOWED_HELPER_SHA256 = frozenset(seams["helper"])
ep.ALLOWED_ENDPOINT_MANIFEST_SHA256 = frozenset(seams["manifest"])
ep.ALLOWED_GUARDIAN_SOURCES = frozenset(tuple(t) for t in seams["sources"])
if seams.get("acceptJob"):
    # TEST-ONLY (this harness process): the windows-latest runner cannot create a
    # job-free child (measured), so READY/STOP protocol coverage replaces the
    # production job verdict with one that ACCEPTS and truthfully REPORTS the
    # membership. Production has no such flag.
    def _report_only(*, caller_in_job, broke_away, child_in_job, nearest_kill):
        return {"inJob": bool(child_in_job), "brokeAway": bool(broke_away) and not child_in_job,
                "callerInJob": bool(caller_in_job), "callerJobKillOnClose": bool(nearest_kill)}

    win.job_verdict = _report_only

from pocketshell.cli import cli  # noqa: E402

sys.argv = ["pocketshell", *sys.argv[2:]]
cli()
