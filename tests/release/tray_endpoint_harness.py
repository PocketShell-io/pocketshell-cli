"""Test-only packaged tray context; no account, manifest or source allowlist bypass."""
import sys

from pocketshell.gateway import service_windows as win
from pocketshell.tray_supervisor import configure_context

# Use the same measured console/RDP mode as the real tray. Hosted CI's outer
# job cannot be escaped; retain the existing v3 test's report-only job seam.
# This is not a NoJob qualification and does not alter session Job limits.
def report_job(*, caller_in_job, broke_away, child_in_job, nearest_kill):
    return {"inJob": bool(child_in_job), "brokeAway": bool(broke_away) and not child_in_job,
            "callerInJob": bool(caller_in_job), "callerJobKillOnClose": bool(nearest_kill)}


win.job_verdict = report_job
configure_context(native_api=win.WindowsApi())

from pocketshell.cli import cli  # noqa: E402

sys.argv = ["pocketshell", *sys.argv[1:]]
cli()
