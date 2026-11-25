"""Report time on the current Actions attempt without touching the release result."""

from datetime import datetime
import json
import os
import subprocess
import sys


JOBS = ("Plan image and release", "Checks", "Image", "Deploy production")
IMAGE_STEPS = {
    "Restore Go compiler cache": "Go compiler cache restore",
    "Persist BuildKit compiler cache mount": "Inject compiler cache into BuildKit",
    "Build (push only main, SHA tag only)": "Buildx build / load / push / layer cache",
    "Install browser smoke harness": "Install browser smoke harness",
    "Smoke image with PostgreSQL, MCP and Chromium": "Image smoke (PostgreSQL, MCP, Chromium)",
    "Post Persist BuildKit compiler cache mount": "Extract BuildKit compiler cache",
    "Post Restore Go compiler cache": "Save compiler cache in Actions",
}
RESULTS = {"success", "failure", "skipped", "cancelled", "timed_out", "neutral"}


def stamp(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
        return parsed if parsed.tzinfo is not None and parsed.year > 1970 else None
    except ValueError:
        return None


def duration(start, end):
    if start is None or end is None or end < start:
        return "—"
    return f"{(end - start).total_seconds():.0f} s"


def result(value):
    return value if isinstance(value, str) and value in RESULTS else "—"


def report(jobs, attempt, created_at=None):
    by_name = {job.get("name"): job for job in jobs if job.get("name") in JOBS}
    started = [stamp(job.get("started_at")) for job in by_name.values() if job.get("conclusion") != "skipped"]
    first = min((item for item in started if item is not None), default=None)
    lines = [f"## Pipeline timings · attempt {attempt}", ""]
    if attempt == 1:
        lines.extend([f"Initial wait until the first runner started: **{duration(stamp(created_at), first)}**.", ""])
    lines.extend(["| Job / step | Duration | Result |", "| --- | ---: | --- |"])
    for name in JOBS:
        job = by_name.get(name)
        if job is None:
            continue  # A rerun may contain only failed jobs and their dependents.
        status = result(job.get("conclusion"))
        elapsed = "—" if status == "skipped" else duration(stamp(job.get("started_at")), stamp(job.get("completed_at")))
        lines.append(f"| **{name}** | {elapsed} | {status} |")
        if name != "Image":
            continue
        for step in job.get("steps", []):
            label = IMAGE_STEPS.get(step.get("name"))
            if label is not None and step.get("conclusion") != "skipped":
                elapsed = duration(stamp(step.get("started_at")), stamp(step.get("completed_at")))
                lines.append(f"| ↳ {label} | {elapsed} | {result(step.get('conclusion'))} |")
    lines.extend(["", "Checks and Image can run in parallel; do not add their durations. VPS timings are in the deployment summary.", ""])
    return "\n".join(lines)


def api(endpoint):
    completed = subprocess.run(["gh", "api", "--method", "GET", endpoint], check=True,
                               timeout=20, capture_output=True, text=True)
    return json.loads(completed.stdout)


def main():
    try:
        run = int(os.environ["GITHUB_RUN_ID"])
        attempt = int(os.environ["GITHUB_RUN_ATTEMPT"])
        base = f"repos/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{run}"
        jobs = api(f"{base}/attempts/{attempt}/jobs?per_page=100")["jobs"]
        created_at = api(base).get("created_at") if attempt == 1 else None
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as summary:
            summary.write(report(jobs, attempt, created_at))
    except (KeyError, OSError, TypeError, ValueError, subprocess.SubprocessError):
        print("Timing summary unavailable for this run attempt.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
