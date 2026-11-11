"""Plan image/deploy work only; Checks must always run. Uncertainty means build."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys


DOC_PATHS = frozenset({
    b"README.md", b"AGENTS.md", b"DESIGN.md", b"PRODUCT.md", b"SPEC.md",
    b"docs/ci-cd.md", b"docs/MCP.md", b"docs/performance.md",
})
SHA_PATTERN = r"[0-9a-fA-F]{40}"


class UnsafePlan(Exception):
    """A fixed, non-sensitive reason why skipping cannot be proven safe."""


def sha(value):
    if not isinstance(value, str) or not re.fullmatch(SHA_PATTERN, value):
        raise UnsafePlan("invalid_sha")
    return value.lower()


class Planner:
    def __init__(self, env, cwd):
        self.env = dict(env, GH_PROMPT_DISABLED="1", GIT_TERMINAL_PROMPT="0",
                        GIT_NO_REPLACE_OBJECTS="1")
        self.cwd = cwd

    def run(self, command):
        return subprocess.run(
            command, cwd=self.cwd, env=self.env, stdin=subprocess.DEVNULL,
            capture_output=True, check=True, timeout=30,
        ).stdout

    def git(self, *arguments):
        return self.run(["git", "--no-pager", "--no-optional-locks", *arguments])

    def api(self, endpoint):
        return json.loads(self.run(["gh", "api", "--method", "GET", endpoint]))

    def production_baseline(self):
        repository = self.env.get("GITHUB_REPOSITORY", "")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", repository):
            raise UnsafePlan("invalid_repository")
        endpoint = f"repos/{repository}/deployments"
        deployments = self.api(endpoint + "?environment=production&per_page=1")
        if not isinstance(deployments, list) or not deployments or not isinstance(deployments[0], dict):
            raise UnsafePlan("no_production_deployment")
        # Never search older deployments: a newer failed/pending run invalidates a skip.
        latest = deployments[0]
        deployment_id = latest.get("id")
        if (type(deployment_id) is not int or deployment_id <= 0
                or latest.get("environment") != "production"
                or latest.get("ref") not in ("main", "refs/heads/main")):
            raise UnsafePlan("unsafe_production_deployment")
        baseline = sha(latest.get("sha"))
        statuses = self.api(f"{endpoint}/{deployment_id}/statuses?per_page=1")
        if (not isinstance(statuses, list) or not statuses
                or not isinstance(statuses[0], dict) or statuses[0].get("state") != "success"):
            raise UnsafePlan("production_not_successful")
        return baseline

    def docs_only(self, baseline, head):
        # Raw, NUL-delimited records retain modes and arbitrary filename bytes.
        # Disabling renames makes BOTH paths of a rename visible as D + A.
        diff = self.git(
            "diff", "--raw", "-z", "--no-abbrev", "--no-renames",
            "--no-ext-diff", "--no-textconv", "--no-relative", "--ignore-submodules=none",
            f"{baseline}...{head}", "--",
        )
        if not diff:
            return False, "docs_only"
        fields = diff.split(b"\0")
        if fields.pop() != b"" or len(fields) % 2:
            raise UnsafePlan("invalid_diff")
        for header, path in zip(fields[::2], fields[1::2]):
            match = re.fullmatch(
                rb":([0-7]{6}) ([0-7]{6}) ([0-9a-f]{40}) ([0-9a-f]{40}) ([AMD])",
                header,
            )
            if not match:
                return True, "unsafe_change"
            old_mode, new_mode, old_blob, new_blob, status = match.groups()
            expected_modes = {
                b"A": (b"000000", b"100644"),
                b"M": (b"100644", b"100644"),
                b"D": (b"100644", b"000000"),
            }
            if (old_mode, new_mode) != expected_modes[status]:
                return True, "unsafe_mode"
            if ((old_blob == b"0" * 40) != (status == b"A")
                    or (new_blob == b"0" * 40) != (status == b"D")):
                raise UnsafePlan("invalid_diff")
            if path not in DOC_PATHS:
                return True, "non_docs_change"
        return False, "docs_only"

    def plan(self):
        head = sha(self.env.get("GITHUB_SHA"))
        checkout = sha(self.git("rev-parse", "--verify", "HEAD^{commit}").decode("ascii").strip())
        if checkout != head:
            raise UnsafePlan("checkout_mismatch")
        with Path(self.env["GITHUB_EVENT_PATH"]).open(encoding="utf-8") as stream:
            event = json.load(stream)
        if not isinstance(event, dict):
            raise UnsafePlan("invalid_event")
        event_name = self.env.get("GITHUB_EVENT_NAME")
        if event_name == "workflow_dispatch":
            return True, "manual_dispatch"
        if event_name not in ("pull_request", "push"):
            raise UnsafePlan("unsupported_event")
        if self.git("rev-parse", "--is-shallow-repository").strip() != b"false":
            raise UnsafePlan("incomplete_history")
        if event_name == "pull_request":
            base = sha(event["pull_request"]["base"]["sha"])
            self.git("cat-file", "-e", f"{base}^{{commit}}")
            baseline = sha(self.git("merge-base", head, base).decode("ascii").strip())
        else:
            if (self.env.get("GITHUB_REF") != "refs/heads/main"
                    or event.get("ref") != "refs/heads/main"
                    or sha(event.get("after")) != head
                    or event.get("deleted", False) is not False):
                raise UnsafePlan("invalid_push")
            baseline = self.production_baseline()
            self.git("cat-file", "-e", f"{baseline}^{{commit}}")
        self.git("merge-base", "--is-ancestor", baseline, head)
        return self.docs_only(baseline, head)


def plan(env=None, cwd=None):
    try:
        return Planner(os.environ if env is None else env, cwd).plan()
    except UnsafePlan as error:
        return True, str(error)
    except Exception:
        # Includes malformed JSON/context, missing history, API/git errors and timeouts.
        # Never log exception text: it may contain metadata, paths or credentials.
        return True, "planner_error"


def write_outputs(build_image, reason):
    payload = f"build_image={str(build_image).lower()}\nreason={reason}\n"
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
        stream.write(payload)
    print(payload, end="")


def main():
    build_image, reason = True, "planner_error"
    try:
        build_image, reason = plan()
    except Exception:
        pass
    try:
        write_outputs(build_image, reason)
    except Exception:
        # Override a possibly partial skip write when the output channel recovers.
        try:
            write_outputs(True, "output_error")
        except Exception:
            print("build_image=true\nreason=output_error")
            print("CI planner output unavailable; refusing to skip", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
