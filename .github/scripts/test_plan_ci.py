"""Planner contracts: temporary Git histories, mocked gh, no Docker/network."""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import plan_ci


REAL_RUN = subprocess.run
SCRIPT = Path(plan_ci.__file__).resolve()


class PlannerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                        GIT_TERMINAL_PROMPT="0", GH_TOKEN="synthetic-private-token",
                        GITHUB_EVENT_NAME="pull_request", GITHUB_REPOSITORY="example/conspect",
                        GITHUB_REF="refs/heads/main", GITHUB_EVENT_PATH=str(self.root / "event.json"),
                        GITHUB_OUTPUT=str(self.root / "output"))
        self.git("init", "-b", "main")
        self.git("config", "user.email", "planner@example.invalid")
        self.git("config", "user.name", "Planner Test")
        self.git("config", "commit.gpgsign", "false")
        for name in plan_ci.DOC_PATHS:
            self.write(name.decode(), "original documentation\n")
        self.write("app.go", "package main\n")
        self.write("internal/noteguide/guide.md", "embedded guide\n")
        self.base = self.commit()
        self.event = {"pull_request": {"base": {"sha": self.base}}}
        self.api_responses = {}
        self.gh_calls = []

    def git(self, *args, input=None):
        return REAL_RUN(
            ["git", "--no-pager", "--no-optional-locks", *args], cwd=self.repo,
            env=self.env, input=input, capture_output=True, check=True, timeout=10,
        ).stdout.decode().strip()

    def write(self, name, content="updated documentation\n"):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)

    def commit(self, *, staged=False):
        if not staged:
            self.git("add", "-A")
        self.git("commit", "--quiet", "--allow-empty", "-m", "Fixture")
        head = self.git("rev-parse", "HEAD")
        self.env["GITHUB_SHA"] = head
        return head

    def push(self, baseline=None):
        self.env["GITHUB_EVENT_NAME"] = "push"
        self.event = {"ref": "refs/heads/main", "after": self.env["GITHUB_SHA"],
                      "before": self.base, "deleted": False}
        self.api_responses = {
            "repos/example/conspect/deployments?environment=production&per_page=1": [{
                "id": 42, "sha": self.base if baseline is None else baseline,
                "environment": "production", "ref": "main",
            }],
            "repos/example/conspect/deployments/42/statuses?per_page=1": [{"state": "success"}],
        }

    @property
    def deployments(self):
        return self.api_responses["repos/example/conspect/deployments?environment=production&per_page=1"]

    @property
    def statuses(self):
        return self.api_responses["repos/example/conspect/deployments/42/statuses?per_page=1"]

    def fake_run(self, command, **kwargs):
        self.assertNotIn("shell", kwargs)
        self.assertIs(kwargs["stdin"], subprocess.DEVNULL)
        self.assertTrue(kwargs["capture_output"])
        self.assertTrue(kwargs["check"])
        self.assertEqual(kwargs["timeout"], 30)
        self.assertEqual(kwargs["env"]["GIT_NO_REPLACE_OBJECTS"], "1")
        if command[0] == "git":
            self.assertEqual(command[1:3], ["--no-pager", "--no-optional-locks"])
            return REAL_RUN(command, **kwargs)
        self.assertEqual(command[:4], ["gh", "api", "--method", "GET"])
        self.assertEqual(kwargs["env"]["GH_PROMPT_DISABLED"], "1")
        self.assertEqual(kwargs["env"]["GH_TOKEN"], "synthetic-private-token")
        self.assertNotIn("synthetic-private-token", str(command))
        self.gh_calls.append(command[4])
        response = self.api_responses[command[4]]
        if isinstance(response, Exception):
            raise response
        output = response if isinstance(response, bytes) else json.dumps(response).encode()
        return subprocess.CompletedProcess(command, 0, output, b"private API stderr")

    def prepare_event(self):
        Path(self.env["GITHUB_EVENT_PATH"]).write_text(json.dumps(self.event))

    def evaluate(self):
        self.prepare_event()
        with patch("plan_ci.subprocess.run", side_effect=self.fake_run):
            return plan_ci.plan(self.env, self.repo)

    def assert_build(self):
        build, reason = self.evaluate()
        self.assertTrue(build, reason)
        self.assertRegex(reason, r"^[a-z_]{1,40}$")

    def assert_skip(self):
        self.assertEqual(self.evaluate(), (False, "docs_only"))

    def test_exact_allowlist(self):
        self.assertEqual(plan_ci.DOC_PATHS, {
            b"README.md", b"AGENTS.md", b"DESIGN.md", b"PRODUCT.md", b"SPEC.md",
            b"docs/ci-cd.md", b"docs/MCP.md", b"docs/performance.md",
        })
        for name in plan_ci.DOC_PATHS:
            self.write(name.decode())
        self.commit()
        self.assert_skip()
        self.assertEqual(self.gh_calls, [])

    def test_docs_add_modify_delete(self):
        self.git("rm", "PRODUCT.md")
        baseline = self.commit()
        self.event["pull_request"]["base"]["sha"] = baseline
        self.write("PRODUCT.md", "new document\n")
        self.write("README.md")
        self.git("rm", "DESIGN.md")
        self.commit()
        self.assert_skip()

    def test_mixed_code_and_docs(self):
        self.write("README.md")
        self.write("app.go", "package changed\n")
        self.commit()
        self.assert_build()

    def test_embedded_markdown_is_code(self):
        self.write("internal/noteguide/guide.md")
        self.commit()
        self.assert_build()

    def test_unknown_paths_including_unusual_filename_bytes(self):
        for name in ("docs/other.md", "docs/mcp.md", "readme.md", ".github/workflows/ci.yml",
                     "README.md\napp.go", "docs/tab\tname.md"):
            with self.subTest(name=name):
                self.write(name)
                self.commit()
                self.assert_build()
        if os.name != "nt":
            name = os.fsdecode(b"docs/invalid-\xff.md")
            self.write(name)
            self.commit()
            self.assert_build()

    def test_docs_rename_checks_both_sides(self):
        self.git("rm", "PRODUCT.md")
        baseline = self.commit()
        self.event["pull_request"]["base"]["sha"] = baseline
        self.git("mv", "README.md", "PRODUCT.md")
        self.commit()
        self.assert_skip()

    def test_rename_from_non_allowlisted_path(self):
        self.git("rm", "README.md")
        baseline = self.commit()
        self.event["pull_request"]["base"]["sha"] = baseline
        self.git("mv", "internal/noteguide/guide.md", "README.md")
        self.commit()
        self.assert_build()

    def test_rename_to_non_allowlisted_path(self):
        self.git("mv", "README.md", "new.md")
        self.commit()
        self.assert_build()

    def test_non_docs_deletion(self):
        self.git("rm", "app.go")
        self.commit()
        self.assert_build()

    def test_submodule_changes_cannot_be_hidden_by_git_config(self):
        self.git("update-index", "--add", "--cacheinfo", f"160000,{self.base},vendor")
        baseline = self.commit(staged=True)
        self.event["pull_request"]["base"]["sha"] = baseline
        self.git("update-index", "--cacheinfo", f"160000,{baseline},vendor")
        self.commit(staged=True)
        self.git("config", "diff.ignoreSubmodules", "all")
        self.assert_build()

    def test_relative_diff_config_cannot_hide_code_outside_cwd(self):
        self.write("app.go", "changed code\n")
        self.commit()
        self.git("config", "diff.relative", "true")
        self.prepare_event()
        with patch("plan_ci.subprocess.run", side_effect=self.fake_run):
            self.assertTrue(plan_ci.plan(self.env, self.repo / "docs")[0])

    def test_executable_mode_change(self):
        self.git("update-index", "--chmod=+x", "README.md")
        self.commit(staged=True)
        self.assert_build()

    def symlink_in_index(self, name):
        blob = self.git("hash-object", "-w", "--stdin", input=b"../app.go")
        self.git("update-index", "--add", "--cacheinfo", f"120000,{blob},{name}")

    def test_regular_document_changed_to_symlink(self):
        self.symlink_in_index("README.md")
        self.commit(staged=True)
        self.assert_build()

    def test_added_document_symlink(self):
        self.git("rm", "README.md")
        baseline = self.commit()
        self.event["pull_request"]["base"]["sha"] = baseline
        self.symlink_in_index("README.md")
        self.commit(staged=True)
        self.assert_build()

    def test_modified_document_symlink(self):
        self.symlink_in_index("README.md")
        baseline = self.commit(staged=True)
        self.event["pull_request"]["base"]["sha"] = baseline
        blob = self.git("hash-object", "-w", "--stdin", input=b"../different.go")
        self.git("update-index", "--cacheinfo", f"120000,{blob},README.md")
        self.commit(staged=True)
        self.assert_build()

    def test_pr_multicommit_includes_earlier_code(self):
        self.write("app.go", "earlier code change\n")
        self.commit()
        self.write("README.md")
        self.commit()
        self.assert_build()
        self.assertEqual(self.gh_calls, [])

    def test_pr_merge_base_excludes_base_branch_changes(self):
        self.git("checkout", "-b", "feature")
        self.write("README.md")
        head = self.commit()
        self.git("checkout", "main")
        self.write("app.go", "base branch changed\n")
        advanced_base = self.commit()
        self.git("checkout", "--detach", head)
        self.env["GITHUB_SHA"] = head
        self.event["pull_request"]["base"]["sha"] = advanced_base
        self.assert_skip()
        self.assertEqual(self.gh_calls, [])

    def test_push_docs_relative_to_latest_production(self):
        self.write("README.md")
        self.commit()
        self.push()
        self.assert_skip()
        self.assertEqual(self.gh_calls, list(self.api_responses))

    def test_push_empty_diff_at_successful_production(self):
        self.push()
        self.assert_skip()

    def test_push_code_backlog_before_docs_only_event(self):
        self.write("app.go", "pending code deployment\n")
        pending = self.commit()
        self.write("README.md")
        self.commit()
        self.push()
        self.event["before"] = pending
        self.assert_build()

    def test_push_before_is_never_a_baseline(self):
        self.write("README.md")
        self.commit()
        self.push()
        self.event["before"] = "untrusted-before; secret"
        self.assert_skip()

    def test_production_ref_may_be_fully_qualified(self):
        self.push()
        self.deployments[0]["ref"] = "refs/heads/main"
        self.assert_skip()

    def test_unsafe_deployment_metadata(self):
        for key, values in {
            "id": [None, "42", True, 0, -1],
            "sha": [None, "HEAD", "a" * 39, "a" * 40 + "\n", "0" * 40],
            "ref": [None, "feature", "refs/heads/feature", self.base],
            "environment": [None, "staging", "Production"],
        }.items():
            for value in values:
                with self.subTest(key=key, value=value):
                    self.push()
                    self.deployments[0][key] = value
                    self.assert_build()

    def test_latest_failed_deployment_never_uses_older_success(self):
        self.push()
        self.deployments.append({"id": 41, "sha": self.base,
                                 "environment": "production", "ref": "main"})
        self.api_responses["repos/example/conspect/deployments/41/statuses?per_page=1"] = [{"state": "success"}]
        for state in ("failure", "error", "pending", "queued", "in_progress", "inactive", "canceled", "unknown", None):
            with self.subTest(state=state):
                self.gh_calls.clear()
                self.statuses[:] = [{"state": state}, {"state": "success"}]
                self.assert_build()
                self.assertEqual(len(self.gh_calls), 2)
                self.assertNotIn("/41/", " ".join(self.gh_calls))

    def test_missing_or_malformed_api_data(self):
        for endpoint_index in (0, 1):
            for value in ([], {}, None, [None], ["unknown"], b"not JSON", b"\xff"):
                with self.subTest(endpoint=endpoint_index, value=value):
                    self.push()
                    endpoint = list(self.api_responses)[endpoint_index]
                    self.api_responses[endpoint] = value
                    self.assert_build()

    def test_api_errors_and_timeouts(self):
        for endpoint_index in (0, 1):
            for error in (FileNotFoundError("private gh path"),
                          subprocess.CalledProcessError(1, ["gh", "private"], stderr=b"token"),
                          subprocess.TimeoutExpired(["gh", "private"], 30)):
                with self.subTest(endpoint=endpoint_index, error=type(error).__name__):
                    self.push()
                    endpoint = list(self.api_responses)[endpoint_index]
                    self.api_responses[endpoint] = error
                    self.assert_build()

    def test_missing_production_commit(self):
        self.push("a" * 40)
        self.assert_build()

    def test_production_commit_not_ancestor(self):
        self.git("checkout", "-b", "diverged")
        self.write("README.md", "other branch\n")
        unrelated = self.commit()
        self.git("checkout", "main")
        self.write("README.md")
        self.commit()
        self.push(unrelated)
        self.assert_build()

    def test_production_commit_ahead_of_head(self):
        self.write("README.md")
        future = self.commit()
        self.git("checkout", "--detach", self.base)
        self.env["GITHUB_SHA"] = self.base
        self.push(future)
        self.assert_build()

    def test_shallow_history(self):
        self.write("README.md")
        head = self.commit()
        (self.repo / ".git" / "shallow").write_text(head + "\n")
        self.assertEqual(self.evaluate(), (True, "incomplete_history"))
        self.assertEqual(self.gh_calls, [])

    def test_missing_pr_base_or_common_history(self):
        for base in ("a" * 40, "0" * 40, "HEAD", None):
            with self.subTest(base=base):
                self.event["pull_request"]["base"]["sha"] = base
                self.assert_build()
        self.git("checkout", "--orphan", "orphan")
        self.write("app.go", "unrelated root commit\n")
        unrelated = self.commit()
        self.git("checkout", "main")
        self.env["GITHUB_SHA"] = self.base
        self.event["pull_request"]["base"]["sha"] = unrelated
        self.assert_build()

    def test_dispatch_always_builds_without_api(self):
        self.write("README.md")
        self.commit()
        self.env["GITHUB_EVENT_NAME"] = "workflow_dispatch"
        self.event = {}
        self.assertEqual(self.evaluate(), (True, "manual_dispatch"))
        self.assertEqual(self.gh_calls, [])

    def test_unknown_or_malformed_context(self):
        for event in (None, [], "private metadata", {}, {"pull_request": []},
                      {"pull_request": {"base": None}}):
            with self.subTest(event=event):
                self.event = event
                self.assert_build()
        self.event = {}
        for name in ("", "release", "pull_request_target"):
            self.env["GITHUB_EVENT_NAME"] = name
            self.assert_build()

    def test_invalid_sha_or_checkout_mismatch(self):
        for value in ("HEAD", "a" * 39, "a" * 40 + "\n", "a" * 40, "0" * 40, "--help"):
            with self.subTest(value=value):
                self.env["GITHUB_SHA"] = value
                self.assert_build()
        del self.env["GITHUB_SHA"]
        self.assert_build()

    def test_malformed_push_context_and_repository(self):
        for key, value in (("GITHUB_REF", "refs/heads/feature"),
                           ("GITHUB_REPOSITORY", "owner/repo?environment=staging"),
                           ("GITHUB_REPOSITORY", "owner/repo/extra"),
                           ("GITHUB_REPOSITORY", "")):
            with self.subTest(key=key, value=value):
                original = self.env.get(key)
                self.push()
                self.env[key] = value
                self.assert_build()
                self.env[key] = original
        for key, value in (("ref", "refs/heads/other"), ("after", "a" * 40),
                           ("after", None), ("deleted", True), ("deleted", "false")):
            with self.subTest(key=key, value=value):
                self.push()
                self.event[key] = value
                self.assert_build()

    def test_git_errors_and_timeouts(self):
        for error in (FileNotFoundError("private path"),
                      subprocess.CalledProcessError(128, ["git", "private metadata"]),
                      subprocess.TimeoutExpired(["git"], 30)):
            with self.subTest(error=type(error).__name__), patch("plan_ci.subprocess.run", side_effect=error):
                self.prepare_event()
                self.assertEqual(plan_ci.plan(self.env, self.repo), (True, "planner_error"))

    def test_unexpected_diff_records_fail_closed(self):
        zero = b"0" * 40
        blob = b"a" * 40
        prefix = b":100644 100644 " + blob + b" " + blob + b" "
        for diff in (prefix + b"R100\0README.md\0PRODUCT.md\0",
                     prefix + b"T\0README.md\0", prefix + b"U\0README.md\0",
                     prefix + b"M\0README.md", b"\0", b"garbage\0README.md\0",
                     b":000000 100644 " + zero + b" " + zero + b" A\0README.md\0"):
            with self.subTest(diff=diff), patch.object(plan_ci.Planner, "git", return_value=diff):
                try:
                    build, _ = plan_ci.Planner(self.env, self.repo).docs_only(self.base, self.base)
                except plan_ci.UnsafePlan:
                    build = True
                self.assertTrue(build)

    def test_subprocess_cli_appends_outputs(self):
        self.write("README.md")
        self.commit()
        self.prepare_event()
        output = Path(self.env["GITHUB_OUTPUT"])
        output.write_text("existing=preserved\n")
        result = REAL_RUN(["python3", str(SCRIPT)], cwd=self.repo, env=self.env,
                          capture_output=True, text=True, check=True, timeout=10)
        self.assertEqual(output.read_text(), "existing=preserved\nbuild_image=false\nreason=docs_only\n")
        self.assertEqual(result.stdout, "build_image=false\nreason=docs_only\n")
        self.assertEqual(result.stderr, "")

    def test_cli_malformed_or_missing_event_outputs_build_without_leaks(self):
        for event_content in ("not JSON private-token", None):
            with self.subTest(event_content=event_content):
                event_path = Path(self.env["GITHUB_EVENT_PATH"])
                if event_content is None:
                    event_path.unlink(missing_ok=True)
                else:
                    event_path.write_text(event_content)
                result = REAL_RUN(["python3", str(SCRIPT)], cwd=self.repo, env=self.env,
                                  capture_output=True, text=True, check=True, timeout=10)
                self.assertEqual(result.stdout, "build_image=true\nreason=planner_error\n")
                self.assertEqual(result.stderr, "")
                self.assertTrue(Path(self.env["GITHUB_OUTPUT"]).read_text().endswith(result.stdout))

    def test_unexpected_planner_exception_still_writes_full_outputs(self):
        with patch.dict(os.environ, self.env, clear=True), \
                patch("plan_ci.plan", side_effect=RuntimeError("private-token /secret/path")), \
                redirect_stdout(io.StringIO()) as stdout, redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(plan_ci.main(), 0)
        self.assertEqual(Path(self.env["GITHUB_OUTPUT"]).read_text(), "build_image=true\nreason=planner_error\n")
        self.assertNotIn("private", stdout.getvalue() + stderr.getvalue())

    def test_partial_output_failure_overrides_skip(self):
        original = plan_ci.write_outputs
        calls = []

        def partial_failure(build, reason):
            calls.append((build, reason))
            original(build, reason)
            if len(calls) == 1:
                raise OSError("private output path")

        with patch.dict(os.environ, self.env, clear=True), \
                patch("plan_ci.plan", return_value=(False, "docs_only")), \
                patch("plan_ci.write_outputs", side_effect=partial_failure), redirect_stdout(io.StringIO()):
            self.assertEqual(plan_ci.main(), 0)
        self.assertEqual(calls, [(False, "docs_only"), (True, "output_error")])
        self.assertTrue(Path(self.env["GITHUB_OUTPUT"]).read_text().endswith("build_image=true\nreason=output_error\n"))

    def test_unavailable_output_channel_fails_not_silent_skip(self):
        self.env["GITHUB_OUTPUT"] = str(self.root / "missing" / "output")
        with patch.dict(os.environ, self.env, clear=True), \
                patch("plan_ci.plan", return_value=(False, "docs_only")), \
                redirect_stdout(io.StringIO()) as stdout, redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(plan_ci.main(), 1)
        self.assertEqual(stdout.getvalue(), "build_image=true\nreason=output_error\n")
        self.assertNotIn(str(self.root), stdout.getvalue() + stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
