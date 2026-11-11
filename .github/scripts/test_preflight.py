"""Fast stdlib-only checks: disposable local Git repos, mocked gofmt, no services.

Run directly with: python3 -B .github/scripts/test_preflight.py
"""

import contextlib
import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import preflight


SECRET = "SYNTHETIC_SECRET_MUST_NOT_APPEAR"
GOOD_GO = b"package example\n\nvar Answer = 42\n"
BAD_GO = b"package example;var Answer=42\n"
REAL_RUN = preflight.run
REAL_SUBPROCESS_RUN = subprocess.run


class RepositoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="test-preflight-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.sandbox = Path(cls.temp.name).resolve()
        checkout = Path(__file__).resolve().parents[2]
        if cls.sandbox.is_relative_to(checkout):
            raise RuntimeError("Test repositories must be outside the checkout")
        # Do not inherit alternate indexes, worktrees, hooks, or user Git config.
        env = {key: value for key, value in os.environ.items()
               if not key.startswith("GIT_")}
        env.update({
            "HOME": str(cls.sandbox),
            "XDG_CONFIG_HOME": str(cls.sandbox),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_ALLOW_PROTOCOL": "file",
            "LC_ALL": "C",
        })
        environment = patch.dict(os.environ, env, clear=True)
        environment.start()
        cls.addClassCleanup(environment.stop)
        cls.seed = cls.sandbox / "seed"
        cls.seed.mkdir()
        cls.git_at(cls.seed, "init", "--quiet", "--template=", "--initial-branch=main")
        for key, value in {
            "user.name": "Preflight Test",
            "user.email": "preflight@example.invalid",
            "commit.gpgSign": "false",
            "core.hooksPath": str(cls.sandbox / "no-hooks"),
            "core.autocrlf": "false",
            "core.fsmonitor": "false",
            "core.quotePath": "false",
            "branch.main.remote": ".",
            "branch.main.merge": "refs/heads/baseline",
        }.items():
            cls.git_at(cls.seed, "config", key, value)
        for name, data in {
            ".gitignore": b"ignored/\n*.secret.py\n",
            "tracked.py": b"answer = 42\n",
            "tracked.json": b'{"answer": 42}\n',
            "tracked.go": GOOD_GO,
            "old name.py": b"old = True\n",
            "delete.py": b"delete = True\n",
            "README.md": b"Fixture, not application source.\n",
        }.items():
            (cls.seed / name).write_bytes(data)
        cls.git_at(cls.seed, "add", "--all")
        cls.git_at(cls.seed, "commit", "--quiet", "-m", "Baseline")
        cls.git_at(cls.seed, "branch", "baseline")

    @staticmethod
    def git_at(root, *args, data=None):
        result = REAL_SUBPROCESS_RUN(
            ["git", "--no-pager", "--no-optional-locks", *args],
            cwd=root, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=5, check=False,
        )
        if result.returncode:
            raise AssertionError("Fixture Git command failed: " + repr(args)
                                 + "\n" + result.stderr.decode("utf-8", "replace"))
        return result.stdout

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="case-", dir=self.sandbox)
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name) / "repo"
        shutil.copytree(self.seed, self.root)
        self.commands = []
        self.gofmt_inputs = []

    def git(self, *args, data=None):
        return self.git_at(self.root, *args, data=data)

    def write(self, name, data):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def commit(self):
        self.git("add", "--all")
        self.git("commit", "--quiet", "-m", "Outgoing changes")

    def local_run(self, args, cwd, data=None):
        self.commands.append((args, data))
        self.assertTrue(Path(cwd).is_relative_to(self.sandbox))
        if args == ["gofmt"]:
            self.gofmt_inputs.append(data)
            if data in (GOOD_GO, BAD_GO):
                return subprocess.CompletedProcess(args, 0, GOOD_GO, b"")
            return subprocess.CompletedProcess(args, 2, b"", SECRET.encode())
        # Fail before execution if preflight ever starts builds or network tools.
        self.assertEqual(args[:3], ["git", "--no-pager", "--no-optional-locks"])
        arguments = args[3:]
        if arguments[:2] == ["-c", "diff.autoRefreshIndex=false"]:
            arguments = arguments[2:]
        self.assertIn(arguments[0], {"rev-parse", "diff", "ls-files", "cat-file"})
        return REAL_RUN(args, cwd, data)

    def evaluate(self, argv=()):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(preflight, "run", side_effect=self.local_run), \
                patch.object(Path, "cwd", return_value=self.root), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = preflight.main(list(argv))
        self.assertEqual(stderr.getvalue(), "")
        self.assertNotIn(SECRET, stdout.getvalue())
        return status, stdout.getvalue()

    def assert_check(self, output, status, check, name, version):
        self.assertIn(f"{status} [{check}] {ascii(name)} ({version})", output)

    def snapshot(self):
        # Include the index, refs, objects, config, reflogs and ignored files.
        files = {}
        for path in self.root.rglob("*"):
            name = path.relative_to(self.root).as_posix()
            mode = path.lstat().st_mode
            if path.is_symlink():
                files[name] = (mode, os.readlink(path))
            elif path.is_file():
                files[name] = (mode, hashlib.sha256(path.read_bytes()).digest())
            else:
                files[name] = (mode, None)
        return files

    def assert_snapshot_unchanged(self, before):
        after = self.snapshot()
        changed = sorted(name for name in before.keys() | after.keys()
                         if before.get(name) != after.get(name))
        self.assertEqual(changed, [], "Preflight changed repository files")

    def test_clean_upstream_does_not_validate_unchanged_sources_or_write_index(self):
        # Copied index stat entries are stale, just as after touching a clean file.
        before_status = self.git("status", "--porcelain=v1", "-z")
        before = self.snapshot()
        status, output = self.evaluate()
        self.assertEqual(self.git("status", "--porcelain=v1", "-z"), before_status)
        self.assertEqual(status, 0)
        self.assertEqual(output.count("PASS [git diff --check]"), 3)
        self.assertNotIn("NOTE:", output)
        self.assertNotIn("[Python AST]", output)
        self.assertNotIn("[JSON]", output)
        self.assertEqual(self.gofmt_inputs, [])
        self.assert_snapshot_unchanged(before)

    def test_outgoing_index_worktree_and_untracked_are_all_checked_read_only(self):
        self.write("tracked.json", b'{"value": ' + SECRET.encode() + b"}\n")
        self.write("tracked.go", BAD_GO)
        self.commit()
        self.write("tracked.py", b"def " + SECRET.encode() + b"(\n")
        self.git("add", "--", "tracked.py")
        self.write("tracked.py", b"corrected = True\n")
        self.write("tracked.json", b'{"corrected": true}\n')
        self.write("tracked.go", GOOD_GO)
        self.write("untracked.py", b"if " + SECRET.encode() + b"\n")
        self.write("ignored/secret.json", SECRET.encode())
        before_status = self.git("status", "--porcelain=v1", "-z", "--untracked-files=all")
        before = self.snapshot()
        status, output = self.evaluate()
        self.assertEqual(status, 1)
        for verdict, check, name, version in [
            ("FAIL", "JSON", "tracked.json", "HEAD"),
            ("FAIL", "Go formatting", "tracked.go", "HEAD"),
            ("FAIL", "Python AST", "tracked.py", "index"),
            ("PASS", "Python AST", "tracked.py", "worktree"),
            ("PASS", "JSON", "tracked.json", "worktree"),
            ("PASS", "Go formatting", "tracked.go", "worktree"),
            ("FAIL", "Python AST", "untracked.py", "worktree"),
        ]:
            self.assert_check(output, verdict, check, name, version)
        self.assertEqual(self.gofmt_inputs, [BAD_GO, GOOD_GO])
        self.assert_snapshot_unchanged(before)
        self.assertEqual(self.git("status", "--porcelain=v1", "-z", "--untracked-files=all"),
                         before_status)

    def test_staged_go_and_json_are_not_replaced_by_corrected_worktree(self):
        self.write("tracked.json", b'{"broken":}\n')
        self.write("tracked.go", BAD_GO)
        self.git("add", "--", "tracked.json", "tracked.go")
        self.write("tracked.json", b"{}\n")
        self.write("tracked.go", GOOD_GO)
        status, output = self.evaluate()
        self.assertEqual(status, 1)
        for check, name in [("JSON", "tracked.json"), ("Go formatting", "tracked.go")]:
            self.assert_check(output, "FAIL", check, name, "index")
            self.assert_check(output, "PASS", check, name, "worktree")

    def test_earlier_outgoing_commit_is_checked_against_upstream_not_head_parent(self):
        self.write("tracked.py", b"def broken(\n")
        self.commit()
        self.write("README.md", b"Later documentation-only commit.\n")
        self.commit()
        self.write("tracked.py", b"corrected = True\n")
        status, output = self.evaluate()
        self.assertEqual(status, 1)
        self.assert_check(output, "FAIL", "Python AST", "tracked.py", "HEAD")
        self.assert_check(output, "PASS", "Python AST", "tracked.py", "worktree")

    def test_identical_go_content_is_formatted_once_but_each_job_is_reported(self):
        self.write("tracked.go", BAD_GO)
        self.git("add", "--", "tracked.go")
        self.write("duplicate.go", BAD_GO)
        status, output = self.evaluate()
        self.assertEqual(status, 1)
        self.assert_check(output, "FAIL", "Go formatting", "tracked.go", "index")
        self.assert_check(output, "FAIL", "Go formatting", "duplicate.go", "worktree")
        self.assertEqual(self.gofmt_inputs, [BAD_GO])

    def test_untracked_sources_checked_but_ignored_and_other_files_not_opened(self):
        self.write("new.py", b"valid = True\n")
        self.write("new.json", b"{broken " + SECRET.encode() + b"}\n")
        self.write("new.go", BAD_GO)
        excluded = {
            self.write("ignored/secret.py", SECRET.encode()),
            self.write("ignored/secret.json", SECRET.encode()),
            self.write("ignored/secret.go", SECRET.encode()),
            self.write("password.secret.py", SECRET.encode()),
            self.write("notes.txt", SECRET.encode()),
        }
        read_bytes = Path.read_bytes

        def guarded_read(path):
            self.assertNotIn(path, excluded, "Ignored/non-source content was opened")
            return read_bytes(path)

        with patch.object(Path, "read_bytes", guarded_read):
            status, output = self.evaluate()
        self.assertEqual(status, 1)
        self.assert_check(output, "PASS", "Python AST", "new.py", "worktree")
        self.assert_check(output, "FAIL", "JSON", "new.json", "worktree")
        self.assert_check(output, "FAIL", "Go formatting", "new.go", "worktree")
        for path in excluded:
            self.assertNotIn(ascii(str(path.relative_to(self.root))), output)

    def test_nul_delimited_rename_and_unusual_paths(self):
        names = ["space name.py", "tab\tname.json", "line\nname.py", "-option.py",
                 "unicode-\u044f.py", "quote'\\name.py"]
        if os.name == "nt":
            names = [name for name in names if not any(c in name for c in '\t\n\\')]
        for name in names:
            self.write(name, b"{}\n" if name.endswith(".json") else b"value = 1\n")
        self.git("add", "--all")
        new_name = "renamed\nname.py" if os.name != "nt" else "renamed name.py"
        self.git("mv", "--", "old name.py", new_name)
        status, output = self.evaluate()
        self.assertEqual(status, 0)
        self.assert_check(output, "PASS", "Python AST", new_name, "index")
        for name in names:
            check = "JSON" if name.endswith(".json") else "Python AST"
            self.assert_check(output, "PASS", check, name, "index")
        self.assertNotIn("'old name.py'", output)
        self.assertNotIn("renamed\nname.py", output)
        batches = [data for args, data in self.commands if args[3:4] == ["cat-file"]]
        self.assertEqual(len(batches), 1)
        for oid in batches[0].splitlines():
            self.assertIn(len(oid), (40, 64))
            self.assertTrue(all(char in b"0123456789abcdef" for char in oid))

    def test_untracked_newline_path_and_nul_source_are_not_truncated(self):
        name = "untracked\nsource.py" if os.name != "nt" else "untracked source.py"
        self.write(name, b"answer = 1\x00" + SECRET.encode())
        status, output = self.evaluate()
        self.assertEqual(status, 1)
        self.assert_check(output, "FAIL", "Python AST", name, "worktree")

    def test_deletions_at_all_three_layers_do_not_try_to_open_deleted_paths(self):
        self.git("rm", "--", "delete.py")
        self.commit()
        self.git("rm", "--", "old name.py")
        (self.root / "tracked.py").unlink()
        status, output = self.evaluate()
        self.assertEqual(status, 0)
        self.assertNotIn("[Python AST]", output)

    def test_whitespace_is_checked_at_each_layer_without_echoing_source(self):
        self.write("README.md", SECRET.encode() + b"  \n")
        self.commit()
        self.write("tracked.py", b"value = 1  \n")
        self.git("add", "--", "tracked.py")
        self.write("tracked.py", b"value = 1\n")
        self.write("tracked.json", b"{}  \n")
        status, output = self.evaluate()
        self.assertEqual(status, 1)
        for version in ("HEAD", "index", "worktree"):
            self.assertIn(f"FAIL [git diff --check] {version}", output)
        self.assert_check(output, "PASS", "Python AST", "tracked.py", "index")
        self.assert_check(output, "PASS", "JSON", "tracked.json", "worktree")

    def test_no_upstream_note_and_explicit_base_override(self):
        base = self.git("rev-parse", "HEAD").strip().decode("ascii")
        self.git("config", "--remove-section", "branch.main")
        self.write("tracked.json", b"{broken}\n")
        self.commit()
        status, output = self.evaluate()
        self.assertEqual(status, 0)
        self.assertIn("NOTE: No local upstream commit", output)
        self.assertIn("--base REF", output)
        self.assertNotIn("[JSON]", output)
        status, output = self.evaluate(["--base", base])
        self.assertEqual(status, 1)
        self.assertNotIn("NOTE:", output)
        self.assert_check(output, "FAIL", "JSON", "tracked.json", "HEAD")

    def test_explicit_base_can_override_existing_upstream(self):
        self.write("tracked.json", b"{broken}\n")
        self.commit()
        status, output = self.evaluate(["--base", "HEAD"])
        self.assertEqual(status, 0)
        self.assertNotIn("[JSON]", output)
        self.assertNotIn("NOTE:", output)

    def test_invalid_base_fails_without_falling_back_or_leaking_git_errors(self):
        status, output = self.evaluate(["--base=--" + SECRET])
        self.assertEqual(status, 1)
        self.assertIn("Invalid --base", output)
        self.assertNotIn("NOTE:", output)
        self.assertEqual(len(self.commands), 2)
        self.assertIn("--end-of-options", self.commands[-1][0])

    def test_git_external_diff_and_textconv_are_not_executed(self):
        self.write(".gitattributes", b"*.py diff=private\n")
        self.git("config", "diff.external", "must-not-execute-" + SECRET)
        self.git("config", "diff.private.textconv", "must-not-execute-" + SECRET)
        self.write("tracked.py", b"value = 2\n")
        self.git("add", "--", "tracked.py")
        self.write("tracked.py", b"value = 3\n")
        status, output = self.evaluate()
        self.assertEqual(status, 0)
        for args, _ in self.commands:
            if args[3:4] == ["diff"]:
                self.assertIn("--no-ext-diff", args)
                self.assertIn("--no-textconv", args)

    def test_symlinks_are_not_followed_in_index_or_worktree(self):
        target = self.root.parent / "outside.py"
        target.write_bytes(SECRET.encode())
        try:
            (self.root / "link.py").symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("Symlinks are unavailable")
        self.git("add", "--", "link.py")
        self.write("untracked.json", b"{}\n")
        (self.root / "outside.json").symlink_to(target)
        read_bytes = Path.read_bytes

        def guarded_read(path):
            self.assertNotEqual(path, target)
            self.assertNotIn(path.name, {"link.py", "outside.json"})
            return read_bytes(path)

        with patch.object(Path, "read_bytes", guarded_read):
            status, output = self.evaluate()
        self.assertEqual(status, 0)
        self.assert_check(output, "SKIP", "Python AST", "link.py", "index")
        self.assert_check(output, "SKIP", "JSON", "outside.json", "worktree")

    def test_unreadable_worktree_file_fails_without_os_error_contents(self):
        target = self.write("unreadable.py", b"value = 1\n")
        read_bytes = Path.read_bytes

        def guarded_read(path):
            if path == target:
                raise PermissionError(SECRET)
            return read_bytes(path)

        with patch.object(Path, "read_bytes", guarded_read):
            status, output = self.evaluate()
        self.assertEqual(status, 1)
        self.assertIn("unreadable or unsafe path", output)

    def test_missing_blob_is_a_controlled_failure_not_a_traceback(self):
        oid = self.git("hash-object", "-w", "--stdin", data=b"value = 99\n").strip().decode("ascii")
        self.git("update-index", "--add", "--cacheinfo", "100644," + oid + ",missing.py")
        (self.root / ".git" / "objects" / oid[:2] / oid[2:]).unlink()
        status, output = self.evaluate()
        self.assertEqual(status, 1)
        self.assertIn("FAIL", output)
        self.assertNotIn("Traceback", output)

    @unittest.skipIf(os.name == "nt", "Windows filenames cannot contain newlines")
    def test_repository_root_with_trailing_newline_is_preserved(self):
        renamed = self.root.with_name("repo with space\n")
        self.root.rename(renamed)
        self.root = renamed
        self.write("new.py", b"value = 1\n")
        status, output = self.evaluate()
        self.assertEqual(status, 0, output)
        self.assert_check(output, "PASS", "Python AST", "new.py", "worktree")


class UnitTests(unittest.TestCase):
    def capture_main(self, error=None, result=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(preflight, "run", side_effect=error, return_value=result), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = preflight.main([])
        self.assertEqual(status, 1)
        self.assertEqual(stderr.getvalue(), "")
        self.assertNotIn(SECRET, stdout.getvalue())
        self.assertIn("FAIL [preflight]", stdout.getvalue())
        return stdout.getvalue()

    def test_run_has_bounded_timeout_pipes_no_shell_and_noninteractive_stdin(self):
        root = Path("fixture")
        with patch.object(preflight.subprocess, "run") as run:
            preflight.run(["git", "status"], root)
            options = run.call_args.kwargs
            self.assertEqual(options["cwd"], root)
            self.assertEqual(options["timeout"], 15)
            self.assertEqual(options["stdin"], subprocess.DEVNULL)
            self.assertEqual(options["stdout"], subprocess.PIPE)
            self.assertEqual(options["stderr"], subprocess.PIPE)
            self.assertFalse(options["check"])
            self.assertFalse(options.get("shell", False))
            preflight.run(["gofmt"], root, GOOD_GO)
            self.assertEqual(run.call_args.kwargs["input"], GOOD_GO)
            self.assertIsNone(run.call_args.kwargs["stdin"])

    def test_subprocess_exceptions_fail_without_stdout_stderr_or_path_leaks(self):
        errors = [
            FileNotFoundError(SECRET),
            PermissionError(SECRET),
            subprocess.TimeoutExpired([SECRET], 15, output=SECRET.encode(), stderr=SECRET.encode()),
            subprocess.CalledProcessError(7, [SECRET], output=SECRET.encode(), stderr=SECRET.encode()),
        ]
        for error in errors:
            with self.subTest(error=type(error).__name__):
                output = self.capture_main(error=error)
                self.assertIn("diagnostics withheld", output)

    def test_nonzero_git_exit_is_a_sanitized_controlled_failure(self):
        output = self.capture_main(result=subprocess.CompletedProcess(
            ["git"], 128, SECRET.encode(), SECRET.encode()))
        self.assertIn("Git inspection failed", output)

    def test_parsers_reject_bad_bytes_without_echoing_source(self):
        cases = [
            (".py", b"def " + SECRET.encode() + b"(\n"),
            (".py", b"value = 1\x00" + SECRET.encode()),
            (".py", b"\xff\n"),
            (".json", b'{"' + SECRET.encode() + b'":}\n'),
            (".json", b"\xff"),
        ]
        with patch.object(preflight, "run") as run:
            for suffix, data in cases:
                with self.subTest(suffix=suffix, data=data):
                    self.assertEqual(preflight.validate(Path("fixture"), suffix, data),
                                     "invalid syntax (diagnostics withheld)")
            self.assertIsNone(preflight.validate(Path("fixture"), ".py", b"value = 42\n"))
            self.assertIsNone(preflight.validate(Path("fixture"), ".json", b"{}\n"))
            run.assert_not_called()

    def test_gofmt_missing_rejected_and_changed_output(self):
        cases = [
            (FileNotFoundError(SECRET), None, "gofmt missing"),
            (None, subprocess.CompletedProcess(["gofmt"], 2, SECRET.encode(), SECRET.encode()),
             "gofmt rejected input"),
            (None, subprocess.CompletedProcess(["gofmt"], 0, GOOD_GO, b""),
             "not gofmt-formatted"),
        ]
        for error, result, expected in cases:
            with self.subTest(expected=expected), \
                    patch.object(preflight, "run", side_effect=error, return_value=result) as run:
                message = preflight.validate(Path("fixture"), ".go", BAD_GO)
                self.assertIn(expected, message)
                self.assertNotIn(SECRET, message)
                run.assert_called_once_with(["gofmt"], Path("fixture"), BAD_GO)

    def test_gofmt_timeout_and_os_errors_reach_main_safely(self):
        for error in [subprocess.TimeoutExpired(["gofmt", SECRET], 15, stderr=SECRET.encode()),
                      PermissionError(SECRET)]:
            with self.subTest(error=type(error).__name__), \
                    patch.object(preflight, "checked_git", return_value=os.fsencode(Path.cwd())), \
                    patch.object(preflight, "preflight", side_effect=lambda *args: preflight.validate(
                        Path("fixture"), ".go", BAD_GO)):
                self.capture_main(error=error)

    def test_batch_blob_reads_preserve_nul_and_newline_bytes(self):
        first, second = b"a" * 40, b"b" * 40
        contents = {first: b"a\x00b\nc", second: b"{}\n"}
        response = b"".join(oid + b" blob " + str(len(contents[oid])).encode()
                            + b"\n" + contents[oid] + b"\n" for oid in (first, second))
        with patch.object(preflight, "run", return_value=subprocess.CompletedProcess(
                ["git"], 0, response, b"")) as run:
            self.assertEqual(preflight.blobs(Path("fixture"), {second, first}), contents)
            self.assertEqual(run.call_args.args[2], first + b"\n" + second + b"\n")
        with patch.object(preflight, "run") as run:
            self.assertEqual(preflight.blobs(Path("fixture"), set()), {})
            run.assert_not_called()

    def test_batch_blob_nonzero_and_wrong_object_type_are_controlled(self):
        oid = b"a" * 40
        for result in [
            subprocess.CompletedProcess(["git"], 128, SECRET.encode(), SECRET.encode()),
            subprocess.CompletedProcess(["git"], 0, oid + b" tree 0\n\n", SECRET.encode()),
        ]:
            with self.subTest(returncode=result.returncode), \
                    patch.object(preflight, "run", return_value=result):
                with self.assertRaises(preflight.PreflightError) as error:
                    preflight.blobs(Path("fixture"), {oid})
                self.assertNotIn(SECRET, str(error.exception))


if __name__ == "__main__":
    unittest.main()
