"""Release safety regressions: synthetic files, mocked Docker and full snapshots only.

Ownership is simulated so these tests run without root. Permissions, symlinks,
atomic writes and the operations flock use real files inside a temporary tree.
Safety regressions are deliberately not marked expectedFailure.
"""

import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import operations
import release
from operations import OperationError


REVISION = "a" * 40
OLD_IMAGE = "ghcr.io/awak3r/c0nspect@sha256:" + "b" * 64
IMAGE = "ghcr.io/awak3r/c0nspect@sha256:" + "c" * 64
TOKEN = "synthetic-registry-token-never-log"
SECRET = "ab" * 32
ENV = (
    "# Preserve this configuration and its secret verbatim.\n"
    f"APP_SECRET={SECRET}\n"
    "OWNER_PASSWORD='synthetic password with spaces'\n"
    f"CONSPECT_IMAGE={OLD_IMAGE}\n"
    "APP_BASE_URL=https://notes.example.com\n"
)


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="conspect-release-test-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / "opt/conspect"
        self.source = self.root / ".releases" / f"{REVISION}-1234-2"
        (self.root / "deploy").mkdir(parents=True, mode=0o750)
        (self.source / "deploy").mkdir(parents=True, mode=0o750)
        self.env = self.root / ".env"
        self.env.write_text(ENV, encoding="utf-8")
        self.env.chmod(0o600)
        self.old_files = {
            "compose.yaml": "# installed compose\nservices: {}\n",
            "deploy/compose.nginx.yaml": "# installed overlay\nservices: {}\n",
            "deploy/operations.py": "# installed operations\n",
        }
        self.new_files = {
            "compose.yaml": "# incoming compose\nservices: {}\n",
            "deploy/compose.nginx.yaml": "# incoming overlay\nservices: {}\n",
            "deploy/operations.py": "# incoming operations\n",
        }
        for directory, files in ((self.root, self.old_files), (self.source, self.new_files)):
            for relative, content in files.items():
                path = directory / relative
                path.write_text(content, encoding="utf-8")
                path.chmod(0o640)
        self.backup = self.root / "backups/conspect-20261110T090000.000000Z"
        self.events = []
        self.commands = []
        self.failures = set()
        self.app_env = {"APP_BASE_URL": "https://notes.example.com", "MCP_ENABLED": "true"}
        self.locked = False
        self.on_lock = None
        self.app_state = "running"
        self.active_image = OLD_IMAGE
        self.registry_directories = []
        self.owners = {}
        self.stdout = io.StringIO()
        self.stderr = io.StringIO()
        self.enter(contextlib.redirect_stdout(self.stdout))
        self.enter(contextlib.redirect_stderr(self.stderr))
        self.enter(patch.dict(os.environ, {"PATH": os.defpath}, clear=True))
        previous_umask = os.umask(0o077)
        self.addCleanup(os.umask, previous_umask)

        # The fixture represents root-owned /opt/conspect, not world-writable /tmp.
        # Keep real type/mode bits for every fixture entry, including symlinks.
        real_stat = Path.stat
        external_parents = set(self.base.parents)

        def owned_stat(path, *, follow_symlinks=True):
            info = list(real_stat(path, follow_symlinks=follow_symlinks))
            if path == self.base or self.base in path.parents:
                info[4] = self.owners.get(path, 0)
            elif path in external_parents:
                info[4] = 0
                info[0] &= ~0o022
            return os.stat_result(info)

        self.enter(patch.object(Path, "stat", owned_stat))
        self.enter(patch.object(release.os, "geteuid", return_value=0))
        self.enter(patch.object(operations, "ROOT", self.root))
        # Fail closed if an accidental unmocked subprocess/Docker path is added.
        self.enter(patch.object(subprocess, "run", side_effect=AssertionError("Unexpected real subprocess")))
        self.enter(patch.object(operations, "run_command", side_effect=AssertionError("Unexpected real Docker")))
        self.compose_check = self.enter(patch.object(release, "check_compose"))
        self.compose = Mock()
        self.compose.image = OLD_IMAGE
        self.compose.env_path = self.env
        self.compose.preflight.side_effect = lambda **kwargs: self.event("preflight")
        self.compose.states.side_effect = lambda: {"app": self.app_state}
        self.compose_factory = self.enter(patch.object(release, "Compose", return_value=self.compose))
        self.snapshot = self.enter(patch.object(release, "create_backup", side_effect=self.fake_backup))
        self.docker = self.enter(patch.object(release, "run_command", side_effect=self.fake_docker))
        self.enter(patch.object(release, "operation_lock", side_effect=self.operation_lock))
        self.mcp_check = self.enter(patch.object(release, "check_mcp", side_effect=lambda url: self.event("mcp-check")))
        self.real_atomic_write = release.atomic_write
        self.writer = self.enter(patch.object(release, "atomic_write", side_effect=self.record_write))

    def enter(self, manager):
        value = manager.__enter__()
        self.addCleanup(manager.__exit__, None, None, None)
        return value

    def event(self, name):
        self.assertTrue(self.locked, f"{name} must run under the operations lock")
        self.events.append(name)
        if name in self.failures:
            if name.startswith("state-"):
                raise OSError("injected state-file disk failure")
            raise OperationError("injected " + name + " failure")

    @contextlib.contextmanager
    def operation_lock(self):
        self.assertEqual(operations.ROOT, self.root)
        with operations.operation_lock():
            self.locked = True
            self.events.append("lock")
            try:
                if self.on_lock:
                    self.on_lock()
                yield
            finally:
                self.events.append("unlock")
                self.locked = False

    def fake_backup(self, compose, output):
        self.assertIs(compose, self.compose)
        self.assertEqual(output, self.root / "backups")
        self.event("backup")
        self.app_state = "exited"
        self.event("backup-stop")
        try:
            self.event("snapshot")
            self.backup.mkdir(parents=True, mode=0o700)
            (self.backup / "config.env").write_bytes(self.env.read_bytes())
            # A full snapshot is mandatory; orchestration must not substitute an
            # env-only backup. Actual pg_dump/tar validation is tested elsewhere.
            for name in ("database.dump", "uploads.tar.gz", "compose.resolved.json", "manifest.json"):
                (self.backup / name).write_bytes(b"synthetic snapshot, not production data")
        finally:
            self.app_state = "running"
            self.event("backup-resume")
        return self.backup

    def fake_docker(self, command, **kwargs):
        self.commands.append((list(command), dict(kwargs), dict(os.environ)))
        self.assertNotIn(TOKEN, " ".join(command))
        if command[:2] == ["docker", "--config"]:
            directory = Path(command[2])
            self.assertTrue(directory.is_dir())
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            if directory not in self.registry_directories:
                self.registry_directories.append(directory)
            if command[3] == "login":
                self.assertEqual(command[4:], ["ghcr.io", "--username", "Awak3r", "--password-stdin"])
                self.assertEqual(kwargs["stdin"].read(), (TOKEN + "\n").encode())
                (directory / "config.json").write_text(TOKEN, encoding="utf-8")
                self.event("login")
            else:
                self.assertEqual(command[3:], ["pull", "--platform", "linux/amd64", IMAGE])
                self.event("pull")
            return ""
        self.assertEqual(command[:2], ["docker", "compose"])
        self.assertEqual(command[command.index("--project-directory") + 1], str(self.root))
        self.assertEqual(command[command.index("--project-name") + 1], "conspect")
        self.assertEqual(command[command.index("--env-file") + 1], str(self.env))
        if command[-3:] == ["config", "--format", "json"]:
            self.assertIn(str(self.source / "compose.yaml"), command)
            self.assertEqual(os.environ.get("CONSPECT_IMAGE"), IMAGE)
            self.assert_installed_files(self.old_files)
            self.assertEqual(self.env.read_text(encoding="utf-8"), ENV)
            self.event("source-config")
            return json.dumps({"services": {"app": {"environment": self.app_env}}})
        elif command[-2:] == ["config", "--quiet"]:
            self.event("live-config")
        elif "up" in command:
            self.assertEqual(command[len(release.compose_command(self.root)):], [
                "up", "--detach", "--no-deps", "--no-build", "--pull", "never",
                "--wait", "--wait-timeout", "180", "app",
            ])
            self.assertEqual(kwargs, {"timeout": 240})
            self.assertEqual(self.env.read_text(encoding="utf-8"), release.replace_image(ENV, IMAGE))
            # A failed health wait can happen after migrations and container start.
            self.app_state = "running"
            self.active_image = IMAGE
            self.event("up")
        elif "stop" in command:
            self.assertEqual(command[len(release.compose_command(self.root)):], ["stop", "--timeout", "30", "app"])
            self.assertEqual(kwargs, {"timeout": 60})
            self.event("stop")
            self.app_state = "exited"
        else:
            self.fail(f"Unexpected Docker call: {command}")
        return ""

    def record_write(self, path, content, mode=0o600):
        if path.name == ".release.json":
            self.event("state-" + json.loads(content)["status"])
        else:
            self.event("write-" + str(path.relative_to(self.root)))
        return self.real_atomic_write(path, content, mode)

    def invoke(self, **overrides):
        arguments = dict(source=self.source, root=self.root, image=IMAGE,
                         username="Awak3r", revision=REVISION, token=TOKEN)
        arguments.update(overrides)
        return release.release(**arguments)

    def assert_installed_files(self, expected):
        for relative, content in expected.items():
            self.assertEqual((self.root / relative).read_text(encoding="utf-8"), content, relative)

    def assert_not_activated(self):
        self.assert_installed_files(self.old_files)
        self.assertEqual(self.env.read_text(encoding="utf-8"), ENV)
        self.assertFalse((self.root / ".release.json").exists())
        self.assertNotIn("up", self.events)
        self.assertEqual(self.app_state, "running")

    def test_success_pulls_validates_snapshots_then_activates_app_under_one_lock(self):
        self.invoke()
        self.assertEqual(self.events[:9], [
            "lock", "preflight", "login", "pull", "source-config", "backup",
            "backup-stop", "snapshot", "backup-resume",
        ])
        self.assertLess(self.events.index("backup-resume"), self.events.index("write-compose.yaml"))
        self.assertLess(self.events.index("live-config"), self.events.index("up"))
        self.assertEqual(self.events[-4:], ["up", "mcp-check", "state-healthy", "unlock"])
        self.mcp_check.assert_called_once_with("https://notes.example.com")
        self.compose_check.assert_called_once_with()
        self.compose_factory.assert_called_once_with(nginx=True)
        self.compose.preflight.assert_called_once_with(backup=True)
        self.snapshot.assert_called_once_with(self.compose, self.root / "backups")
        self.assert_installed_files(self.new_files)
        self.assertEqual(self.app_state, "running")
        self.assertEqual(self.active_image, IMAGE)
        self.assertEqual(self.env.read_text(encoding="utf-8"), release.replace_image(ENV, IMAGE))
        self.assertEqual(self.env.stat().st_mode & 0o777, 0o600)
        marker = self.root / ".release.json"
        state = json.loads(marker.read_text(encoding="utf-8"))
        self.assertEqual({key: state[key] for key in ("revision", "image", "previous_image", "backup", "status")}, {
            "revision": REVISION, "image": IMAGE, "previous_image": OLD_IMAGE,
            "backup": str(self.backup), "status": "healthy",
        })
        self.assertTrue(state["updated_at"])
        self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.backup / "config.env").read_text(encoding="utf-8"), ENV)
        for relative, original in self.old_files.items():
            saved = self.backup / "deployment" / relative
            self.assertEqual(saved.read_text(encoding="utf-8"), original)
            self.assertEqual(saved.stat().st_mode & 0o777, 0o640)
        self.assertEqual((self.backup / "deployment").stat().st_mode & 0o777, 0o700)
        for path in self.registry_directories:
            self.assertFalse(path.exists())
        for value in (TOKEN, SECRET):
            self.assertNotIn(value, self.stdout.getvalue() + self.stderr.getvalue() + marker.read_text())

    def test_real_operations_lock_prevents_competing_backup_during_replacement(self):
        original_event = self.event

        def contend(name):
            original_event(name)
            with self.assertRaises(OperationError):
                with operations.operation_lock():
                    self.fail("A second operation acquired the release lock during " + name)

        with patch.object(self, "event", side_effect=contend):
            self.invoke()
        # The same lock must also be released on completion.
        with operations.operation_lock():
            pass

    def test_existing_operation_lock_blocks_pull_backup_and_activation(self):
        with operations.operation_lock(), self.assertRaises(OperationError):
            self.invoke()
        self.docker.assert_not_called()
        self.snapshot.assert_not_called()
        self.assert_not_activated()

    def test_pull_failure_does_not_take_snapshot_or_mutate_installation(self):
        self.failures.add("pull")
        with self.assertRaises(OperationError):
            self.invoke()
        self.snapshot.assert_not_called()
        self.assert_not_activated()
        self.assertTrue(self.registry_directories)
        self.assertTrue(all(not path.exists() for path in self.registry_directories))

    def test_login_failure_removes_ephemeral_credentials_without_pulling(self):
        self.failures.add("login")
        with self.assertRaises(OperationError):
            self.invoke()
        self.assertNotIn("pull", self.events)
        self.snapshot.assert_not_called()
        self.assert_not_activated()
        self.assertTrue(all(not path.exists() for path in self.registry_directories))

    def test_invalid_source_compose_aborts_before_backup_or_live_writes(self):
        self.failures.add("source-config")
        with self.assertRaises(OperationError):
            self.invoke()
        self.snapshot.assert_not_called()
        self.assert_not_activated()
        self.assertNotIn("CONSPECT_IMAGE", os.environ)

    def test_failed_full_snapshot_resumes_old_app_but_never_activates(self):
        self.failures.add("snapshot")
        with self.assertRaises(OperationError):
            self.invoke()
        self.assertEqual(self.events[-3:], ["snapshot", "backup-resume", "unlock"])
        self.assert_not_activated()

    def test_compose_capability_failure_aborts_before_preflight_pull_backup_or_writes(self):
        def missing_start_wait():
            self.assertTrue(self.locked)
            raise OperationError("Docker Compose start --wait is required.")

        self.compose_check.side_effect = missing_start_wait
        with self.assertRaisesRegex(OperationError, "start --wait"):
            self.invoke()
        self.compose_check.assert_called_once_with()
        self.compose_factory.assert_not_called()
        self.docker.assert_not_called()
        self.snapshot.assert_not_called()
        self.writer.assert_not_called()
        self.assertEqual(self.events, ["lock", "unlock"])
        self.assertFalse(self.backup.exists())
        self.assert_not_activated()

    def test_preflight_failure_aborts_before_pull_or_snapshot(self):
        self.failures.add("preflight")
        with self.assertRaises(OperationError):
            self.invoke()
        self.docker.assert_not_called()
        self.snapshot.assert_not_called()
        self.assert_not_activated()

    def test_stopped_app_is_not_automatically_recovered_by_release(self):
        self.app_state = "exited"
        with self.assertRaises(OperationError):
            self.invoke()
        self.docker.assert_not_called()
        self.snapshot.assert_not_called()
        self.assertEqual(self.app_state, "exited")

    def test_up_health_failure_stops_new_app_without_binary_or_env_rollback(self):
        self.failures.add("up")
        with self.assertRaises(OperationError):
            self.invoke()
        self.assertEqual(self.events[-4:], ["up", "stop", "state-failed", "unlock"])
        self.assertEqual(self.app_state, "exited")
        self.assertEqual(self.active_image, IMAGE)
        self.assert_installed_files(self.new_files)
        self.assertEqual(self.env.read_text(encoding="utf-8"), release.replace_image(ENV, IMAGE))
        state = json.loads((self.root / ".release.json").read_text(encoding="utf-8"))
        self.assertEqual(state["status"], "failed")
        self.assertEqual(state["backup"], str(self.backup))
        self.assertEqual(self.events.count("up"), 1)
        self.assertIn("App left offline", self.stderr.getvalue())

    def test_mcp_discovery_failure_stops_new_app_and_keeps_verified_backup(self):
        self.failures.add("mcp-check")
        with self.assertRaisesRegex(OperationError, "mcp-check"):
            self.invoke()
        self.assertEqual(self.events[-5:], ["up", "mcp-check", "stop", "state-failed", "unlock"])
        self.assertEqual(self.app_state, "exited")
        self.assertEqual(self.env.read_text(), release.replace_image(ENV, IMAGE))
        state = json.loads((self.root / ".release.json").read_text())
        self.assertEqual(state["status"], "failed")
        self.assertEqual(state["backup"], str(self.backup))

    def test_invalid_mcp_configuration_aborts_before_backup_and_activation(self):
        for override in ({"APP_BASE_URL": "http://notes.example.com"},
                         {"APP_BASE_URL": "https://notes.example.com/path"},
                         {"MCP_ENABLED": "not-a-boolean"}):
            with self.subTest(override=override):
                self.app_env = {"APP_BASE_URL": "https://notes.example.com", "MCP_ENABLED": "true", **override}
                with self.assertRaises(OperationError):
                    self.invoke()
                self.snapshot.assert_not_called()
                self.mcp_check.assert_not_called()
                self.assert_not_activated()

    def test_trailing_slash_in_existing_origin_is_normalized_before_public_check(self):
        self.app_env["APP_BASE_URL"] += "/"
        self.invoke()
        self.mcp_check.assert_called_once_with("https://notes.example.com")

    def test_explicitly_disabled_mcp_skips_public_oauth_check(self):
        self.app_env["MCP_ENABLED"] = "false"
        self.invoke()
        self.mcp_check.assert_not_called()
        self.assertEqual(self.events[-3:], ["up", "state-healthy", "unlock"])

    def test_stop_failure_warns_without_attempting_rollback(self):
        self.failures.update({"up", "stop"})
        with self.assertRaisesRegex(OperationError, "injected up failure"):
            self.invoke()
        self.assertIn("Could not confirm the failed app stopped", self.stderr.getvalue())
        self.assertEqual(self.events.count("up"), 1)
        self.assert_installed_files(self.new_files)

    def test_live_config_failure_restores_old_configs_before_any_app_replacement(self):
        self.failures.add("live-config")
        with self.assertRaises(OperationError):
            self.invoke()
        self.assert_installed_files(self.old_files)
        self.assertEqual(self.env.read_text(encoding="utf-8"), ENV)
        self.assertEqual(self.app_state, "running")
        self.assertNotIn("up", self.events)
        self.assertNotIn("stop", self.events)
        self.assertEqual(json.loads((self.root / ".release.json").read_text())["status"], "failed")

    def test_failed_state_write_must_not_skip_stopping_unhealthy_app(self):
        self.failures.update({"up", "state-failed"})
        with self.assertRaises((OperationError, OSError)):
            self.invoke()
        self.assertIn("stop", self.events, "State persistence is best effort; stopping the migrated app is mandatory")
        self.assertEqual(self.app_state, "exited")

    def test_env_changed_by_preceding_locked_operation_is_preserved(self):
        updated_env = ENV.replace(SECRET, "cd" * 32)
        # Model a restore finishing after release starts, before it owns the lock.
        self.on_lock = lambda: self.env.write_text(updated_env, encoding="utf-8")
        # Only orchestration matters here; don't enforce the other tests' old ENV.
        config = json.dumps({"services": {"app": {"environment": self.app_env}}})
        with patch.object(release, "run_command", return_value=config):
            self.invoke()
        self.assertEqual((self.backup / "config.env").read_text(encoding="utf-8"), updated_env)
        self.assertEqual(self.env.read_text(encoding="utf-8"), release.replace_image(updated_env, IMAGE))

    def test_inherited_compose_and_docker_overrides_are_not_used(self):
        overrides = {
            "COMPOSE_FILE": "/outside/compose.yaml", "COMPOSE_PROFILES": "unwanted-profile",
            "COMPOSE_PROJECT_NAME": "other", "CONSPECT_IMAGE": "mutable:latest",
            "DOCKER_CONFIG": "/outside/credentials", "DOCKER_HOST": "ssh://outside",
            "DOCKER_CONTEXT": "outside", "MCP_ENABLED": "false",
            "MCP_API_URL": "http://outside", "APP_BASE_URL": "https://outside.example.com",
        }
        os.environ.update(overrides)
        self.invoke()
        for command, _, environment in self.commands:
            for name in overrides:
                if name == "CONSPECT_IMAGE" and str(self.source / "compose.yaml") in command:
                    self.assertEqual(environment[name], IMAGE)
                else:
                    self.assertNotIn(name, environment)

    def test_invalid_image_revision_and_registry_user_are_rejected_before_docker(self):
        for arguments in (
            {"image": "ghcr.io/awak3r/c0nspect:latest"},
            {"image": IMAGE.replace("awak3r", "other")},
            {"image": IMAGE + "\n"}, {"revision": "a" * 7},
            {"revision": "../" + REVISION}, {"username": "--password=secret"},
        ):
            with self.subTest(arguments=arguments), self.assertRaises(OperationError):
                self.invoke(**arguments)
        self.docker.assert_not_called()
        self.snapshot.assert_not_called()

    def test_nonroot_invocation_is_rejected(self):
        with patch.object(release.os, "geteuid", return_value=1000), self.assertRaises(OperationError):
            self.invoke()
        self.docker.assert_not_called()

    def test_env_requires_regular_root_owned_private_file(self):
        for mode, owner in ((0o644, 0), (0o660, 0), (0o600, 1000)):
            with self.subTest(mode=oct(mode), owner=owner):
                self.env.chmod(mode)
                self.owners[self.env] = owner
                with self.assertRaises(OperationError):
                    self.invoke()
        self.docker.assert_not_called()
        self.snapshot.assert_not_called()

    def test_missing_env_or_nginx_overlay_aborts_before_docker(self):
        for path in (self.env, self.source / "deploy/compose.nginx.yaml"):
            with self.subTest(path=path):
                content = path.read_bytes()
                path.unlink()
                with self.assertRaises(OperationError):
                    self.invoke()
                path.write_bytes(content)
                path.chmod(0o600)
        self.docker.assert_not_called()

    def test_untrusted_directory_ownership_and_permissions_are_rejected(self):
        for path in (self.root, self.root.parent, self.source, self.source.parent):
            for mode, owner in ((0o770, 0), (0o757, 0), (0o750, 1000)):
                with self.subTest(path=path, mode=oct(mode), owner=owner):
                    previous_mode = path.stat().st_mode & 0o777
                    path.chmod(mode)
                    self.owners[path] = owner
                    try:
                        with self.assertRaises(OperationError):
                            self.invoke()
                    finally:
                        path.chmod(previous_mode)
                        self.owners.pop(path)
        self.docker.assert_not_called()
        self.snapshot.assert_not_called()

    def test_source_and_target_file_symlinks_are_rejected_without_touching_referent(self):
        outside = self.base / "outside-secret"
        outside.write_text("must remain private", encoding="utf-8")
        for directory, relative in (
            (self.root, ".env"), (self.root, "compose.yaml"),
            (self.source, "compose.yaml"), (self.source, "deploy/operations.py"),
        ):
            with self.subTest(directory=directory, relative=relative):
                path = directory / relative
                content = path.read_bytes()
                path.unlink()
                path.symlink_to(outside)
                try:
                    with self.assertRaises(OperationError):
                        self.invoke()
                    self.assertEqual(outside.read_text(), "must remain private")
                    self.assertTrue(path.is_symlink())
                finally:
                    path.unlink()
                    path.write_bytes(content)
                    path.chmod(0o600)
        self.docker.assert_not_called()

    def test_target_directory_symlink_is_rejected(self):
        outside = self.base / "outside-deploy"
        (self.root / "deploy").rename(outside)
        (self.root / "deploy").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(OperationError):
            self.invoke()
        self.docker.assert_not_called()
        self.snapshot.assert_not_called()

    def test_source_deploy_directory_symlink_must_be_rejected(self):
        outside = self.base / "outside-source"
        (self.source / "deploy").rename(outside)
        (self.source / "deploy").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(OperationError):
            self.invoke()
        self.docker.assert_not_called()
        self.snapshot.assert_not_called()

    def test_symlinked_backup_root_must_be_rejected_before_snapshot(self):
        outside = self.base / "outside-backups"
        outside.mkdir(mode=0o700)
        (self.root / "backups").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(OperationError):
            self.invoke()
        self.snapshot.assert_not_called()
        self.assertEqual(list(outside.iterdir()), [])

    def test_bytecode_is_not_installed_or_backed_up_as_deployment_source(self):
        cache = self.source / "deploy/__pycache__"
        cache.mkdir()
        (cache / "operations.cpython-312.pyc").write_bytes(b"\xff\x00")
        (self.source / "deploy/stray.pyc").write_bytes(b"\xff\x00")
        self.invoke()
        self.assertFalse((self.root / "deploy/__pycache__").exists())
        self.assertFalse((self.root / "deploy/stray.pyc").exists())

    def test_cli_reads_registry_token_from_stdin_and_reports_failure(self):
        argv = ["release.py", "--root", str(self.root), "--source", str(self.source),
                "--image", IMAGE, "--registry-user", "Awak3r", "--revision", REVISION]
        self.failures.add("up")
        with patch.object(release.sys, "argv", argv), patch.object(release.sys, "stdin", io.StringIO(TOKEN + "\n")):
            self.assertEqual(release.main(), 1)
        self.assertEqual(self.app_state, "exited")
        self.assertNotIn(TOKEN, self.stdout.getvalue() + self.stderr.getvalue())


class ReleaseHelperTests(unittest.TestCase):
    def test_replace_image_preserves_all_nonimage_lines_including_secret(self):
        for content in (ENV, ENV.replace("CONSPECT_IMAGE=", "export CONSPECT_IMAGE =")):
            with self.subTest(content=content):
                result = release.replace_image(content, IMAGE)
                self.assertEqual(result, ENV.replace(OLD_IMAGE, IMAGE))
        no_image = f"# comment\nAPP_SECRET={SECRET}"
        self.assertEqual(release.replace_image(no_image, IMAGE), no_image + f"\nCONSPECT_IMAGE={IMAGE}\n")

    def test_duplicate_image_definition_is_rejected(self):
        with self.assertRaises(OperationError):
            release.replace_image(ENV + "export CONSPECT_IMAGE=second\n", IMAGE)

    def test_invalid_tokens_never_reach_docker_or_error_messages(self):
        for token in ("", "x" * 65537, "secret\nsecond", "secret\rsecond"):
            with self.subTest(length=len(token)), patch.object(release, "run_command") as docker:
                with self.assertRaises(OperationError) as raised:
                    release.pull_image(IMAGE, "Awak3r", token)
                docker.assert_not_called()
                if token:
                    self.assertNotIn(token, str(raised.exception))

    def test_registry_errors_classify_stage_without_leaking_private_output(self):
        for output, reason in ((b"denied: secret-token", "permission denied"),
                               (b"manifest unknown secret-token", "not found"),
                               (b"x509: secret-token", "certificate"),
                               (b"unexpected secret-token", "registry/network")):
            error = OperationError("private Docker failure")
            error.command_stderr = output
            with patch.object(release, "run_command", side_effect=error):
                with self.assertRaises(OperationError) as raised:
                    release.registry_command(["docker", "pull", IMAGE], "pull")
                self.assertIn("GHCR pull failed", str(raised.exception))
                self.assertIn(reason, str(raised.exception))
                self.assertNotIn("secret-token", str(raised.exception))

    def test_atomic_write_is_private_and_replaces_link_instead_of_following_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root / "outside"
            outside.write_text("unchanged", encoding="utf-8")
            target = root / "state"
            target.symlink_to(outside)
            release.atomic_write(target, "private state\n")
            self.assertFalse(target.is_symlink())
            self.assertEqual(outside.read_text(), "unchanged")
            self.assertEqual(target.read_text(), "private state\n")
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertEqual(list(root.glob(".release-*")), [])

    def test_atomic_replace_failure_preserves_original_and_cleans_temporary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / ".env"
            target.write_text(ENV, encoding="utf-8")
            with patch.object(release.os, "replace", side_effect=OSError("disk failure")), self.assertRaises(OSError):
                release.atomic_write(target, "replacement")
            self.assertEqual(target.read_text(encoding="utf-8"), ENV)
            self.assertEqual(list(root.glob(".release-*")), [])

    def test_compose_paths_use_installation_env_and_project_not_staging_directory(self):
        root = Path("/opt/conspect")
        source = root / ".releases" / f"{REVISION}-1234-2"
        self.assertEqual(release.compose_command(root, source), [
            "docker", "compose", "--project-directory", str(root), "--project-name", "conspect",
            "--env-file", str(root / ".env"), "-f", str(source / "compose.yaml"),
            "-f", str(source / "deploy/compose.nginx.yaml"),
        ])


if __name__ == "__main__":
    unittest.main()
