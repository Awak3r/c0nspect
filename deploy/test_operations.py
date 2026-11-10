"""Operational safety tests. Docker/PostgreSQL are faked; no deployment occurs."""

import contextlib
import io
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from typing import BinaryIO
from unittest.mock import Mock, patch

import backup
import operations
import restore
from operations import (
    BUNDLE_FILES,
    Compose,
    OperationError,
    secret_fingerprint,
    sha256,
    validate_bundle,
    validate_uploads,
)

SECRET = "ab" * 32


def make_archive(path, *, name="uploads/image.png", kind=tarfile.REGTYPE):
    with tarfile.open(path, "w:gz") as archive:
        directory = tarfile.TarInfo("uploads/")
        directory.type = tarfile.DIRTYPE
        directory.mode = 0o755
        archive.addfile(directory)
        member = tarfile.TarInfo(name)
        member.type = kind
        member.linkname = "../../outside"
        member.mode = 0o600
        if kind == tarfile.REGTYPE:
            member.size = 5
            archive.addfile(member, io.BytesIO(b"image"))
        else:
            archive.addfile(member)


class FakeCompose:
    def __init__(self, root):
        self.env_path = root / ".env"
        self.env_path.write_text("APP_SECRET=" + SECRET + "\n", encoding="utf-8")
        self.config = {"services": {"app": {"environment": {"APP_SECRET": SECRET}}}}
        self.db_name = "conspect"
        self.db_user = "conspect"
        self.image_id = "sha256:test-image"
        self.fingerprint = secret_fingerprint(SECRET)
        self.running = {"app": "running"}
        self.managed_services: tuple[str, ...] = ("app",)
        self.events = []
        self.fail_on: str | None = None

    def event(self, label):
        self.events.append(label)
        if label == self.fail_on:
            raise OperationError("injected " + label + " failure")

    def preflight(self, *, backup=False):
        self.event("preflight")

    def states(self):
        return {service: self.running[service] for service in self.managed_services}

    def stop(self, services):
        for service in services:
            self.event("stop-" + service)
            self.running[service] = "exited"

    def resume(self, states, *, restored=False):
        assert set(states) == {"app"}
        for service in self.managed_services:
            if states[service] == "running":
                self.event("start-" + service)
                self.running[service] = "running"

    def call(self, *arguments: str, stdin: BinaryIO | None = None, stdout: BinaryIO | None = None) -> str:
        if "pg_dump" in arguments:
            self.event("dump")
            assert stdout is not None
            stdout.write(b"PGDMP fake dump for orchestration tests, not real SQL")
        elif "pg_restore" in arguments:
            self.event("dump-list" if "--list" in arguments else "restore-db")
            assert stdin is not None
            assert stdin.read().startswith(b"PGDMP")
        elif "dropdb" in arguments:
            self.event("drop-db")
        elif "createdb" in arguments:
            self.event("create-db")
        else:
            raise AssertionError(arguments)
        return ""

    def helper(self, entrypoint: str, *arguments: str, stdin: BinaryIO | None = None, stdout: BinaryIO | None = None) -> None:
        if entrypoint == "sh":
            self.event("clean-uploads")
            assert "-mindepth 1" in arguments[-1]
        elif "--create" in arguments:
            self.event("archive")
            assert stdout is not None
            with tarfile.open(fileobj=stdout, mode="w:gz") as archive:
                member = tarfile.TarInfo("uploads/")
                member.type = tarfile.DIRTYPE
                member.mode = 0o755
                archive.addfile(member)
        else:
            self.event("extract")
            assert "--no-same-owner" in arguments
            assert stdin is not None
            assert stdin.read(2) == b"\x1f\x8b"


class OperationsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.compose = FakeCompose(self.root)
        self.output = self.root / "backups"
        self.previous_umask = os.umask(0o077)
        self.stdout = contextlib.redirect_stdout(io.StringIO())
        self.stderr = contextlib.redirect_stderr(io.StringIO())
        self.stdout.__enter__()
        self.stderr.__enter__()

    def tearDown(self):
        self.stderr.__exit__(None, None, None)
        self.stdout.__exit__(None, None, None)
        os.umask(self.previous_umask)
        self.directory.cleanup()

    def bundle(self):
        directory = backup.create_backup(self.compose, self.output)
        self.compose.events.clear()
        return directory

    def update_checksums(self, directory):
        path = directory / "manifest.json"
        manifest = json.loads(path.read_text())
        manifest["files"] = {name: sha256(directory / name) for name in BUNDLE_FILES}
        path.write_text(json.dumps(manifest))

    def test_backup_orders_snapshot_before_restart_and_protects_secrets(self):
        directory = backup.create_backup(self.compose, self.output)
        self.assertEqual(self.compose.events, ["preflight", "stop-app", "dump", "archive", "start-app"])
        self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        for name in (*BUNDLE_FILES, "manifest.json"):
            self.assertEqual((directory / name).stat().st_mode & 0o077, 0)
        self.assertEqual(validate_bundle(directory)["app_secret_sha256"], self.compose.fingerprint)
        self.assertEqual(list(self.output.glob(".partial-*")), [])

    def test_backup_failure_removes_partial_and_restarts_original_app(self):
        for failure in ("dump", "archive"):
            with self.subTest(failure=failure):
                self.compose.fail_on = failure
                self.compose.events.clear()
                with self.assertRaises(OperationError):
                    backup.create_backup(self.compose, self.output)
                self.assertEqual(list(self.output.iterdir()), [])
                self.assertEqual(self.compose.events[-1], "start-app")

    def test_backup_does_not_start_previously_stopped_app(self):
        self.compose.running["app"] = "exited"
        backup.create_backup(self.compose, self.output)
        self.assertNotIn("start-app", self.compose.events)

    def test_backup_preflight_failure_does_not_stop_services(self):
        self.compose.fail_on = "preflight"
        with self.assertRaises(OperationError):
            backup.create_backup(self.compose, self.output)
        self.assertEqual(self.compose.events, ["preflight"])

    def test_restore_cleans_before_extract_and_restarts_after_both_succeed(self):
        restore.restore_backup(self.compose, self.bundle())
        self.assertEqual(self.compose.events, [
            "preflight", "dump-list", "stop-app", "drop-db", "create-db", "restore-db",
            "clean-uploads", "extract", "start-app",
        ])

    def test_restore_never_starts_services_that_were_stopped(self):
        directory = self.bundle()
        self.compose.running = {"app": "exited"}
        restore.restore_backup(self.compose, directory)
        self.assertFalse(any(event.startswith("start-") for event in self.compose.events))

    def test_restore_failures_leave_writers_stopped(self):
        directory = self.bundle()
        for failure in ("drop-db", "create-db", "restore-db", "clean-uploads", "extract", "start-app"):
            with self.subTest(failure=failure):
                self.compose.running = {"app": "running"}
                self.compose.events.clear()
                self.compose.fail_on = failure
                with self.assertRaises(OperationError):
                    restore.restore_backup(self.compose, directory)
                self.assertEqual(self.compose.running, {"app": "exited"})
                self.assertEqual(self.compose.events[-1], "stop-app")
                if failure in {"drop-db", "create-db", "restore-db", "clean-uploads", "extract"}:
                    self.assertNotIn("start-app", self.compose.events)

    def test_dump_validation_failure_does_not_stop_or_delete(self):
        directory = self.bundle()
        self.compose.fail_on = "dump-list"
        with self.assertRaises(OperationError):
            restore.restore_backup(self.compose, directory)
        self.assertEqual(self.compose.events, ["preflight", "dump-list"])

    def test_secret_mismatch_is_rejected_before_mutation(self):
        directory = self.bundle()
        self.compose.fingerprint = secret_fingerprint("cd" * 32)
        with self.assertRaisesRegex(OperationError, "APP_SECRET"):
            restore.restore_backup(self.compose, directory)
        self.assertEqual(self.compose.events, [])

    def test_database_mismatch_is_rejected_before_mutation(self):
        directory = self.bundle()
        self.compose.db_name = "another_database"
        with self.assertRaisesRegex(OperationError, "POSTGRES_DB"):
            restore.restore_backup(self.compose, directory)
        self.assertEqual(self.compose.events, [])

    def test_corruption_is_rejected_before_mutation(self):
        directory = self.bundle()
        (directory / "database.dump").write_bytes(b"corrupt")
        with self.assertRaisesRegex(OperationError, "integrity"):
            restore.restore_backup(self.compose, directory)
        self.assertEqual(self.compose.events, [])

    def test_unsafe_uploads_rejected_even_if_checksum_matches(self):
        directory = self.bundle()
        for name, kind in (
            ("uploads/../escape", tarfile.REGTYPE), ("/absolute", tarfile.REGTYPE),
            ("other/file", tarfile.REGTYPE), ("uploads/link", tarfile.SYMTYPE),
            ("uploads/hardlink", tarfile.LNKTYPE), ("uploads/device", tarfile.CHRTYPE),
            ("uploads", tarfile.REGTYPE),
        ):
            with self.subTest(name=name, kind=kind):
                make_archive(directory / "uploads.tar.gz", name=name, kind=kind)
                self.update_checksums(directory)
                with self.assertRaises(OperationError):
                    restore.restore_backup(self.compose, directory)
                self.assertEqual(self.compose.events, [])

    def test_partial_directory_is_not_restorable_even_with_manifest(self):
        directory = self.bundle()
        partial = directory.with_name(".partial-complete-looking")
        directory.rename(partial)
        with self.assertRaisesRegex(OperationError, "Partial"):
            validate_bundle(partial)

    def test_symlinked_bundle_file_is_rejected(self):
        directory = self.bundle()
        file = directory / "database.dump"
        outside = self.root / "outside.dump"
        file.rename(outside)
        file.symlink_to(outside)
        with self.assertRaisesRegex(OperationError, "integrity"):
            validate_bundle(directory)

    def test_invalid_manifest_rejected(self):
        directory = self.bundle()
        for manifest in ([], {"format": 2, "files": {}}, {"format": 1, "files": {"../escape": "hash"}}):
            with self.subTest(manifest=manifest):
                (directory / "manifest.json").write_text(json.dumps(manifest))
                with self.assertRaises(OperationError):
                    validate_bundle(directory)

    def test_invalid_gzip_and_missing_archive_root_rejected(self):
        path = self.root / "uploads.tar.gz"
        path.write_bytes(b"not gzip")
        with self.assertRaises(OperationError):
            validate_uploads(path)
        with tarfile.open(path, "w:gz"):
            pass
        with self.assertRaisesRegex(OperationError, "no uploads"):
            validate_uploads(path)

    def test_concurrent_operations_are_rejected(self):
        (self.root / "deploy").mkdir()
        with (
            patch.object(operations, "ROOT", self.root),
            operations.operation_lock(),
            self.assertRaisesRegex(OperationError, "already running"),
            operations.operation_lock(),
        ):
            self.fail("Second lock must not be acquired")

    def test_secret_validation_uses_decoded_hex(self):
        self.assertEqual(secret_fingerprint(SECRET), secret_fingerprint(SECRET.upper()))
        for secret in (None, "", "ab" * 31, "ab" * 33, "z" * 64):
            with self.subTest(secret=secret), self.assertRaises(OperationError):
                secret_fingerprint(secret)

    def test_docker_errors_do_not_expose_stderr(self):
        result = subprocess.CompletedProcess(["docker"], 1, stdout=b"", stderr=b"private-secret-or-note")
        with (
            patch.object(operations.subprocess, "run", return_value=result),
            self.assertRaises(OperationError) as error,
        ):
            operations.run_command(["docker", "anything"])
        self.assertNotIn("private-secret", str(error.exception))

    def test_helper_cleanup_occurs_even_when_client_fails(self):
        compose = Compose.__new__(Compose)
        compose.call = Mock(side_effect=OperationError("client failed"))
        result = subprocess.CompletedProcess(["docker"], 0, stdout=b"", stderr=b"")
        with (
            patch.object(operations.subprocess, "run", return_value=result) as run,
            self.assertRaisesRegex(OperationError, "client failed"),
        ):
            compose.helper("tar", "--extract")
        self.assertEqual(run.call_args.args[0][:3], ["docker", "rm", "--force"])
        arguments = compose.call.call_args.args
        self.assertEqual(arguments[:8], ("run", "--rm", "--no-deps", "--pull", "never", "-T", "--name", run.call_args.args[0][-1]))
        self.assertEqual(arguments[8:], ("--user", "10001:10001", "--entrypoint", "tar", "app", "--extract"))

    def test_helper_cleanup_failure_is_not_silently_ignored(self):
        compose = Compose.__new__(Compose)
        compose.call = Mock()
        result = subprocess.CompletedProcess(["docker"], 1, stdout=b"", stderr=b"daemon unavailable")
        with (
            patch.object(operations.subprocess, "run", return_value=result),
            self.assertRaisesRegex(OperationError, "keep app stopped"),
        ):
            compose.helper("tar", "--extract")

    def test_restore_interruption_leaves_services_stopped(self):
        directory = self.bundle()
        with (
            patch.object(self.compose, "helper", side_effect=KeyboardInterrupt),
            self.assertRaises(KeyboardInterrupt),
        ):
            restore.restore_backup(self.compose, directory)
        self.assertEqual(self.compose.running, {"app": "exited"})
        self.assertNotIn("start-app", self.compose.events)

    def test_non_ascii_secret_fingerprint_is_rejected_safely(self):
        directory = self.bundle()
        path = directory / "manifest.json"
        manifest = json.loads(path.read_text())
        manifest["app_secret_sha256"] = "not-a-fingerprint-\u2603"
        path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(OperationError, "APP_SECRET"):
            restore.restore_backup(self.compose, directory)
        self.assertEqual(self.compose.events, [])

    def test_backup_restart_failure_keeps_completed_bundle(self):
        self.compose.fail_on = "start-app"
        with self.assertRaises(OperationError):
            backup.create_backup(self.compose, self.output)
        complete = list(self.output.glob("conspect-*"))
        self.assertEqual(len(complete), 1)
        validate_bundle(complete[0])
        self.assertEqual(list(self.output.glob(".partial-*")), [])

    def test_compose_rejects_combined_overlays_before_configuration(self):
        with (
            patch.object(operations, "run_command") as run,
            self.assertRaisesRegex(OperationError, "only one"),
        ):
            Compose(local=True, nginx=True)
        run.assert_not_called()

    def configured_compose(self, **selectors):
        self.compose.env_path.chmod(0o600)
        config = self.compose_config("postgres://conspect:password@db:5432/conspect")
        with (
            patch.object(operations, "ROOT", self.root),
            patch.object(operations, "run_command", side_effect=[json.dumps(config), "sha256:test"]),
        ):
            return Compose(**selectors)

    def test_compose_defaults_to_production_and_all_selectors_manage_only_app(self):
        for selectors, overlay in (
            ({}, "nginx"), ({"nginx": True}, "nginx"), ({"local": True}, "local"),
        ):
            with self.subTest(selectors=selectors):
                compose = self.configured_compose(**selectors)
                self.assertEqual(compose.command, [
                    "docker", "compose", "--project-directory", str(self.root), "--project-name", "conspect",
                    "--env-file", str(self.root / ".env"), "-f", str(self.root / "compose.yaml"),
                    "-f", str(self.root / "deploy" / f"compose.{overlay}.yaml"),
                ])
                self.assertEqual(compose.managed_services, ("app",))

    def test_all_selectors_inspect_stop_and_resume_only_app(self):
        for selectors in ({}, {"nginx": True}, {"local": True}):
            with self.subTest(selectors=selectors):
                compose = self.configured_compose(**selectors)
                compose.container = Mock(return_value={"State": {"Status": "running"}})
                compose.call = Mock()
                self.assertEqual(compose.states(), {"app": "running"})
                compose.container.assert_called_once_with("app")
                compose.resume({"app": "running"})
                compose.call.assert_called_once_with("start", "--wait", "--wait-timeout", "120", "app")
                compose.call.reset_mock()
                compose.resume({"app": "running"}, restored=True)
                compose.call.assert_called_once_with("up", "--detach", "--no-deps", "--wait", "--wait-timeout", "120", "app")
                compose.call.reset_mock()
                compose.container.return_value = {"State": {"Status": "exited"}}
                compose.stop(["app"])
                compose.call.assert_called_once_with("stop", "--timeout", "30", "app")

    def test_all_selectors_never_resume_stopped_or_absent_app(self):
        for selectors in ({}, {"nginx": True}, {"local": True}):
            for state in ("exited", "created", "absent"):
                with self.subTest(selectors=selectors, state=state):
                    compose = self.configured_compose(**selectors)
                    compose.container = Mock(return_value=None if state == "absent" else {"State": {"Status": state}})
                    compose.call = Mock()
                    states = compose.states()
                    self.assertEqual(states, {"app": state})
                    compose.resume(states)
                    compose.resume(states, restored=True)
                    compose.call.assert_not_called()

    def test_all_selectors_reject_unstable_app_and_unconfirmed_stop(self):
        for selectors in ({}, {"nginx": True}, {"local": True}):
            with self.subTest(selectors=selectors):
                compose = self.configured_compose(**selectors)
                compose.container = Mock(return_value={"State": {"Status": "restarting"}})
                compose.call = Mock()
                with self.assertRaisesRegex(OperationError, "stabilize"):
                    compose.states()
                compose.call.assert_not_called()
                with self.assertRaisesRegex(OperationError, "Could not verify app stopped"):
                    compose.stop(["app"])

    def test_all_selectors_reject_live_app_secret_mismatch_before_backup(self):
        for selectors in ({}, {"nginx": True}, {"local": True}):
            with self.subTest(selectors=selectors):
                compose = self.configured_compose(**selectors)
                app_env = dict(compose.app_env, APP_SECRET="cd" * 32)
                containers = {
                    "db": {"State": {"Status": "running"}, "Config": {"Env": [
                        f"{key}={value}" for key, value in compose.db_env.items()
                    ]}},
                    "app": {"Config": {"Env": [f"{key}={value}" for key, value in app_env.items()]},
                            "Image": compose.image_id},
                }
                compose.container = Mock(side_effect=containers.__getitem__)
                compose.call = Mock(return_value="170006")
                with self.assertRaisesRegex(OperationError, "APP_SECRET"):
                    backup.create_backup(compose, self.output)
                self.assertFalse(self.output.exists())
                self.assertEqual(compose.call.call_count, 1)
                self.assertIn("psql", compose.call.call_args.args)

    def test_backup_and_restore_cli_preserve_overlay_selection(self):
        for script in (backup, restore):
            action_name = "create_backup" if script is backup else "restore_backup"
            for flags, local, nginx in (([], False, False), (["--local"], True, False), (["--nginx"], False, True)):
                with (
                    self.subTest(script=script.__name__, flags=flags),
                    patch.object(script.sys, "argv", [script.__name__, *flags, *(
                        ["--output", str(self.output)] if script is backup else [str(self.output), "--yes"]
                    )]),
                    patch.object(script, "operation_lock", return_value=contextlib.nullcontext()),
                    patch.object(script, "Compose", return_value=self.compose) as constructor,
                    patch.object(script, action_name) as action,
                ):
                    self.assertEqual(script.main(), 0)
                    constructor.assert_called_once_with(local=local, nginx=nginx)
                    action.assert_called_once_with(self.compose, self.output.resolve())

    def test_backup_and_restore_cli_reject_combined_overlays(self):
        for script in (backup, restore):
            arguments = ["--local", "--nginx"]
            if script is restore:
                arguments += [str(self.output), "--yes"]
            with (
                self.subTest(script=script.__name__),
                patch.object(script.sys, "argv", [script.__name__, *arguments]),
                patch.object(script, "Compose") as constructor,
                self.assertRaises(SystemExit) as error,
            ):
                script.main()
            self.assertEqual(error.exception.code, 2)
            constructor.assert_not_called()

    def compose_config(self, database_url):
        return {"services": {
            "app": {"image": "conspect:local", "environment": {
                "APP_SECRET": SECRET, "DATA_DIR": "/data", "DATABASE_URL": database_url,
            }},
            "db": {"environment": {
                "POSTGRES_DB": "conspect", "POSTGRES_USER": "conspect", "POSTGRES_PASSWORD": "password",
            }},
        }}

    def test_compose_rejects_database_url_that_would_snapshot_wrong_data(self):
        self.compose.env_path.chmod(0o600)
        for url in (
            "postgres://conspect:password@remote/conspect", "postgres://conspect:password@db/other",
            "postgres://other:password@db/conspect", "postgres://conspect:wrong@db/conspect",
            "postgres://conspect:password@db:1234/conspect", "postgres://conspect:password@db:invalid/conspect",
            "postgres://conspect:password@db/conspect?host=remote", "postgres://conspect:password@db/conspect?dbname=other",
            "postgres://conspect:password@db/conspect?service=remote", "postgres://conspect:password@db/conspect#fragment",
        ):
            with (
                self.subTest(url=url),
                patch.object(operations, "ROOT", self.root),
                patch.object(operations, "run_command", return_value=json.dumps(self.compose_config(url))),
                self.assertRaisesRegex(OperationError, "DATABASE_URL"),
            ):
                Compose()

    def test_compose_accepts_encoded_credentials_and_explicit_local_overlay(self):
        self.compose.env_path.chmod(0o600)
        config = self.compose_config("postgres://conspect:p%40ssword@db:5432/conspect?sslmode=disable")
        config["services"]["db"]["environment"]["POSTGRES_PASSWORD"] = "p@ssword"
        with (
            patch.object(operations, "ROOT", self.root),
            patch.object(operations, "run_command", side_effect=[json.dumps(config), "sha256:test"]),
        ):
            compose = Compose(local=True)
        self.assertIn(str(self.root / "deploy" / "compose.local.yaml"), compose.command)


if __name__ == "__main__":
    unittest.main()
