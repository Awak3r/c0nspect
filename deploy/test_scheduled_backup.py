"""Scheduled retention tests use fake Docker and private, synthetic local bundles."""

import configparser
import contextlib
import io
import json
import os
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch

import backup
import scheduled_backup
from operations import OperationError, validate_bundle
from test_operations import FakeCompose

ROOT = Path(__file__).resolve().parent.parent


class ScheduledBackupTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.previous_umask = os.umask(0o077)
        self.compose = FakeCompose(self.root)
        self.compose.managed_services = ("app",)
        self.output = self.root / "backups"
        self.start = datetime.fromisoformat("2026-10-01T03:30:00+00:00")
        self.stdout = io.StringIO()
        self.stderr = io.StringIO()
        self.output_context = contextlib.redirect_stdout(self.stdout)
        self.error_context = contextlib.redirect_stderr(self.stderr)
        self.output_context.__enter__()
        self.error_context.__enter__()
        self.root_patch = patch.object(scheduled_backup, "ROOT", self.root)
        self.root_patch.start()

    def tearDown(self):
        self.root_patch.stop()
        self.error_context.__exit__(None, None, None)
        self.output_context.__exit__(None, None, None)
        os.umask(self.previous_umask)
        self.temporary.cleanup()

    def bundle(self, day):
        with patch.object(backup, "now", return_value=self.start + timedelta(days=day)):
            return backup.create_backup(self.compose, self.output)

    def invoke(self, *arguments):
        with (
            patch.object(scheduled_backup.sys, "argv", ["scheduled_backup.py", *arguments]),
            patch.object(scheduled_backup, "operation_lock", return_value=contextlib.nullcontext()),
            patch.object(scheduled_backup, "Compose", return_value=self.compose),
        ):
            return scheduled_backup.main()

    def test_failed_snapshot_never_prunes_or_exposes_error_payload(self):
        old = self.bundle(0)
        live_data = self.root / "live-data"
        live_data.write_text("unchanged", encoding="utf-8")
        with (
            patch.object(scheduled_backup, "create_backup", side_effect=RuntimeError("private-error-payload")),
            patch.object(scheduled_backup, "prune_backups") as prune,
        ):
            self.assertEqual(self.invoke("--nginx"), 1)
        prune.assert_not_called()
        validate_bundle(old)
        self.assertEqual(live_data.read_text(encoding="utf-8"), "unchanged")
        self.assertNotIn("private-error-payload", self.stderr.getvalue())

    def test_success_keeps_newest_14_verified_bundles(self):
        previous = [self.bundle(day) for day in range(17)]
        # Retention follows UTC names, not mutable filesystem mtimes.
        os.utime(previous[0], (2000000000, 2000000000))
        with patch.object(backup, "now", return_value=self.start + timedelta(days=17)):
            self.assertEqual(self.invoke("--nginx"), 0)
        remaining = sorted(self.output.iterdir())
        self.assertEqual(len(remaining), 14)
        self.assertEqual([path.name for path in remaining[:-1]], [path.name for path in previous[-13:]])
        self.assertNotIn(previous[0], remaining)
        for path in remaining:
            validate_bundle(path)
            self.assertEqual(path.stat().st_mode & 0o077, 0)
        self.assertEqual(self.compose.running["app"], "running")

    def test_partial_symlink_nested_and_unrecognized_entries_are_preserved(self):
        old = self.bundle(0)
        partial = self.output / ".partial-operator"
        partial.mkdir()
        (partial / "keep.txt").write_text("partial", encoding="utf-8")
        unrecognized = self.bundle(1).rename(self.output / "conspect-manual")
        extra = self.bundle(2)
        (extra / "operator-directory").mkdir()
        (extra / "operator-directory" / "keep.txt").write_text("keep", encoding="utf-8")
        manual = self.output / "manual"
        manual.mkdir()
        nested = manual / old.name
        shutil.copytree(old, nested)
        invalid_name = self.output / "conspect-20269999T033000.000000Z"
        shutil.copytree(old, invalid_name)
        newest = self.bundle(3)
        with tempfile.TemporaryDirectory() as external:
            outside = Path(external) / old.name
            shutil.copytree(old, outside)
            link = self.output / "conspect-20200101T033000.000000Z"
            link.symlink_to(outside, target_is_directory=True)
            self.assertEqual(scheduled_backup.prune_backups(self.compose, newest, 1), 1)
            self.assertTrue(link.is_symlink())
            validate_bundle(outside)
        for path in (partial, unrecognized, extra, manual, invalid_name, newest):
            self.assertTrue(path.is_dir(), path.name)
        validate_bundle(nested)
        self.assertFalse(old.exists())

    def test_other_database_user_or_postgres_major_is_never_pruned(self):
        protected = []
        for day, (field, value) in enumerate((
            ("postgres_db", "other_database"), ("postgres_user", "other_user"), ("postgres_major", 16),
        )):
            path = self.bundle(day)
            manifest_path = path / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest[field] = value
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            protected.append(path)
        old = self.bundle(3)
        newest = self.bundle(4)
        self.assertEqual(scheduled_backup.prune_backups(self.compose, newest, 1), 1)
        self.assertFalse(old.exists())
        for path in protected:
            validate_bundle(path)

    def test_corrupt_or_symlinked_bundle_files_are_not_deleted(self):
        corrupt = self.bundle(0)
        (corrupt / "database.dump").write_bytes(b"corrupt")
        linked = self.bundle(1)
        (linked / "config.env").unlink()
        (linked / "config.env").symlink_to(self.compose.env_path)
        newest = self.bundle(2)
        self.assertEqual(scheduled_backup.prune_backups(self.compose, newest, 1), 0)
        self.assertTrue(corrupt.is_dir())
        self.assertTrue((linked / "config.env").is_symlink())
        validate_bundle(newest)

    def test_old_candidate_is_validated_again_before_deletion(self):
        old = self.bundle(0)
        newest = self.bundle(1)
        with patch.object(scheduled_backup, "validate_bundle", wraps=validate_bundle) as check:
            self.assertEqual(scheduled_backup.prune_backups(self.compose, newest, 1), 1)
        self.assertGreaterEqual(sum(call.args[0] == old for call in check.call_args_list), 2)
        validate_bundle(newest)

    def test_candidate_changed_during_validation_aborts_cleanup(self):
        old = self.bundle(0)
        newest = self.bundle(1)
        checks = 0

        def changed(path):
            nonlocal checks
            manifest = validate_bundle(path)
            if path == old:
                checks += 1
                if checks > 1:
                    manifest["postgres_db"] = "changed"
            return manifest

        with (
            patch.object(scheduled_backup, "validate_bundle", side_effect=changed),
            self.assertRaises(OperationError),
        ):
            scheduled_backup.prune_backups(self.compose, newest, 1)
        validate_bundle(old)
        validate_bundle(newest)

    def test_new_snapshot_is_never_pruned_after_clock_skew(self):
        later = self.bundle(10)
        newest = self.bundle(0)
        with self.assertRaises(OperationError):
            scheduled_backup.prune_backups(self.compose, newest, 1)
        validate_bundle(later)
        validate_bundle(newest)

    def test_retention_refuses_new_snapshot_outside_dedicated_directory(self):
        old = self.bundle(0)
        external = self.root / "other-backups" / old.name
        shutil.copytree(old, external)
        with self.assertRaises(OperationError):
            scheduled_backup.prune_backups(self.compose, external, 1)
        validate_bundle(old)
        validate_bundle(external)

    def test_symlinked_backup_root_is_rejected_before_snapshot(self):
        with tempfile.TemporaryDirectory() as external:
            self.output.symlink_to(external, target_is_directory=True)
            with patch.object(scheduled_backup, "create_backup") as snapshot:
                self.assertEqual(self.invoke("--nginx"), 1)
            snapshot.assert_not_called()
            self.assertEqual(list(Path(external).iterdir()), [])
            self.assertTrue(self.output.is_symlink())

    def test_retention_failure_preserves_new_snapshot_and_hides_details(self):
        old = self.bundle(0)
        newest = self.bundle(1)
        with (
            patch.object(scheduled_backup, "create_backup", return_value=newest),
            patch.object(scheduled_backup.shutil, "rmtree", side_effect=OSError("secret-cleanup-error")),
        ):
            self.assertEqual(self.invoke("--nginx", "--keep", "1"), 1)
        validate_bundle(old)
        validate_bundle(newest)
        self.assertNotIn("secret-cleanup-error", self.stderr.getvalue())

    def test_cli_selectors_defaults_keep_and_lock_scope(self):
        newest = self.output / "conspect-20261020T033000.000000Z"
        for flags, local, nginx, keep in (
            ([], False, False, 14), (["--local"], True, False, 14),
            (["--nginx", "--keep", "3"], False, True, 3),
        ):
            active = False

            @contextlib.contextmanager
            def locked():
                nonlocal active
                active = True
                try:
                    yield
                finally:
                    active = False

            def require_lock(*arguments, **keywords):
                self.assertTrue(active)
                return self.compose

            def snapshot(compose, output):
                self.assertTrue(active)
                self.assertIs(compose, self.compose)
                self.assertEqual(output, self.output)
                return newest

            def prune(compose, path, count):
                self.assertTrue(active)
                self.assertIs(compose, self.compose)
                self.assertEqual((path, count), (newest, keep))
                return 0

            with (
                self.subTest(flags=flags),
                patch.object(scheduled_backup.sys, "argv", ["scheduled_backup.py", *flags]),
                patch.object(scheduled_backup, "operation_lock", side_effect=locked),
                patch.object(scheduled_backup, "Compose", side_effect=require_lock) as constructor,
                patch.object(scheduled_backup, "create_backup", side_effect=snapshot),
                patch.object(scheduled_backup, "prune_backups", side_effect=prune),
            ):
                self.assertEqual(scheduled_backup.main(), 0)
                constructor.assert_called_once_with(local=local, nginx=nginx)
                self.assertFalse(active)

    def test_invalid_cli_rejected_before_lock_or_configuration(self):
        for arguments in (
            ["--keep", "0"], ["--keep", "-1"], ["--keep", "not-a-number"],
            ["--nginx", "--local"], ["--output", str(self.root / "elsewhere")],
        ):
            with (
                self.subTest(arguments=arguments),
                patch.object(scheduled_backup.sys, "argv", ["scheduled_backup.py", *arguments]),
                patch.object(scheduled_backup, "operation_lock") as lock,
                patch.object(scheduled_backup, "Compose") as constructor,
                self.assertRaises(SystemExit) as error,
            ):
                scheduled_backup.main()
            self.assertEqual(error.exception.code, 2)
            lock.assert_not_called()
            constructor.assert_not_called()


class ScheduledUnitTests(unittest.TestCase):
    def test_root_service_and_daily_utc_timer_contract(self):
        service = configparser.ConfigParser(interpolation=None)
        service.read_string((ROOT / "deploy" / "conspect-backup.service").read_text(encoding="utf-8"))
        settings = service["Service"]
        self.assertEqual(settings["Type"], "oneshot")
        self.assertEqual((settings["User"], settings["Group"]), ("root", "root"))
        self.assertEqual(settings["WorkingDirectory"], "/opt/conspect")
        self.assertEqual(settings["ExecStart"].split(), [
            "/usr/bin/python3", "/opt/conspect/deploy/scheduled_backup.py", "--nginx", "--keep", "14",
        ])
        self.assertEqual(settings["UMask"], "0077")
        self.assertEqual(settings["Nice"], "10")
        self.assertEqual(settings["TimeoutStartSec"], "1h")
        self.assertEqual(settings["KillSignal"], "SIGINT")
        self.assertNotIn("EnvironmentFile", settings)
        timer = configparser.ConfigParser(interpolation=None)
        timer.read_string((ROOT / "deploy" / "conspect-backup.timer").read_text(encoding="utf-8"))
        self.assertEqual(timer["Timer"]["OnCalendar"], "*-*-* 03:30:00 UTC")
        self.assertEqual(timer["Timer"]["RandomizedDelaySec"], "10m")
        self.assertTrue(timer["Timer"].getboolean("Persistent"))
        self.assertEqual(timer["Timer"]["Unit"], "conspect-backup.service")
        self.assertEqual(timer["Install"]["WantedBy"], "timers.target")


if __name__ == "__main__":
    unittest.main()
