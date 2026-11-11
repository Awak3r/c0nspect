import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import install_uploader  # noqa: E402

KEY = "csp_private-test-credential"


class OriginTests(unittest.TestCase):
    def test_accepts_https_origins(self):
        for raw in ("https://conspect.awak3r.ru", "https://conspect.awak3r.ru/",
                    "https://conspect.awak3r.ru/api/v1", "https://host.tld:8443/api/v1/"):
            self.assertEqual(install_uploader.valid_origin(raw), raw.rstrip("/"))

    def test_accepts_local_http(self):
        self.assertEqual(install_uploader.valid_origin("http://localhost:8080"), "http://localhost:8080")
        self.assertEqual(install_uploader.valid_origin("http://127.0.0.1"), "http://127.0.0.1")

    def test_rejects_insecure_or_shaped_urls(self):
        for raw in ("ftp://conspect.awak3r.ru", "http://conspect.awak3r.ru", "https://host/mcp",
                    "https://user:pw@host", "https://host/?q=1", "https://host/#frag",
                    "https://host/api/v2", "https://host\\backslash", "https://host %20"):
            with self.assertRaises(install_uploader.InstallError):
                install_uploader.valid_origin(raw)


class KeyTests(unittest.TestCase):
    def test_accepts_printable_csp_keys(self):
        self.assertEqual(install_uploader.valid_key(KEY), KEY)

    def test_rejects_without_echoing(self):
        for bad in ("short", "x" * 5000, "abc_private", KEY + "\n", KEY + " x"):
            with self.assertRaises(install_uploader.InstallError) as caught:
                install_uploader.valid_key(bad)
            self.assertNotIn(bad, str(caught.exception))
        with self.assertRaises(install_uploader.InstallError):
            install_uploader.valid_key("")

    def test_reads_regular_files_only(self):
        with tempfile.TemporaryDirectory() as home:
            root = Path(home)
            good = root / "key"
            good.write_text(KEY + "\n", encoding="utf-8")
            os.chmod(good, 0o600)
            self.assertEqual(install_uploader.read_key_file(good), KEY)
            with self.assertRaises(install_uploader.InstallError):
                install_uploader.read_key_file(root / "absent")
            with self.assertRaises(install_uploader.InstallError):
                install_uploader.read_key_file(root)
            big = root / "big"
            big.write_text("csp_" + "x" * 5000, encoding="utf-8")
            with self.assertRaises(install_uploader.InstallError):
                install_uploader.read_key_file(big)


class InstallTests(unittest.TestCase):
    class Args:
        files_root = ""
        url = "https://conspect.awak3r.ru"
        key_file = None
        bin_dir = ""
        config_dir = ""
        go = "go"
        check_project_id = None
        check_path = None
        replace = False

    def args(self, home, **overrides):
        args = self.Args()
        Path(home, "study").mkdir(exist_ok=True)
        args.files_root = str(Path(home) / "study")
        args.bin_dir = str(Path(home) / "bin")
        args.config_dir = str(home)
        for name, value in overrides.items():
            setattr(args, name, value)
        return args

    def stub_runner(self, script):
        class Result:
            returncode = 0
            stderr = b""
            stdout = b"usage\n"
        return lambda argv, cwd=None: script.append(argv) or Result()

    def fake_go_build(self, argv, cwd=None):
        if "build" in argv:
            output = [arg for arg in argv if arg.endswith(".tmp")]
            Path(output[0]).write_bytes(b"fake-binary")
        return self.stub_runner(argv)()

    def test_happy_flow_writes_private_files(self):
        with tempfile.TemporaryDirectory() as home:
            script = []
            key_source = Path(home) / "exported-key"
            key_source.write_text(KEY + "\n", encoding="utf-8")
            args = self.args(home, key_file=str(key_source), replace=False)
            with patch.object(install_uploader, "build_binary") as build:
                build.return_value = Path(args.bin_dir) / "conspect-upload"
                with patch.object(install_uploader, "__name__", "install_uploader"):
                    install_uploader.install(args, runner=self.stub_runner(script))
            config_dir = Path(home) / "conspect"
            key_path = config_dir / "api-key"
            config_path = config_dir / "upload.json"
            self.assertTrue(key_path.exists() and config_path.exists())
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(key_path.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(config_path.stat().st_mode), 0o600)
            self.assertEqual(key_path.read_text(encoding="utf-8").strip(), KEY)
            payload = json.loads(config_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["url"], "https://conspect.awak3r.ru")
            self.assertEqual(payload["files_root"], str(Path(home) / "study"))
            self.assertEqual(payload["key_file"], str(key_path))

    def test_existing_files_require_replace(self):
        with tempfile.TemporaryDirectory() as home:
            args = self.args(home)
            args.check_project_id = None
            config_dir = Path(home) / "conspect"
            config_dir.mkdir()
            existing = []
            for name in ("upload.json", "api-key"):
                (config_dir / name).write_text("x", encoding="utf-8")
                existing.append(config_dir / name)
            (Path(home) / "bin").mkdir()
            binary = Path(home) / "bin" / "conspect-upload"
            binary.write_bytes(b"x")
            with patch.object(install_uploader, "plan_key", return_value=(KEY, False)):
                with self.assertRaises(install_uploader.InstallError):
                    install_uploader.install(args, runner=self.stub_runner([]))
            args.replace = True
            with patch.object(install_uploader, "plan_key", return_value=(KEY, False)):
                with patch.object(install_uploader, "build_binary") as build:
                    build.return_value = binary
                    install_uploader.install(args, runner=self.stub_runner([]))
            payload = json.loads((config_dir / "upload.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["key_file"], str(config_dir / "api-key"))

    def test_prompted_key_is_validated_and_not_echoed(self):
        with tempfile.TemporaryDirectory() as home:
            args = self.args(home)
            with patch.object(install_uploader, "build_binary") as build:
                build.return_value = Path(args.bin_dir) / "conspect-upload"
                with patch.object(install_uploader.getpass, "getpass", return_value=KEY):
                    install_uploader.install(args, runner=self.stub_runner([]))
            self.assertEqual((Path(home) / "conspect" / "api-key").read_text().strip(), KEY)
        # A second machine state without an existing key: an invalid prompt is refused.
        with tempfile.TemporaryDirectory() as home:
            args = self.args(home)
            with patch.object(install_uploader.getpass, "getpass", return_value="not-a-key"):
                with self.assertRaises(install_uploader.InstallError) as caught:
                    install_uploader.install(args, runner=self.stub_runner([]))
            self.assertNotIn("not-a-key", str(caught.exception))
            self.assertFalse((Path(home) / "conspect" / "api-key").exists())

    def test_config_must_live_outside_checkout(self):
        with tempfile.TemporaryDirectory() as home:
            repo = install_uploader.Path(install_uploader.__file__).resolve().parents[2]
            args = self.args(home)
            args.config_dir = str(repo)
            with self.assertRaises(install_uploader.InstallError):
                install_uploader.install(args, runner=self.stub_runner([]))

    def test_files_root_must_be_existing_absolute_directory(self):
        with tempfile.TemporaryDirectory() as home:
            args = self.args(home)
            args.files_root = "relative/path"
            with self.assertRaises(install_uploader.InstallError):
                install_uploader.install(args, runner=self.stub_runner([]))


if __name__ == "__main__":
    unittest.main()
