"""Migration contracts using synthetic keys/temp files; no network or real Zed."""

from contextlib import redirect_stderr, redirect_stdout
from email.message import Message
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib import error, request

import configure_zed as zed


KEY = "csp_synthetic-test-key"
OTHER = "other-server-secret-never-print"
SUCCESS = {
    "jsonrpc": "2.0", "id": 1, "result": {
        "protocolVersion": zed.PROTOCOL, "capabilities": {},
        "serverInfo": {"name": "test", "version": "1"},
    },
}


class Response(io.BytesIO):
    status = 200

    def __init__(self, body=None, content_type="application/json"):
        super().__init__(json.dumps(SUCCESS if body is None else body).encode())
        self.headers = Message()
        self.headers["Content-Type"] = content_type

    def geturl(self):
        return zed.DEFAULT_ORIGIN + "/mcp"


class ConfigureZedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.settings = self.root / "settings.json"
        self.keyfile = self.root / "private-key.txt"
        self.keyfile.write_text(KEY + "\n", encoding="utf-8")
        self.keyfile.chmod(0o600)
        self.cfg = {
            "command": "C:\\old\\Windows.exe", "args": [],
            "env": {
                "CONSPECT_URL": zed.DEFAULT_ORIGIN,
                "CONSPECT_API_KEY_FILE": str(self.keyfile),
                "CONSPECT_FILES_ROOT": "C:\\Users\\synthetic\\imports",
            },
        }
        self.write_config()
        # Even an accidentally unmocked probe cannot open a live connection.
        self.network = patch("configure_zed.request.OpenerDirector.open", side_effect=AssertionError("unexpected network"))
        self.network.start()
        self.addCleanup(self.network.stop)

    def write_config(self, cfg=None):
        value = json.dumps(self.cfg if cfg is None else cfg)
        self.prefix = ('\ufeff{// outside комментарий\r\n"other": "' + OTHER + '",\r\n'
                       '"context_servers": {/* keep before */ "conspect": ')
        self.suffix = (', // keep after\r\n"elsewhere": {"env": {"SECRET": "' + OTHER
                       + '"}, "command":"x",},},\r\n"text":"// not a comment /* \\\" */",}\r\n')
        self.settings.write_bytes((self.prefix + value + self.suffix).encode("utf-8"))
        self.settings.chmod(0o600)

    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = zed.main(["--settings", str(self.settings), *args])
        output = out.getvalue() + err.getvalue()
        self.assertNotIn(KEY, output)
        self.assertNotIn(OTHER, output)
        self.assertNotIn("old\\\\Windows.exe", output)
        return code, output

    def files(self):
        return {p.name: p.read_bytes() for p in self.root.iterdir() if p.is_file()}

    def test_default_and_check_are_offline_and_read_only(self):
        before = self.files()
        with patch.dict(os.environ, {"CONSPECT_API_KEY": "csp_ambient-must-not-use"}):
            for flags in ((), ("--check",)):
                with self.subTest(flags=flags):
                    code, output = self.run_cli(*flags)
                    self.assertEqual(code, 0)
                    self.assertIn("mode: offline", output)
                    self.assertIn("CONSPECT_API_KEY_FILE", output)
                    self.assertNotIn("csp_ambient-must-not-use", output)
                    self.assertEqual(self.files(), before)

    def test_preserves_every_byte_outside_exact_value(self):
        plan = zed.prepare(self.settings)
        expected = self.prefix + json.dumps({
            "url": zed.DEFAULT_ORIGIN + "/mcp", "headers": {"Authorization": "Bearer " + KEY},
        }) + self.suffix
        self.assertEqual(plan.updated, expected.encode("utf-8"))
        parsed = zed.JSONC(plan.updated.decode()).parse().value
        self.assertEqual(parsed["other"], OTHER)
        self.assertEqual(parsed["context_servers"]["elsewhere"]["env"]["SECRET"], OTHER)
        self.assertNotIn("command", parsed["context_servers"]["conspect"])
        self.assertNotIn(KEY, repr(plan))

    def test_only_conspect_key_file_is_opened(self):
        text = self.settings.read_text(encoding="utf-8")
        text = text.replace('"SECRET": "' + OTHER + '"', '"CONSPECT_API_KEY_FILE": "/nonexistent/not-read"')
        self.settings.write_bytes(text.encode())
        with patch("configure_zed.read_regular", wraps=zed.read_regular) as read:
            zed.prepare(self.settings)
        self.assertEqual([call.args[0] for call in read.call_args_list], [self.settings, self.keyfile])

    def test_inline_and_existing_header_sources(self):
        for source in ("inline", "Authorization", "authorization", "X-API-Key"):
            with self.subTest(source=source):
                if source == "inline":
                    cfg = {"command": "old.exe", "env": {"CONSPECT_API_KEY": KEY}}
                else:
                    cfg = {"url": zed.DEFAULT_ORIGIN + "/mcp", "headers": {
                        source: ("Bearer " if source.lower() == "authorization" else "") + KEY,
                    }}
                self.write_config(cfg)
                self.assertEqual(zed.prepare(self.settings).key, KEY)
                self.assertEqual(self.run_cli()[0], 0)

    def test_ambiguous_or_invalid_credentials_refused(self):
        configs = [
            {"command": "x", "env": {}},
            {"command": "x", "env": {"CONSPECT_API_KEY": KEY, "CONSPECT_API_KEY_FILE": str(self.keyfile)}},
            {"command": "x", "env": {"CONSPECT_API_KEY": KEY}, "headers": {"Authorization": "Bearer " + KEY}},
            {"url": zed.DEFAULT_ORIGIN + "/mcp", "headers": {"Authorization": "Bearer " + KEY, "authorization": "Bearer " + KEY}},
            {"url": zed.DEFAULT_ORIGIN + "/mcp", "command": "x", "headers": {"Authorization": "Bearer " + KEY}},
            {"url": zed.DEFAULT_ORIGIN + "/mcp", "headers": {"Authorization": "Basic " + OTHER}},
            {"command": "x", "env": {"CONSPECT_API_KEY": "bad-key"}},
            {"command": "x", "env": {"CONSPECT_API_KEY": KEY + "\r\n"}},
            {"command": "x", "env": {"CONSPECT_API_KEY_FILE": "relative.txt"}},
            {"command": "x", "env": []},
        ]
        for cfg in configs:
            with self.subTest(cfg_kind=list(cfg)):
                self.write_config(cfg)
                before = self.files()
                self.assertEqual(self.run_cli("--apply")[0], 1)
                self.assertEqual(self.files(), before)

    def test_bad_key_file_is_not_dumped(self):
        for data in (b"not-a-key", KEY.encode() + b"\x00", b"\xff", b"a" * 4097):
            with self.subTest(length=len(data)):
                self.keyfile.write_bytes(data)
                self.assertEqual(self.run_cli()[0], 1)

    def test_missing_conspect_and_wrong_shapes(self):
        for text in ('{}', '[]', '{"context_servers": []}', '{"context_servers":{"conspect":null}}'):
            with self.subTest(text=text):
                self.settings.write_text(text)
                self.assertEqual(self.run_cli()[0], 1)

    def test_malformed_and_duplicate_jsonc_refused(self):
        good = self.settings.read_bytes()
        bad = [
            b'{"context_servers":{},"context_servers":{}}',
            b'{"context_servers":{"conspect":{},"conspect":{}}}',
            b'{"context_servers":{},"context_\\u0073ervers":{}}',
            b'{"x":{"env":{"A":1,"A":2}}}',
            b'{"x":NaN}', b'{"x":Infinity}', b'{"x":01}', b'{"x":1,,}',
            b'{"x":1} trailing', b'/* unterminated', b'{"x":"unterminated}',
            b'\xff', b'{', good[:-3],
        ]
        for text in bad:
            with self.subTest(text=text[:32]):
                self.settings.write_bytes(text)
                before = self.files()
                self.assertEqual(self.run_cli("--apply")[0], 1)
                self.assertEqual(self.files(), before)

    def test_symlink_settings_key_and_parent_refused(self):
        target = self.root / "target"
        target.write_bytes(self.settings.read_bytes())
        self.settings.unlink()
        self.settings.symlink_to(target)
        self.assertEqual(self.run_cli()[0], 1)
        self.settings.unlink()
        self.write_config()
        self.keyfile.unlink()
        self.keyfile.symlink_to(target)
        self.assertEqual(self.run_cli()[0], 1)
        link = self.root / "link"
        real = self.root / "directory"
        real.mkdir()
        (real / "settings.json").write_bytes(self.settings.read_bytes())
        link.symlink_to(real, target_is_directory=True)
        with self.assertRaises(zed.ConfigError):
            zed.prepare(link / "settings.json")

    def test_hard_link_settings_refused(self):
        os.link(self.settings, self.root / "linked")
        self.assertEqual(self.run_cli()[0], 1)

    def test_url_canonicalization(self):
        for raw in ("https://EXAMPLE.com:443", "https://example.com/", "https://example.com/api/v1/"):
            self.assertEqual(zed.endpoint(raw), "https://example.com/mcp")
        self.assertEqual(zed.endpoint("https://[::1]:8443"), "https://[::1]:8443/mcp")
        self.assertEqual(zed.endpoint("https://example.com/mcp", True), "https://example.com/mcp")

    def test_unsafe_urls_refused(self):
        urls = ("http://example.com", "https://u:p@example.com", "https://example.com?",
                "https://example.com#", "https://example.com/%6dcp", "https://example.com/owner",
                "https://example.com\\@evil.test", "https://example.com:0", "https://example.com:",
                "https://example.com:65536", "https://example.com\n", "https://a..test", "https://")
        for url in urls:
            with self.subTest(url=url):
                self.cfg["env"]["CONSPECT_URL"] = url
                self.write_config()
                before = self.files()
                self.assertEqual(self.run_cli("--apply")[0], 1)
                self.assertEqual(self.files(), before)

    def test_drive_path_mapping(self):
        self.assertEqual(str(zed.local_path(r"C:\Users\synthetic\settings.json")), "/mnt/c/Users/synthetic/settings.json")
        self.assertEqual(zed.windows_path(Path("/mnt/d/Users/test/settings.json")), r"D:\Users\test\settings.json")
        self.cfg["env"]["CONSPECT_API_KEY_FILE"] = r"C:\Users\synthetic\private.txt"
        self.write_config()
        real_read = zed.read_regular

        def mapped_read(path, limit):
            if str(path) == "/mnt/c/Users/synthetic/private.txt":
                return real_read(self.keyfile, limit)
            return real_read(path, limit)

        with patch("configure_zed.read_regular", side_effect=mapped_read):
            self.assertEqual(zed.prepare(self.settings).key, KEY)

    def test_probe_sends_only_one_initialize_with_same_key(self):
        before = self.files()
        opener = Mock()
        opener.open.return_value = Response()
        with patch("configure_zed.request.build_opener", return_value=opener) as build:
            self.assertEqual(self.run_cli("--probe")[0], 0)
        build.assert_called_once()
        self.assertIsInstance(build.call_args.args[0], request.ProxyHandler)
        self.assertEqual(build.call_args.args[0].proxies, {})
        self.assertIsInstance(build.call_args.args[1], zed.NoRedirect)
        opener.open.assert_called_once()
        req = opener.open.call_args.args[0]
        self.assertEqual(opener.open.call_args.kwargs, {"timeout": 20})
        self.assertEqual(req.full_url, zed.DEFAULT_ORIGIN + "/mcp")
        self.assertEqual(req.method, "POST")
        self.assertEqual(req.get_header("Authorization"), "Bearer " + KEY)
        self.assertEqual(json.loads(req.data)["method"], "initialize")
        self.assertEqual(json.loads(req.data)["params"]["capabilities"], {})
        self.assertEqual(self.files(), before)

    def test_no_redirect_following(self):
        handler = zed.NoRedirect()
        req = request.Request(zed.DEFAULT_ORIGIN + "/mcp")
        self.assertIsNone(handler.redirect_request(req, None, 302, "secret", {}, "https://other.test/mcp"))

    def test_failed_auth_and_unavailable_do_not_create_backup_or_replace(self):
        for mode in ("--apply", "--probe"):
            for status in (401, 403, 302, 503, None):
                with self.subTest(mode=mode, status=status):
                    before = self.files()
                    exc = error.HTTPError(zed.DEFAULT_ORIGIN, status, OTHER, {}, io.BytesIO(KEY.encode())) if status else error.URLError(KEY)
                    opener = Mock()
                    opener.open.side_effect = exc
                    with patch("configure_zed.request.build_opener", return_value=opener):
                        code, output = self.run_cli(mode)
                    self.assertEqual(code, 1)
                    if status in (401, 403):
                        self.assertIn("may not yet accept csp_ keys", output)
                    self.assertEqual(self.files(), before)

    def test_invalid_initialize_is_not_success(self):
        for body in ([], {}, {"jsonrpc": "2.0", "id": 1, "error": {"message": KEY}},
                     {**SUCCESS, "id": True}, {**SUCCESS, "result": {}}, {**SUCCESS, "id": 2}):
            with self.subTest(kind=type(body).__name__):
                before = self.files()
                opener = Mock()
                opener.open.return_value = Response(body)
                with patch("configure_zed.request.build_opener", return_value=opener):
                    self.assertEqual(self.run_cli("--apply")[0], 1)
                self.assertEqual(self.files(), before)

    def test_unexpected_response_type_or_size_refused(self):
        for response in (Response(content_type="text/html"), Response(KEY * zed.MAX_RESPONSE)):
            before = self.files()
            opener = Mock()
            opener.open.return_value = response
            with patch("configure_zed.request.build_opener", return_value=opener):
                self.assertEqual(self.run_cli("--apply")[0], 1)
            self.assertEqual(self.files(), before)

    def test_apply_backs_up_and_atomically_replaces(self):
        before = self.settings.read_bytes()
        plan = zed.prepare(self.settings)
        real_replace = os.replace
        with patch("configure_zed.probe") as probe, patch("configure_zed.os.replace", wraps=real_replace) as replace:
            code, output = self.run_cli("--apply")
        self.assertEqual(code, 0)
        self.assertIn("mode: applied", output)
        probe.assert_called_once()
        self.assertEqual(probe.call_args.args[0].key, KEY)
        replace.assert_called_once()
        self.assertEqual(replace.call_args.args[1], self.settings)
        self.assertEqual(replace.call_args.args[0].parent, self.settings.parent)
        self.assertEqual(self.settings.read_bytes(), plan.updated)
        backups = list(self.root.glob("*.bak"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), before)
        self.assertEqual(stat.S_IMODE(backups[0].stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.settings.stat().st_mode), 0o600)
        self.assertFalse(list(self.root.glob("*.tmp")))

    def test_repeated_apply_uses_unique_backups(self):
        with patch("configure_zed.probe"):
            self.assertEqual(self.run_cli("--apply")[0], 0)
            self.assertEqual(self.run_cli("--apply")[0], 0)
        self.assertEqual(len(list(self.root.glob("*.bak"))), 2)

    def test_mode_preserved_with_private_read_only_original(self):
        self.settings.chmod(0o400)
        with patch("configure_zed.probe"):
            self.assertEqual(self.run_cli("--apply")[0], 0)
        self.assertEqual(stat.S_IMODE(self.settings.stat().st_mode), 0o400)
        self.assertEqual(stat.S_IMODE(next(self.root.glob("*.bak")).stat().st_mode), 0o600)

    def test_nonprivate_settings_or_directory_refuse_before_probe(self):
        for file_mode, directory_mode in ((0o644, 0o700), (0o600, 0o777)):
            with self.subTest(file_mode=file_mode):
                self.settings.chmod(file_mode)
                self.root.chmod(directory_mode)
                before = self.files()
                with patch("configure_zed.probe") as probe:
                    self.assertEqual(self.run_cli("--apply")[0], 1)
                    probe.assert_not_called()
                self.assertEqual(self.files(), before)
        self.root.chmod(0o700)

    def test_no_apply_in_checkout(self):
        plan = zed.prepare(self.settings)
        plan.path = Path(zed.__file__).resolve().parents[2] / "settings.json"
        with self.assertRaises(zed.ConfigError), patch("configure_zed.probe") as probe:
            zed.apply(plan)
        probe.assert_not_called()

    def test_concurrent_edit_after_probe_is_not_overwritten(self):
        def edit(_):
            self.settings.write_bytes(b"// concurrent edit\n{}")

        with patch("configure_zed.probe", side_effect=edit):
            code, output = self.run_cli("--apply")
        self.assertEqual(code, 1)
        self.assertIn("changed since inspection", output)
        self.assertEqual(self.settings.read_bytes(), b"// concurrent edit\n{}")
        self.assertFalse(list(self.root.glob("*.bak")))

    def test_concurrent_edit_after_temp_write_is_not_overwritten(self):
        real_unchanged = zed.unchanged
        count = 0

        def edit(plan):
            nonlocal count
            count += 1
            if count == 2:
                self.settings.write_bytes(b"{} // edited during backup")
            real_unchanged(plan)

        with patch("configure_zed.probe"), patch("configure_zed.unchanged", side_effect=edit):
            self.assertEqual(self.run_cli("--apply")[0], 1)
        self.assertEqual(self.settings.read_bytes(), b"{} // edited during backup")
        self.assertFalse(list(self.root.glob("*.bak")))
        self.assertFalse(list(self.root.glob("*.tmp")))

    def test_equal_bytes_but_replaced_inode_refused(self):
        plan = zed.prepare(self.settings)
        other = self.root / "replacement"
        other.write_bytes(plan.original)
        other.chmod(0o600)
        os.replace(other, self.settings)
        with self.assertRaises(zed.ConfigError):
            zed.unchanged(plan)

    def test_replace_or_write_failure_preserves_settings_and_cleans_up(self):
        for target in ("configure_zed.os.replace", "configure_zed.os.fsync"):
            with self.subTest(target=target):
                before = self.files()
                with patch("configure_zed.probe"), patch(target, side_effect=OSError(KEY + OTHER)):
                    self.assertEqual(self.run_cli("--apply")[0], 1)
                self.assertEqual(self.files(), before)

    def test_windows_acl_required_and_matching_without_chmod(self):
        with patch("configure_zed.windows_path", return_value=r"C:\Users\test\settings.json"), patch("configure_zed.windows_acl", return_value="private-DACL") as acl, patch("configure_zed.os.fchmod") as chmod, patch("configure_zed.probe"):
            self.assertEqual(self.run_cli("--apply")[0], 0)
            self.assertGreaterEqual(acl.call_count, 6)
            chmod.assert_not_called()

    def test_windows_acl_mismatch_or_unavailable_prevents_replacement(self):
        for responses in (["directory", "original", "mismatch"], zed.ConfigError("Windows ACL privacy could not be verified.")):
            with self.subTest(kind=type(responses).__name__):
                before = self.files()
                with patch("configure_zed.windows_path", return_value=r"C:\Users\test\settings.json"), patch("configure_zed.windows_acl", side_effect=responses), patch("configure_zed.probe"):
                    self.assertEqual(self.run_cli("--apply")[0], 1)
                self.assertEqual(self.files(), before)

    def test_windows_metadata_helper_uses_no_file_contents_or_acl_mutation(self):
        result = subprocess.CompletedProcess([], 0, b'{"private":true,"dacl":"D:private"}', b"")
        with patch("configure_zed.shutil.which", return_value="powershell.exe"), patch("configure_zed.subprocess.run", return_value=result) as run:
            self.assertEqual(zed.windows_acl(Path("/mnt/c/Users/test/settings.json")), "D:private")
        kwargs = run.call_args.kwargs
        self.assertEqual(kwargs["env"]["CONSPECT_ZED_ACL_PATH"], r"C:\Users\test\settings.json")
        self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(kwargs["timeout"], 10)
        self.assertNotIn(KEY, str(run.call_args))
        self.assertNotIn("Set-Acl", zed.ACL_SCRIPT)
        for output in (b'{"private":false,"dacl":"D:public"}', KEY.encode()):
            result.stdout = output
            with patch("configure_zed.shutil.which", return_value="powershell.exe"), patch("configure_zed.subprocess.run", return_value=result):
                with self.assertRaises(zed.ConfigError) as caught:
                    zed.windows_acl(Path("/mnt/c/Users/test/settings.json"))
                self.assertNotIn(KEY, str(caught.exception))
        with patch("configure_zed.shutil.which", return_value=None):
            with self.assertRaises(zed.ConfigError):
                zed.windows_acl(Path("/mnt/c/Users/test/settings.json"))

    def test_cli_errors_do_not_echo_arbitrary_arguments(self):
        for flags in (("--unknown", KEY), ("--apply", "--probe")):
            self.assertEqual(self.run_cli(*flags)[0], 1)


if __name__ == "__main__":
    unittest.main()
