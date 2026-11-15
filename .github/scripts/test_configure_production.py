"""Offline contracts: all subprocesses mocked; remote scripts use a virtual server tree."""

from contextlib import redirect_stderr, redirect_stdout
import base64
import io
import json
import os
from pathlib import Path, PurePosixPath
import shlex
import stat
import struct
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import configure_production as production


PUBLIC = "ssh-ed25519 " + base64.b64encode(
    struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + bytes(range(32))
).decode()
HOST_PUBLIC = "ssh-ed25519 " + base64.b64encode(
    struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + b"h" * 32
).decode()
PRIVATE = b"-----BEGIN OPENSSH PRIVATE KEY-----\nsynthetic-secret-never-print\n-----END OPENSSH PRIVATE KEY-----\n"
PERSONAL = b"personal-identity-never-upload"


@unittest.skipUnless(os.name == "posix", "apply deliberately requires POSIX file ownership and locking")
class ConfigureProductionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.state = self.base / "config/deploy"
        self.trust = self.base / "trusted hosts"
        self.trust.write_text("server.example " + HOST_PUBLIC + "\n")
        self.identity = self.base / "personal identity"
        self.identity.write_bytes(PERSONAL)
        self.identity.chmod(0o600)
        self.calls = []
        self.failure = None
        self.environment_exists = True
        self.subprocess = patch.object(production.subprocess, "run", side_effect=self.process)
        self.subprocess.start()
        self.addCleanup(self.subprocess.stop)

    def cli(self, command="plan", *extra):
        out, err = io.StringIO(), io.StringIO()
        argv = [command, "--host", "server.example", "--user", "ubuntu", "--known-hosts", str(self.trust),
                "--identity-file", str(self.identity), "--state-dir", str(self.state), *extra]
        with redirect_stdout(out), redirect_stderr(err):
            status = production.main(argv)
        text = out.getvalue() + err.getvalue()
        for secret in (PRIVATE.decode(), PERSONAL.decode(), PUBLIC, HOST_PUBLIC, "unexpected-raw-error"):
            self.assertNotIn(secret, text)
        return status, text

    def args(self, **changes):
        values = dict(command="apply", host="server.example", user="ubuntu", port=22, root="/opt/conspect",
                      repo="Awak3r/c0nspect", environment="production", known_hosts=str(self.trust),
                      identity_file=str(self.identity), state_dir=str(self.state), yes=True)
        values.update(changes)
        return production.validate(SimpleNamespace(**values))

    def process(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        self.assertNotIn("shell", kwargs)
        self.assertEqual(kwargs["timeout"], production.TIMEOUT)
        self.assertEqual(kwargs["stdout"], subprocess.PIPE)
        self.assertEqual(kwargs["stderr"], subprocess.PIPE)
        self.assertNotIn(PRIVATE.decode(), repr(argv))
        self.assertNotIn(PERSONAL.decode(), repr(argv))
        if self.failure:
            result = self.failure(argv, kwargs)
            if result is not None:
                return result
        output, code = b"", 0
        if argv[:3] == ["gh", "auth", "status"]:
            pass
        elif argv[0] == "ssh-keygen":
            key = Path(argv[argv.index("-f") + 1])
            if "-y" in argv:
                output = (PUBLIC + "\n").encode()
            else:
                self.assertFalse(os.path.lexists(key))
                key.write_bytes(PRIVATE)
                key.chmod(0o600)
                key.with_suffix(".pub").write_text(PUBLIC + " " + production.MARKER + "\n")
                key.with_suffix(".pub").chmod(0o644)
        elif argv[0] == "ssh":
            self.assertIn("StrictHostKeyChecking=yes", argv)
            self.assertIn("BatchMode=yes", argv)
            self.assertIn("UpdateHostKeys=no", argv)
            self.assertIn("GlobalKnownHostsFile=" + os.devnull, argv)
            self.assertEqual(argv[argv.index("-F") + 1], os.devnull)
            if "HostKeyAlgorithms=ssh-ed25519" in argv:
                self.assertEqual(argv[argv.index("-l") + 1], "root")
                self.assertEqual(argv[argv.index("-i") + 1], str(self.state / "deploy_ed25519"))
                self.assertIn("IdentityAgent=none", argv)
                output = b"conspect-root-ok\n"
            elif production.REMOTE_INSPECT in argv[-1]:
                output = (HOST_PUBLIC + " root@server\n").encode()
            elif production.REMOTE_AUTHORIZE in argv[-1]:
                self.assertEqual(kwargs["input"], (PUBLIC + "\n").encode())
            else:
                self.fail_test("Unexpected SSH command")
        elif argv[:2] == ["gh", "api"]:
            if "GET" in argv and not self.environment_exists:
                output, code = b"HTTP/2.0 404 Not Found\n{}", 1
        elif argv[:2] not in (["gh", "secret"], ["gh", "variable"]):
            self.fail_test("Unexpected subprocess")
        return subprocess.CompletedProcess(argv, code, output, b"unexpected-raw-error")

    def fail_test(self, message):
        self.fail(message)  # pragma: no cover

    def snapshot(self):
        return {str(p.relative_to(self.base)): (p.lstat().st_mode, p.read_bytes() if p.is_file() else None)
                for p in self.base.rglob("*")}

    def github_edits(self):
        return [a for a, _ in self.calls if a[:2] in (["gh", "secret"], ["gh", "variable"])
                or a[:2] == ["gh", "api"] and "PUT" in a]

    def test_plan_is_generic_offline_readonly(self):
        before = self.snapshot()
        status, output = self.cli()
        self.assertEqual(status, 0)
        self.assertIn("offline, read-only", output)
        self.assertIn("DEPLOY_USER=root", output)
        self.assertNotIn(str(self.identity), output)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.snapshot(), before)

    def test_apply_requires_yes(self):
        status, output = self.cli("apply")
        self.assertEqual(status, 1)
        self.assertIn("requires --yes", output)
        self.assertFalse(self.state.exists())
        self.assertFalse(self.calls)

    def test_reject_invalid_fields_without_commands_or_writes(self):
        cases = {
            "--host": ["https://server", "root@server", "server:22", "[::1]", "-server", "a\nsecret", "fe80::1%eth0"],
            "--port": ["0", "65536", "abc"],
            "--user": ["admin"],
            "--root": ["relative", "/", "/opt/../root", "/opt/./app", "/opt/app;echo", "/opt//app", "/opt/app/"],
            "--repo": ["-x/name", "owner/name/extra", "owner/..", "owner/"],
            "--environment": ["../production", "bad name", "-prod", "x" * 101],
            "--state-dir": ["relative", str(self.base / "a/../b"), str(production.CHECKOUT / "state"),
                            str(self.base / "%h"), str(self.base / "${HOME}")],
            "--known-hosts": ["relative", str(self.base / "missing")],
            "--identity-file": ["relative", str(self.base / "missing")],
        }
        before = self.snapshot()
        for option, values in cases.items():
            for value in values:
                with self.subTest(option=option, value=value):
                    self.assertEqual(self.cli("plan", option, value)[0], 1)
        self.assertFalse(self.calls)
        self.assertEqual(self.snapshot(), before)

    def test_default_state_platform_locations(self):
        args = self.args()
        with patch.dict(os.environ, {"XDG_CONFIG_HOME": str(self.base / "xdg"), "APPDATA": str(self.base / "appdata")}):
            for platform, parent in (("linux", self.base / "xdg"), ("win32", self.base / "appdata"),
                                     ("darwin", Path.home() / "Library/Application Support")):
                with patch.object(production.sys, "platform", platform):
                    self.assertEqual(production.default_state(args), parent / "conspect/deploy/Awak3r/c0nspect/production/server.example-22")
        self.assertEqual(self.calls, [])

    def test_success_order_secrets_stdin_and_private_modes(self):
        self.assertEqual(self.cli("apply", "--yes")[0], 0)
        self.assertEqual(self.calls[0][0], ["gh", "auth", "status"])
        author = next(i for i, (a, _) in enumerate(self.calls) if a[0] == "ssh" and production.REMOTE_AUTHORIZE in a[-1])
        root = next(i for i, (a, _) in enumerate(self.calls) if "HostKeyAlgorithms=ssh-ed25519" in a)
        first_api = next(i for i, (a, _) in enumerate(self.calls) if a[:2] == ["gh", "api"])
        self.assertLess(author, root)
        self.assertLess(root, first_api)
        self.assertEqual(len(self.github_edits()), 6)
        values = {a[3]: k["input"] for a, k in self.calls if a[:2] in (["gh", "secret"], ["gh", "variable"])}
        self.assertEqual(values, {"DEPLOY_SSH_KEY": PRIVATE, "DEPLOY_KNOWN_HOSTS": ("server.example " + HOST_PUBLIC + "\n").encode(),
                                  "DEPLOY_HOST": b"server.example", "DEPLOY_USER": b"root", "DEPLOY_PORT": b"22", "DEPLOY_PATH": b"/opt/conspect"})
        self.assertEqual(self.identity.read_bytes(), PERSONAL)
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o700)
        for path in self.state.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertFalse(any("PUT" in a for a, _ in self.calls))
        self.assertFalse(any("workflow" in a or "ssh-keyscan" in a for a, _ in self.calls))

    def test_absent_environment_created_only_after_root_test(self):
        self.environment_exists = False
        self.assertEqual(self.cli("apply", "--yes")[0], 0)
        puts = [a for a, _ in self.calls if a[:2] == ["gh", "api"] and "PUT" in a]
        self.assertEqual(puts, [["gh", "api", "--method", "PUT", "repos/Awak3r/c0nspect/environments/production"]])

    def test_api_non404_errors_do_not_attempt_creation(self):
        self.failure = lambda a, k: subprocess.CompletedProcess(a, 1, b"HTTP/2.0 403 Forbidden", b"secret") if a[:2] == ["gh", "api"] else None
        self.assertEqual(self.cli("apply", "--yes")[0], 1)
        self.assertFalse(self.github_edits())

    def test_retry_reuses_exact_key_after_partial_github_update(self):
        self.failure = lambda a, k: subprocess.CompletedProcess(a, 1, b"", b"secret") if a[:3] == ["gh", "variable", "set"] else None
        self.assertEqual(self.cli("apply", "--yes")[0], 1)
        key = (self.state / "deploy_ed25519").read_bytes()
        self.failure = None
        self.assertEqual(self.cli("apply", "--yes")[0], 0)
        self.assertEqual((self.state / "deploy_ed25519").read_bytes(), key)
        self.assertEqual(sum(a[0] == "ssh-keygen" and "-t" in a for a, _ in self.calls), 1)

    def test_interrupt_after_private_key_creation_recovers_public_half(self):
        args = self.args()
        with production.locked_state(args):
            key = self.state / "deploy_ed25519"
            key.write_bytes(PRIVATE)
            key.chmod(0o600)
        self.assertEqual(self.cli("apply", "--yes")[0], 0)
        self.assertFalse(any("-t" in a for a, _ in self.calls))
        # ssh-keygen's initial 0644 public half must also survive a retry.
        (self.state / "deploy_ed25519.pub").chmod(0o644)
        self.assertEqual(self.cli("apply", "--yes")[0], 0)

    def test_unmanaged_state_and_changed_config_refused(self):
        self.state.mkdir(parents=True, mode=0o700)
        self.assertEqual(self.cli("apply", "--yes")[0], 1)
        self.assertFalse(any(a[0] == "ssh" for a, _ in self.calls))
        self.state.rmdir()
        with production.locked_state(self.args()):
            pass
        self.assertEqual(self.cli("apply", "--yes", "--root", "/other")[0], 1)

    def test_lock_released_and_concurrent_apply_refused(self):
        args = self.args()
        with production.locked_state(args):
            self.assertEqual(self.cli("apply", "--yes")[0], 1)
            self.assertFalse(any(a[0] == "ssh" for a, _ in self.calls))
        self.assertEqual(self.cli("apply", "--yes")[0], 0)

    def test_symlink_and_hardlink_inputs_refused(self):
        for option, target in (("--known-hosts", self.trust), ("--identity-file", self.identity)):
            for kind in ("symbolic", "hard"):
                link = self.base / (kind + "-link")
                link.symlink_to(target) if kind == "symbolic" else os.link(target, link)
                self.assertEqual(self.cli("plan", option, str(link))[0], 1)
                link.unlink()
        alias = self.base / "alias"
        alias.symlink_to(self.base, target_is_directory=True)
        self.assertEqual(self.cli("plan", "--state-dir", str(alias / "fresh"))[0], 1)
        self.assertFalse(self.calls)

    def test_key_paths_refuse_links_malformed_and_mismatch(self):
        self.assertEqual(self.cli("apply", "--yes")[0], 0)
        key = self.state / "deploy_ed25519"
        for kind in ("symlink", "hardlink", "malformed", "wrong-mode"):
            with self.subTest(kind=kind):
                key.unlink()
                if kind == "symlink":
                    key.symlink_to(self.identity)
                elif kind == "hardlink":
                    os.link(self.identity, key)
                else:
                    key.write_bytes(b"invalid" if kind == "malformed" else PRIVATE)
                    key.chmod(0o644 if kind == "wrong-mode" else 0o600)
                self.calls.clear()
                self.assertEqual(self.cli("apply", "--yes")[0], 1)
                self.assertFalse(self.github_edits())
                key.unlink()
                key.write_bytes(PRIVATE)
                key.chmod(0o600)
        (self.state / "deploy_ed25519.pub").write_text(HOST_PUBLIC)
        self.assertEqual(self.cli("apply", "--yes")[0], 1)
        self.assertEqual(key.read_bytes(), PRIVATE)

    def test_state_permissions_unmanaged_contents_and_orphan_public_key_refused(self):
        args = self.args()
        with production.locked_state(args):
            pass
        for kind in ("permissions", "extra-file", "orphan-public"):
            with self.subTest(kind=kind):
                if kind == "permissions":
                    self.state.chmod(0o755)
                else:
                    path = self.state / ("personal-key" if kind == "extra-file" else "deploy_ed25519.pub")
                    path.write_text(PUBLIC)
                    path.chmod(0o600)
                self.assertEqual(self.cli("apply", "--yes")[0], 1)
                self.assertFalse(self.github_edits())
                self.assertFalse((self.state / "deploy_ed25519").exists())
                self.state.chmod(0o700)
                if kind != "permissions":
                    path.unlink()

    def test_invalid_private_key_and_non_ed25519_derivation_not_uploaded(self):
        with production.locked_state(self.args()):
            key = self.state / "deploy_ed25519"
            key.write_bytes(PRIVATE)
            key.chmod(0o600)
        for code, output in ((1, PRIVATE), (0, b"ssh-rsa AAAA")):
            self.failure = lambda a, k: subprocess.CompletedProcess(a, code, output, PERSONAL) if a[0] == "ssh-keygen" else None
            self.assertEqual(self.cli("apply", "--yes")[0], 1)
            self.assertFalse(self.github_edits())
            self.assertEqual(key.read_bytes(), PRIVATE)

    def test_personal_agent_connection_and_root_proof_are_separate(self):
        args = self.args(identity_file=None)
        production.apply(args)
        initial = [a for a, _ in self.calls if a[0] == "ssh" and "HostKeyAlgorithms=ssh-ed25519" not in a]
        self.assertTrue(initial)
        self.assertTrue(all("-i" not in a for a in initial))
        self.assertTrue(all("IdentityAgent=none" not in a for a in initial))
        self.calls.clear()
        self.failure = lambda a, k: subprocess.CompletedProcess(a, 0, b"not-root-proof\n", b"") if "HostKeyAlgorithms=ssh-ed25519" in a else None
        self.assertEqual(self.cli("apply", "--yes")[0], 1)
        self.assertFalse(self.github_edits())

    def test_failed_atomic_config_publication_can_retry_without_adopting_state(self):
        original = production.atomic
        def interrupted(path, data):
            if path.name == "config.json":
                raise KeyboardInterrupt
            original(path, data)
        with patch.object(production, "atomic", side_effect=interrupted):
            self.assertEqual(self.cli("apply", "--yes")[0], 1)
        self.assertFalse(self.state.exists())
        self.assertEqual(self.cli("apply", "--yes")[0], 0)

    def test_wrong_key_type_and_invalid_host_key_stop_edits(self):
        for output in (b"ssh-rsa AAAA", b"ssh-ed25519 !!!!", b"ssh-ed25519 " + base64.b64encode(b"bad")):
            self.failure = lambda a, k: subprocess.CompletedProcess(a, 0, output, b"") if a[0] == "ssh" else None
            self.assertEqual(self.cli("apply", "--yes")[0], 1)
            self.assertFalse(self.github_edits())
            self.assertFalse((self.state / "deploy_ed25519").exists())

    def test_auth_inspection_authorization_and_root_failures_are_sanitized(self):
        for failure in ("auth", "inspect", "authorize", "root"):
            def fail(a, k):
                match = (failure == "auth" and a[:3] == ["gh", "auth", "status"]
                         or failure == "inspect" and a[0] == "ssh" and production.REMOTE_INSPECT in a[-1]
                         or failure == "authorize" and a[0] == "ssh" and production.REMOTE_AUTHORIZE in a[-1]
                         or failure == "root" and "HostKeyAlgorithms=ssh-ed25519" in a)
                if match:
                    raise subprocess.CalledProcessError(1, ["unexpected-raw-error"], output=PRIVATE, stderr=PERSONAL)
            self.failure = fail
            self.calls.clear()
            status, text = self.cli("apply", "--yes")
            self.assertEqual(status, 1)
            self.assertFalse(self.github_edits())
            if failure == "root":
                self.assertIn("administrator", text)
                self.assertIn("No SSH policy bypass", text)

    def test_timeout_never_exposes_command_or_stdin(self):
        def fail(a, k):
            raise subprocess.TimeoutExpired(["unexpected-raw-error"], 60, output=PRIVATE, stderr=PERSONAL)
        self.failure = fail
        self.assertEqual(self.cli("apply", "--yes")[0], 1)
        self.assertFalse(self.state.exists())

    def test_ipv6_custom_port_root_and_quoting(self):
        self.assertEqual(self.cli("apply", "--yes", "--host", "2001:db8::1", "--port", "2222", "--user", "root")[0], 0)
        self.assertEqual((self.state / "known_hosts").read_text(), "[2001:db8::1]:2222 " + HOST_PUBLIC + "\n")
        for argv, _ in self.calls:
            if argv[0] == "ssh" and "HostKeyAlgorithms=ssh-ed25519" not in argv:
                decoded = shlex.split(argv[-1])
                self.assertEqual(decoded[:2], ["python3", "-c"])
                self.assertIn(decoded[2], (production.REMOTE_INSPECT, production.REMOTE_AUTHORIZE))
                self.assertIn('UserKnownHostsFile="' + str(self.trust) + '"', argv)
        args = self.args()
        self.assertEqual(shlex.split(production.remote_python(args, "print('quoted')", "a'b c")),
                         ["sudo", "-n", "python3", "-c", "print('quoted')", "a'b c"])


class RemoteScriptTests(unittest.TestCase):
    """Execute only the inline Python, mapping every absolute path to temp storage."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.base.chmod(0o700)
        for directory in ("root", "etc/ssh", "opt/conspect/deploy"):
            (self.base / directory).mkdir(parents=True, mode=0o700)
        for name in (".env", "deploy/bootstrap.py", "deploy/release.py"):
            path = self.base / "opt/conspect" / name
            path.write_bytes(b"server-secret-never-print")
            path.chmod(0o600)
        (self.base / "etc/ssh/ssh_host_ed25519_key.pub").write_text(HOST_PUBLIC + " host@server\n")
        self.authorized = self.base / "root/.ssh/authorized_keys"
        self.unsafe = None

    def execute(self, code, data=b""):
        base, unsafe = self.base, self.unsafe

        class RemotePath:
            def __init__(self, value):
                self.logical = PurePosixPath(value)
                self.real = base / str(self.logical).lstrip("/")

            def __fspath__(self):
                return str(self.real)

            def __truediv__(self, value):
                return RemotePath(self.logical / value)

            @property
            def parent(self):
                return RemotePath(self.logical.parent)

            @property
            def parents(self):
                return tuple(RemotePath(p) for p in self.logical.parents)

            def lstat(self):
                info = self.real.lstat()
                # Virtual server files belong to root, irrespective of the test UID.
                return SimpleNamespace(st_uid=1000 if str(self.logical) == unsafe else 0,
                                       st_mode=info.st_mode, st_nlink=info.st_nlink,
                                       st_ino=info.st_ino, st_size=info.st_size)

            def mkdir(self, **kwargs):
                self.real.mkdir(**kwargs)

            def open(self, *args):
                return self.real.open(*args)

        stdin = SimpleNamespace(buffer=io.BytesIO(data))
        stdout = SimpleNamespace(buffer=io.BytesIO())
        with patch("pathlib.Path", RemotePath), patch("sys.stdin", stdin), patch("sys.stdout", stdout), \
                patch("sys.argv", ["-c", "/opt/conspect"]), patch("os.geteuid", return_value=0):
            exec(compile(code, "<remote-script>", "exec"), {})
        return stdout.buffer.getvalue()

    def test_inspection_returns_only_host_public_key(self):
        output = self.execute(production.REMOTE_INSPECT)
        self.assertEqual(production.public_key(output), HOST_PUBLIC)
        self.assertNotIn(b"server-secret", output)
        self.assertFalse(self.authorized.exists())

    def test_missing_unsafe_or_untrusted_installation_refused(self):
        self.unsafe = "/opt/conspect/deploy/release.py"
        with self.assertRaises(ValueError):
            self.execute(production.REMOTE_INSPECT)
        self.unsafe = None
        (self.base / "opt/conspect/.env").chmod(0o644)
        with self.assertRaises(ValueError):
            self.execute(production.REMOTE_INSPECT)
        (self.base / "opt/conspect/.env").unlink()
        with self.assertRaises(FileNotFoundError):
            self.execute(production.REMOTE_INSPECT)

    def test_append_is_restricted_idempotent_and_preserves_existing_bytes(self):
        self.authorized.parent.mkdir(mode=0o700)
        old = b"# existing trust\nno-agent-forwarding ssh-ed25519 old-key personal\nssh-rsa another-key no-newline"
        self.authorized.write_bytes(old)
        self.authorized.chmod(0o600)
        for _ in range(2):
            self.execute(production.REMOTE_AUTHORIZE, (PUBLIC + "\n").encode())
        self.assertEqual(self.authorized.read_bytes(), old + b"\nrestrict " + PUBLIC.encode() + b" conspect-actions-deploy-v1\n")
        self.assertEqual(stat.S_IMODE(self.authorized.stat().st_mode), 0o600)

    def test_fresh_root_authorization_and_invalid_input(self):
        with self.assertRaises(ValueError):
            self.execute(production.REMOTE_AUTHORIZE, b"ssh-rsa AAAA")
        self.assertFalse(self.authorized.parent.exists())
        self.execute(production.REMOTE_AUTHORIZE, PUBLIC.encode())
        self.assertEqual(stat.S_IMODE(self.authorized.parent.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(self.authorized.stat().st_mode), 0o600)

    def test_remote_symlink_hardlink_and_writable_authorized_keys_refused(self):
        self.authorized.parent.mkdir(mode=0o700)
        original = self.base / "original"
        original.write_text("preserve me")
        original.chmod(0o600)
        for kind in ("symlink", "hardlink", "writable"):
            with self.subTest(kind=kind):
                if kind == "symlink":
                    self.authorized.symlink_to(original)
                elif kind == "hardlink":
                    os.link(original, self.authorized)
                else:
                    self.authorized.write_text("preserve me")
                    self.authorized.chmod(0o666)
                with self.assertRaises(ValueError):
                    self.execute(production.REMOTE_AUTHORIZE, PUBLIC.encode())
                self.authorized.unlink()
                self.assertEqual(original.read_text(), "preserve me")


if __name__ == "__main__":
    unittest.main()
