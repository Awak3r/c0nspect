"""Transport contracts only: fake SSH/git, synthetic credentials, no live host."""

import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from deploy import Deployment, IMAGE


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.env = {
            "DEPLOY_HOST": "example.com",
            "DEPLOY_USER": "root",
            "DEPLOY_STATE": str(self.base / "state"),
            "DEPLOY_SSH_KEY": "synthetic-test-key",
            "DEPLOY_KNOWN_HOSTS": "example.com ssh-ed25519 synthetic-test-host-key",
            "GITHUB_SHA": "a" * 40,
            "GITHUB_RUN_ID": "1234",
            "GITHUB_RUN_ATTEMPT": "2",
            "GITHUB_ACTOR": "Awak3r",
            "IMAGE_DIGEST": "sha256:" + "b" * 64,
            "GITHUB_TOKEN": "synthetic-test-token",
            "GITHUB_OUTPUT": str(self.base / "output"),
        }
        self.environment = patch.dict(os.environ, self.env, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def test_defaults_and_unique_staging(self):
        deployment = Deployment()
        self.assertEqual(deployment.port, "22")
        self.assertEqual(deployment.root, "/opt/conspect")
        self.assertEqual(deployment.staging, f"/opt/conspect/.releases/{'a' * 40}-1234-2")
        os.environ["GITHUB_RUN_ATTEMPT"] = "3"
        self.assertNotEqual(deployment.staging, Deployment().staging)
        with patch.dict(os.environ, {"RUNNER_TEMP": str(self.base)}):
            del os.environ["DEPLOY_STATE"]
            self.assertEqual(Deployment().state, self.base / "conspect-deploy")

    def test_invalid_configuration_rejected_before_any_ssh(self):
        invalid = {
            "DEPLOY_HOST": ["-oProxyCommand=evil", "host;id", "host name", "a..b", "a:b", "host/dir"],
            "DEPLOY_USER": ["deploy", "root;id", ""],
            "DEPLOY_PORT": ["0", "65536", "22;id", "22\n"],
            "DEPLOY_PATH": ["/", "relative", "/opt/../etc", "/opt/./app", "/opt//app", "/opt/app/", "/opt/a;id", "/opt/a b"],
            "GITHUB_SHA": ["HEAD", "a" * 39, "a" * 40 + ";id"],
            "GITHUB_RUN_ID": ["0", "-1", "1/2"],
            "GITHUB_RUN_ATTEMPT": ["0", "1;id"],
            "GITHUB_ACTOR": ["a;id", "-bad", "a b"],
            "IMAGE_DIGEST": ["latest", "sha256:123", "sha256:" + "b" * 64 + ";id"],
            "DEPLOY_STATE": ["relative"],
        }
        for name, values in invalid.items():
            for value in values:
                with self.subTest(name=name, value=value), patch.dict(os.environ, {name: value}):
                    with self.assertRaises(ValueError):
                        Deployment()

    def test_ipv4_ipv6_and_bot_actor(self):
        for host in ["127.0.0.1", "::1", "2001:db8::1", "ci.example.com"]:
            with self.subTest(host=host), patch.dict(os.environ, {"DEPLOY_HOST": host, "GITHUB_ACTOR": "dependabot[bot]"}):
                self.assertEqual(Deployment().host, host)

    def test_private_credentials_and_configured_output(self):
        deployment = Deployment()
        deployment.configure()
        self.assertEqual(deployment.state.stat().st_mode & 0o777, 0o700)
        for name in ["identity", "known_hosts"]:
            self.assertEqual((deployment.state / name).stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.base / "output").read_text(), "configured=true\n")
        with self.assertRaises(FileExistsError):
            deployment.configure()

    def test_missing_secrets_leave_no_state(self):
        for secret in ["DEPLOY_SSH_KEY", "DEPLOY_KNOWN_HOSTS"]:
            with self.subTest(secret=secret), patch.dict(os.environ, {secret: ""}):
                deployment = Deployment()
                with self.assertRaises(ValueError):
                    deployment.configure()
                self.assertFalse(deployment.state.exists())

    @patch("deploy.subprocess.run")
    def test_ssh_strict_options_no_shell_and_timeout(self, run):
        deployment = Deployment()
        command = shlex.join(["echo", "a b; $(id)"])
        deployment.ssh(command)
        argv = run.call_args.args[0]
        self.assertEqual(argv[-3:], ["--", "example.com", command])
        self.assertIn("StrictHostKeyChecking=yes", argv)
        self.assertIn("BatchMode=yes", argv)
        self.assertIn("IdentitiesOnly=yes", argv)
        self.assertIn("IdentityAgent=none", argv)
        self.assertIn("ServerAliveCountMax=4", argv)
        self.assertIn(f"UserKnownHostsFile={deployment.state / 'known_hosts'}", argv)
        self.assertEqual(argv[1:4], ["-F", "/dev/null", "-T"])
        self.assertEqual(run.call_args.kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(run.call_args.kwargs["timeout"], 120)
        self.assertNotIn("shell", run.call_args.kwargs)

    @patch("deploy.subprocess.run")
    def test_release_archive_and_token_only_on_stdin(self, run):
        deployment = Deployment()
        deployment.configure()
        deployment.release()
        calls = run.call_args_list
        self.assertEqual(len(calls), 4)
        self.assertEqual(calls[0].args[0], ["git", "archive", "--format=tar", "a" * 40, "compose.yaml", "deploy"])
        self.assertIn("mkdir -- " + deployment.staging, calls[1].args[0][-1])
        self.assertEqual(shlex.split(calls[2].args[0][-1]), ["tar", "-xf", "-", "-C", deployment.staging])
        command = shlex.split(calls[3].args[0][-1])
        self.assertEqual(command[:2], ["python3", deployment.staging + "/deploy/release.py"])
        options = dict(zip(command[2::2], command[3::2]))
        self.assertEqual(options, {
            "--source": deployment.staging,
            "--root": "/opt/conspect",
            "--image": IMAGE + "@sha256:" + "b" * 64,
            "--registry-user": "Awak3r",
            "--revision": "a" * 40,
        })
        self.assertEqual(calls[3].kwargs["input"], b"synthetic-test-token\n")
        self.assertIsNone(calls[3].kwargs["stdin"])
        for call in calls:
            self.assertNotIn("synthetic-test-token", str(call.args))
        self.assertTrue((deployment.state / "staged").exists())

    @patch("deploy.subprocess.run")
    def test_invalid_token_prevents_remote_side_effects(self, run):
        for token in ["", "token\nsecond", "token\r"]:
            with self.subTest(token=token), patch.dict(os.environ, {"GITHUB_TOKEN": token}):
                with self.assertRaises(ValueError):
                    Deployment().release()
        run.assert_not_called()

    @patch("deploy.subprocess.run")
    def test_cleanup_only_removes_confirmed_staging(self, run):
        deployment = Deployment()
        deployment.configure()
        deployment.cleanup()
        run.assert_not_called()
        self.assertFalse(deployment.state.exists())
        deployment.configure()
        (deployment.state / "staged").touch()
        deployment.cleanup()
        self.assertEqual(shlex.split(run.call_args.args[0][-1]), ["rm", "-rf", "--", deployment.staging])
        self.assertFalse(deployment.state.exists())

    @patch("deploy.subprocess.run", side_effect=subprocess.TimeoutExpired("ssh", 60))
    def test_cleanup_failure_still_removes_private_credentials(self, run):
        deployment = Deployment()
        deployment.configure()
        (deployment.state / "staged").touch()
        with self.assertRaises(subprocess.TimeoutExpired):
            deployment.cleanup()
        self.assertFalse(deployment.state.exists())

    @patch("deploy.subprocess.run")
    def test_failed_staging_creation_does_not_mark_foreign_directory(self, run):
        deployment = Deployment()
        deployment.configure()
        run.side_effect = [None, subprocess.CalledProcessError(1, "ssh")]
        with self.assertRaises(subprocess.CalledProcessError):
            deployment.release()
        self.assertFalse((deployment.state / "staged").exists())


if __name__ == "__main__":
    unittest.main()
