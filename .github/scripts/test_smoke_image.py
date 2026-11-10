"""Image smoke contracts: fake Docker/HTTP, no production configuration or host."""

from contextlib import redirect_stderr, redirect_stdout
from email.message import Message
import io
import itertools
import json
import os
import subprocess
import unittest
from unittest.mock import Mock, patch

import smoke_image as smoke


class ImageSmokeTests(unittest.TestCase):
    def setUp(self):
        self.image = "ghcr.io/example/conspect:" + "a" * 40
        self.containers = []
        self.networks = []
        self.commands = []
        self.http_calls = []
        self.environments = {}
        self.fail_at = None
        self.timeout_at = None
        self.ready = True
        self.responses = {
            "/healthz": (200, {}, b""),
            "/.well-known/oauth-protected-resource/mcp": (200, {"Content-Type": "application/json"}, {
                "resource": smoke.BASE_URL + "/mcp", "authorization_servers": [smoke.BASE_URL],
                "bearer_methods_supported": ["header"],
            }),
            "/.well-known/oauth-authorization-server": (200, {"Content-Type": "application/json; charset=utf-8"}, {
                "issuer": smoke.BASE_URL,
                "authorization_endpoint": smoke.BASE_URL + "/oauth/authorize",
                "token_endpoint": smoke.BASE_URL + "/oauth/token",
                "registration_endpoint": smoke.BASE_URL + "/oauth/register",
                "revocation_endpoint": smoke.BASE_URL + "/oauth/revoke",
                "code_challenge_methods_supported": ["S256"],
            }),
            "/mcp": (401, {"WWW-Authenticate": f'Bearer resource_metadata="{smoke.RESOURCE_METADATA}", error="invalid_token"'}, {}),
        }
        for context in (
            patch("smoke_image.subprocess.run", side_effect=self.fake_docker),
            patch("smoke_image.http.client.HTTPConnection", side_effect=self.fake_connection),
            patch("smoke_image.time.sleep"),
            patch.dict(os.environ, {"DATABASE_URL": "production-must-not-be-used", "APP_SECRET": "production-must-not-be-used"}),
        ):
            context.start()
            self.addCleanup(context.stop)

    def fake_docker(self, command, **kwargs):
        self.assertEqual(command[0], "docker")
        self.assertIs(kwargs["stdin"], subprocess.DEVNULL)
        self.assertTrue(kwargs["capture_output"])
        self.assertTrue(kwargs["text"])
        self.assertGreater(kwargs["timeout"], 0)
        self.assertLessEqual(kwargs["timeout"], 180)
        self.assertNotIn("shell", kwargs)
        self.commands.append(command)
        arguments = command[1:]
        output = ""
        if arguments[:2] == ["image", "inspect"]:
            operation = "inspect"
        elif arguments[:2] == ["network", "create"]:
            operation = "network"
            self.networks.append("network-owned")
        elif arguments[0] == "run":
            operation = "db" if arguments[-1] == smoke.POSTGRES_IMAGE else "app"
            self.containers.append(operation + "-owned")
            self.environments[operation] = kwargs["env"]
        elif arguments[0] == "exec":
            operation = "ready"
            if not self.ready:
                return subprocess.CompletedProcess(command, 1, "", "not ready")
        elif arguments[:2] == ["container", "ls"]:
            operation = "list-containers"
            output = "\n".join(self.containers)
        elif arguments[:2] == ["network", "ls"]:
            operation = "list-networks"
            output = "\n".join(self.networks)
        elif arguments[:2] == ["container", "rm"]:
            operation = "remove-" + arguments[-1].removesuffix("-owned")
            if self.fail_at != operation:
                self.containers.remove(arguments[-1])
        elif arguments[:2] == ["network", "rm"]:
            operation = "remove-network"
            if self.fail_at != operation:
                self.networks.remove(arguments[-1])
        else:
            self.fail(f"unexpected Docker command: {command}")
        # Fail after creation to simulate Docker leaving a partially started resource.
        if operation == self.timeout_at:
            raise subprocess.TimeoutExpired(command, kwargs["timeout"], output="private raw Docker output")
        code = 125 if operation == self.fail_at else 0
        return subprocess.CompletedProcess(command, code, output, "private raw Docker output")

    def fake_connection(self, host, port, timeout):
        self.assertEqual((host, port), ("127.0.0.1", 18080))
        self.assertEqual(timeout, 3)
        connection = Mock()

        def getresponse():
            method, path = connection.request.call_args.args
            self.http_calls.append((method, path, connection.request.call_args.kwargs))
            status, values, data = self.responses[path]
            headers = Message()
            for key, value in values.items():
                headers[key] = value
            response = Mock(status=status, headers=headers)
            response.read.return_value = json.dumps(data).encode() if isinstance(data, (dict, list)) else data
            return response

        connection.getresponse.side_effect = getresponse
        return connection

    def assert_clean(self):
        self.assertEqual(self.containers, [])
        self.assertEqual(self.networks, [])

    def test_successful_checks_isolation_and_cleanup(self):
        instance = smoke.ImageSmoke(self.image)
        instance.run()
        self.assert_clean()
        network = next(command for command in self.commands if command[1:3] == ["network", "create"])
        self.assertNotIn("--internal", network)
        self.assertIn(instance.selector, network)
        runs = [command for command in self.commands if command[1] == "run"]
        self.assertEqual(len(runs), 2)
        database, app = runs
        self.assertEqual(database[-1], "postgres:17-alpine")
        self.assertEqual(app[-1], self.image)
        self.assertNotIn("--publish", database)
        self.assertEqual(app[app.index("--publish") + 1], "127.0.0.1:18080:8080")
        self.assertIn("--pull=never", app)
        self.assertIn("--read-only", app)
        self.assertIn("/data/uploads:rw,uid=10001,gid=10001", app)
        for command in runs:
            self.assertEqual(command[command.index("--network") + 1], instance.network)
            self.assertEqual(command[command.index("--platform") + 1], "linux/amd64")
            self.assertIn(instance.selector, command)
            self.assertNotIn("--env-file", command)
            self.assertNotIn("--volume", command)
        ready = next(command for command in self.commands if command[1] == "exec")
        self.assertIn("pg_isready", ready)
        self.assertEqual(ready[ready.index("--host") + 1], "127.0.0.1")
        environment = self.environments["app"]
        self.assertEqual(environment["APP_BASE_URL"], smoke.BASE_URL)
        self.assertEqual(environment["APP_ADDR"], ":8080")
        self.assertEqual(environment["MCP_API_URL"], "http://127.0.0.1:8080")
        self.assertEqual(environment["MCP_ENABLED"], "true")
        self.assertEqual(environment["TRUST_PROXY"], "false")
        self.assertRegex(environment["APP_SECRET"], r"^[0-9a-f]{64}$")
        self.assertGreaterEqual(len(environment["OWNER_PASSWORD"]), 32)
        password = self.environments["db"]["POSTGRES_PASSWORD"]
        self.assertEqual(environment["DATABASE_URL"], f"postgres://smoke:{password}@db:5432/smoke?sslmode=disable")
        for secret in (password, environment["APP_SECRET"], environment["OWNER_PASSWORD"]):
            self.assertNotIn(secret, str(self.commands))
        self.assertEqual([(method, path) for method, path, _ in self.http_calls], [
            ("GET", "/healthz"), ("GET", "/.well-known/oauth-protected-resource/mcp"),
            ("GET", "/.well-known/oauth-authorization-server"), ("POST", "/mcp"),
        ])
        post = self.http_calls[-1][2]
        self.assertEqual(post["body"], b"{}")
        self.assertEqual(post["headers"]["Content-Type"], "application/json")
        self.assertNotIn("Authorization", post["headers"])
        for command in self.commands:
            if command[1:3] in (["container", "ls"], ["network", "ls"]):
                self.assertEqual(command[command.index("--filter") + 1], "label=" + instance.selector)
        removals = [command for command in self.commands if command[2] == "rm"]
        self.assertEqual([command[-1] for command in removals], ["db-owned", "app-owned", "network-owned"])
        self.assertTrue(all("--volumes" in command for command in removals[:2]))

    def test_unique_resource_ownership(self):
        first, second = smoke.ImageSmoke(self.image), smoke.ImageSmoke(self.image)
        self.assertNotEqual(first.selector, second.selector)
        self.assertNotEqual(first.network, second.network)
        self.assertRegex(first.network, r"^conspect-smoke-[0-9a-f]{32}$")

    def test_missing_local_image_does_not_create_resources_or_pull(self):
        self.fail_at = "inspect"
        with self.assertRaisesRegex(smoke.SmokeError, "Inspect local app image"):
            smoke.ImageSmoke(self.image).run()
        self.assert_clean()
        self.assertEqual(len(self.commands), 1)

    def test_cleanup_after_partial_docker_creation_failure(self):
        for operation in ("network", "db", "app"):
            with self.subTest(operation=operation):
                self.fail_at = operation
                with self.assertRaises(smoke.SmokeError):
                    smoke.ImageSmoke(self.image).run()
                self.assert_clean()

    def test_cleanup_after_docker_timeout(self):
        self.timeout_at = "db"
        with self.assertRaisesRegex(smoke.SmokeError, "Docker command timed out"):
            smoke.ImageSmoke(self.image).run()
        self.assert_clean()

    def test_readiness_waits_are_bounded_and_cleanup_runs(self):
        for target in ("database", "app"):
            with self.subTest(target=target):
                self.ready = target != "database"
                self.responses["/healthz"] = (503, {}, b"unavailable")
                with patch("smoke_image.time.monotonic", side_effect=itertools.count(0, 31)):
                    with self.assertRaisesRegex(smoke.SmokeError, "Timed out waiting"):
                        smoke.ImageSmoke(self.image).run()
                self.assert_clean()

    def test_cleanup_on_interruption(self):
        with patch("smoke_image.check_endpoints", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                smoke.ImageSmoke(self.image).run()
        self.assert_clean()

    def test_cleanup_keeps_trying_after_one_removal_fails(self):
        self.fail_at = "remove-db"
        instance = smoke.ImageSmoke(self.image)
        with self.assertRaisesRegex(smoke.SmokeError, "Cleanup failed"):
            instance.run()
        self.assertEqual(self.containers, ["db-owned"])
        self.assertIn(["docker", "container", "rm", "--force", "--volumes", "app-owned"], self.commands)
        self.assertIn(["docker", "network", "rm", "network-owned"], self.commands)

    def test_cleanup_network_is_attempted_if_container_listing_fails(self):
        self.fail_at = "list-containers"
        with self.assertRaisesRegex(smoke.SmokeError, "Cleanup failed"):
            smoke.ImageSmoke(self.image).run()
        self.assertIn(["docker", "network", "rm", "network-owned"], self.commands)

    def test_incorrect_discovery_is_rejected_and_cleaned(self):
        for path in ("/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-authorization-server"):
            status, headers, document = self.responses[path]
            for key in document:
                with self.subTest(path=path, field=key):
                    changed = dict(document, **{key: "http://incorrect.invalid"})
                    self.responses[path] = (status, headers, changed)
                    with self.assertRaises(smoke.SmokeError):
                        smoke.ImageSmoke(self.image).run()
                    self.assert_clean()
            self.responses[path] = (status, headers, document)

    def test_plain_pkce_is_not_accepted_alongside_s256(self):
        path = "/.well-known/oauth-authorization-server"
        self.responses[path][2]["code_challenge_methods_supported"] = ["S256", "plain"]
        with self.assertRaisesRegex(smoke.SmokeError, "PKCE S256"):
            smoke.ImageSmoke(self.image).run()
        self.assert_clean()

    def test_bad_discovery_responses_do_not_pass_or_redirect(self):
        for response in (
            (302, {"Location": "https://production.invalid"}, b""),
            (200, {"Content-Type": "text/html"}, b"not metadata"),
            (200, {"Content-Type": "application/json"}, b"{invalid"),
            (200, {"Content-Type": "application/json"}, []),
            (200, {"Content-Type": "application/json"}, b"x" * (smoke.MAX_RESPONSE_BYTES + 1)),
        ):
            with self.subTest(status=response[0], content_type=response[1].get("Content-Type")):
                self.responses["/.well-known/oauth-protected-resource/mcp"] = response
                with self.assertRaises(smoke.SmokeError):
                    smoke.ImageSmoke(self.image).run()
                self.assert_clean()
                self.assertFalse(any("production.invalid" in path for _, path, _ in self.http_calls))

    def test_invalid_mcp_status_or_challenge_is_rejected_and_cleaned(self):
        valid = self.responses["/mcp"][1]["WWW-Authenticate"]
        for status, challenge in (
            (200, valid), (403, valid), (401, ""), (401, valid.replace("Bearer", "Basic")),
            (401, valid.replace(smoke.RESOURCE_METADATA, "https://wrong.invalid/metadata")),
            (401, valid.replace("invalid_token", "invalid_request")),
            (401, valid + ', error="invalid_token"'), (401, "Bearer malformed"),
        ):
            with self.subTest(status=status, challenge=challenge):
                self.responses["/mcp"] = (status, {"WWW-Authenticate": challenge}, {})
                with self.assertRaisesRegex(smoke.SmokeError, "expected HTTP 401"):
                    smoke.ImageSmoke(self.image).run()
                self.assert_clean()

    def test_challenge_order_scheme_case_and_extra_fields_are_not_significant(self):
        self.responses["/mcp"] = (401, {"WWW-Authenticate": (
            f'bearer error="invalid_token", realm="smoke", resource_metadata="{smoke.RESOURCE_METADATA}"'
        )}, {})
        smoke.ImageSmoke(self.image).run()
        self.assert_clean()

    def test_http_failure_is_sanitized_and_connection_closed(self):
        connection = Mock()
        connection.request.side_effect = OSError("private HTTP diagnostics")
        with patch("smoke_image.http.client.HTTPConnection", return_value=connection):
            with self.assertRaisesRegex(smoke.SmokeError, r"^GET /healthz: HTTP request failed\.$"):
                smoke.request("GET", "/healthz")
        connection.close.assert_called_once()

    def test_cli_failure_does_not_print_raw_docker_output_or_secrets(self):
        self.fail_at = "app"
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(smoke.sys, "argv", ["smoke_image.py", self.image]), redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(smoke.main(), 1)
        self.assert_clean()
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("Start smoke app: Docker command failed", stderr.getvalue())
        self.assertNotIn("private raw Docker output", stderr.getvalue())
        for key in ("APP_SECRET", "OWNER_PASSWORD", "DATABASE_URL"):
            self.assertNotIn(self.environments["app"][key], stderr.getvalue())

    def test_cli_success_is_reported_only_after_cleanup(self):
        stdout = io.StringIO()
        with patch.object(smoke.sys, "argv", ["smoke_image.py", self.image]), redirect_stdout(stdout):
            self.assertEqual(smoke.main(), 0)
        self.assert_clean()
        self.assertIn("Image smoke passed", stdout.getvalue())

    def test_invalid_cli_does_not_call_docker(self):
        for arguments in ([], [self.image, "extra"], ["--privileged"], ["image with whitespace"]):
            with self.subTest(arguments=arguments):
                with patch.object(smoke.sys, "argv", ["smoke_image.py", *arguments]), redirect_stderr(io.StringIO()):
                    self.assertNotEqual(smoke.main(), 0)
                self.assertEqual(self.commands, [])


if __name__ == "__main__":
    unittest.main()
