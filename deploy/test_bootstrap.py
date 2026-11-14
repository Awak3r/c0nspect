"""Offline bootstrap regressions: real temporary files/flocks, no provisioning.

Only ownership is simulated. File types, modes, link counts, atomic staging and
both bootstrap/operations locks use the real filesystem. Unsafe behavior is not
marked expectedFailure: implementation fixes belong in bootstrap.py.
"""

import contextlib
from copy import deepcopy
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import socket
import ssl
import stat
import subprocess
import tempfile
import threading
import traceback
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch
from urllib.parse import parse_qs

import bootstrap
import operations
from operations import OperationError


REVISION = "a" * 40
IMAGE = "ghcr.io/awak3r/c0nspect@sha256:" + "b" * 64
ORIGIN = "https://notes.example.net"
DATABASE_PASSWORD = "c2" * 32
APP_SECRET = "d3" * 32
OWNER_PASSWORD = "offline-owner-password-never-log"
PRIVATE = "synthetic-inherited-secret-never-log"
INSTALLATION_ID = "e4" * 16
OTHER_INSTALLATION_ID = "f5" * 16
APP_IMAGE_ID = "sha256:" + "16" * 32
DB_IMAGE_ID = "sha256:" + "27" * 32
SESSION_COOKIE = "synthetic-session-cookie-never-log"
COMPOSE = b"""# Synthetic approved source; never passed to a real Docker client.
services:
  app:
    image: ${CONSPECT_IMAGE:?choose an immutable digest}
    environment:
      APP_BASE_URL: ${APP_BASE_URL}
      APP_SECRET: ${APP_SECRET}
      DATABASE_URL: ${DATABASE_URL}
      MCP_ENABLED: ${MCP_ENABLED:-true}
      DATA_DIR: /data
  db:
    image: postgres:17-alpine
    environment:
      POSTGRES_DB: ${POSTGRES_DB}
      POSTGRES_USER: ${POSTGRES_USER}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
"""


class BootstrapFixture(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="conspect-bootstrap-test-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.root = self.base / "opt/conspect"
        self.root.parent.mkdir(mode=0o750)
        self.source = self.base / "approved-source"
        (self.source / "deploy").mkdir(parents=True, mode=0o750)
        self.home = self.base / "root-home"
        self.home.mkdir(mode=0o700)
        deployment = Path(bootstrap.__file__).parent
        # Stage no real application/source tree. These two small production
        # templates keep proxy-generation tests faithful to the supported setup.
        self.source_bytes = {
            "compose.yaml": COMPOSE,
            "deploy/compose.nginx.yaml": (deployment / "compose.nginx.yaml").read_bytes(),
            "deploy/nginx.tls.conf": (deployment / "nginx.tls.conf").read_bytes(),
            "deploy/operations.py": b"# Synthetic deployment placeholder; never executed.\n",
        }
        for name, data in self.source_bytes.items():
            path = self.source / name
            path.write_bytes(data)
            path.chmod(0o640)
        self.host = self.base / "host"
        for name, data in {
            "etc/caddy/Caddyfile": b"{\n    admin off\n}\n# existing NaiveProxy site\n",
            "etc/nginx/nginx.conf": b"# Existing shared nginx configuration\n",
            "etc/hosts": b"127.0.0.1 localhost\n",
            "etc/systemd/system/existing-vpn.service": b"# Existing VPN, do not touch\n",
            "etc/docker/daemon.json": b'{"live-restore":true}\n',
        }.items():
            path = self.host / name
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
            path.write_bytes(data)
            path.chmod(0o600)

        self.events = []
        self.commands = []
        self.states_written = []
        self.failures = set()
        self.errors = {}
        self.owners = {}
        self.inventory = {"containers": "", "names": "", "volumes": "", "networks": ""}
        self.containers = {}
        self.volumes = {}
        self.networks = {}
        self.container_inspections = []
        self.cached_db_image_id = DB_IMAGE_ID
        self.project_lock = self.base / "opt/global.lock"
        self.enter(patch.object(bootstrap, "PROJECT_LOCK", self.project_lock))
        self.bootstrap_locked = False
        self.operation_locked = False
        self.started = False
        self.db_present = False
        self.backup_count = 0
        self.on_event = None
        self.current_command = None
        self.previous_root = self.base / "unrelated-operations-root"
        self.stdout = io.StringIO()
        self.stderr = io.StringIO()
        self.enter(contextlib.redirect_stdout(self.stdout))
        self.enter(contextlib.redirect_stderr(self.stderr))
        self.enter(patch.dict(os.environ, {"PATH": os.defpath, "HOME": str(self.home)}, clear=True))
        self.enter(patch.object(Path, "home", return_value=self.home))
        old_umask = os.umask(0o077)
        self.addCleanup(os.umask, old_umask)

        self.real_stat = Path.stat
        real_fstat = os.fstat
        external_parents = set(self.base.parents)

        def owned_stat(path, *, follow_symlinks=True):
            info = list(self.real_stat(path, follow_symlinks=follow_symlinks))
            if path == self.base or self.base in path.parents:
                info[4] = self.owners.get(path, 0)
            elif path in external_parents:
                # /tmp is only a stand-in for a trusted /opt ancestor.
                info[4] = 0
                info[0] &= ~0o022
            return os.stat_result(info)

        def owned_fstat(descriptor):
            info = list(real_fstat(descriptor))
            info[4] = 0
            for path, owner in self.owners.items():
                try:
                    entry = self.real_stat(path, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if (entry.st_dev, entry.st_ino) == (info[2], info[1]):
                    info[4] = owner
            return os.stat_result(info)

        self.enter(patch.object(Path, "stat", owned_stat))
        self.enter(patch.object(os, "fstat", owned_fstat))
        self.enter(patch.object(bootstrap.os, "geteuid", return_value=0))
        self.enter(patch.object(bootstrap.sys, "platform", "linux"))
        self.enter(patch.object(operations, "ROOT", self.previous_root))
        # All external entry points fail closed, even if orchestration grows a
        # new subprocess or network path not covered by the fakes below.
        self.process = self.enter(patch.object(subprocess, "run", side_effect=AssertionError("Unexpected real subprocess")))
        self.enter(patch.object(subprocess, "Popen", side_effect=AssertionError("Unexpected real subprocess")))
        self.enter(patch.object(os, "system", side_effect=AssertionError("Unexpected shell command")))
        self.network = self.enter(patch.object(socket, "socket", side_effect=AssertionError("Unexpected network socket")))
        self.dns = self.enter(patch.object(socket, "getaddrinfo", side_effect=AssertionError("Unexpected DNS lookup")))
        self.enter(patch.object(socket, "create_connection", side_effect=AssertionError("Unexpected network connection")))
        self.https = self.enter(patch.object(http.client, "HTTPSConnection", side_effect=AssertionError("Unexpected HTTPS connection")))
        self.enter(patch.object(operations, "run_command", side_effect=AssertionError("Unexpected real Docker")))
        self.which = self.enter(patch.object(bootstrap.shutil, "which", return_value="/usr/bin/docker"))

        self.real_bootstrap_lock = bootstrap.bootstrap_lock
        self.real_free_port = bootstrap.free_port
        self.real_check_resources = bootstrap.check_resources
        self.real_atomic_write = bootstrap.atomic_write
        self.real_public_owner_check = bootstrap.public_owner_check
        self.enter(patch.object(bootstrap, "bootstrap_lock", side_effect=self.bootstrap_lock))
        self.enter(patch.object(bootstrap, "operation_lock", side_effect=self.operation_lock))
        self.local_docker = self.enter(patch.object(bootstrap, "check_local_docker", side_effect=lambda: self.event("local-docker")))
        self.prerequisites = self.enter(patch.object(bootstrap, "ensure_prerequisites", side_effect=self.fake_prerequisites))
        self.resources = self.enter(patch.object(bootstrap, "check_resources", side_effect=lambda root: self.event("resources")))
        self.port = self.enter(patch.object(bootstrap, "free_port", side_effect=lambda port: self.event("port")))
        self.docker = self.enter(patch.object(bootstrap, "run_command", side_effect=self.fake_command))
        self.compose = Mock()
        self.compose.preflight.side_effect = lambda **kwargs: self.operation_event("preflight")
        self.compose.container.side_effect = self.fake_container
        self.compose_factory = self.enter(patch.object(bootstrap, "Compose", side_effect=self.fake_compose))
        self.snapshot = self.enter(patch.object(bootstrap, "create_backup", side_effect=self.fake_backup))
        self.validator = self.enter(patch.object(bootstrap, "validate_bundle", side_effect=self.fake_validate))
        self.mcp = self.enter(patch.object(bootstrap, "check_mcp", side_effect=lambda url: self.operation_event("public")))
        self.public_owner = self.enter(patch.object(bootstrap, "public_owner_check", side_effect=lambda root, url: self.operation_event("public-owner")))
        self.byte_tokens = self.enter(patch.object(bootstrap.secrets, "token_bytes", return_value=bytes.fromhex(INSTALLATION_ID)))
        self.hex_tokens = self.enter(patch.object(bootstrap.secrets, "token_hex", side_effect=[DATABASE_PASSWORD, APP_SECRET]))
        self.owner_token = self.enter(patch.object(bootstrap.secrets, "token_urlsafe", return_value=OWNER_PASSWORD))
        self.writer = self.enter(patch.object(bootstrap, "atomic_write", side_effect=self.record_write))

    def enter(self, manager):
        value = manager.__enter__()
        self.addCleanup(manager.__exit__, None, None, None)
        return value

    def event(self, name):
        self.events.append(name)
        if self.on_event:
            self.on_event(name)
        if name in self.errors:
            raise self.errors[name]
        if name in self.failures:
            raise OperationError("Synthetic bootstrap " + name + " failure")

    def operation_event(self, name):
        self.assertTrue(self.operation_locked, name + " must hold the real operations lock")
        self.assertEqual(operations.ROOT, self.root)
        if self.current_command == "install":
            self.assertTrue(self.bootstrap_locked, name + " must hold the bootstrap lock")
        self.event(name)

    @contextlib.contextmanager
    def bootstrap_lock(self, root):
        with self.real_bootstrap_lock(root):
            self.bootstrap_locked = True
            self.event("bootstrap-lock")
            try:
                yield
            finally:
                self.events.append("bootstrap-unlock")
                self.bootstrap_locked = False

    @contextlib.contextmanager
    def operation_lock(self):
        self.assertEqual(operations.ROOT, self.root)
        with operations.operation_lock():
            self.operation_locked = True
            self.event("operations-lock")
            try:
                yield
            finally:
                self.events.append("operations-unlock")
                self.operation_locked = False

    def fake_prerequisites(self, **kwargs):
        if self.current_command == "install":
            self.assertTrue(self.bootstrap_locked)
        self.event("prerequisites")

    def fake_command(self, command, **kwargs):
        command = list(command)
        self.commands.append((command, dict(kwargs), dict(os.environ)))
        self.assertGreater(kwargs.get("timeout", 0), 0)
        self.assertLessEqual(kwargs["timeout"], 300)
        for value in (DATABASE_PASSWORD, APP_SECRET, OWNER_PASSWORD, PRIVATE):
            self.assertNotIn(value, " ".join(command))
        for name in os.environ:
            self.assertFalse(name.startswith(("DOCKER_", "COMPOSE_")), name)
            self.assertNotIn(name, bootstrap.ENV_FIELDS)
        inventories = {
            ("docker", "ps", "--all", "--filter", "label=com.docker.compose.project=conspect", "--format", "{{.ID}}"): "containers",
            ("docker", "ps", "--all", "--format", "{{.Names}}"): "names",
            ("docker", "volume", "ls", "--format", "{{.Name}}"): "volumes",
            ("docker", "network", "ls", "--format", "{{.Name}}"): "networks",
        }
        if tuple(command) in inventories:
            name = inventories[tuple(command)]
            self.assertTrue(self.bootstrap_locked or self.operation_locked)
            self.event("inventory-" + name)
            retained = {
                "containers": [item["Id"] for item in self.containers.values()
                               if (item["Config"].get("Labels") or {}).get("com.docker.compose.project") == "conspect"],
                "names": [item["Name"].lstrip("/") for item in self.containers.values()],
                "volumes": list(self.volumes),
                "networks": list(self.networks),
            }[name]
            return "\n".join([*self.inventory[name].splitlines(), *retained])
        if command[:2] == ["docker", "inspect"]:
            self.assertEqual(len(command), 3)
            self.assertTrue(self.bootstrap_locked or self.operation_locked)
            self.event("inspect-container")
            for item in self.containers.values():
                if command[2] in (item["Id"], item["Name"].lstrip("/")):
                    return json.dumps([item])
            self.fail("Unexpected container inspection: " + repr(command))
        if len(command) == 4 and command[0] == "docker" and command[1] in ("volume", "network") and command[2] == "inspect":
            self.assertTrue(self.bootstrap_locked or self.operation_locked)
            self.event("inspect-" + command[1])
            retained = self.volumes if command[1] == "volume" else self.networks
            self.assertIn(command[3], retained)
            return json.dumps([retained[command[3]]])
        if command == ["docker", "pull", "--platform", "linux/amd64", IMAGE]:
            self.operation_event("pull-image")
            return ""
        prefix = [
            "docker", "compose", "--project-directory", str(self.root),
            "--project-name", "conspect", "--env-file", str(self.root / ".env"),
            "-f", str(self.root / "compose.yaml"), "-f", str(self.root / "deploy/compose.nginx.yaml"),
        ]
        self.assertEqual(command[:len(prefix)], prefix)
        arguments = command[len(prefix):]
        if arguments == ["config", "--quiet"]:
            self.operation_event("config")
        elif arguments == ["ps", "--all", "--quiet", "db"]:
            self.operation_event("db-present")
            return "synthetic-db-id\n" if self.db_present else ""
        elif arguments == ["pull", "db"]:
            self.operation_event("pull-db")
        elif arguments and arguments[0] == "up":
            self.assertEqual(arguments, [
                "up", "--detach", "--no-recreate", "--no-build", "--pull", "never", "--wait",
                "--wait-timeout", "180", "app", "db",
            ])
            self.assertEqual(kwargs, {"timeout": 240})
            # Model --no-recreate: a changed cached postgres tag must not replace
            # an existing DB container, its configuration or its actual image ID.
            self.seed_resources()
            self.started = self.db_present = True
            self.operation_event("up")
        else:
            self.fail("Unexpected Docker/provisioning command: " + repr(command))
        return ""

    def fake_compose(self, *, nginx):
        self.assertIs(nginx, True)
        self.operation_event("compose")
        environment = self.environment()
        self.compose.app_env = {**environment, "DATA_DIR": "/data"}
        self.compose.db_env = {name: environment[name] for name in ("POSTGRES_DB", "POSTGRES_USER", "POSTGRES_PASSWORD")}
        self.compose.image_id = APP_IMAGE_ID
        self.compose.image = IMAGE
        return self.compose

    def seed_resources(self, *, root=None, identity=None):
        root = self.root if root is None else root
        identity = self.state()["installation_id"] if identity is None else identity
        environment = self.environment()
        labels = {
            "io.conspect.installation": identity,
            "com.docker.compose.project": "conspect",
            "com.docker.compose.project.working_dir": str(root),
        }
        for service in ("app", "db"):
            if service not in self.containers:
                actual_env = {**environment, "DATA_DIR": "/data"} if service == "app" else {
                    name: environment[name] for name in ("POSTGRES_DB", "POSTGRES_USER", "POSTGRES_PASSWORD")
                }
                self.containers[service] = {
                    "Id": "synthetic-" + service + "-id",
                    "Name": "/conspect-" + service + "-1",
                    "Image": APP_IMAGE_ID if service == "app" else self.cached_db_image_id,
                    "State": {"Status": "running", "Health": {"Status": "healthy"}},
                    "Config": {
                        "Labels": {**labels, "com.docker.compose.service": service},
                        "Env": [name + "=" + value for name, value in actual_env.items()],
                    },
                }
        for collection, names in (
            (self.volumes, ("conspect_db_data", "conspect_uploads")),
            (self.networks, ("conspect_backend", "conspect_frontend")),
        ):
            for name in names:
                collection.setdefault(name, {"Name": name, "Labels": dict(labels)})

    def fake_container(self, service):
        self.assertIn(service, ("app", "db"))
        item = deepcopy(self.containers.get(service))
        self.container_inspections.append((service, item))
        return item

    def fake_backup(self, compose, output):
        self.assertIs(compose, self.compose)
        self.assertEqual(output, self.root / "backups")
        self.operation_event("backup")
        self.backup_count += 1
        bundle = output / ("conspect-synthetic-" + str(self.backup_count))
        bundle.mkdir(parents=True, mode=0o700)
        (bundle / "config.env").write_bytes((self.root / ".env").read_bytes())
        for name in ("database.dump", "uploads.tar.gz", "compose.resolved.json", "manifest.json"):
            (bundle / name).write_bytes(b"Synthetic local backup; never restored.\n")
        return bundle

    def fake_validate(self, bundle):
        self.operation_event("validate-backup")
        self.assertEqual(bundle.parent, self.root / "backups")
        self.assertTrue(bundle.is_dir())
        self.assertEqual({path.name for path in bundle.iterdir()}, {
            "config.env", "database.dump", "uploads.tar.gz", "compose.resolved.json", "manifest.json",
        })
        return {"format": 1}

    def record_write(self, path, content, mode=0o600):
        self.assertTrue(self.base in path.parents, "All writes must stay in the temporary fixture")
        self.assertNotIn(self.host, path.parents)
        self.assertNotIn(self.source, path.parents)
        if path.name == ".bootstrap.json":
            self.states_written.append(json.loads(content))
        return self.real_atomic_write(path, content, mode)

    def arguments(self, command="install", **overrides):
        values = {"root": self.root}
        if command != "verify":
            values.update(source=self.source, url=ORIGIN, image=IMAGE, revision=REVISION, proxy="caddy", port=8096)
        if command == "install":
            values["yes"] = True
        values.update(overrides)
        arguments = [command]
        for name, value in values.items():
            flag = "--" + name.replace("_", "-")
            if isinstance(value, bool):
                if value:
                    arguments.append(flag)
            elif value is not None:
                arguments.extend((flag, str(value)))
        return arguments

    def cli(self, command="install", argv=None, **overrides):
        self.stdout.seek(0)
        self.stdout.truncate()
        self.stderr.seek(0)
        self.stderr.truncate()
        self.current_command = command
        result = bootstrap.main(self.arguments(command, **overrides) if argv is None else argv)
        self.assertEqual(operations.ROOT, self.previous_root, "Restore the shared operations root even on failure")
        return result

    @property
    def output(self):
        return self.stdout.getvalue() + self.stderr.getvalue()

    def environment(self):
        return dict(line.split("=", 1) for line in (self.root / ".env").read_text().splitlines() if line and not line.startswith("#"))

    def state(self):
        return json.loads((self.root / ".bootstrap.json").read_text())

    def write_state(self, state):
        (self.root / ".bootstrap.json").write_text(json.dumps(state), encoding="utf-8")

    def tree(self, directory):
        result = {}
        for path in [directory, *sorted(directory.rglob("*"))]:
            info = self.real_stat(path, follow_symlinks=False)
            data = os.readlink(path) if stat.S_ISLNK(info.st_mode) else path.read_bytes() if stat.S_ISREG(info.st_mode) else None
            result[str(path.relative_to(directory))] = (
                info.st_mode, info.st_ino, info.st_nlink, info.st_mtime_ns, info.st_ctime_ns, data,
            )
        return result

    def immutable_files(self):
        return {
            name: ((self.root / name).read_bytes(), self.real_stat(self.root / name).st_ino,
                   stat.S_IMODE((self.root / name).stat().st_mode))
            for name in self.state()["files"]
        }

    def reset_activity(self):
        self.events.clear()
        self.commands.clear()
        self.states_written.clear()
        self.container_inspections.clear()
        for mock in (self.local_docker, self.prerequisites, self.resources, self.port, self.docker, self.compose_factory,
                     self.snapshot, self.validator, self.mcp, self.public_owner, self.byte_tokens, self.hex_tokens,
                     self.owner_token, self.writer, self.compose.preflight, self.compose.container):
            mock.reset_mock()

    def assert_no_initialization(self, *, identity_generated=False):
        self.assertFalse(os.path.lexists(self.root))
        if identity_generated:
            self.byte_tokens.assert_called_once_with(16)
        else:
            self.byte_tokens.assert_not_called()
        self.hex_tokens.assert_not_called()
        self.owner_token.assert_not_called()
        self.compose_factory.assert_not_called()
        self.snapshot.assert_not_called()
        self.mcp.assert_not_called()
        self.public_owner.assert_not_called()
        self.assertNotIn("up", self.events)

    def assert_validated_backup(self, bundle):
        self.assertTrue(self.validator.called, "A real backup pointer must be validated before public success")
        self.assertTrue(all(invocation == call(bundle) for invocation in self.validator.call_args_list))

    def assert_docker_read_only(self):
        for command, _, _ in self.commands:
            self.assertTrue(
                command[:2] in (["docker", "ps"], ["docker", "inspect"])
                or command[:3] in (["docker", "volume", "ls"], ["docker", "volume", "inspect"],
                                    ["docker", "network", "ls"], ["docker", "network", "inspect"]),
                "Expected only read-only resource inspection: " + repr(command),
            )

    def assert_private_output(self):
        for value in (DATABASE_PASSWORD, APP_SECRET, OWNER_PASSWORD, PRIVATE, SESSION_COOKIE):
            self.assertNotIn(value, self.output)


class BootstrapCLITests(BootstrapFixture):
    def test_plan_is_offline_read_only_and_does_not_generate_credentials(self):
        before = self.tree(self.base)
        environment = dict(os.environ)
        with patch.object(bootstrap, "stage_installation", side_effect=AssertionError("Plan must not stage")), \
                patch.object(bootstrap, "generated_files", side_effect=AssertionError("Plan must not generate secrets")), \
                patch.object(bootstrap.tempfile, "mkdtemp", side_effect=AssertionError("Plan must not make directories")):
            self.assertEqual(self.cli("plan"), 0)
        self.assertEqual(self.tree(self.base), before)
        self.assertEqual(dict(os.environ), environment)
        self.assertIn("PLAN ONLY", self.output)
        self.assertIn(IMAGE, self.output)
        self.assertIn("exit 2", self.output)
        for mock in (self.docker, self.local_docker, self.prerequisites, self.resources, self.port, self.compose_factory,
                     self.snapshot, self.validator, self.mcp, self.public_owner, self.byte_tokens, self.hex_tokens,
                     self.owner_token, self.writer, self.process, self.network, self.dns, self.https):
            mock.assert_not_called()

    def test_plan_runs_without_linux_root_or_docker_and_preserves_unmanaged_target(self):
        self.root.mkdir(mode=0o750)
        (self.root / ".env").write_text(PRIVATE, encoding="utf-8")
        before = self.tree(self.base)
        self.which.return_value = None
        with patch.object(bootstrap.sys, "platform", "win32"), patch.object(bootstrap.os, "geteuid", return_value=1000):
            self.assertEqual(self.cli("plan"), 0)
        self.assertIn("Docker client on PATH: missing", self.output)
        self.assertEqual(self.tree(self.base), before)
        self.assert_private_output()
        self.prerequisites.assert_not_called()
        self.docker.assert_not_called()

    def test_default_root_source_and_port_are_only_planned_not_created(self):
        with patch.object(bootstrap, "DEFAULT_ROOT", self.root), patch.object(bootstrap, "SOURCE", self.source):
            self.assertEqual(self.cli("plan", root=None, source=None, port=None), 0)
        self.assertIn(str(self.root), self.output)
        self.assert_no_initialization()
        self.docker.assert_not_called()

    def test_no_default_image_or_environment_image_can_replace_required_digest(self):
        os.environ["CONSPECT_IMAGE"] = IMAGE
        for command in ("plan", "install"):
            with self.subTest(command=command):
                self.assertEqual(self.cli(command, image=None), 1)
        self.assert_no_initialization()
        self.prerequisites.assert_not_called()
        self.docker.assert_not_called()

    def test_mutable_unapproved_or_inexact_images_and_revisions_are_rejected(self):
        images = (
            "conspect:local", "ghcr.io/awak3r/c0nspect:latest",
            "ghcr.io/awak3r/c0nspect:sha-" + REVISION,
            IMAGE.replace("awak3r", "other"), IMAGE.replace("c0nspect", "conspect"),
            IMAGE.replace("sha256", "sha512"), IMAGE[:-1], IMAGE + "b", IMAGE.upper(),
            IMAGE + "\n", IMAGE + " --privileged", IMAGE + ";" + PRIVATE,
        )
        for image in images:
            with self.subTest(image=image):
                self.assertEqual(self.cli(image=image), 1)
                self.assert_private_output()
        for revision in ("a" * 7, "a" * 39, "a" * 41, "A" * 40, "g" * 40, "../" + REVISION, REVISION + "\n"):
            with self.subTest(revision=revision):
                self.assertEqual(self.cli(revision=revision), 1)
        self.assert_no_initialization()
        self.prerequisites.assert_not_called()
        self.docker.assert_not_called()

    def test_invalid_origins_and_caddy_injection_are_rejected_before_any_effect(self):
        origins = (
            "http://notes.example.net", "//notes.example.net", "https://localhost",
            "https://127.0.0.1", "https://10.0.0.1", "https://[::1]",
            "https://user:" + PRIVATE + "@notes.example.net",
            ORIGIN + "/prefix", ORIGIN + "?" + PRIVATE, ORIGIN + "#" + PRIVATE,
            ORIGIN + ":", ORIGIN + ":0", ORIGIN + ":65536", ORIGIN + ":abc",
            "https://-bad.example.net", "https://bad_.example.net", "https://notes.example.net.",
            "https://" + "a" * 64 + ".example.net", "https://nötés.example.net",
            ORIGIN + "\n}\n:443 { respond " + PRIVATE + " }",
            ORIGIN + "\r\nimport /etc/caddy/Caddyfile", ORIGIN + "\t", ORIGIN + "\x7f",
            ORIGIN + "%0aimport", ORIGIN + "\\evil", "https://{env." + PRIVATE + "}",
            "https://notes.example.net;import", "https://notes.example.net{evil}",
        )
        for origin in origins:
            with self.subTest(origin=origin):
                self.assertEqual(self.cli(url=origin), 1)
                self.assert_private_output()
        self.assert_no_initialization()
        self.prerequisites.assert_not_called()
        self.docker.assert_not_called()

    def test_origins_are_canonicalized_and_custom_ports_are_explicit(self):
        for raw, expected in (
            ("https://NOTES.Example.NET:443/", ORIGIN),
            (ORIGIN + "/", ORIGIN), (ORIGIN + ":8443/", ORIGIN + ":8443"),
            ("https://8.8.8.8/", "https://8.8.8.8"),
            ("https://[2606:4700:4700:0000:0000:0000:0000:1111]:443/", "https://[2606:4700:4700::1111]"),
        ):
            with self.subTest(raw=raw):
                self.assertEqual(bootstrap.public_origin(raw), expected)
        self.assertEqual(self.cli("plan", url=ORIGIN + ":8443", proxy="external"), 0)
        self.assertEqual(self.cli("plan", url=ORIGIN + ":8443", proxy="nginx"), 1)
        for proxy in ("caddy", "nginx"):
            with self.subTest(proxy=proxy):
                self.assertEqual(self.cli("plan", url="https://8.8.8.8", proxy=proxy), 1)
        self.assert_no_initialization()

    def test_bracketed_ipv6_origin_with_trailing_authority_junk_is_rejected(self):
        for origin in ("https://[2606:4700:4700::1111]evil", "https://[2606:4700:4700::1111]}import"):
            with self.subTest(origin=origin), self.assertRaises(OperationError):
                bootstrap.public_origin(origin)

    def test_unsafe_root_source_overlap_and_ports_are_rejected(self):
        for field in ("root", "source"):
            for value in ("relative", "/", str(self.base / "a/../escape"), str(self.base) + "/" + PRIVATE + "\n", "nul\x00path"):
                with self.subTest(field=field, value=value):
                    self.assertEqual(self.cli(**{field: value}), 1)
                    self.assert_private_output()
        for root, source in ((self.root, self.root), (self.root, self.root / "source"), (self.source / "app", self.source)):
            with self.subTest(root=root, source=source):
                self.assertEqual(self.cli(root=root, source=source), 1)
        for port in (0, 443, 1023, 65536, -1, PRIVATE):
            with self.subTest(port=port):
                self.assertEqual(self.cli(port=port), 1)
                self.assert_private_output()
        self.assert_no_initialization()
        self.prerequisites.assert_not_called()
        self.docker.assert_not_called()

    def test_install_requires_yes_and_deps_opt_in_does_not_bypass_it(self):
        for install_deps in (False, True):
            with self.subTest(install_deps=install_deps):
                self.assertEqual(self.cli(yes=False, install_deps=install_deps), 1)
                self.assertIn("--yes", self.output)
        self.assert_no_initialization()
        self.prerequisites.assert_not_called()
        self.docker.assert_not_called()

    def test_install_and_verify_require_linux_root_before_prerequisites(self):
        for command in ("install", "verify"):
            with self.subTest(command=command, reason="not-root"), patch.object(bootstrap.os, "geteuid", return_value=1000):
                self.assertEqual(self.cli(command), 1)
            with self.subTest(command=command, reason="not-linux"), patch.object(bootstrap.sys, "platform", "darwin"):
                self.assertEqual(self.cli(command), 1)
        self.assert_no_initialization()
        self.prerequisites.assert_not_called()
        self.docker.assert_not_called()

    def test_parser_errors_do_not_echo_arguments_or_allow_secret_cli_options(self):
        arguments = (
            [], [PRIVATE], ["install", "--owner-password", PRIVATE],
            self.arguments() + ["--registry-token", PRIVATE],
            self.arguments(port=PRIVATE), self.arguments(proxy=PRIVATE),
            self.arguments("plan") + ["--yes"],
            self.arguments("verify") + ["--install-deps"],
            self.arguments("plan") + ["--install-deps"],
        )
        for argv in arguments:
            with self.subTest(argv=argv):
                self.assertEqual(self.cli(argv=argv), 1)
                self.assertNotIn(PRIVATE, self.output)
                self.assertIn("Invalid bootstrap arguments", self.output)
        self.assert_no_initialization()
        self.prerequisites.assert_not_called()
        self.docker.assert_not_called()


class BootstrapInstallTests(BootstrapFixture):
    def test_first_install_stages_private_credentials_and_immutable_manifest_once(self):
        source_before = self.tree(self.source)
        self.assertEqual(self.cli(), 0)
        environment = self.environment()
        self.assertEqual(environment["POSTGRES_PASSWORD"], DATABASE_PASSWORD)
        self.assertEqual(environment["APP_SECRET"], APP_SECRET)
        self.assertEqual(environment["OWNER_PASSWORD"], OWNER_PASSWORD)
        self.assertEqual(environment["OWNER_USERNAME"], "admin")
        self.assertEqual(environment["DATABASE_URL"], "postgres://conspect:" + DATABASE_PASSWORD + "@db:5432/conspect?sslmode=disable")
        self.assertEqual(environment["APP_BASE_URL"], ORIGIN)
        self.assertEqual(environment["CONSPECT_IMAGE"], IMAGE)
        self.assertEqual(environment["CONSPECT_HTTP_PORT"], "8096")
        self.assertEqual(environment["CONSPECT_INSTALLATION_ID"], INSTALLATION_ID)
        self.assertEqual(environment["MCP_ENABLED"], "true")
        self.assertEqual((self.root / "owner-login.txt").read_text(), "URL: " + ORIGIN + "/login\nUsername: admin\nPassword: " + OWNER_PASSWORD + "\n")
        state = self.state()
        self.assertEqual(state["format"], bootstrap.FORMAT)
        self.assertEqual(state["installation_id"], INSTALLATION_ID)
        self.assertEqual(state["inputs"], {"url": ORIGIN, "image": IMAGE, "revision": REVISION, "proxy": "caddy", "port": 8096})
        self.assertEqual(state["status"], "healthy")
        self.assertEqual(set(state["files"]), set(self.source_bytes) | {".env", "owner-login.txt", "proxy/conspect.caddy"})
        for name, checksum in state["files"].items():
            path = self.root / name
            self.assertEqual(checksum, hashlib.sha256(path.read_bytes()).hexdigest(), name)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600, name)
            self.assertEqual(path.stat().st_nlink, 1, name)
        self.assertEqual(stat.S_IMODE((self.root / ".bootstrap.json").stat().st_mode), 0o600)
        for name, data in self.source_bytes.items():
            self.assertEqual((self.root / name).read_bytes(), data)
        self.assertEqual(self.tree(self.source), source_before)
        self.assertEqual(self.hex_tokens.call_args_list, [call(32), call(32)])
        self.byte_tokens.assert_called_once_with(16)
        self.owner_token.assert_called_once_with(24)
        self.assertEqual(self.states_written[0]["status"], "prepared")
        for saved in self.states_written:
            self.assertEqual(saved["files"], state["files"])
            self.assertEqual(saved["inputs"], state["inputs"])
            self.assertEqual(saved["installation_id"], state["installation_id"])
        self.assertEqual(list(self.root.parent.glob(".conspect-bootstrap-*")), [])
        self.assertTrue(self.started)
        self.prerequisites.assert_called_once_with(install=False)
        self.resources.assert_called_once_with(self.root)
        self.port.assert_called_once_with(8096)
        self.snapshot.assert_called_once_with(self.compose, self.root / "backups")
        self.assert_validated_backup(self.root / state["backup"])
        self.mcp.assert_called_once_with(ORIGIN)
        self.public_owner.assert_called_once_with(self.root, ORIGIN)
        self.local_docker.assert_called_once_with()
        self.assertLess(self.events.index("resources"), self.events.index("prerequisites"))
        self.assertLess(self.events.index("port"), self.events.index("prerequisites"))
        self.assertLess(self.events.index("local-docker"), self.events.index("prerequisites"))
        self.assertLess(self.events.index("inventory-volumes"), self.events.index("prerequisites"))
        self.assertLess(self.events.index("inventory-volumes"), self.events.index("config"))
        self.assertLess(self.events.index("config"), self.events.index("pull-image"))
        self.assertLess(self.events.index("up"), self.events.index("backup"))
        self.assertLess(self.events.index("validate-backup"), self.events.index("public"))
        self.assertLess(self.events.index("public"), self.events.index("public-owner"))
        self.assertEqual(self.events[-2:], ["operations-unlock", "bootstrap-unlock"])
        self.assertIn("LOCAL ONLY", self.output)
        self.assert_private_output()
        for value in (DATABASE_PASSWORD, APP_SECRET, OWNER_PASSWORD):
            self.assertNotIn(value, (self.root / ".bootstrap.json").read_text())

    def test_staging_is_atomic_and_only_publishes_a_complete_private_installation(self):
        real_rename = Path.rename
        observed = []

        def rename(stage, target):
            if stage.name.startswith(".conspect-bootstrap-"):
                self.assertEqual(target, self.root)
                self.assertFalse(target.exists())
                marker = json.loads((stage / ".bootstrap.json").read_text())
                self.assertEqual(marker["status"], "prepared")
                for name, checksum in marker["files"].items():
                    path = stage / name
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                    self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), checksum)
                observed.append(stage)
            return real_rename(stage, target)

        with patch.object(Path, "rename", rename):
            self.assertEqual(self.cli(), 0)
        self.assertEqual(len(observed), 1)
        self.assertFalse(observed[0].exists())

    def test_staging_failure_removes_partial_tree_without_publishing_credentials(self):
        with patch.object(bootstrap, "generated_files", side_effect=OSError(PRIVATE)):
            self.assertEqual(self.cli(), 1)
        self.assert_no_initialization(identity_generated=True)
        self.assertEqual(list(self.root.parent.glob(".conspect-bootstrap-*")), [])
        self.assert_private_output()

    def test_only_app_db_start_with_no_build_and_loopback_production_overlay(self):
        self.assertEqual(self.cli(port=18096), 0)
        self.assertEqual(self.environment()["CONSPECT_HTTP_PORT"], "18096")
        overlay = (self.root / "deploy/compose.nginx.yaml").read_text()
        self.assertIn('127.0.0.1:${CONSPECT_HTTP_PORT:-8096}:8080', overlay)
        self.assertNotIn("0.0.0.0", overlay)
        self.assertNotIn("5432:", overlay)
        self.assertIn("reverse_proxy 127.0.0.1:18096", (self.root / "proxy/conspect.caddy").read_text())
        self.assertEqual(self.compose_factory.call_args_list, [call(nginx=True), call(nginx=True)])
        self.assertIn("--no-recreate", [command for command, _, _ in self.commands if "up" in command][0])
        self.assertIn("io.conspect.installation: ${CONSPECT_INSTALLATION_ID:-legacy}", overlay)
        self.assertEqual(overlay.count("labels: *installation-labels"), 6)
        for item in self.containers.values():
            self.assertEqual(item["Config"]["Labels"]["io.conspect.installation"], INSTALLATION_ID)
        for item in [*self.volumes.values(), *self.networks.values()]:
            self.assertEqual(item["Labels"]["io.conspect.installation"], INSTALLATION_ID)
        up = [command for command, _, _ in self.commands if "up" in command]
        self.assertEqual(len(up), 1)
        self.assertEqual(up[0][-2:], ["app", "db"])
        self.assertIn("--no-build", up[0])
        self.assertEqual(up[0][up[0].index("--pull") + 1], "never")
        for command, _, _ in self.commands:
            self.assertNotIn("build", command)
            self.assertNotIn("down", command)
            self.assertNotIn("restart", command)
            self.assertNotIn("compose.local.yaml", " ".join(command))

    def test_prerequisite_installation_requires_explicit_opt_in(self):
        self.assertEqual(self.cli(install_deps=True), 0)
        self.prerequisites.assert_called_once_with(install=True)

    def test_prerequisite_failure_does_not_generate_secrets_or_create_installation(self):
        self.failures.add("prerequisites")
        self.assertEqual(self.cli(), 1)
        self.assert_no_initialization()
        self.resources.assert_called_once_with(self.root)
        self.port.assert_called_once_with(8096)
        self.local_docker.assert_called_once_with()
        self.assertLess(self.events.index("inventory-volumes"), self.events.index("prerequisites"))
        self.assert_docker_read_only()

    def test_occupied_port_refuses_before_staging_and_does_not_stop_services(self):
        self.failures.add("port")
        self.assertEqual(self.cli(), 1)
        self.assert_no_initialization()
        self.docker.assert_not_called()
        self.local_docker.assert_not_called()
        self.prerequisites.assert_not_called()
        self.assertNotIn("up", self.events)

    def test_insufficient_resources_refuse_before_docker_or_credential_creation(self):
        self.failures.add("resources")
        self.assertEqual(self.cli(), 1)
        self.assert_no_initialization()
        self.docker.assert_not_called()
        self.port.assert_not_called()
        self.prerequisites.assert_not_called()

    def test_identical_retry_reuses_credentials_sources_and_verified_backup(self):
        self.assertEqual(self.cli(), 0)
        files = self.immutable_files()
        state = self.state()
        backups = self.tree(self.root / "backups")
        self.reset_activity()
        self.assertEqual(self.cli(), 0)
        self.assertEqual(self.immutable_files(), files)
        self.assertEqual(self.state()["files"], state["files"])
        self.assertEqual(self.state()["backup"], state["backup"])
        self.assertEqual(self.state()["installation_id"], state["installation_id"])
        self.assertEqual(self.tree(self.root / "backups"), backups)
        self.byte_tokens.assert_not_called()
        self.hex_tokens.assert_not_called()
        self.owner_token.assert_not_called()
        self.snapshot.assert_not_called()
        self.port.assert_not_called()
        self.assert_validated_backup(self.root / state["backup"])
        self.assertNotIn("pull-db", self.events)
        self.assertLess(self.events.index("inspect-container"), self.events.index("prerequisites"))
        self.assertLess(self.events.index("inspect-volume"), self.events.index("pull-image"))
        self.assertLess(self.events.index("inspect-network"), self.events.index("up"))
        self.assert_private_output()

    def assert_failure_resumes(self, failure):
        self.failures.add(failure)
        self.assertEqual(self.cli(), 1)
        self.assertTrue(self.root.is_dir())
        before = self.immutable_files()
        self.assertNotEqual(self.state()["status"], "healthy")
        self.assertNotIn("HEALTHY:", self.output)
        self.failures.clear()
        self.reset_activity()
        self.assertEqual(self.cli(), 0)
        self.assertEqual(self.immutable_files(), before)
        self.byte_tokens.assert_not_called()
        self.hex_tokens.assert_not_called()
        self.owner_token.assert_not_called()
        self.port.assert_not_called()
        self.assertEqual(self.backup_count, 1)
        self.assertEqual(self.state()["status"], "healthy")

    def test_config_failure_after_staging_is_resumable(self):
        self.assert_failure_resumes("config")

    def test_image_pull_failure_after_staging_is_resumable(self):
        self.assert_failure_resumes("pull-image")

    def test_start_failure_after_staging_is_resumable_without_teardown(self):
        self.assert_failure_resumes("up")
        self.assertTrue(self.started)

    def test_local_preflight_failure_is_not_public_success_or_backup_success(self):
        self.failures.add("preflight")
        self.assertEqual(self.cli(), 1)
        self.assertEqual(self.state()["status"], "starting")
        self.snapshot.assert_not_called()
        self.mcp.assert_not_called()
        self.assertTrue(self.started)
        self.assert_private_output()

    def test_public_failure_exit_two_preserves_containers_then_verify_can_finish(self):
        self.errors["public"] = OperationError(PRIVATE)
        self.assertEqual(self.cli(), 2)
        self.assertEqual(self.state()["status"], "local-ready")
        self.assertIn("LOCAL_READY:", self.output)
        self.assertNotIn("HEALTHY:", self.output)
        self.assertTrue(self.started)
        self.assert_private_output()
        files = self.immutable_files()
        backups = self.tree(self.root / "backups")
        self.errors.clear()
        self.reset_activity()
        self.assertEqual(self.cli("verify"), 0)
        self.assertEqual(self.state()["status"], "healthy")
        self.assertIn("HEALTHY:", self.output)
        self.assertEqual(self.immutable_files(), files)
        self.assertEqual(self.tree(self.root / "backups"), backups)
        self.assertTrue(self.started)
        self.prerequisites.assert_called_once_with()
        self.assert_docker_read_only()
        self.assert_validated_backup(self.root / self.state()["backup"])
        self.public_owner.assert_called_once_with(self.root, ORIGIN)
        for mock in (self.snapshot, self.byte_tokens, self.hex_tokens, self.owner_token, self.resources, self.port):
            mock.assert_not_called()

    def test_backup_creation_failure_is_failure_not_local_ready_or_healthy_success(self):
        self.failures.add("backup")
        self.assertEqual(self.cli(), 1)
        self.assertNotIn("backup", self.state())
        self.assertNotEqual(self.state()["status"], "healthy")
        self.assertNotIn("HEALTHY:", self.output)
        self.assertNotIn("LOCAL_READY:", self.output)
        self.validator.assert_not_called()
        self.mcp.assert_not_called()
        self.assertTrue(self.started)

    def test_backup_integrity_failure_cannot_report_healthy_or_public_success(self):
        self.failures.add("validate-backup")
        self.assertEqual(self.cli(), 1)
        self.assertNotIn("backup", self.state())
        self.assertNotEqual(self.state()["status"], "healthy")
        self.assertNotIn("HEALTHY:", self.output)
        self.mcp.assert_not_called()
        self.assertTrue(self.started)
        self.assertEqual(self.backup_count, 1)

    def test_retry_revalidates_existing_backup_instead_of_silently_replacing_it(self):
        self.assertEqual(self.cli(), 0)
        files = self.immutable_files()
        self.reset_activity()
        self.failures.add("validate-backup")
        self.assertEqual(self.cli(), 1)
        self.assertEqual(self.immutable_files(), files)
        self.snapshot.assert_not_called()
        self.mcp.assert_not_called()
        self.assertNotIn("HEALTHY:", self.output)

    def test_verify_revalidates_saved_backup_before_claiming_healthy(self):
        self.assertEqual(self.cli(), 0)
        self.reset_activity()
        self.failures.add("validate-backup")
        self.assertEqual(self.cli("verify"), 1)
        self.assert_validated_backup(self.root / self.state()["backup"])
        self.mcp.assert_not_called()
        self.assertNotIn("HEALTHY:", self.output)

    def test_verify_cannot_turn_failed_backup_creation_into_healthy(self):
        self.failures.add("backup")
        self.assertEqual(self.cli(), 1)
        self.failures.clear()
        self.reset_activity()
        self.assertEqual(self.cli("verify"), 1)
        self.assertNotEqual(self.state()["status"], "healthy")
        self.assertNotIn("HEALTHY:", self.output)
        self.mcp.assert_not_called()
        self.snapshot.assert_not_called()

    def test_verify_cannot_turn_failed_backup_validation_into_healthy(self):
        self.failures.add("validate-backup")
        self.assertEqual(self.cli(), 1)
        self.failures.clear()
        self.reset_activity()
        self.assertEqual(self.cli("verify"), 1)
        self.assertNotEqual(self.state()["status"], "healthy")
        self.assertNotIn("HEALTHY:", self.output)
        self.mcp.assert_not_called()

    def assert_proxy_artifact_only(self, proxy, filename):
        host_before = self.tree(self.host)
        self.assertEqual(self.cli(proxy=proxy), 0)
        self.assertEqual(self.tree(self.host), host_before)
        self.assertEqual([path.name for path in (self.root / "proxy").iterdir()], [filename])
        text = (self.root / "proxy" / filename).read_text()
        self.assertIn("127.0.0.1:8096", text)
        for command, _, _ in self.commands:
            self.assertEqual(command[0], "docker")
            self.assertFalse(any(word in command for word in ("restart", "reload", "stop", "down", "systemctl", "service")))
            self.assertNotIn("nginx", command)
            self.assertNotIn("caddy", command)
        return text

    def test_caddy_is_only_a_private_independent_fragment_no_host_service_change(self):
        text = self.assert_proxy_artifact_only("caddy", "conspect.caddy")
        self.assertIn(ORIGIN + " {", text)
        self.assertIn("header_up X-Forwarded-For {remote_host}", text)
        self.assertIn("header_up X-Forwarded-Proto {scheme}", text)
        self.assertNotIn("\nadmin ", text)

    def test_nginx_uses_safe_real_template_but_never_changes_host_files_or_services(self):
        text = self.assert_proxy_artifact_only("nginx", "conspect.nginx.conf")
        self.assertIn("server_name notes.example.net;", text)
        self.assertIn("/etc/letsencrypt/live/notes.example.net/fullchain.pem", text)
        self.assertNotIn("notes.example.com", text)
        self.assertIn("proxy_pass http://127.0.0.1:8096;", text)
        self.assertIn("proxy_set_header X-Forwarded-For $remote_addr;", text)
        self.assertIn("proxy_set_header X-Forwarded-Proto $scheme;", text)
        self.assertNotIn("$proxy_add_x_forwarded_for", text)

    def test_external_proxy_mode_only_generates_whole_origin_instructions(self):
        text = self.assert_proxy_artifact_only("external", "instructions.txt")
        for route in ("/login", "/mcp", "/oauth/*", "/.well-known/*"):
            self.assertIn(route, text)

    def test_inherited_docker_compose_and_app_environment_never_reaches_provisioning(self):
        overrides = {name: PRIVATE for name in bootstrap.ENV_FIELDS}
        overrides.update({
            "DOCKER_HOST": "ssh://" + PRIVATE, "DOCKER_CONTEXT": PRIVATE,
            "DOCKER_CONFIG": "/outside/" + PRIVATE, "DOCKER_TLS_VERIFY": "1",
            "DOCKER_CERT_PATH": "/outside/" + PRIVATE,
            "COMPOSE_FILE": "/outside/compose.yaml", "COMPOSE_PROJECT_NAME": PRIVATE,
            "COMPOSE_PROFILES": "proxy", "COMPOSE_ENV_FILES": "/outside/" + PRIVATE,
        })
        os.environ.update(overrides)
        os.environ["UNRELATED_SETTING"] = "preserved"
        observed = []

        def observe(name):
            if name in ("prerequisites", "resources", "config", "compose", "backup", "public"):
                observed.append(name)
                for variable in overrides:
                    self.assertNotIn(variable, os.environ, name + ": " + variable)

        self.on_event = observe
        self.assertEqual(self.cli(), 0)
        self.assertTrue(observed)
        self.assertEqual(os.environ["UNRELATED_SETTING"], "preserved")
        self.assertEqual(self.environment()["CONSPECT_IMAGE"], IMAGE)
        self.assertEqual(self.environment()["APP_BASE_URL"], ORIGIN)
        self.assert_private_output()

    def test_verify_sanitizes_inherited_environment_without_generating_new_credentials(self):
        self.assertEqual(self.cli(), 0)
        self.reset_activity()
        overrides = {"DOCKER_HOST": PRIVATE, "COMPOSE_FILE": PRIVATE, "APP_BASE_URL": PRIVATE, "MCP_ENABLED": "false"}
        os.environ.update(overrides)

        def observe(name):
            for variable in overrides:
                self.assertNotIn(variable, os.environ)

        self.on_event = observe
        self.assertEqual(self.cli("verify"), 0)
        self.hex_tokens.assert_not_called()
        self.owner_token.assert_not_called()
        self.assert_private_output()

    def test_operating_system_error_does_not_disclose_private_details(self):
        self.errors["pull-image"] = OSError(PRIVATE + DATABASE_PASSWORD)
        self.assertEqual(self.cli(), 1)
        self.assertIn("details withheld", self.output)
        self.assert_private_output()
        self.assertEqual(self.state()["status"], "prepared")


class BootstrapSecurityTests(BootstrapFixture):
    def test_unmanaged_empty_root_or_existing_env_is_never_adopted(self):
        self.root.mkdir(mode=0o750)
        for existing_env in (False, True):
            with self.subTest(existing_env=existing_env):
                if existing_env:
                    (self.root / ".env").write_text(PRIVATE, encoding="utf-8")
                before = self.tree(self.base)
                self.assertEqual(self.cli(install_deps=True), 1)
                self.assertEqual(self.tree(self.base), before)
                self.assertIn("without a bootstrap marker", self.output)
                self.assert_private_output()
        self.prerequisites.assert_not_called()
        self.docker.assert_not_called()
        self.hex_tokens.assert_not_called()

    def test_retained_conspect_volumes_containers_or_networks_refuse_before_creation(self):
        cases = (
            ("containers", "old-project-id\n"), ("names", "unrelated\nconspect-app-1\n"),
            ("volumes", "other_data\nconspect_db_data\n"), ("volumes", "conspect_uploads\n"),
            ("networks", "conspect_backend\n"), ("networks", "conspect_frontend\n"),
        )
        for kind, value in cases:
            with self.subTest(kind=kind, value=value):
                self.inventory = dict.fromkeys(self.inventory, "")
                self.inventory[kind] = value
                self.assertEqual(self.cli(), 1)
                self.assertIn("Refusing to attach old data", self.output)
                self.assert_no_initialization()
        self.port.assert_called_with(8096)
        self.prerequisites.assert_not_called()
        self.writer.assert_not_called()

    def test_unrelated_docker_resources_are_not_removed_or_adopted(self):
        self.inventory.update(names="caddy-naive\nnginx\nvpn\n", volumes="other_db_data\n", networks="other_backend\n")
        self.assertEqual(self.cli(), 0)
        self.assertFalse(any("rm" in command or "prune" in command for command, _, _ in self.commands))

    def test_changed_inputs_refuse_without_overwrite_or_external_work(self):
        self.assertEqual(self.cli(), 0)
        files = self.immutable_files()
        for override in (
            {"url": "https://changed.example.net"},
            {"image": IMAGE[:-1] + "c"}, {"revision": "c" * 40},
            {"proxy": "external"}, {"port": 18096},
        ):
            with self.subTest(override=override):
                before = self.tree(self.root)
                self.reset_activity()
                self.assertEqual(self.cli(**override), 1)
                self.assertEqual(self.tree(self.root), before)
                self.assertEqual(self.immutable_files(), files)
                self.prerequisites.assert_not_called()
                self.docker.assert_not_called()
                self.hex_tokens.assert_not_called()
                self.snapshot.assert_not_called()

    def test_changed_source_bytes_or_file_set_refuse_without_overwrite(self):
        self.assertEqual(self.cli(), 0)
        files = self.immutable_files()
        changed = self.source / "deploy/operations.py"
        original = changed.read_bytes()
        added = self.source / "deploy/extra.py"
        for modification in ("bytes", "added", "removed"):
            with self.subTest(modification=modification):
                if modification == "bytes":
                    changed.write_bytes(original + b"# changed approved source\n")
                elif modification == "added":
                    added.write_bytes(b"# another source file\n")
                else:
                    changed.unlink()
                try:
                    before = self.tree(self.root)
                    self.reset_activity()
                    self.assertEqual(self.cli(), 1)
                    self.assertEqual(self.tree(self.root), before)
                    self.assertEqual(self.immutable_files(), files)
                    self.prerequisites.assert_not_called()
                    self.docker.assert_not_called()
                    self.hex_tokens.assert_not_called()
                finally:
                    if added.exists():
                        added.unlink()
                    changed.write_bytes(original)
                    changed.chmod(0o640)

    def test_changed_env_credentials_installed_source_or_proxy_are_preserved_and_refused(self):
        self.assertEqual(self.cli(), 0)
        for name in (".env", "owner-login.txt", "compose.yaml", "deploy/operations.py", "proxy/conspect.caddy"):
            path = self.root / name
            original = path.read_bytes()
            with self.subTest(name=name):
                path.write_bytes(original + PRIVATE.encode())
                before = self.tree(self.root)
                self.reset_activity()
                try:
                    self.assertEqual(self.cli(), 1)
                    self.assertEqual(self.tree(self.root), before)
                    self.assertIn(PRIVATE.encode(), path.read_bytes())
                    self.assert_private_output()
                    self.prerequisites.assert_not_called()
                    self.docker.assert_not_called()
                    self.hex_tokens.assert_not_called()
                finally:
                    path.write_bytes(original)

    def test_untrusted_root_parent_source_and_source_file_are_rejected(self):
        for path in (self.root.parent, self.source, self.source.parent, self.source / "compose.yaml"):
            for mode, owner in ((0o777, 0), (0o775, 0), (0o750, 1000)):
                with self.subTest(path=path, mode=oct(mode), owner=owner):
                    previous = stat.S_IMODE(path.stat().st_mode)
                    path.chmod(mode)
                    self.owners[path] = owner
                    try:
                        self.assertEqual(self.cli(), 1)
                        self.assert_no_initialization()
                    finally:
                        path.chmod(previous)
                        self.owners.pop(path)
        self.prerequisites.assert_not_called()
        self.docker.assert_not_called()

    def test_source_deploy_and_nested_parents_must_not_be_untrusted(self):
        nested = self.source / "deploy/nested"
        nested.mkdir(mode=0o750)
        (nested / "placeholder.py").write_bytes(b"# synthetic nested source\n")
        args = SimpleNamespace(source=self.source, root=self.root)
        for directory in (self.source / "deploy", nested):
            for mode, owner in ((0o777, 0), (0o750, 1000)):
                with self.subTest(directory=directory, mode=oct(mode), owner=owner):
                    directory.chmod(mode)
                    self.owners[directory] = owner
                    try:
                        with self.assertRaises(OperationError):
                            bootstrap.source_files(args, trusted=True)
                    finally:
                        directory.chmod(0o750)
                        self.owners.pop(directory)
        self.assert_no_initialization()

    def test_source_file_symlinks_and_hardlinks_are_not_read_or_staged(self):
        victim = self.base / "source-victim"
        for name in ("compose.yaml", "deploy/operations.py", "deploy/nginx.tls.conf"):
            path = self.source / name
            original = path.read_bytes()
            for kind in ("symlink", "hardlink"):
                with self.subTest(name=name, kind=kind):
                    victim.write_bytes(original)
                    victim.chmod(0o600)
                    path.unlink()
                    path.symlink_to(victim) if kind == "symlink" else os.link(victim, path)
                    before = victim.read_bytes()
                    try:
                        self.assertEqual(self.cli(), 1)
                        self.assertEqual(victim.read_bytes(), before)
                        self.assert_no_initialization()
                    finally:
                        path.unlink()
                        path.write_bytes(original)
                        path.chmod(0o640)
                        victim.unlink()
        self.prerequisites.assert_not_called()
        self.docker.assert_not_called()

    def test_source_root_and_deploy_directory_symlinks_are_refused(self):
        for path in (self.source / "deploy", self.source):
            with self.subTest(path=path):
                outside = self.base / "real-source-directory"
                path.rename(outside)
                path.symlink_to(outside, target_is_directory=True)
                before = self.tree(outside)
                try:
                    self.assertEqual(self.cli(), 1)
                    self.assertEqual(self.tree(outside), before)
                    self.assert_no_initialization()
                finally:
                    path.unlink()
                    outside.rename(path)
        self.prerequisites.assert_not_called()

    def test_source_with_symlinked_ancestor_is_refused_not_silently_trusted(self):
        real_parent = self.base / "source-parent"
        real_parent.mkdir(mode=0o750)
        self.source.rename(real_parent / "approved-source")
        alias = self.base / "source-parent-alias"
        alias.symlink_to(real_parent, target_is_directory=True)
        self.source = alias / "approved-source"
        before = self.tree(real_parent)
        self.assertEqual(self.cli(), 1)
        self.assertEqual(self.tree(real_parent), before)
        self.assert_no_initialization()
        self.prerequisites.assert_not_called()

    def test_target_with_symlinked_ancestor_is_refused_before_creation(self):
        real_parent = self.base / "real-target-parent"
        (real_parent / "opt").mkdir(parents=True, mode=0o750)
        alias = self.base / "target-parent-alias"
        alias.symlink_to(real_parent, target_is_directory=True)
        self.root = alias / "opt/conspect"
        self.assertEqual(self.cli(), 1)
        self.assert_no_initialization()
        self.prerequisites.assert_not_called()
        self.assertEqual(list((real_parent / "opt").iterdir()), [])

    def test_installed_root_symlink_is_not_adopted(self):
        self.assertEqual(self.cli(), 0)
        outside = self.base / "real-installed-root"
        self.root.rename(outside)
        self.root.symlink_to(outside, target_is_directory=True)
        before = self.tree(outside)
        self.reset_activity()
        self.assertEqual(self.cli(), 1)
        self.assertEqual(self.tree(outside), before)
        self.prerequisites.assert_not_called()
        self.docker.assert_not_called()
        self.assertTrue(self.root.is_symlink())

    def test_installed_private_files_and_manifest_refuse_symlinks_and_hardlinks(self):
        self.assertEqual(self.cli(), 0)
        victim = self.base / "installed-file-victim"
        for name in (".env", "owner-login.txt", ".bootstrap.json", "compose.yaml", "deploy/operations.py", "proxy/conspect.caddy"):
            path = self.root / name
            original = path.read_bytes()
            for kind in ("symlink", "hardlink"):
                with self.subTest(name=name, kind=kind):
                    victim.write_bytes(original)
                    victim.chmod(0o600)
                    path.unlink()
                    path.symlink_to(victim) if kind == "symlink" else os.link(victim, path)
                    self.reset_activity()
                    try:
                        self.assertEqual(self.cli(), 1)
                        self.assertEqual(victim.read_bytes(), original)
                        self.prerequisites.assert_not_called()
                        self.docker.assert_not_called()
                        self.hex_tokens.assert_not_called()
                    finally:
                        path.unlink()
                        path.write_bytes(original)
                        path.chmod(0o600)
                        victim.unlink()

    def test_installed_proxy_parent_symlink_is_refused_even_if_file_hash_matches(self):
        self.assertEqual(self.cli(), 0)
        proxy = self.root / "proxy"
        outside = self.base / "real-proxy-artifacts"
        proxy.rename(outside)
        proxy.symlink_to(outside, target_is_directory=True)
        before = self.tree(outside)
        self.reset_activity()
        self.assertEqual(self.cli(), 1)
        self.assertEqual(self.tree(outside), before)
        self.prerequisites.assert_not_called()
        self.docker.assert_not_called()

    def test_private_files_require_root_ownership_mode_600_and_single_link(self):
        self.assertEqual(self.cli(), 0)
        for name in (".env", "owner-login.txt", ".bootstrap.json"):
            path = self.root / name
            for mode, owner in ((0o644, 0), (0o660, 0), (0o600, 1000)):
                with self.subTest(name=name, mode=oct(mode), owner=owner):
                    path.chmod(mode)
                    self.owners[path] = owner
                    self.reset_activity()
                    try:
                        self.assertEqual(self.cli(), 1)
                        self.prerequisites.assert_not_called()
                        self.docker.assert_not_called()
                        self.hex_tokens.assert_not_called()
                    finally:
                        path.chmod(0o600)
                        self.owners.pop(path)

    def test_malformed_marker_and_unsafe_manifest_paths_are_not_adopted(self):
        self.assertEqual(self.cli(), 0)
        original = self.state()
        malformed = [[], {}, {**original, "format": 999}, {**original, "files": []}, {**original, "inputs": []}]
        malformed.extend({**original, "installation_id": identity} for identity in ("", "a" * 31, "a" * 33, "A" * 32, "g" * 32, None, 123))
        malformed.append({name: value for name, value in original.items() if name != "installation_id"})
        for name in ("../outside", "/outside"):
            state = deepcopy(original)
            state["files"][name] = "a" * 64
            malformed.append(state)
        state = deepcopy(original)
        state["files"][".env"] = 123
        malformed.append(state)
        for value in malformed:
            with self.subTest(marker=value):
                self.write_state(value)
                before = (self.root / ".bootstrap.json").read_bytes()
                self.reset_activity()
                try:
                    self.assertEqual(self.cli(), 1)
                    self.assertEqual((self.root / ".bootstrap.json").read_bytes(), before)
                    self.prerequisites.assert_not_called()
                    self.docker.assert_not_called()
                    self.hex_tokens.assert_not_called()
                finally:
                    self.write_state(original)

    def test_invalid_backup_pointers_refuse_without_replacement_or_public_success(self):
        self.assertEqual(self.cli(), 0)
        original = self.state()
        for pointer in ("/outside", "../outside", "backups/../outside", "other/snapshot"):
            with self.subTest(pointer=pointer):
                self.write_state({**original, "backup": pointer})
                self.reset_activity()
                self.assertEqual(self.cli(), 1)
                self.snapshot.assert_not_called()
                self.validator.assert_not_called()
                self.mcp.assert_not_called()
                self.assertNotIn("HEALTHY:", self.output)

    def test_private_file_is_bounded_regular_and_rejects_directories(self):
        path = self.base / "private-file"
        path.mkdir(mode=0o700)
        with self.assertRaises(OperationError):
            bootstrap.private_file(path)
        path.rmdir()
        with path.open("wb") as stream:
            stream.truncate(2 * 1024 * 1024 + 1)
        path.chmod(0o600)
        with self.assertRaises(OperationError):
            bootstrap.private_file(path)

    def test_existing_bootstrap_lock_excludes_install_before_external_work(self):
        with self.real_bootstrap_lock(self.root):
            self.assertEqual(self.cli(), 1)
        self.assertIn("Another bootstrap", self.output)
        self.assert_no_initialization()
        self.prerequisites.assert_not_called()
        self.docker.assert_not_called()
        with self.real_bootstrap_lock(self.root):
            pass

    def test_existing_operations_lock_blocks_retry_before_pull_or_activation(self):
        self.failures.add("config")
        self.assertEqual(self.cli(), 1)
        before = self.immutable_files()
        self.failures.clear()
        self.reset_activity()
        with patch.object(operations, "ROOT", self.root):
            with operations.operation_lock():
                # main must restore to the root visible at entry, not a global
                # hardcoded /opt path. Check that restoration outside cli().
                self.current_command = "install"
                self.assertEqual(bootstrap.main(self.arguments()), 1)
                self.assertEqual(operations.ROOT, self.root)
        self.assertEqual(operations.ROOT, self.previous_root)
        self.assertEqual(self.immutable_files(), before)
        self.assert_docker_read_only()
        self.assertNotIn("pull-image", self.events)
        self.assertNotIn("up", self.events)
        self.snapshot.assert_not_called()
        self.hex_tokens.assert_not_called()

    def test_both_real_locks_exclude_a_concurrent_thread_through_activation(self):
        results = []

        def contend():
            for name, manager in (("bootstrap", self.real_bootstrap_lock(self.root)), ("operations", operations.operation_lock())):
                try:
                    with manager:
                        results.append((name, "acquired"))
                except OperationError:
                    results.append((name, "blocked"))

        def at_pull(name):
            if name == "pull-image":
                thread = threading.Thread(target=contend, daemon=True)
                thread.start()
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive(), "Lock contention must fail immediately, never hang")

        self.on_event = at_pull
        self.assertEqual(self.cli(), 0)
        self.assertEqual(results, [("bootstrap", "blocked"), ("operations", "blocked")])
        with self.real_bootstrap_lock(self.root), patch.object(operations, "ROOT", self.root), operations.operation_lock():
            pass

    def test_bootstrap_lock_refuses_symlink_hardlink_bad_modes_and_wrong_owner(self):
        lock = self.project_lock
        victim = self.base / "lock-victim"
        victim.write_bytes(PRIVATE.encode())
        victim.chmod(0o600)
        for kind in ("symlink", "hardlink", "public", "owner"):
            with self.subTest(kind=kind):
                if kind == "symlink":
                    lock.symlink_to(victim)
                elif kind == "hardlink":
                    os.link(victim, lock)
                else:
                    lock.write_bytes(b"existing lock content\n")
                    lock.chmod(0o644 if kind == "public" else 0o600)
                    if kind == "owner":
                        self.owners[lock] = 1000
                try:
                    self.assertEqual(self.cli(), 1)
                    self.assertEqual(victim.read_bytes(), PRIVATE.encode())
                    self.assert_no_initialization()
                finally:
                    self.owners.pop(lock, None)
                    lock.unlink()
        self.prerequisites.assert_not_called()
        self.docker.assert_not_called()


class BootstrapOwnershipTests(BootstrapFixture):
    def assert_ownership_refusal(self, *, command="install", before_prerequisites=True):
        files = self.immutable_files()
        marker = (self.root / ".bootstrap.json").read_bytes()
        resources = deepcopy((self.containers, self.volumes, self.networks))
        self.reset_activity()
        self.assertEqual(self.cli(command), 1)
        self.assertEqual(self.immutable_files(), files)
        self.assertEqual((self.root / ".bootstrap.json").read_bytes(), marker)
        self.assertEqual((self.containers, self.volumes, self.networks), resources)
        self.assert_docker_read_only()
        self.assertNotIn("up", self.events)
        self.assertNotIn("pull-image", self.events)
        if before_prerequisites:
            self.prerequisites.assert_not_called()
            self.compose_factory.assert_not_called()
        for mock in (self.snapshot, self.mcp, self.public_owner, self.byte_tokens, self.hex_tokens, self.owner_token):
            mock.assert_not_called()
        self.assert_private_output()

    def test_real_owned_resources_accepts_only_matching_retained_resources_read_only(self):
        self.assertEqual(self.cli(), 0)
        self.reset_activity()
        with bootstrap.bootstrap_lock(self.root):
            bootstrap.owned_resources(self.root, self.state())
        self.assert_docker_read_only()
        for kind in ("container", "volume", "network"):
            self.assertIn("inspect-" + kind, self.events)
        self.compose_factory.assert_not_called()
        self.snapshot.assert_not_called()
        self.byte_tokens.assert_not_called()

    def test_foreign_or_missing_container_identity_project_and_working_dir_refuse_before_up(self):
        self.assertEqual(self.cli(), 0)
        for service in ("app", "db"):
            labels = self.containers[service]["Config"]["Labels"]
            for field, foreign in (
                ("io.conspect.installation", OTHER_INSTALLATION_ID),
                ("com.docker.compose.project", "another-project"),
                ("com.docker.compose.project.working_dir", str(self.base / "installation-B")),
            ):
                original = dict(labels)
                for value in (foreign, None):
                    with self.subTest(service=service, field=field, value=value):
                        labels.clear()
                        labels.update(original)
                        if value is None:
                            labels.pop(field)
                        else:
                            labels[field] = value
                        try:
                            self.assert_ownership_refusal()
                        finally:
                            labels.clear()
                            labels.update(original)

    def test_unlabeled_named_container_with_null_docker_labels_is_cleanly_refused(self):
        self.assertEqual(self.cli(), 0)
        self.containers["app"]["Config"]["Labels"] = None
        self.assert_ownership_refusal()

    def test_foreign_or_unlabeled_volumes_and_networks_refuse_before_prerequisite_changes(self):
        self.assertEqual(self.cli(), 0)
        for kind, collection in (("volume", self.volumes), ("network", self.networks)):
            for name, resource in collection.items():
                original = deepcopy(resource["Labels"])
                cases = (
                    {**original, "io.conspect.installation": OTHER_INSTALLATION_ID},
                    {**original, "com.docker.compose.project": "another-project"},
                    {"com.docker.compose.project": "conspect"}, {}, None,
                )
                for labels in cases:
                    with self.subTest(kind=kind, name=name, labels=labels):
                        resource["Labels"] = labels
                        try:
                            self.assert_ownership_refusal()
                        finally:
                            resource["Labels"] = deepcopy(original)

    def test_unexpected_conspect_container_name_blocks_retry_without_cleanup(self):
        self.assertEqual(self.cli(), 0)
        self.inventory["names"] = "conspect-competing-restore-1\n"
        self.assert_ownership_refusal()
        self.assertIn("Unexpected Conspect containers", self.output)

    def test_prepared_installation_a_refuses_resources_of_b_after_image_pull_failure(self):
        self.failures.add("pull-image")
        self.assertEqual(self.cli(), 1)
        self.assertEqual(self.state()["status"], "prepared")
        self.assertEqual(self.containers, {})
        self.failures.clear()
        self.seed_resources(root=self.base / "installation-B", identity=OTHER_INSTALLATION_ID)
        self.assert_ownership_refusal()
        self.assertEqual(self.state()["status"], "prepared")
        self.assertIn("different installation", self.output)

    def test_retained_resource_ownership_is_rechecked_under_operations_lock(self):
        self.failures.add("pull-image")
        self.assertEqual(self.cli(), 1)
        self.failures.clear()
        files = self.immutable_files()
        marker = (self.root / ".bootstrap.json").read_bytes()
        self.reset_activity()

        def competing_installation(name):
            if name == "operations-lock":
                self.seed_resources(root=self.base / "installation-B", identity=OTHER_INSTALLATION_ID)

        self.on_event = competing_installation
        self.assertEqual(self.cli(), 1)
        self.assertEqual(self.immutable_files(), files)
        self.assertEqual((self.root / ".bootstrap.json").read_bytes(), marker)
        self.assertIn("operations-lock", self.events)
        self.assert_docker_read_only()
        self.compose_factory.assert_not_called()
        self.snapshot.assert_not_called()
        self.byte_tokens.assert_not_called()
        self.assertNotIn("pull-image", self.events)
        self.assertNotIn("up", self.events)

    def test_verify_refuses_foreign_volume_before_backup_or_public_success(self):
        self.assertEqual(self.cli(), 0)
        self.volumes["conspect_db_data"]["Labels"]["io.conspect.installation"] = OTHER_INSTALLATION_ID
        self.assert_ownership_refusal(command="verify", before_prerequisites=False)
        self.validator.assert_not_called()

    def test_inventory_failure_cannot_authorize_prerequisite_changes(self):
        self.failures.add("inventory-volumes")
        self.assertEqual(self.cli(install_deps=True), 1)
        self.assert_no_initialization()
        self.prerequisites.assert_not_called()
        self.assert_docker_read_only()


class BootstrapGuardTests(BootstrapFixture):
    def test_global_project_lock_excludes_a_different_installation_root(self):
        original_root = self.root
        other_root = self.base / "another-parent/conspect"
        other_root.parent.mkdir(mode=0o750)
        with self.real_bootstrap_lock(original_root):
            self.root = other_root
            self.assertEqual(self.cli(), 1)
            self.assertIn("Another bootstrap", self.output)
            self.assert_no_initialization()
            self.prerequisites.assert_not_called()
            self.local_docker.assert_not_called()
            self.docker.assert_not_called()
        self.assertEqual(stat.S_IMODE(self.project_lock.stat().st_mode), 0o600)
        self.assertFalse(original_root.exists())
        with self.real_bootstrap_lock(other_root):
            with self.assertRaises(OperationError), self.real_bootstrap_lock(original_root):
                self.fail("Different roots must still serialize the fixed Conspect Docker project")

    def test_local_docker_capability_failure_prevents_prerequisite_and_secret_generation(self):
        self.failures.add("local-docker")
        self.assertEqual(self.cli(install_deps=True), 1)
        self.assert_no_initialization()
        self.local_docker.assert_called_once_with()
        self.prerequisites.assert_not_called()
        self.docker.assert_not_called()
        self.assertLess(self.events.index("port"), self.events.index("local-docker"))

    def test_compose_capability_check_must_finish_before_any_identity_or_secret_generation(self):
        observed = []

        def check_capabilities(**kwargs):
            self.assertFalse(self.root.exists())
            self.byte_tokens.assert_not_called()
            self.hex_tokens.assert_not_called()
            self.owner_token.assert_not_called()
            observed.append(kwargs)
            raise OperationError("Synthetic Compose missing up --no-recreate or start --wait")

        self.prerequisites.side_effect = check_capabilities
        self.assertEqual(self.cli(install_deps=True), 1)
        self.assertEqual(observed, [{"install": True}])
        self.assert_no_initialization()
        self.assert_docker_read_only()

    def test_absent_containers_are_inspected_before_up_and_health_checked_afterwards(self):
        self.assertEqual(self.cli(), 0)
        self.assertEqual(self.container_inspections[:2], [("app", None), ("db", None)])
        self.assertLess(self.events.index("compose"), self.events.index("up"))
        self.assertGreater(max(index for index, name in enumerate(self.events) if name == "compose"), self.events.index("up"))
        self.assertTrue(all(container is not None for _, container in self.container_inspections[2:]))

    def test_existing_app_or_db_environment_mismatch_refuses_before_up(self):
        self.assertEqual(self.cli(), 0)
        for service, fields in (
            ("app", ("APP_SECRET", "DATABASE_URL", "APP_BASE_URL", "DATA_DIR")),
            ("db", ("POSTGRES_DB", "POSTGRES_USER", "POSTGRES_PASSWORD")),
        ):
            for field in fields:
                with self.subTest(service=service, field=field):
                    original = list(self.containers[service]["Config"]["Env"])
                    values = dict(value.split("=", 1) for value in original)
                    values[field] = PRIVATE
                    self.containers[service]["Config"]["Env"] = [name + "=" + value for name, value in values.items()]
                    files = self.immutable_files()
                    marker = (self.root / ".bootstrap.json").read_bytes()
                    retained = deepcopy(self.containers)
                    self.reset_activity()
                    try:
                        self.assertEqual(self.cli(), 1)
                        self.assertEqual(self.immutable_files(), files)
                        self.assertEqual((self.root / ".bootstrap.json").read_bytes(), marker)
                        self.assertEqual(self.containers, retained)
                        self.assertNotIn("up", self.events)
                        self.compose_factory.assert_called_once_with(nginx=True)
                        for mock in (self.snapshot, self.mcp, self.public_owner, self.byte_tokens, self.hex_tokens):
                            mock.assert_not_called()
                        self.assert_private_output()
                    finally:
                        self.containers[service]["Config"]["Env"] = original

    def test_existing_app_image_mismatch_cannot_be_updated_or_recreated_by_bootstrap(self):
        self.assertEqual(self.cli(), 0)
        self.containers["app"]["Image"] = "sha256:" + "38" * 32
        retained = deepcopy(self.containers)
        files = self.immutable_files()
        self.reset_activity()
        self.assertEqual(self.cli(), 1)
        self.assertIn("different image", self.output)
        self.assertEqual(self.containers, retained)
        self.assertEqual(self.immutable_files(), files)
        self.assertNotIn("up", self.events)
        self.snapshot.assert_not_called()
        self.mcp.assert_not_called()

    def test_no_recreate_retry_preserves_db_container_when_mutable_postgres_cache_changes(self):
        self.assertEqual(self.cli(), 0)
        original_db = deepcopy(self.containers["db"])
        original_app = deepcopy(self.containers["app"])
        self.cached_db_image_id = "sha256:" + "49" * 32
        self.reset_activity()
        self.assertEqual(self.cli(), 0)
        self.assertEqual(self.containers["db"], original_db)
        self.assertEqual(self.containers["app"], original_app)
        self.assertNotEqual(self.containers["db"]["Image"], self.cached_db_image_id)
        up = [command for command, _, _ in self.commands if "up" in command]
        self.assertEqual(len(up), 1)
        self.assertIn("--no-recreate", up[0])
        self.assertIn("--no-build", up[0])
        self.assertEqual(up[0][up[0].index("--pull") + 1], "never")
        self.assertNotIn("pull-db", self.events)
        self.assertNotIn("--force-recreate", up[0])
        self.byte_tokens.assert_not_called()
        self.hex_tokens.assert_not_called()
        self.snapshot.assert_not_called()

    def test_public_owner_mismatch_is_local_ready_not_healthy_then_verify_can_correlate(self):
        self.errors["public-owner"] = OperationError(PRIVATE)
        self.assertEqual(self.cli(), 2)
        self.assertEqual(self.state()["status"], "local-ready")
        self.assertIn("LOCAL_READY:", self.output)
        self.assertNotIn("HEALTHY:", self.output)
        self.assertLess(self.events.index("validate-backup"), self.events.index("public"))
        self.assertLess(self.events.index("public"), self.events.index("public-owner"))
        self.assert_private_output()
        retained = deepcopy((self.containers, self.volumes, self.networks))
        files = self.immutable_files()
        self.errors.clear()
        self.reset_activity()
        self.assertEqual(self.cli("verify"), 0)
        self.assertEqual(self.state()["status"], "healthy")
        self.assertEqual(self.immutable_files(), files)
        self.assertEqual((self.containers, self.volumes, self.networks), retained)
        self.assert_docker_read_only()
        self.public_owner.assert_called_once_with(self.root, ORIGIN)
        self.snapshot.assert_not_called()
        self.byte_tokens.assert_not_called()
        self.hex_tokens.assert_not_called()

    def test_failed_mcp_discovery_never_sends_owner_credentials(self):
        self.failures.add("public")
        self.assertEqual(self.cli(), 2)
        self.public_owner.assert_not_called()
        self.https.assert_not_called()
        self.assertEqual(self.state()["status"], "local-ready")
        self.assert_private_output()


class BootstrapPublicOwnerTests(BootstrapFixture):
    def setUp(self):
        super().setUp()
        self.root.mkdir(mode=0o700)
        self.login_password = OWNER_PASSWORD + "&extra=field+suffix"
        (self.root / "owner-login.txt").write_text(
            "URL: " + ORIGIN + "/login\nUsername: admin\nPassword: " + self.login_password + "\n", encoding="utf-8",
        )
        (self.root / "owner-login.txt").chmod(0o600)
        self.headers = {
            "Set-Cookie": "conspect_session=" + SESSION_COOKIE + "; Path=/; Secure; HttpOnly; SameSite=Lax",
            "Location": "/projects",
        }
        self.response = Mock(status=303)
        self.response.getheader.side_effect = lambda name, default=None: self.headers.get(name, default)
        self.response.read.return_value = (PRIVATE + OWNER_PASSWORD + SESSION_COOKIE).encode()
        self.connection = Mock()
        self.connection.getresponse.return_value = self.response
        self.client = self.enter(patch.object(http.client, "HTTPSConnection", return_value=self.connection))

    def assert_single_direct_request(self, *, port=None, origin=ORIGIN):
        self.client.assert_called_once_with("notes.example.net", port, timeout=15)
        self.connection.request.assert_called_once()
        args, kwargs = self.connection.request.call_args
        self.assertEqual(args, ("POST", "/login"))
        self.assertEqual(parse_qs(kwargs["body"]), {"username": ["admin"], "password": [self.login_password]})
        self.assertEqual(kwargs["headers"], {"Origin": origin, "Content-Type": "application/x-www-form-urlencoded"})
        self.connection.close.assert_called_once_with()
        self.docker.assert_not_called()
        self.process.assert_not_called()
        self.network.assert_not_called()
        self.dns.assert_not_called()
        self.https.assert_not_called()
        self.assert_private_output()

    def test_verified_https_owner_login_requires_303_and_secure_httponly_session(self):
        os.environ.update({"HTTP_PROXY": "http://" + PRIVATE, "HTTPS_PROXY": "http://" + PRIVATE, "ALL_PROXY": "http://" + PRIVATE})
        self.real_public_owner_check(self.root, ORIGIN)
        self.assert_single_direct_request()
        self.connection.getresponse.assert_called_once_with()
        self.response.read.assert_called_once_with(65537)

    def test_explicit_public_https_port_is_used_without_redirect_or_ambient_proxy(self):
        self.real_public_owner_check(self.root, ORIGIN + ":8443")
        self.assert_single_direct_request(port=8443, origin=ORIGIN + ":8443")

    def test_wrong_installation_owner_401_is_refused_without_logging_credentials(self):
        self.response.status = 401
        with self.assertRaisesRegex(OperationError, "this installation owner"):
            self.real_public_owner_check(self.root, ORIGIN)
        self.assert_single_direct_request()
        self.response.read.assert_not_called()

    def test_login_redirects_to_any_other_location_are_not_followed(self):
        for status, location in ((301, "/projects"), (302, "/projects"), (307, "/projects"),
                                 (308, "/projects"), (303, "https://other.example.net/" + PRIVATE),
                                 (303, ORIGIN + "/projects"), (303, "/login")):
            with self.subTest(status=status, location=location):
                self.response.status = status
                self.headers["Location"] = location
                self.client.reset_mock()
                self.connection.reset_mock()
                with self.assertRaises(OperationError):
                    self.real_public_owner_check(self.root, ORIGIN)
                self.assert_single_direct_request()

    def test_cookie_name_secure_and_httponly_are_all_required(self):
        for cookie in ("", "unrelated=" + SESSION_COOKIE + "; Secure; HttpOnly",
                       "conspect_session=" + SESSION_COOKIE + "; HttpOnly",
                       "conspect_session=" + SESSION_COOKIE + "; Secure"):
            with self.subTest(cookie=cookie):
                self.headers["Set-Cookie"] = cookie
                self.client.reset_mock()
                self.connection.reset_mock()
                with self.assertRaises(OperationError):
                    self.real_public_owner_check(self.root, ORIGIN)
                self.assert_single_direct_request()

    def test_network_tls_or_http_failure_is_sanitized_and_closes_connection(self):
        for target, error in ((self.connection.request, OSError(PRIVATE + OWNER_PASSWORD)),
                              (self.connection.request, ssl.SSLCertVerificationError(PRIVATE)),
                              (self.connection.getresponse, http.client.BadStatusLine(PRIVATE)),
                              (self.response.read, http.client.IncompleteRead(PRIVATE.encode()))):
            with self.subTest(target=target):
                self.client.reset_mock()
                self.connection.reset_mock()
                self.response.read.reset_mock()
                target.side_effect = error
                try:
                    with self.assertRaises(OperationError) as caught:
                        self.real_public_owner_check(self.root, ORIGIN)
                    rendered = "".join(traceback.format_exception(type(caught.exception), caught.exception, caught.exception.__traceback__))
                    for value in (PRIVATE, OWNER_PASSWORD, SESSION_COOKIE):
                        self.assertNotIn(value, rendered)
                    self.assert_single_direct_request()
                finally:
                    target.side_effect = None

    def test_malformed_cookie_from_wrong_public_server_is_a_sanitized_refusal(self):
        self.headers["Set-Cookie"] = "Secure=" + PRIVATE
        with self.assertRaises(OperationError):
            self.real_public_owner_check(self.root, ORIGIN)
        self.assert_single_direct_request()


class BootstrapLocalCheckTests(BootstrapFixture):
    def local_compose(self):
        compose = Mock()
        compose.app_env = {"APP_BASE_URL": ORIGIN, "MCP_ENABLED": "true"}
        containers = {
            service: {
                "State": {"Status": "running", "Health": {"Status": "healthy"}},
                "Config": {"Labels": {"com.docker.compose.project.working_dir": str(self.root)}},
            }
            for service in ("app", "db")
        }
        compose.container.side_effect = containers.get
        return compose, containers

    def test_local_check_really_preflights_both_healthy_containers_and_canonical_origin(self):
        compose, _ = self.local_compose()
        compose.app_env["APP_BASE_URL"] = "https://NOTES.EXAMPLE.NET:443/"
        self.assertEqual(bootstrap.check_local(compose, self.root), ORIGIN)
        compose.preflight.assert_called_once_with(backup=True)
        self.assertEqual(compose.container.call_args_list, [unittest.mock.call("app"), unittest.mock.call("db")])
        self.network.assert_not_called()
        self.docker.assert_not_called()
        self.mcp.assert_not_called()

    def test_local_check_rejects_absent_stopped_unhealthy_or_missing_health_for_either_service(self):
        for service in ("app", "db"):
            for state in (None, {"Status": "exited", "Health": {"Status": "healthy"}},
                          {"Status": "running", "Health": {"Status": "unhealthy"}},
                          {"Status": "running", "Health": {"Status": "starting"}}, {"Status": "running"}):
                with self.subTest(service=service, state=state):
                    compose, containers = self.local_compose()
                    if state is None:
                        containers[service] = None
                    else:
                        containers[service]["State"] = state
                    with self.assertRaises(OperationError):
                        bootstrap.check_local(compose, self.root)

    def test_local_check_rejects_container_from_other_installation_or_missing_label(self):
        for service in ("app", "db"):
            for labels in ({}, {"com.docker.compose.project.working_dir": str(self.base / "other")}):
                with self.subTest(service=service, labels=labels):
                    compose, containers = self.local_compose()
                    containers[service]["Config"]["Labels"] = labels
                    with self.assertRaises(OperationError):
                        bootstrap.check_local(compose, self.root)

    def test_local_check_propagates_preflight_failure_without_inspection_or_network(self):
        compose, _ = self.local_compose()
        compose.preflight.side_effect = OperationError("Synthetic preflight failed")
        with self.assertRaises(OperationError):
            bootstrap.check_local(compose, self.root)
        compose.container.assert_not_called()
        self.mcp.assert_not_called()

    def test_local_check_requires_remote_mcp_and_valid_public_origin(self):
        for value in ("false", "", None, "1", "yes"):
            with self.subTest(mcp=value):
                compose, _ = self.local_compose()
                compose.app_env["MCP_ENABLED"] = value
                with self.assertRaises(OperationError):
                    bootstrap.check_local(compose, self.root)
        for value in ("", "http://notes.example.net", ORIGIN + "/mcp", "https://127.0.0.1", "https://user:" + PRIVATE + "@notes.example.net"):
            with self.subTest(origin=value):
                compose, _ = self.local_compose()
                compose.app_env["APP_BASE_URL"] = value
                with self.assertRaises(OperationError):
                    bootstrap.check_local(compose, self.root)


class BootstrapResourceTests(BootstrapFixture):
    def test_port_probe_binds_only_loopback_and_never_connects_or_stops_services(self):
        with patch.object(bootstrap.socket, "socket") as factory:
            connection = factory.return_value.__enter__.return_value
            self.real_free_port(8096)
            factory.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
            connection.bind.assert_called_once_with(("127.0.0.1", 8096))
            connection.connect.assert_not_called()
            connection.listen.assert_not_called()
            factory.return_value.__exit__.assert_called_once()
        self.docker.assert_not_called()
        self.process.assert_not_called()

    def test_port_probe_failure_is_sanitized_and_never_reclaims_port(self):
        with patch.object(bootstrap.socket, "socket") as factory:
            factory.return_value.__enter__.return_value.bind.side_effect = OSError(PRIVATE)
            with self.assertRaisesRegex(OperationError, "occupied") as caught:
                self.real_free_port(8096)
        self.assertNotIn(PRIVATE, str(caught.exception))
        self.docker.assert_not_called()
        self.process.assert_not_called()

    def resource_check(self, memory, free):
        with patch.object(Path, "read_text", return_value=memory), \
                patch.object(bootstrap.shutil, "disk_usage", return_value=SimpleNamespace(free=free)) as disk:
            result = self.real_check_resources(self.root)
            disk.assert_called_once_with(self.root.parent)
            return result

    def test_resource_budget_accepts_exact_minimum_without_commands(self):
        self.assertIsNone(self.resource_check("MemTotal: 786432 kB\n", 2 * 1024 ** 3))
        self.docker.assert_not_called()
        self.process.assert_not_called()

    def test_resource_budget_refuses_low_memory_or_disk(self):
        for memory, free in ((786431, 10 * 1024 ** 3), (786432, 2 * 1024 ** 3 - 1)):
            with self.subTest(memory=memory, free=free), \
                    patch.object(Path, "read_text", return_value="MemTotal: " + str(memory) + " kB\n"), \
                    patch.object(bootstrap.shutil, "disk_usage", return_value=SimpleNamespace(free=free)), \
                    self.assertRaisesRegex(OperationError, "768 MiB"):
                self.real_check_resources(self.root)

    def test_missing_malformed_or_unreadable_memory_fails_closed_without_private_details(self):
        for content in ("", "MemTotal: not-a-number kB\n"):
            with self.subTest(content=content), patch.object(Path, "read_text", return_value=content), \
                    self.assertRaisesRegex(OperationError, "Cannot inspect"):
                self.real_check_resources(self.root)
        with patch.object(Path, "read_text", side_effect=OSError(PRIVATE)), \
                self.assertRaises(OperationError) as caught:
            self.real_check_resources(self.root)
        self.assertNotIn(PRIVATE, str(caught.exception))


if __name__ == "__main__":
    unittest.main()
