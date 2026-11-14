"""Prerequisite safety tests: fake root, processes and HTTPS; no real provisioning."""

import hashlib
import io
import json
import os
import stat
import subprocess
import tempfile
import traceback
import unittest
from http.client import HTTPMessage, IncompleteRead
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.error import URLError
from urllib.request import Request

import operations
import prerequisites
from operations import OperationError

BINARY = b"synthetic pinned Compose executable, never executed\n"
SECRET = "synthetic-private-value-never-log"


class DownloadResponse(io.BytesIO):
    def __init__(self, data, url):
        super().__init__(data)
        self.url = url

    def geturl(self):
        return self.url


class CommandFailure(OperationError):
    def __init__(self):
        super().__init__(SECRET)
        self.command_stderr = SECRET.encode()


class PrerequisiteTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="conspect-prerequisites-test-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.home = self.base / "root"
        self.home.mkdir(mode=0o700)
        self.plugin = self.base / "usr/local/lib/docker/cli-plugins/docker-compose"
        self.socket = self.base / "run/docker.sock"
        self.systemd = self.base / "run/systemd/system"
        self.systemd.mkdir(parents=True, mode=0o755)
        self.owners = {}
        self.programs = {"docker", "tar", "apt-get", "systemctl", "dpkg-query"}
        self.commands = []
        self.failures = {}
        self.endpoint = "unix:///var/run/docker.sock"
        self.info = {"OSType": "linux", "Architecture": "x86_64", "ClientInfo": {"Plugins": []}}
        self.raw_info = None
        self.tar_version = "tar (GNU tar) 1.35\n"
        self.packages = "base-files\tinstall ok installed\n"
        self.units = ""
        self.compose_ready = True
        self.ready_after_install = True
        self.missing_flags = {"start": set(), "up": set()}
        self.package_install_works = True
        self.download_bytes = BINARY
        self.download_url = prerequisites.COMPOSE_URL
        self.replace_events = []
        self.enter(patch.dict(os.environ, {"PATH": os.defpath, "HOME": str(self.home)}, clear=True))
        self.enter(patch.object(prerequisites.platform, "system", return_value="Linux"))
        self.enter(patch.object(prerequisites.platform, "machine", return_value="x86_64"))
        self.enter(patch.object(prerequisites.platform, "freedesktop_os_release", return_value={
            "ID": "ubuntu", "VERSION_ID": "24.04",
        }))
        self.enter(patch.object(prerequisites.sys, "version_info", (3, 10, 0)))
        self.enter(patch.object(prerequisites.os, "geteuid", return_value=0))
        self.enter(patch.object(prerequisites.shutil, "which", side_effect=lambda name: (
            "/usr/bin/" + name if name in self.programs else None
        )))
        self.enter(patch.object(prerequisites, "COMPOSE_PATH", self.plugin))
        self.enter(patch.object(prerequisites, "DOCKER_SOCKET", self.socket))
        self.engine_state = tuple(self.base / path.relative_to("/") for path in prerequisites.ENGINE_STATE_PATHS)
        self.enter(patch.object(prerequisites, "ENGINE_STATE_PATHS", self.engine_state))
        self.enter(patch.object(prerequisites, "SYSTEMD_PATH", self.systemd))
        self.enter(patch.object(Path, "home", return_value=self.home))

        # Ownership is simulated, but file types, modes, symlinks and atomic writes are real.
        real_stat = Path.stat
        external_parents = set(self.base.parents)

        def owned_stat(path, *, follow_symlinks=True):
            info = list(real_stat(path, follow_symlinks=follow_symlinks))
            if path == self.base or self.base in path.parents:
                info[4] = self.owners.get(path, 0)
            elif path in external_parents:
                info[4] = 0
                info[0] = int(info[0]) & ~0o022
            return os.stat_result(info)

        self.enter(patch.object(Path, "stat", owned_stat))
        self.enter(patch.object(subprocess, "run", side_effect=AssertionError("Unexpected real subprocess")))
        self.enter(patch.object(operations, "run_command", side_effect=AssertionError("Unexpected real command")))
        self.command = self.enter(patch.object(prerequisites, "run_command", side_effect=self.fake_command))
        self.opener = Mock()
        self.opener.open.side_effect = self.fake_download
        self.enter(patch.object(prerequisites, "build_opener", return_value=self.opener))
        real_replace = os.replace

        def replace(source, target):
            self.replace_events.append((source, target))
            real_replace(source, target)
            self.compose_ready = self.ready_after_install

        self.enter(patch.object(prerequisites.os, "replace", side_effect=replace))

    def enter(self, manager):
        value = manager.__enter__()
        self.addCleanup(manager.__exit__, None, None, None)
        return value

    def fake_command(self, arguments, *, stdin, timeout):
        self.assertEqual(stdin, subprocess.DEVNULL)
        self.assertGreater(timeout, 0)
        self.assertLessEqual(timeout, 900)
        self.commands.append(list(arguments))
        key = tuple(arguments)
        if key in self.failures:
            raise self.failures[key]
        if arguments[:3] == ["docker", "context", "inspect"]:
            return json.dumps(self.endpoint)
        if arguments[:2] == ["docker", "info"]:
            return self.raw_info if self.raw_info is not None else json.dumps(self.info)
        if arguments[:2] == ["docker", "compose"]:
            self.assertEqual(arguments[3:], ["--help"])
            command = arguments[2]
            flags = set(prerequisites.COMPOSE_FLAGS[command]) - self.missing_flags[command]
            if not self.compose_ready:
                flags.discard("--wait-timeout")
            return "Usage: docker compose " + command + "\nFlags:\n" + "".join(
                "      " + flag + " value   Help without any numbered version\n" for flag in sorted(flags)
            )
        if arguments == ["tar", "--version"]:
            return self.tar_version
        if arguments[0] == "dpkg-query":
            return self.packages
        if arguments[:2] == ["systemctl", "list-units"]:
            return self.units
        if arguments == ["systemctl", "enable", "--now", "docker.service"]:
            return ""
        if arguments[:4] == ["env", "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=l", "apt-get"]:
            if arguments[4] == "install" and self.package_install_works:
                if "docker.io" in arguments:
                    self.programs.add("docker")
                if "tar" in arguments:
                    self.programs.add("tar")
            return ""
        raise AssertionError("Unexpected command: " + repr(arguments))

    def fake_download(self, url, *, timeout):
        self.assertEqual(url, prerequisites.COMPOSE_URL)
        self.assertEqual(timeout, 30)
        return DownloadResponse(self.download_bytes, self.download_url)

    def enable_test_digest(self):
        self.enter(patch.object(prerequisites, "COMPOSE_SHA256", hashlib.sha256(BINARY).hexdigest()))

    def request_compose_install(self):
        self.compose_ready = False
        self.enable_test_digest()

    def write_plugin(self, content=BINARY, *, mode=0o755):
        self.plugin.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        self.plugin.write_bytes(content)
        self.plugin.chmod(mode)

    def docker_config(self, data):
        path = self.home / ".docker/config.json"
        path.parent.mkdir(exist_ok=True, mode=0o700)
        path.write_text(json.dumps(data), encoding="utf-8")
        path.chmod(0o600)
        return path

    def assert_no_install(self):
        self.opener.open.assert_not_called()
        self.assertEqual(self.replace_events, [])
        self.assertFalse(any(command[0] == "env" or command[:2] == ["systemctl", "enable"]
                             for command in self.commands))

    def assert_secret_free(self, function, regex):
        with self.assertRaisesRegex(OperationError, regex) as caught:
            function()
        rendered = "".join(traceback.format_exception(type(caught.exception), caught.exception,
                                                     caught.exception.__traceback__))
        self.assertNotIn(SECRET, rendered)
        self.assertFalse(hasattr(caught.exception, "command_stderr"))

    def test_official_release_pin_is_immutable(self):
        self.assertEqual(prerequisites.COMPOSE_VERSION, "v5.7.1")
        self.assertEqual(prerequisites.COMPOSE_SHA256,
                         "af426722a8af5de812fcee30cc1c39f0639f5f723cbadefb25e5d4db054064cf")
        self.assertEqual(prerequisites.COMPOSE_URL,
                         "https://github.com/docker/compose/releases/download/v5.7.1/docker-compose-linux-x86_64")

    def test_check_local_docker_is_read_only_without_compose_or_tar(self):
        self.programs.remove("tar")
        self.compose_ready = False
        self.failures[("docker", "compose", "start", "--help")] = OperationError(SECRET)
        self.info["ClientInfo"]["Plugins"] = [{"Name": "compose", "Path": "/opt/" + SECRET}]
        self.assertIsNone(prerequisites.check_local_docker())
        self.assertEqual(self.commands, [
            ["docker", "context", "inspect", "--format", "{{json .Endpoints.docker.Host}}"],
            ["docker", "info", "--format", "{{json .}}"],
        ])
        self.assert_no_install()
        self.assertFalse(self.plugin.parent.exists())
        self.assertFalse((self.home / ".docker").exists())

    def test_check_local_docker_requires_client_without_installing(self):
        self.programs.remove("docker")
        with self.assertRaisesRegex(OperationError, "Missing dependency: Docker"):
            prerequisites.check_local_docker()
        self.assertEqual(self.commands, [])
        self.assert_no_install()

    def test_check_local_docker_rejects_remote_or_unavailable_daemon(self):
        self.endpoint = "ssh://" + SECRET
        self.assert_secret_free(prerequisites.check_local_docker, "local default Unix socket")
        self.endpoint = "unix:///var/run/docker.sock"
        self.failures[("docker", "info", "--format", "{{json .}}")] = OperationError(SECRET)
        self.assert_secret_free(prerequisites.check_local_docker, "unavailable")
        self.failures.clear()
        self.info["Architecture"] = "aarch64"
        self.assert_secret_free(prerequisites.check_local_docker, "linux/amd64")
        self.assert_no_install()

    def test_check_compose_is_read_only_and_does_not_require_numbered_version(self):
        self.assertIsNone(prerequisites.check_compose())
        self.assertEqual(self.commands, [
            ["docker", "context", "inspect", "--format", "{{json .Endpoints.docker.Host}}"],
            ["docker", "info", "--format", "{{json .}}"],
            ["docker", "compose", "start", "--help"],
            ["docker", "compose", "up", "--help"],
        ])
        self.assert_no_install()
        self.assertFalse(self.plugin.parent.exists())

    def test_daemon_amd64_aliases_are_accepted(self):
        for architecture in ("amd64", "x86_64"):
            with self.subTest(architecture=architecture):
                self.info["Architecture"] = architecture
                prerequisites.check_compose()
        self.assert_no_install()

    def test_wrong_or_malformed_daemon_platform_fails_before_compose(self):
        for operating_system, architecture in (
            ("windows", "amd64"), ("linux", "aarch64"), ("linux", ""),
            (None, "amd64"), ("linux", None), ("linux", []), ("linux", {}),
        ):
            with self.subTest(operating_system=operating_system, architecture=architecture):
                self.commands.clear()
                self.info.update(OSType=operating_system, Architecture=architecture)
                with self.assertRaisesRegex(OperationError, "linux/amd64"):
                    prerequisites.ensure_prerequisites(install=True)
                self.assertFalse(any(command[:2] == ["docker", "compose"] for command in self.commands))
        self.assert_no_install()

    def test_invalid_docker_info_is_secret_free(self):
        for raw in (SECRET, "null", "[]", '"' + SECRET + '"'):
            with self.subTest(raw=raw):
                self.raw_info = raw
                self.assert_secret_free(prerequisites.check_compose, "linux/amd64")
        self.assert_no_install()

    def test_only_local_default_socket_context_is_accepted(self):
        for endpoint in ("tcp://" + SECRET, "ssh://" + SECRET, "unix:///run/user/1000/docker.sock", None, {}):
            with self.subTest(endpoint=endpoint):
                self.commands.clear()
                self.endpoint = endpoint
                self.assert_secret_free(prerequisites.check_compose, "local default Unix socket")
                self.assertEqual(len(self.commands), 1)
        self.endpoint = "unix:///run/docker.sock"
        prerequisites.check_compose()
        self.assert_no_install()

    def test_malformed_context_output_is_rejected(self):
        command = ("docker", "context", "inspect", "--format", "{{json .Endpoints.docker.Host}}")
        with patch.object(prerequisites, "run_command", return_value=SECRET) as run:
            self.assert_secret_free(prerequisites.check_compose, "local default Unix socket")
        self.assertEqual(run.call_args.args[0], list(command))
        self.assert_no_install()

    def test_up_requires_no_recreate_to_preserve_existing_containers(self):
        self.assertIn("--no-recreate", prerequisites.COMPOSE_FLAGS["up"])
        self.missing_flags["up"].add("--no-recreate")
        with self.assertRaisesRegex(OperationError, "--no-recreate"):
            prerequisites.check_compose()
        self.assert_no_install()

    def test_every_required_option_is_checked_separately(self):
        for command, flags in prerequisites.COMPOSE_FLAGS.items():
            for flag in flags:
                with self.subTest(command=command, flag=flag):
                    self.missing_flags[command].add(flag)
                    with self.assertRaisesRegex(OperationError, "start --wait --wait-timeout"):
                        prerequisites.check_compose()
                    self.missing_flags[command].clear()
        self.assert_no_install()

    def test_descriptions_and_flag_prefixes_do_not_count_as_capabilities(self):
        for help_text in (
            "Description: supports --wait --wait-timeout --no-build --pull --no-deps --no-recreate\n",
            "  --wait-timeout int  Timeout\n",
            "  --wait-extra bool\n  --wait-timeout-extra int\n",
        ):
            with (
                self.subTest(help_text=help_text),
                patch.object(prerequisites, "_command", side_effect=[json.dumps(self.endpoint), json.dumps(self.info), help_text]),
                self.assertRaisesRegex(OperationError, "compatible plugin"),
            ):
                prerequisites.check_compose()
        self.assert_no_install()

    def test_process_failures_and_timeouts_never_disclose_output(self):
        commands = (
            ("docker", "context", "inspect", "--format", "{{json .Endpoints.docker.Host}}"),
            ("docker", "info", "--format", "{{json .}}"),
            ("docker", "compose", "start", "--help"),
            ("docker", "compose", "up", "--help"),
        )
        for command in commands:
            for kind in ("exit", "timeout", "decode"):
                with self.subTest(command=command, kind=kind):
                    error = CommandFailure()
                    if kind == "timeout":
                        error = subprocess.TimeoutExpired(SECRET, 30, output=SECRET, stderr=SECRET)
                    elif kind == "decode":
                        error = UnicodeDecodeError("utf-8", SECRET.encode() + b"\xff", len(SECRET), len(SECRET) + 1, SECRET)
                    self.failures[command] = error
                    self.assert_secret_free(prerequisites.check_compose, "Docker")
                    self.failures.clear()
        self.assert_no_install()

    def test_docker_and_compose_environment_overrides_are_rejected(self):
        for name in ("DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH",
                     "DOCKER_API_VERSION", "DOCKER_CLI_PLUGIN_EXTRA_DIRS", "COMPOSE_FILE", "COMPOSE_PROJECT_NAME"):
            with self.subTest(name=name), patch.dict(os.environ, {name: SECRET}):
                for function in (prerequisites.check_local_docker, prerequisites.check_compose,
                                 prerequisites.ensure_prerequisites):
                    self.assert_secret_free(function, "environment overrides")
        self.assertEqual(self.commands, [])
        self.assert_no_install()

    def test_checks_require_linux_root_and_python_310(self):
        for attribute, value in (("geteuid", 1000), ("system", "Darwin"), ("version_info", (3, 9, 9))):
            owner = {"geteuid": os, "system": prerequisites.platform, "version_info": prerequisites.sys}[attribute]
            manager = patch.object(owner, attribute, value) if attribute == "version_info" else patch.object(
                owner, attribute, return_value=value
            )
            with self.subTest(attribute=attribute), manager:
                for function in (prerequisites.check_local_docker, prerequisites.check_compose,
                                 lambda: prerequisites.ensure_prerequisites(install=True)):
                    with self.assertRaisesRegex(OperationError, "root|Python 3.10"):
                        function()
        self.assertEqual(self.commands, [])
        self.assert_no_install()

    def test_default_reports_all_missing_dependencies_without_installing(self):
        self.programs.difference_update({"docker", "tar"})
        with self.assertRaisesRegex(OperationError, "Missing dependencies: docker.io, tar"):
            prerequisites.ensure_prerequisites()
        self.assertEqual(self.commands, [])
        self.assert_no_install()

    def test_default_missing_compose_fails_without_installing(self):
        self.failures[("docker", "compose", "start", "--help")] = OperationError(SECRET)
        self.assert_secret_free(prerequisites.ensure_prerequisites, "compatible plugin")
        self.assert_no_install()

    def test_gnu_tar_is_verified_before_installing_any_packages(self):
        for output in ("bsdtar 3.7.2\n", "BusyBox " + SECRET, ""):
            with self.subTest(output=output):
                self.tar_version = output
                self.assert_secret_free(lambda: prerequisites.ensure_prerequisites(install=True), "GNU tar")
        self.assert_no_install()

    def test_existing_compatible_dependencies_are_never_mutated(self):
        for install in (False, True):
            with self.subTest(install=install):
                self.assertIsNone(prerequisites.ensure_prerequisites(install=install))
        self.assert_no_install()
        self.assertFalse((self.home / ".docker").exists())
        self.assertFalse(self.plugin.parent.exists())

    def test_installation_is_limited_to_tested_distribution_and_architecture(self):
        for distribution, version, architecture in (
            ("debian", "12", "x86_64"), ("ubuntu", "22.04", "x86_64"),
            ("ubuntu", "24.04", "aarch64"), ("ubuntu", "24.10", "amd64"),
        ):
            with (
                self.subTest(distribution=distribution, version=version, architecture=architecture),
                patch.object(prerequisites.platform, "freedesktop_os_release",
                             return_value={"ID": distribution, "VERSION_ID": version}),
                patch.object(prerequisites.platform, "machine", return_value=architecture),
                self.assertRaisesRegex(OperationError, "only Ubuntu 24.04 amd64"),
            ):
                prerequisites.ensure_prerequisites(install=True)
        self.assertEqual(self.commands, [])
        self.assert_no_install()

    def test_verification_still_works_on_other_linux_distributions(self):
        with patch.object(prerequisites.platform, "freedesktop_os_release", side_effect=AssertionError("No install")):
            prerequisites.ensure_prerequisites()
        self.assert_no_install()

    def test_clean_server_installs_distro_docker_without_upgrade_or_shell(self):
        self.programs.difference_update({"docker", "tar"})
        self.request_compose_install()
        self.assertIsNone(prerequisites.ensure_prerequisites(install=True))
        installs = [command for command in self.commands if command[0] == "env"]
        self.assertEqual(installs, [
            ["env", "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=l", "apt-get", "update"],
            ["env", "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=l", "apt-get", "install", "--yes",
             "--no-upgrade", "--no-remove", "--no-install-recommends", "docker.io", "tar"],
        ])
        self.assertIn(["systemctl", "enable", "--now", "docker.service"], self.commands)
        self.assertFalse(any("restart" in command or "sh" in command or "curl" in command for command in self.commands))
        self.assertEqual(self.plugin.read_bytes(), BINARY)
        self.assertEqual(stat.S_IMODE(self.plugin.stat().st_mode), 0o755)
        self.assertEqual(self.plugin.stat().st_uid, 0)
        self.assertEqual(list(self.plugin.parent.iterdir()), [self.plugin])
        self.assertEqual(len(self.replace_events), 1)
        self.assertEqual(Path(self.replace_events[0][0]).parent, self.plugin.parent)
        self.assertEqual(self.replace_events[0][1], self.plugin)
        self.assertEqual(self.commands[-4:], [
            ["docker", "context", "inspect", "--format", "{{json .Endpoints.docker.Host}}"],
            ["docker", "info", "--format", "{{json .}}"],
            ["docker", "compose", "start", "--help"],
            ["docker", "compose", "up", "--help"],
        ])

    def test_existing_engine_with_missing_tar_only_installs_tar(self):
        self.programs.remove("tar")
        prerequisites.ensure_prerequisites(install=True)
        self.assertEqual(self.commands[:2], [
            ["docker", "context", "inspect", "--format", "{{json .Endpoints.docker.Host}}"],
            ["docker", "info", "--format", "{{json .}}"],
        ])
        install = next(command for command in self.commands if "install" in command)
        self.assertEqual(install[-1], "tar")
        self.assertNotIn("docker.io", install)
        self.assertFalse(any(command[0] in {"systemctl", "dpkg-query"} for command in self.commands))
        self.opener.open.assert_not_called()

    def test_existing_engine_only_needs_compose_and_is_not_touched(self):
        self.request_compose_install()
        real_download = prerequisites._download_compose

        def download(target):
            self.assertEqual(self.commands[:2], [
                ["docker", "context", "inspect", "--format", "{{json .Endpoints.docker.Host}}"],
                ["docker", "info", "--format", "{{json .}}"],
            ])
            real_download(target)

        with patch.object(prerequisites, "_download_compose", side_effect=download):
            prerequisites.ensure_prerequisites(install=True)
        self.assertFalse(any(command[0] in {"env", "systemctl", "dpkg-query"} for command in self.commands))
        self.assertEqual(self.plugin.read_bytes(), BINARY)

    def test_remote_context_blocks_installing_missing_tar_and_compose(self):
        self.programs.remove("tar")
        self.compose_ready = False
        self.endpoint = "ssh://" + SECRET
        self.assert_secret_free(lambda: prerequisites.ensure_prerequisites(install=True), "local default Unix socket")
        self.assertEqual(len(self.commands), 1)
        self.assert_no_install()

    def test_unavailable_daemon_blocks_installing_missing_tar_and_compose(self):
        self.programs.remove("tar")
        self.compose_ready = False
        self.failures[("docker", "info", "--format", "{{json .}}")] = OperationError(SECRET)
        self.assert_secret_free(lambda: prerequisites.ensure_prerequisites(install=True), "unavailable")
        self.assertEqual(len(self.commands), 2)
        self.assert_no_install()

    def test_wrong_daemon_platform_blocks_installing_missing_tar_and_compose(self):
        self.programs.remove("tar")
        self.compose_ready = False
        for operating_system, architecture in (("windows", "amd64"), ("linux", "aarch64")):
            with self.subTest(operating_system=operating_system, architecture=architecture):
                self.commands.clear()
                self.info.update(OSType=operating_system, Architecture=architecture)
                self.assert_secret_free(lambda: prerequisites.ensure_prerequisites(install=True), "linux/amd64")
                self.assertEqual(len(self.commands), 2)
                self.assert_no_install()

    def test_stopped_or_broken_existing_daemon_is_not_started(self):
        self.failures[("docker", "info", "--format", "{{json .}}")] = OperationError(SECRET)
        self.assert_secret_free(lambda: prerequisites.ensure_prerequisites(install=True), "will not be started")
        self.assert_no_install()

    def test_engine_package_conflicts_block_installation(self):
        self.programs.remove("docker")
        for name in ("docker.io", "docker-ce", "docker-ce-cli:amd64", "containerd.io", "containerd", "moby-engine", "runc"):
            with self.subTest(name=name):
                self.packages = name + "\tinstall ok installed\n"
                with self.assertRaisesRegex(OperationError, "conflicting docker.io/containerd"):
                    prerequisites.ensure_prerequisites(install=True)
        self.assert_no_install()

    def test_retained_runtime_data_and_package_config_block_distro_install(self):
        self.programs.remove("docker")
        for path in self.engine_state:
            with self.subTest(path=path):
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                path.mkdir(mode=0o700)
                with self.assertRaisesRegex(OperationError, "retained data"):
                    prerequisites.ensure_prerequisites(install=True)
                path.rmdir()
        self.packages = "docker.io\tdeinstall ok config-files\n"
        with self.assertRaisesRegex(OperationError, "conflicting docker.io/containerd"):
            prerequisites.ensure_prerequisites(install=True)
        self.assert_no_install()

    def test_existing_daemon_binary_socket_and_runtime_services_block_distro_install(self):
        self.programs.remove("docker")
        self.programs.add("dockerd")
        with self.assertRaisesRegex(OperationError, "existing Docker/container runtime"):
            prerequisites.ensure_prerequisites(install=True)
        self.programs.remove("dockerd")
        self.socket.write_bytes(b"synthetic existing daemon socket")
        with self.assertRaisesRegex(OperationError, "existing Docker/container runtime"):
            prerequisites.ensure_prerequisites(install=True)
        self.socket.unlink()
        for unit in ("docker.service", "containerd.service", "snap.docker.dockerd.service"):
            self.units = unit + " loaded active running\n"
            with self.subTest(unit=unit), self.assertRaisesRegex(OperationError, "existing Docker/container runtime"):
                prerequisites.ensure_prerequisites(install=True)
        self.assert_no_install()

    def test_unknown_package_or_service_state_fails_closed(self):
        self.programs.remove("docker")
        inspections = (
            (("dpkg-query", "--show", "--showformat=${binary:Package}\t${Status}\n"), "installed packages"),
            (("systemctl", "list-units", "--all", "--type=service", "--no-legend", "--plain", "--no-pager",
              "docker.service", "containerd.service", "snap.docker.dockerd.service"), "runtime services"),
        )
        for command, message in inspections:
            with self.subTest(command=command):
                self.failures[command] = OperationError(SECRET)
                self.assert_secret_free(lambda: prerequisites.ensure_prerequisites(install=True), message)
                self.failures.clear()
        self.assert_no_install()

    def test_docker_install_requires_apt_and_systemd(self):
        self.programs.remove("docker")
        for program in ("apt-get", "systemctl"):
            with self.subTest(program=program):
                self.programs.remove(program)
                with self.assertRaisesRegex(OperationError, "apt-get|systemd"):
                    prerequisites.ensure_prerequisites(install=True)
                self.programs.add(program)
        with (
            patch.object(prerequisites, "SYSTEMD_PATH", self.base / "not-systemd"),
            self.assertRaisesRegex(OperationError, "systemd"),
        ):
            prerequisites.ensure_prerequisites(install=True)
        self.assert_no_install()

    def test_failed_package_install_does_not_enable_docker_or_download_compose(self):
        self.programs.remove("docker")
        environment = ("env", "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=l", "apt-get")
        commands = (
            (environment + ("update",), "apt-get update failed"),
            (environment + ("install", "--yes", "--no-upgrade", "--no-remove", "--no-install-recommends", "docker.io"),
             "Installing missing Ubuntu packages failed"),
        )
        for command, message in commands:
            with self.subTest(command=command):
                self.failures[command] = OperationError(SECRET)
                self.assert_secret_free(lambda: prerequisites.ensure_prerequisites(install=True), message)
                self.failures.clear()
        self.opener.open.assert_not_called()
        self.assertNotIn(["systemctl", "enable", "--now", "docker.service"], self.commands)

    def test_dependencies_must_really_be_available_after_apt(self):
        self.programs.remove("docker")
        self.package_install_works = False
        with self.assertRaisesRegex(OperationError, "did not provide Docker/GNU tar"):
            prerequisites.ensure_prerequisites(install=True)
        self.opener.open.assert_not_called()

    def test_unmanaged_destination_is_never_overwritten(self):
        self.request_compose_install()
        self.write_plugin(SECRET.encode())
        self.assert_secret_free(lambda: prerequisites.ensure_prerequisites(install=True), "unmanaged Compose plugin")
        self.assertEqual(self.plugin.read_bytes(), SECRET.encode())
        self.assert_no_install()

    def test_known_managed_destination_can_be_repaired_atomically(self):
        self.request_compose_install()
        self.write_plugin(mode=0o600)
        prerequisites.ensure_prerequisites(install=True)
        self.assertEqual(self.plugin.read_bytes(), BINARY)
        self.assertEqual(stat.S_IMODE(self.plugin.stat().st_mode), 0o755)
        self.assertEqual(len(self.replace_events), 1)

    def test_user_plugin_is_preserved_even_if_it_matches_the_pin(self):
        self.request_compose_install()
        candidate = self.home / ".docker/cli-plugins/docker-compose"
        candidate.parent.mkdir(parents=True, mode=0o700)
        candidate.write_bytes(BINARY)
        with self.assertRaisesRegex(OperationError, "shadows"):
            prerequisites.ensure_prerequisites(install=True)
        self.assertEqual(candidate.read_bytes(), BINARY)
        self.assert_no_install()
        self.assertFalse(self.plugin.exists())

    def test_custom_configured_plugin_is_preserved_with_private_config(self):
        self.request_compose_install()
        custom = self.base / "custom/plugins"
        custom.mkdir(parents=True, mode=0o755)
        candidate = custom / "docker-compose"
        candidate.write_bytes(SECRET.encode())
        config = self.docker_config({"auths": {"private": SECRET}, "cliPluginsExtraDirs": [str(custom)]})
        before = config.read_bytes()
        self.assert_secret_free(lambda: prerequisites.ensure_prerequisites(install=True), "shadows")
        self.assertEqual(config.read_bytes(), before)
        self.assertEqual(candidate.read_bytes(), SECRET.encode())
        self.assert_no_install()

    def test_active_custom_plugin_metadata_fails_even_without_config_entry(self):
        self.request_compose_install()
        self.info["ClientInfo"]["Plugins"] = [{"Name": "compose", "Path": "/opt/" + SECRET}]
        self.assert_secret_free(lambda: prerequisites.ensure_prerequisites(install=True), "shadows")
        self.assert_no_install()

    def test_lower_priority_system_plugin_can_be_superseded_without_modification(self):
        self.request_compose_install()
        self.info["ClientInfo"]["Plugins"] = [{"Name": "compose", "Path": str(prerequisites.LOWER_PRIORITY_PLUGINS[0])}]
        prerequisites.ensure_prerequisites(install=True)
        self.assertEqual(self.plugin.read_bytes(), BINARY)

    def test_private_docker_config_is_not_rewritten_during_successful_install(self):
        self.request_compose_install()
        config = self.docker_config({"auths": {"private": SECRET}, "cliPluginsExtraDirs": [str(self.plugin.parent)]})
        before = config.read_bytes()
        prerequisites.ensure_prerequisites(install=True)
        self.assertEqual(config.read_bytes(), before)
        self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o600)
        self.assertFalse((config.parent / "cli-plugins").exists())

    def test_invalid_private_config_is_rejected_without_disclosure(self):
        self.request_compose_install()
        config = self.docker_config({})
        for content in (SECRET, "[]", '{"cliPluginsExtraDirs": "' + SECRET + '"}', '{"cliPluginsExtraDirs": [null]}'):
            with self.subTest(content=content):
                config.write_text(content, encoding="utf-8")
                self.assert_secret_free(lambda: prerequisites.ensure_prerequisites(install=True), "config|search paths")
        self.assert_no_install()

    def test_symlinked_destination_does_not_touch_victim(self):
        self.request_compose_install()
        victim = self.base / "victim"
        victim.write_bytes(SECRET.encode())
        self.plugin.parent.mkdir(parents=True, mode=0o755)
        self.plugin.symlink_to(victim)
        with self.assertRaisesRegex(OperationError, "no symlinks"):
            prerequisites.ensure_prerequisites(install=True)
        self.assertEqual(victim.read_bytes(), SECRET.encode())
        self.assertTrue(self.plugin.is_symlink())
        self.assert_no_install()

    def test_symlinked_install_parent_is_rejected(self):
        self.request_compose_install()
        self.plugin.parent.parent.mkdir(parents=True, mode=0o755)
        destination = self.base / "elsewhere"
        destination.mkdir(mode=0o755)
        self.plugin.parent.symlink_to(destination, target_is_directory=True)
        with self.assertRaisesRegex(OperationError, "no symlinks"):
            prerequisites.ensure_prerequisites(install=True)
        self.assertEqual(list(destination.iterdir()), [])
        self.assert_no_install()

    def test_symlinked_user_directory_and_config_are_rejected(self):
        self.request_compose_install()
        config = self.docker_config({"auths": {"private": SECRET}})
        victim = self.base / "private-config"
        config.rename(victim)
        config.symlink_to(victim)
        with self.assertRaisesRegex(OperationError, "no symlinks"):
            prerequisites.ensure_prerequisites(install=True)
        config.unlink()
        config.parent.rmdir()
        config.parent.symlink_to(self.base, target_is_directory=True)
        with self.assertRaisesRegex(OperationError, "no symlinks"):
            prerequisites.ensure_prerequisites(install=True)
        self.assertIn(SECRET, victim.read_text(encoding="utf-8"))
        self.assert_no_install()

    def test_untrusted_permissions_ownership_and_hardlinks_fail_before_download(self):
        self.request_compose_install()
        self.write_plugin()
        for path in (self.plugin, self.plugin.parent, self.plugin.parent.parent):
            with self.subTest(path=path, condition="writable"):
                original = stat.S_IMODE(path.stat().st_mode)
                path.chmod(original | 0o020)
                with self.assertRaisesRegex(OperationError, "root-owned"):
                    prerequisites.ensure_prerequisites(install=True)
                path.chmod(original)
            with self.subTest(path=path, condition="owner"):
                self.owners[path] = 1000
                with self.assertRaisesRegex(OperationError, "root-owned"):
                    prerequisites.ensure_prerequisites(install=True)
                self.owners.clear()
        os.link(self.plugin, self.base / "hardlink")
        with self.assertRaisesRegex(OperationError, "regular file"):
            prerequisites.ensure_prerequisites(install=True)
        self.assert_no_install()

    def test_download_checksum_failure_preserves_old_plugin_and_cleans_temporary(self):
        self.request_compose_install()
        self.write_plugin()
        self.download_bytes = SECRET.encode()
        self.assert_secret_free(lambda: prerequisites.ensure_prerequisites(install=True), "SHA-256 verification failed")
        self.assertEqual(self.plugin.read_bytes(), BINARY)
        self.assertEqual(self.replace_events, [])
        self.assertEqual(list(self.plugin.parent.iterdir()), [self.plugin])

    def test_download_failure_is_sanitized_and_partial_file_is_removed(self):
        self.request_compose_install()
        for error in (URLError(SECRET), TimeoutError(SECRET), IncompleteRead(SECRET.encode(), 100)):
            with self.subTest(error=type(error).__name__):
                self.opener.open.side_effect = error
                self.assert_secret_free(lambda: prerequisites.ensure_prerequisites(install=True), "HTTPS access")
                self.assertFalse(self.plugin.exists())
                self.assertEqual(list(self.plugin.parent.iterdir()), [])
        self.assertEqual(self.replace_events, [])

    def test_non_https_download_and_redirect_are_rejected(self):
        self.request_compose_install()
        self.download_url = "http://" + SECRET
        self.assert_secret_free(lambda: prerequisites.ensure_prerequisites(install=True), "must use HTTPS")
        self.assertEqual(list(self.plugin.parent.iterdir()), [])
        redirect = prerequisites._HTTPSRedirects()
        with io.BytesIO() as stream, self.assertRaisesRegex(OperationError, "non-HTTPS redirect"):
            redirect.redirect_request(Request(prerequisites.COMPOSE_URL), stream, 302, "", HTTPMessage(), "http://" + SECRET)
        self.assertEqual(self.replace_events, [])

    def test_download_has_a_total_deadline_and_never_executes_unverified_bytes(self):
        self.request_compose_install()
        with (
            patch.object(prerequisites.time, "monotonic", side_effect=[0, 181]),
            self.assertRaisesRegex(OperationError, "download timed out"),
        ):
            prerequisites.ensure_prerequisites(install=True)
        self.assertFalse(self.plugin.exists())
        self.assertEqual(list(self.plugin.parent.iterdir()), [])
        self.assertEqual(self.replace_events, [])

    def test_temporary_file_is_private_until_checksum_is_verified(self):
        self.request_compose_install()
        real_download = prerequisites._download_compose

        def download(target):
            self.assertEqual(stat.S_IMODE(os.fstat(target.fileno()).st_mode), 0o600)
            self.assertFalse(self.plugin.exists())
            real_download(target)
            self.assertEqual(stat.S_IMODE(os.fstat(target.fileno()).st_mode), 0o600)

        with patch.object(prerequisites, "_download_compose", side_effect=download):
            prerequisites.ensure_prerequisites(install=True)
        self.assertEqual(stat.S_IMODE(self.plugin.stat().st_mode), 0o755)

    def test_custom_file_appearing_during_download_is_not_clobbered(self):
        self.request_compose_install()
        real_download = prerequisites._download_compose

        def download(target):
            real_download(target)
            self.plugin.write_bytes(SECRET.encode())

        with patch.object(prerequisites, "_download_compose", side_effect=download):
            self.assert_secret_free(lambda: prerequisites.ensure_prerequisites(install=True), "unmanaged Compose plugin")
        self.assertEqual(self.plugin.read_bytes(), SECRET.encode())
        self.assertEqual(list(self.plugin.parent.iterdir()), [self.plugin])
        self.assertEqual(self.replace_events, [])

    def test_installation_rechecks_actual_docker_plugin_capabilities(self):
        self.request_compose_install()
        self.ready_after_install = False
        with self.assertRaisesRegex(OperationError, "compatible plugin"):
            prerequisites.ensure_prerequisites(install=True)
        self.assertEqual(self.plugin.read_bytes(), BINARY)
        self.assertEqual(len(self.replace_events), 1)
        self.assertFalse(any(command[:3] in (["docker", "compose", "up"], ["docker", "compose", "start"])
                             and command[-1] != "--help" for command in self.commands))


if __name__ == "__main__":
    unittest.main()
