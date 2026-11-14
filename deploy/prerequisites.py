"""Read-only prerequisite checks and opt-in Ubuntu 24.04 amd64 provisioning."""

import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from http.client import HTTPException
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, build_opener

from operations import OperationError, run_command

COMPOSE_VERSION = "v5.7.1"
COMPOSE_URL = (
    "https://github.com/docker/compose/releases/download/"
    + COMPOSE_VERSION + "/docker-compose-linux-x86_64"
)
# Verified against both official v5.7.1 checksums.txt and the asset's .sha256.
COMPOSE_SHA256 = "af426722a8af5de812fcee30cc1c39f0639f5f723cbadefb25e5d4db054064cf"
COMPOSE_PATH = Path("/usr/local/lib/docker/cli-plugins/docker-compose")
LOWER_PRIORITY_PLUGINS = (
    Path("/usr/local/libexec/docker/cli-plugins/docker-compose"),
    Path("/usr/lib/docker/cli-plugins/docker-compose"),
    Path("/usr/libexec/docker/cli-plugins/docker-compose"),
)
DOCKER_SOCKET = Path("/var/run/docker.sock")
ENGINE_STATE_PATHS = (
    Path("/var/lib/docker"), Path("/var/lib/containerd"),
    Path("/var/snap/docker"), Path("/etc/docker/daemon.json"),
)
SYSTEMD_PATH = Path("/run/systemd/system")
AMD64_ALIASES = {"amd64", "x86_64"}
COMPOSE_FLAGS = {
    "start": ("--wait", "--wait-timeout"),
    "up": ("--wait", "--wait-timeout", "--no-build", "--pull", "--no-deps", "--no-recreate"),
}
COMPOSE_ERROR = (
    "Docker Compose must support start --wait --wait-timeout and "
    "up --wait --wait-timeout --no-build --pull --no-deps --no-recreate. "
    "Install a compatible plugin or opt in to prerequisite installation on Ubuntu 24.04 amd64."
)
PATH_ERROR = (
    "Compose installation requires real, root-owned directories and a regular file, "
    "with no symlinks or group/other write permissions, under /usr/local/lib/docker/cli-plugins."
)
SHADOW_ERROR = (
    "An existing user/custom Compose plugin shadows the managed installation location. "
    "Update or remove it manually; prerequisite installation will not overwrite user plugins or Docker config."
)


def _command(arguments, message, *, timeout=30):
    try:
        return run_command(arguments, stdin=subprocess.DEVNULL, timeout=timeout)
    except (OperationError, OSError, subprocess.SubprocessError, UnicodeError):
        # Neither subprocess output nor chained exceptions may disclose host secrets.
        raise OperationError(message) from None


def _check_host():
    if platform.system() != "Linux" or getattr(os, "geteuid", lambda: -1)() != 0:
        raise OperationError("Run prerequisite checks as root on the target Linux server.")
    # Standalone provisioning also runs outside the project's Python tooling baseline.
    if sys.version_info < (3, 10):  # noqa: UP036
        raise OperationError("Python 3.10 or newer is required; rerun with a supported Python interpreter.")
    if any(name.startswith(("DOCKER_", "COMPOSE_")) for name in os.environ):
        raise OperationError(
            "Unset DOCKER_* and COMPOSE_* environment overrides; use the local default Docker socket."
        )


def _check_install_platform():
    try:
        release = platform.freedesktop_os_release()
    except OSError:
        raise OperationError("Cannot identify this distribution; install prerequisites manually.") from None
    if (release.get("ID") != "ubuntu" or release.get("VERSION_ID") != "24.04"
            or platform.machine().lower() not in AMD64_ALIASES):
        raise OperationError(
            "Automatic prerequisite installation supports only Ubuntu 24.04 amd64; "
            "install dependencies manually on other systems."
        )


def _check_daemon():
    endpoint = _command(
        ["docker", "context", "inspect", "--format", "{{json .Endpoints.docker.Host}}"],
        "Cannot inspect the Docker context; configure the local default Docker socket and retry.",
    )
    try:
        local = json.loads(endpoint) in ("unix:///var/run/docker.sock", "unix:///run/docker.sock")
    except (ValueError, TypeError):
        local = False
    if not local:
        raise OperationError(
            "Docker must use the local default Unix socket, not a remote or rootless context. "
            "Select the local default Docker context before retrying."
        )
    raw = _command(
        ["docker", "info", "--format", "{{json .}}"],
        "The local Docker daemon is unavailable; check Docker installation, service and socket permissions. "
        "An existing engine will not be started or restarted automatically.",
    )
    try:
        info = json.loads(raw)
    except (ValueError, TypeError):
        info = None
    if (not isinstance(info, dict) or info.get("OSType") != "linux"
            or not isinstance(info.get("Architecture"), str) or info["Architecture"] not in AMD64_ALIASES):
        raise OperationError(
            "The Docker daemon must be linux/amd64 (x86_64 is accepted), matching the published image. "
            "Use the supported local Linux amd64 server before deploying."
        )
    return info


def _check_compose_capabilities():
    for command, required in COMPOSE_FLAGS.items():
        help_text = _command(["docker", "compose", command, "--help"], COMPOSE_ERROR)
        options = set(re.findall(r"(?m)^\s*(?:-[A-Za-z],\s*)?(--[a-z][a-z0-9-]*)(?=\s|=|$)", help_text))
        if not set(required).issubset(options):
            raise OperationError(COMPOSE_ERROR)


def check_local_docker() -> None:
    """Verify the host, Docker client and local daemon without requiring Compose."""
    _check_host()
    if not shutil.which("docker"):
        raise OperationError("Missing dependency: Docker. Install Docker or opt in to prerequisite installation.")
    _check_daemon()


def check_compose() -> None:
    """Verify the local image platform and required Compose flags without mutation."""
    check_local_docker()
    _check_compose_capabilities()


def _check_tar():
    output = _command(["tar", "--version"], "Cannot verify GNU tar; install GNU tar and retry.")
    if not output.startswith("tar (GNU tar) "):
        raise OperationError("GNU tar is required; replace the non-GNU tar on PATH before retrying.")


def _no_existing_engine():
    message = (
        "An existing Docker/container runtime, retained data or service was detected but the Docker client is missing. "
        "Repair that installation/PATH manually; refusing to install conflicting docker.io/containerd packages."
    )
    if shutil.which("dockerd") or any(os.path.lexists(path) for path in (DOCKER_SOCKET, *ENGINE_STATE_PATHS)):
        raise OperationError(message)
    packages = _command(
        ["dpkg-query", "--show", "--showformat=${binary:Package}\t${Status}\n"],
        "Cannot inspect installed packages; refusing automatic Docker installation.",
    )
    conflicts = {
        "docker.io", "docker-ce", "docker-ce-cli", "docker-engine", "moby-engine", "moby-cli",
        "containerd", "containerd.io", "podman-docker", "runc",
    }
    for line in packages.splitlines():
        name, separator, _ = line.partition("\t")
        if separator and name.split(":", 1)[0] in conflicts:
            raise OperationError(message)
    units = _command(
        ["systemctl", "list-units", "--all", "--type=service", "--no-legend", "--plain", "--no-pager",
         "docker.service", "containerd.service", "snap.docker.dockerd.service"],
        "Cannot inspect runtime services; refusing automatic Docker installation.",
    )
    if units.strip():
        raise OperationError(message)


def _install_packages(packages):
    if not shutil.which("apt-get"):
        raise OperationError("apt-get is unavailable; install the missing dependencies manually.")
    if "docker.io" in packages:
        if not SYSTEMD_PATH.is_dir() or not shutil.which("systemctl"):
            raise OperationError("Automatic Docker installation requires Ubuntu booted with systemd.")
        _no_existing_engine()
    environment = ["env", "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=l"]
    _command(
        environment + ["apt-get", "update"],
        "apt-get update failed; check Ubuntu package sources and networking locally, then retry.", timeout=300,
    )
    _command(
        environment + ["apt-get", "install", "--yes", "--no-upgrade", "--no-remove",
                       "--no-install-recommends", *packages],
        "Installing missing Ubuntu packages failed; inspect apt locally before retrying.", timeout=900,
    )
    if "docker.io" in packages:
        # Only a newly installed engine is enabled; existing engines are never restarted.
        _command(
            ["systemctl", "enable", "--now", "docker.service"],
            "Docker was installed but could not be enabled/started; inspect docker.service locally.", timeout=60,
        )


def _entry(path):
    try:
        return path.lstat()
    except FileNotFoundError:
        return None


def _trusted_directories(path, *, create=False):
    for directory in reversed((path, *path.parents)):
        info = _entry(directory)
        if info is None and create:
            directory.mkdir(mode=0o755)
            info = directory.lstat()
        if info is not None and (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022):
            raise OperationError(PATH_ERROR)


def _trusted_file(path):
    info = _entry(path)
    if info is not None and (
        not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_nlink != 1
    ):
        raise OperationError(PATH_ERROR)
    return info


def _check_plugin_destination():
    _trusted_directories(COMPOSE_PATH.parent)
    if _trusted_file(COMPOSE_PATH) is not None:
        # Only these exact pinned bytes at our own destination are considered managed.
        checksum = hashlib.sha256()
        with COMPOSE_PATH.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                checksum.update(block)
        if checksum.hexdigest() != COMPOSE_SHA256:
            raise OperationError(
                "An unmanaged Compose plugin already occupies /usr/local/lib/docker/cli-plugins/docker-compose. "
                "Update or remove it manually; prerequisite installation will not overwrite it."
            )


def _check_plugin_shadows(info):
    config_directory = Path.home() / ".docker"
    _trusted_directories(config_directory)
    config = config_directory / "config.json"
    extra = []
    if _trusted_file(config) is not None:
        try:
            data = json.loads(config.read_text(encoding="utf-8"))
            extra = data.get("cliPluginsExtraDirs", []) if isinstance(data, dict) else None
        except (ValueError, UnicodeError):
            raise OperationError("Cannot read Docker CLI config safely; repair it manually before installing Compose.") from None
        if not isinstance(extra, list) or any(not isinstance(path, str) or not Path(path).is_absolute() for path in extra):
            raise OperationError("Docker CLI plugin search paths are invalid; repair Docker config manually.")
    for directory in [config_directory / "cli-plugins", *(Path(path) for path in extra)]:
        if ".." in directory.parts:
            raise OperationError(SHADOW_ERROR)
        _trusted_directories(directory)
        candidate = directory / "docker-compose"
        if candidate != COMPOSE_PATH and _entry(candidate) is not None:
            raise OperationError(SHADOW_ERROR)
    client = info.get("ClientInfo", {})
    plugins = client.get("Plugins", []) if isinstance(client, dict) else None
    if not isinstance(plugins, list):
        raise OperationError(SHADOW_ERROR)
    for plugin in plugins:
        if isinstance(plugin, dict) and plugin.get("Name") == "compose":
            path = plugin.get("Path")
            if not isinstance(path, str) or Path(path) not in (COMPOSE_PATH, *LOWER_PRIORITY_PLUGINS):
                raise OperationError(SHADOW_ERROR)


class _HTTPSRedirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urlsplit(newurl).scheme != "https":
            raise OperationError("Compose download refused a non-HTTPS redirect.")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _download_compose(target):
    checksum = hashlib.sha256()
    size = 0
    deadline = time.monotonic() + 180
    opener = build_opener(_HTTPSRedirects())
    with opener.open(COMPOSE_URL, timeout=30) as response:
        if urlsplit(response.geturl()).scheme != "https":
            raise OperationError("Compose download must use HTTPS.")
        while True:
            block = response.read(1024 * 1024)
            if time.monotonic() > deadline:
                raise OperationError("Compose download timed out; check networking and retry.")
            if not block:
                break
            size += len(block)
            if size > 128 * 1024 * 1024:
                raise OperationError("Compose download exceeded the allowed size; refusing installation.")
            target.write(block)
            checksum.update(block)
    if checksum.hexdigest() != COMPOSE_SHA256:
        raise OperationError("Pinned Compose SHA-256 verification failed; no plugin was installed. Retry from a trusted network.")


def _install_compose(info):
    temporary = None
    try:
        _check_plugin_shadows(info)
        _check_plugin_destination()
        _trusted_directories(COMPOSE_PATH.parent, create=True)
        descriptor, temporary = tempfile.mkstemp(prefix=".compose-", dir=COMPOSE_PATH.parent)
        with os.fdopen(descriptor, "wb") as target:
            _download_compose(target)
            target.flush()
            os.fchmod(target.fileno(), 0o755)
            os.fsync(target.fileno())
        _check_plugin_destination()
        os.replace(temporary, COMPOSE_PATH)
        temporary = None
        descriptor = os.open(COMPOSE_PATH.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except (OSError, HTTPException, ValueError):
        raise OperationError(
            "Could not safely download/install pinned Compose; check HTTPS access, CA certificates, disk and root path permissions."
        ) from None
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass


def ensure_prerequisites(*, install=False) -> None:
    """Verify prerequisites; install missing packages/pinned Compose only with opt-in."""
    _check_host()
    if install:
        _check_install_platform()
    docker_available = bool(shutil.which("docker"))
    # Do not mutate even unrelated dependencies until an existing engine is safe to use.
    info = _check_daemon() if install and docker_available else None
    packages = []
    if not docker_available:
        packages.append("docker.io")
    if not shutil.which("tar"):
        packages.append("tar")
    if packages and not install:
        raise OperationError(
            "Missing dependencies: " + ", ".join(packages) + ". "
            "Install Docker and GNU tar manually, or opt in to prerequisite installation on Ubuntu 24.04 amd64."
        )
    if shutil.which("tar"):
        _check_tar()
    if packages:
        _install_packages(packages)
        if not shutil.which("docker") or not shutil.which("tar"):
            raise OperationError("Dependency installation did not provide Docker/GNU tar on PATH; inspect apt and PATH locally.")
        _check_tar()
    if info is None:
        info = _check_daemon()
    try:
        _check_compose_capabilities()
    except OperationError:
        if not install:
            raise
        _install_compose(info)
        # Recheck discovery/capabilities, not just the downloaded executable's version.
        check_compose()
