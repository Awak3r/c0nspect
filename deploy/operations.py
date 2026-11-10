"""Shared, local-only deployment operations (Python 3.10+, Linux)."""

import fcntl
import hashlib
import json
import os
import re
import subprocess
import tarfile
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from urllib.parse import parse_qsl, unquote, urlsplit

ROOT = Path(__file__).resolve().parent.parent
BUNDLE_FILES = ("database.dump", "uploads.tar.gz", "config.env", "compose.resolved.json")


class OperationError(RuntimeError):
    pass


def run_command(arguments, *, stdin=None, stdout=None, timeout=900):
    try:
        result = subprocess.run(
            arguments, stdin=stdin, stdout=stdout if stdout is not None else subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise OperationError("Docker command could not finish; check Docker and available disk space.") from error
    if result.returncode:
        # Docker/pg_restore output can contain configuration or private note data.
        error = OperationError(
            f"Docker command failed (exit {result.returncode}); output withheld to protect secrets/data. "
            "Inspect the service locally before retrying."
        )
        # Callers may classify a registry error without logging raw private output.
        error.command_stderr = result.stderr
        raise error
    return result.stdout.decode("utf-8") if stdout is None else ""


def secret_fingerprint(secret):
    if not isinstance(secret, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", secret):
        raise OperationError("APP_SECRET must be exactly 64 hex characters.")
    return hashlib.sha256(bytes.fromhex(secret)).hexdigest()


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path, value):
    with path.open("x", encoding="utf-8") as target:
        json.dump(value, target, indent=2)
        target.write("\n")


def now():
    return datetime.now(timezone.utc)


@contextmanager
def operation_lock():
    descriptor = os.open(ROOT / "deploy" / ".operations.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise OperationError("Another backup/restore is already running.") from error
        yield


def validate_uploads(path):
    root_seen = False
    try:
        with tarfile.open(path, "r|gz") as archive:
            for member in archive:
                name = PurePosixPath(member.name)
                if name.is_absolute() or ".." in name.parts or not name.parts or name.parts[0] != "uploads":
                    raise OperationError("Unsafe path in uploads archive.")
                if not (member.isfile() or member.isdir()):
                    raise OperationError("Uploads archive contains a link or special file; refusing restore.")
                if name == PurePosixPath("uploads"):
                    if not member.isdir():
                        raise OperationError("Uploads archive root must be a directory.")
                    root_seen = True
    except (tarfile.TarError, OSError, EOFError) as error:
        raise OperationError("Uploads archive is unreadable or corrupt.") from error
    if not root_seen:
        raise OperationError("Uploads archive has no uploads/ directory.")


def validate_bundle(directory):
    if directory.name.startswith(".partial-"):
        raise OperationError("Partial backup directories cannot be restored.")
    manifest_path = directory / "manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise OperationError("Backup has no regular manifest.json; partial backups cannot be restored.")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise OperationError("Backup manifest is unreadable.") from error
    if not isinstance(manifest, dict) or manifest.get("format") != 1 or not isinstance(manifest.get("files"), dict):
        raise OperationError("Unsupported backup format.")
    if set(manifest["files"]) != set(BUNDLE_FILES):
        raise OperationError("Backup manifest has an unexpected file set.")
    for name in BUNDLE_FILES:
        path = directory / name
        if path.is_symlink() or not path.is_file() or sha256(path) != manifest["files"][name]:
            raise OperationError(f"Backup integrity check failed: {name}.")
    validate_uploads(directory / "uploads.tar.gz")
    return manifest


class Compose:
    def __init__(self, *, local=False, nginx=False):
        if local and nginx:
            raise OperationError("Choose only one of --local and --nginx.")
        self.managed_services = ("app",) if nginx else ("app", "proxy")
        self.env_path = ROOT / ".env"
        if not self.env_path.is_file() or self.env_path.stat().st_mode & 0o077:
            raise OperationError("Create .env and restrict it with chmod 600 .env first.")
        self.command = [
            "docker", "compose", "--project-directory", str(ROOT), "--project-name", "conspect",
            "--env-file", str(self.env_path), "-f", str(ROOT / "compose.yaml"),
        ]
        if local:
            self.command += ["-f", str(ROOT / "deploy" / "compose.local.yaml")]
        elif nginx:
            self.command += ["-f", str(ROOT / "deploy" / "compose.nginx.yaml")]
        self.config = json.loads(self.call("config", "--format", "json"))
        services = self.config["services"]
        self.app_env = services["app"]["environment"]
        self.db_env = services["db"]["environment"]
        self.db_name = self.db_env["POSTGRES_DB"]
        self.db_user = self.db_env["POSTGRES_USER"]
        self.fingerprint = secret_fingerprint(self.app_env.get("APP_SECRET"))
        if self.db_name in {"postgres", "template0", "template1"}:
            raise OperationError("Use a dedicated database, not postgres/template0/template1.")
        if self.app_env.get("DATA_DIR") != "/data":
            raise OperationError("These scripts require the Compose /data/uploads volume.")
        try:
            database_url = urlsplit(self.app_env.get("DATABASE_URL", ""))
            same_database = (
                database_url.scheme in {"postgres", "postgresql"}
                and database_url.hostname == "db" and database_url.port in {None, 5432}
                and unquote(database_url.path) == "/" + self.db_name
                and unquote(database_url.username or "") == self.db_user
                and unquote(database_url.password or "") == self.db_env["POSTGRES_PASSWORD"]
                and not database_url.fragment
                and all(key in {"sslmode", "connect_timeout", "application_name"}
                        for key, value in parse_qsl(database_url.query, keep_blank_values=True))
            )
        except ValueError:
            same_database = False
        if not same_database:
            raise OperationError(
                "DATABASE_URL must address the configured Compose db/user/password; "
                "only sslmode/connect_timeout/application_name query parameters are supported by these scripts."
            )
        self.image = services["app"]["image"]
        self.image_id = run_command(["docker", "image", "inspect", "--format", "{{.Id}}", self.image]).strip()

    def call(self, *arguments, **streams):
        return run_command(self.command + list(arguments), **streams)

    def container(self, service):
        identifiers = self.call("ps", "--all", "--quiet", service).split()
        if not identifiers:
            return None
        if len(identifiers) != 1:
            raise OperationError("Operations require exactly one container per service.")
        return json.loads(run_command(["docker", "inspect", identifiers[0]]))[0]

    def states(self):
        states = {}
        for service in self.managed_services:
            container = self.container(service)
            state = container["State"]["Status"] if container else "absent"
            if state not in {"running", "exited", "created", "absent"}:
                raise OperationError(f"{service} is {state}; stabilize it before backup/restore.")
            states[service] = state
        return states

    def preflight(self, *, backup=False):
        database = self.container("db")
        if not database or database["State"]["Status"] != "running":
            raise OperationError("Start db and wait for health before running this operation.")
        actual_db = dict(item.split("=", 1) for item in database["Config"]["Env"])
        for key in ("POSTGRES_DB", "POSTGRES_USER"):
            if actual_db.get(key) != self.db_env.get(key):
                raise OperationError("Database container/config mismatch; reconcile configuration first.")
        version = self.call(
            "exec", "-T", "db", "psql", "--username", self.db_user, "--dbname", self.db_name,
            "--no-psqlrc", "--tuples-only", "--no-align", "--command", "SHOW server_version_num",
        ).strip()
        if not version.isdecimal() or int(version) // 10000 != 17:
            raise OperationError("These operations require a PostgreSQL 17 server.")
        if backup:
            app = self.container("app")
            if app:
                actual = dict(item.split("=", 1) for item in app["Config"]["Env"])
                for key in ("APP_SECRET", "DATABASE_URL", "DATA_DIR"):
                    if actual.get(key) != self.app_env.get(key):
                        raise OperationError("App container/config mismatch; do not back up a different APP_SECRET or database.")
                if app["Image"] != self.image_id:
                    raise OperationError("App image changed without recreating the app; back up before replacing the image.")

    def stop(self, services):
        self.call("stop", "--timeout", "30", *services)
        for service in services:
            container = self.container(service)
            if container and container["State"]["Status"] not in {"exited", "created"}:
                raise OperationError(f"Could not verify {service} stopped; aborting.")

    def resume(self, states, *, restored=False):
        for service in self.managed_services:
            if states[service] != "running":
                continue
            if restored:
                self.call("up", "--detach", "--no-deps", "--wait", "--wait-timeout", "120", service)
            else:
                self.call("start", "--wait", "--wait-timeout", "120", service)

    def helper(self, entrypoint, *arguments, **streams):
        name = "conspect-ops-" + uuid.uuid4().hex
        try:
            self.call(
                "run", "--rm", "--no-deps", "--pull", "never", "-T", "--name", name,
                "--user", "10001:10001", "--entrypoint", entrypoint, "app", *arguments, **streams,
            )
        finally:
            # A killed Docker client can leave its one-off container running.
            try:
                result = subprocess.run(
                    ["docker", "rm", "--force", name], capture_output=True,
                    timeout=30, check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as error:
                raise OperationError(f"Cannot clean up helper {name}; keep app stopped and remove it manually.") from error
            if result.returncode and b"No such container" not in result.stderr:
                raise OperationError(f"Cannot confirm helper {name} cleanup; keep app stopped and inspect Docker.")


def add_compose_arguments(parser):
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--local", action="store_true", help="Use deploy/compose.local.yaml (same volumes/project).")
    group.add_argument(
        "--nginx", action="store_true",
        help="Use deploy/compose.nginx.yaml; manage only app, never host nginx or the Caddy service.",
    )
