#!/usr/bin/env python3
"""Deploy a verified GHCR digest to an existing root-owned host-nginx installation."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

import operations
from backup import create_backup
from operations import Compose, OperationError, operation_lock, run_command

IMAGE_PATTERN = r"ghcr\.io/awak3r/c0nspect@sha256:[0-9a-f]{64}"


def atomic_write(path, content, mode=0o600):
    descriptor, temporary = tempfile.mkstemp(prefix=".release-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as target:
            os.fchmod(target.fileno(), mode)
            target.write(content)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def replace_image(content, image):
    lines = content.splitlines(keepends=True)
    matches = [index for index, line in enumerate(lines)
               if re.match(r"^(?:export\s+)?CONSPECT_IMAGE\s*=", line)]
    if len(matches) > 1:
        raise OperationError("Duplicate CONSPECT_IMAGE in .env; reconcile it locally first.")
    if matches:
        lines[matches[0]] = f"CONSPECT_IMAGE={image}\n"
        return "".join(lines)
    return content.rstrip("\n") + f"\nCONSPECT_IMAGE={image}\n"


def trusted_directory(path):
    if path.is_symlink() or not path.is_dir():
        raise OperationError("Deployment paths must be existing real directories.")
    for directory in (path, *path.parents):
        info = directory.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise OperationError("Deployment paths and parents must be root-owned and not group/other writable.")


def deployment_files(source, root):
    if (source / "deploy").is_symlink() or not (source / "deploy").is_dir():
        raise OperationError("Release deploy directory must be a real directory.")
    files = [source / "compose.yaml", *sorted((source / "deploy").rglob("*"))]
    result = []
    for source_file in files:
        if source_file.is_symlink():
            raise OperationError("Release source must not contain symbolic links.")
        if source_file.is_dir():
            continue
        if not source_file.is_file():
            raise OperationError("Release is missing a regular deployment file.")
        relative = source_file.relative_to(source)
        if "__pycache__" in relative.parts or source_file.suffix == ".pyc":
            continue
        target = root / relative
        if target.is_symlink():
            raise OperationError("Refusing to replace a symlink in the installation.")
        parent = target.parent
        while parent != root:
            if parent.exists() or parent.is_symlink():
                trusted_directory(parent)
            parent = parent.parent
        result.append((source_file, target))
    return result


def pull_image(image, username, token):
    if not token or len(token) > 65536 or "\n" in token or "\r" in token:
        raise OperationError("Supply a single-line registry token through stdin.")
    # Authentication exists only for this pull; never leave a workflow token on disk.
    with tempfile.TemporaryDirectory(prefix="conspect-registry-") as directory:
        command = ["docker", "--config", directory]
        with tempfile.TemporaryFile() as secret:
            secret.write((token + "\n").encode())
            secret.seek(0)
            registry_command(command + ["login", "ghcr.io", "--username", username, "--password-stdin"], "login", stdin=secret)
        registry_command(command + ["pull", "--platform", "linux/amd64", image], "pull")


def registry_command(command, stage, **streams):
    try:
        return run_command(command, **streams)
    except OperationError as error:
        output = getattr(error, "command_stderr", b"").decode("utf-8", errors="replace").lower()
        reason = "registry/network operation failed"
        for terms, description in (
            (("denied", "unauthorized", "forbidden"), "registry permission denied"),
            (("not found", "manifest unknown"), "image/digest not found or not readable"),
            (("timeout", "deadline exceeded"), "registry connection timed out"),
            (("certificate", "x509"), "registry TLS certificate failure"),
            (("no such file", "permission denied", "error saving credentials"), "Docker credential-directory failure"),
        ):
            if any(term in output for term in terms):
                reason = description
                break
        raise OperationError(f"GHCR {stage} failed: {reason}; no application update was started.") from error


def compose_command(root, source=None):
    source = source or root
    return ["docker", "compose", "--project-directory", str(root), "--project-name", "conspect",
            "--env-file", str(root / ".env"), "-f", str(source / "compose.yaml"),
            "-f", str(source / "deploy/compose.nginx.yaml")]


def release(source, root, image, username, revision, token):
    if not re.fullmatch(IMAGE_PATTERN, image) or not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise OperationError("Only an immutable Conspect GHCR digest and full Git revision are accepted.")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9\[\]-]*", username):
        raise OperationError("Invalid registry username.")
    if os.geteuid() != 0:
        raise OperationError("Run as root on the existing host-nginx installation.")
    trusted_directory(root)
    trusted_directory(source)
    env_path = root / ".env"
    if env_path.is_symlink() or not env_path.is_file():
        raise OperationError("An existing private .env is required; this is not a provisioning tool.")
    info = env_path.stat()
    if info.st_uid != 0 or info.st_mode & 0o077:
        raise OperationError(".env must be root-owned and mode 0600.")
    files = deployment_files(source, root)
    if not (source / "deploy/compose.nginx.yaml").is_file():
        raise OperationError("Release is missing the host-nginx overlay.")
    # Ignore inherited overrides: .env is the installation's source of truth.
    for name in list(os.environ):
        if name.startswith("COMPOSE_") or name in {"CONSPECT_IMAGE", "DOCKER_CONFIG", "DOCKER_HOST", "DOCKER_CONTEXT"}:
            os.environ.pop(name, None)
    operations.ROOT = root
    with operation_lock():
        if env_path.is_symlink() or not env_path.is_file():
            raise OperationError("An existing private .env is required.")
        info = env_path.stat()
        if info.st_uid != 0 or info.st_mode & 0o077:
            raise OperationError(".env must be root-owned and mode 0600.")
        old_env = env_path.read_text(encoding="utf-8")
        next_env = replace_image(old_env, image)
        backup_root = root / "backups"
        if backup_root.is_symlink():
            raise OperationError("Backup destination must not be a symlink.")
        if backup_root.exists():
            trusted_directory(backup_root)
        current = Compose(nginx=True)
        current.preflight(backup=True)
        if current.states().get("app") != "running":
            raise OperationError("App must be running before an automated release; recover it manually first.")
        print("Pulling immutable image before the maintenance window...", flush=True)
        pull_image(image, username, token)
        # Resolve incoming Compose without changing the live installation or exposing secrets.
        previous_image = os.environ.get("CONSPECT_IMAGE")
        try:
            os.environ["CONSPECT_IMAGE"] = image
            run_command(compose_command(root, source) + ["config", "--quiet"])
        finally:
            if previous_image is None:
                os.environ.pop("CONSPECT_IMAGE", None)
            else:
                os.environ["CONSPECT_IMAGE"] = previous_image
        backup = create_backup(current, backup_root)
        state = {"revision": revision, "image": image, "previous_image": current.image,
                 "backup": str(backup), "status": "activating",
                 "updated_at": datetime.now(timezone.utc).isoformat()}
        marker = root / ".release.json"
        atomic_write(marker, json.dumps(state, indent=2) + "\n")
        # Save the previous deployment files alongside the private data/config backup.
        saved = backup / "deployment"
        saved.mkdir(mode=0o700)
        for _, target in files:
            if target.is_file():
                destination = saved / target.relative_to(root)
                destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                shutil.copy2(target, destination)
        activated = False
        try:
            for source_file, target in files:
                target.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
                atomic_write(target, source_file.read_text(encoding="utf-8"), 0o640)
            atomic_write(env_path, next_env)
            command = compose_command(root)
            run_command(command + ["config", "--quiet"])
            activated = True
            # Never recreate PostgreSQL, start Caddy, rebuild, or pull mutable DB tags.
            run_command(command + ["up", "--detach", "--no-deps", "--no-build", "--pull", "never",
                                   "--wait", "--wait-timeout", "180", "app"], timeout=240)
        except BaseException:
            state["status"] = "failed"
            if activated:
                # Startup may already have migrated the DB: no automatic binary downgrade.
                try:
                    run_command(compose_command(root) + ["stop", "--timeout", "30", "app"], timeout=60)
                except OperationError:
                    print("Could not confirm the failed app stopped; inspect it locally.", file=sys.stderr)
                print(f"Release failed. App left offline; recover using the verified backup: {backup}", file=sys.stderr)
            else:
                atomic_write(env_path, old_env)
                for _, target in files:
                    original = saved / target.relative_to(root)
                    if original.is_file():
                        atomic_write(target, original.read_text(encoding="utf-8"), original.stat().st_mode & 0o777)
            try:
                atomic_write(marker, json.dumps(state, indent=2) + "\n")
            except OSError:
                print("Could not persist failure status; inspect the app and backup locally.", file=sys.stderr)
            raise
        state["status"] = "healthy"
        atomic_write(marker, json.dumps(state, indent=2) + "\n")
        print(f"Healthy release: {revision}; recovery backup: {backup}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--registry-user", required=True)
    parser.add_argument("--revision", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        release(args.source.absolute(), args.root.absolute(), args.image, args.registry_user,
                args.revision, sys.stdin.readline(65538).rstrip("\n"))
    except (OperationError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"Release failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
