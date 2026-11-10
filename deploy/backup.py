#!/usr/bin/env python3
"""Consistent PostgreSQL + uploads backup; no remote destination is configured."""

import argparse
import os
import shutil
import sys
import tempfile
from pathlib import Path

from operations import (
    BUNDLE_FILES,
    ROOT,
    Compose,
    OperationError,
    add_compose_arguments,
    now,
    operation_lock,
    sha256,
    validate_uploads,
    write_json,
)


def create_backup(compose, output):
    compose.preflight(backup=True)
    states = compose.states()
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    partial = Path(tempfile.mkdtemp(prefix=".partial-", dir=output))
    destination = output / ("conspect-" + now().strftime("%Y%m%dT%H%M%S.%fZ"))
    stopped = False
    try:
        shutil.copyfile(compose.env_path, partial / "config.env")
        write_json(partial / "compose.resolved.json", compose.config)
        print("Stopping app for a consistent database + uploads snapshot...", flush=True)
        stopped = True
        compose.stop(["app"])
        with (partial / "database.dump").open("xb") as target:
            compose.call(
                "exec", "-T", "db", "pg_dump", "--username", compose.db_user,
                "--dbname", compose.db_name, "--format=custom", "--no-owner", "--no-acl", stdout=target,
            )
        with (partial / "uploads.tar.gz").open("xb") as target:
            compose.helper("tar", "--create", "--gzip", "--file=-", "--directory=/data", "uploads", stdout=target)
        validate_uploads(partial / "uploads.tar.gz")
        manifest = {
            "format": 1,
            "created_at": now().isoformat(),
            "postgres_major": 17,
            "postgres_db": compose.db_name,
            "postgres_user": compose.db_user,
            "app_image_id": compose.image_id,
            "app_secret_sha256": compose.fingerprint,
            "files": {name: sha256(partial / name) for name in BUNDLE_FILES},
        }
        write_json(partial / "manifest.json", manifest)
        for name in (*BUNDLE_FILES, "manifest.json"):
            with (partial / name).open("rb") as source:
                os.fsync(source.fileno())
        partial.rename(destination)
        print(f"Backup published locally: {destination}", flush=True)
    finally:
        shutil.rmtree(partial, ignore_errors=True)
        # A backup never mutates stored data. Restore the prior running state even
        # when pg_dump/tar fails; never start an app that was already stopped.
        if stopped:
            compose.resume({"app": states["app"], "proxy": "exited"})
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "backups", help="Local destination directory (default: ./backups).")
    add_compose_arguments(parser)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        with operation_lock():
            create_backup(Compose(local=args.local, nginx=args.nginx), args.output.expanduser().resolve())
    except (OperationError, OSError, ValueError, KeyError, KeyboardInterrupt) as error:
        print(f"Backup failed: {error or 'interrupted'}. No partial bundle is considered complete.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
