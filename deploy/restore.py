#!/usr/bin/env python3
"""Destructively replace the dedicated database and uploads from a verified bundle."""

import argparse
import hmac
import os
import sys
from pathlib import Path

from operations import (
    Compose,
    OperationError,
    add_compose_arguments,
    operation_lock,
    validate_bundle,
)


def restore_backup(compose, directory):
    manifest = validate_bundle(directory)
    if manifest.get("postgres_major") != 17:
        raise OperationError("Backup is not a PostgreSQL 17 snapshot.")
    if manifest.get("postgres_db") != compose.db_name or manifest.get("postgres_user") != compose.db_user:
        raise OperationError("POSTGRES_DB/POSTGRES_USER must match the backup. Restore with the saved configuration first.")
    fingerprint = manifest.get("app_secret_sha256")
    if not isinstance(fingerprint, str) or not hmac.compare_digest(fingerprint.encode("utf-8"), compose.fingerprint.encode("ascii")):
        raise OperationError("APP_SECRET differs from the backup; restore the original secret before proceeding.")
    compose.preflight()
    states = compose.states()
    services = list(reversed(compose.managed_services))
    # Validate the custom-dump header/TOC before stopping services or deleting data.
    # Full validation still happens during pg_restore, with the app kept offline.
    with (directory / "database.dump").open("rb") as source:
        compose.call("exec", "-T", "db", "pg_restore", "--list", stdin=source)
    try:
        print("Stopping managed application services; replacing ALL database contents and uploads...", flush=True)
        compose.stop(services)
        compose.call(
            "exec", "-T", "db", "dropdb", "--username", compose.db_user,
            "--force", "--if-exists", "--", compose.db_name,
        )
        compose.call(
            "exec", "-T", "db", "createdb", "--username", compose.db_user,
            "--owner", compose.db_user, "--", compose.db_name,
        )
        with (directory / "database.dump").open("rb") as source:
            compose.call(
                "exec", "-T", "db", "pg_restore", "--username", compose.db_user,
                "--dbname", compose.db_name, "--no-owner", "--no-acl",
                "--exit-on-error", "--single-transaction", stdin=source,
            )
        # Remove stale/unreferenced files too, including dotfiles, but keep the
        # volume's writable root directory and its UID 10001 ownership intact.
        compose.helper(
            "sh", "-ec", "test -d /data/uploads && find /data/uploads -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +",
        )
        with (directory / "uploads.tar.gz").open("rb") as source:
            compose.helper(
                "tar", "--extract", "--gzip", "--file=-", "--directory=/data",
                "--no-same-owner", "--no-same-permissions", stdin=source,
            )
        # Recreate only services that were running, so restored config/image is
        # applied. A fresh deployment stays stopped until the operator starts it.
        compose.resume(states, restored=True)
    except BaseException:
        try:
            compose.stop(services)
        except (OperationError, OSError):
            print("Could not confirm services stopped; inspect Docker before doing anything else.", file=sys.stderr)
        print(
            "RESTORE FAILED: managed application services must remain stopped. Database/uploads may be incomplete. "
            "Fix the cause and rerun restore; do not serve a mixed snapshot.", file=sys.stderr,
        )
        raise
    print("Restore complete. Previously stopped/absent services were NOT started.", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("backup", type=Path, help="Complete conspect-* backup directory (not a .partial-* directory).")
    parser.add_argument("--yes", action="store_true", help="Confirm irreversible replacement of the database and uploads.")
    add_compose_arguments(parser)
    args = parser.parse_args()
    if not args.yes:
        parser.error("Pass --yes only after making a separate safety backup; this replaces ALL current data.")
    os.umask(0o077)
    try:
        with operation_lock():
            restore_backup(Compose(local=args.local, nginx=args.nginx), args.backup.expanduser().resolve())
    except (OperationError, OSError, ValueError, KeyError, KeyboardInterrupt) as error:
        print(f"Restore failed: {error or 'interrupted'}.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
