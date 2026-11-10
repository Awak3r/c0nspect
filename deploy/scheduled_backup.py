#!/usr/bin/env python3
"""Create one local snapshot, then prune only verified own bundles in ROOT/backups."""

import argparse
import os
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path

from backup import create_backup
from operations import (
    BUNDLE_FILES,
    ROOT,
    Compose,
    OperationError,
    add_compose_arguments,
    operation_lock,
    validate_bundle,
)

BUNDLE_NAME = re.compile(r"conspect-([0-9]{8}T[0-9]{6}\.[0-9]{6}Z)")
EXPECTED_FILES = set(BUNDLE_FILES) | {"manifest.json"}


def backup_directory() -> Path:
    directory = ROOT / "backups"
    if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
        raise OperationError("The dedicated local backup directory must not be a symlink or file.")
    return directory


def bundle_time(path: Path, compose) -> datetime | None:
    match = BUNDLE_NAME.fullmatch(path.name)
    if not match or path.is_symlink() or not path.is_dir():
        return None
    try:
        timestamp = datetime.strptime(match[1], "%Y%m%dT%H%M%S.%fZ")
        # Extra content may belong to the operator; never recursively delete it.
        if {entry.name for entry in path.iterdir()} != EXPECTED_FILES:
            return None
        manifest = validate_bundle(path)
    except (OperationError, OSError, ValueError):
        return None
    if (
        manifest.get("postgres_major") != 17
        or manifest.get("postgres_db") != compose.db_name
        or manifest.get("postgres_user") != compose.db_user
    ):
        return None
    return timestamp


def prune_backups(compose, newest: Path, keep: int) -> int:
    directory = backup_directory()
    if keep < 1 or newest.parent != directory:
        raise OperationError("Retention requires a new snapshot in the dedicated directory and keep >= 1.")
    candidates: list[tuple[datetime, Path]] = []
    skipped = 0
    for path in directory.iterdir():
        timestamp = bundle_time(path, compose)
        if timestamp is None:
            skipped += 1
        else:
            candidates.append((timestamp, path))
    candidates.sort(reverse=True)
    if newest not in [path for timestamp, path in candidates[:keep]]:
        # Preserve the new snapshot even after clock skew or an invalid publish.
        raise OperationError("New snapshot is not a verified newest retained bundle; no pruning performed.")
    removed = 0
    for timestamp, path in candidates[keep:]:
        if bundle_time(path, compose) != timestamp:
            raise OperationError("A retention candidate changed; remaining cleanup was stopped.")
        shutil.rmtree(path)
        removed += 1
    print(f"Local retention: removed {removed} older verified backups; kept {min(keep, len(candidates))}.", flush=True)
    if skipped:
        print(f"Retention left {skipped} unrecognized or different-database entries untouched.", file=sys.stderr)
    return removed


def positive_keep(value: str) -> int:
    try:
        keep = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("keep must be a positive integer") from error
    if keep < 1:
        raise argparse.ArgumentTypeError("keep must be a positive integer")
    return keep


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    add_compose_arguments(parser)
    parser.add_argument("--keep", type=positive_keep, default=14, help="Retain this many newest verified local bundles (default: 14).")
    args = parser.parse_args()
    os.umask(0o077)
    try:
        with operation_lock():
            directory = backup_directory()
            compose = Compose(local=args.local, nginx=args.nginx)
            newest = create_backup(compose, directory)
            prune_backups(compose, newest, args.keep)
    except (Exception, KeyboardInterrupt):
        # Unattended journals must not receive config values or dump/error payloads.
        print(
            "Scheduled local backup/retention failed. Any newly completed snapshot is kept; "
            "no further cleanup is attempted. Check app readiness and local Docker/disk status; "
            "error details withheld to protect secrets.", file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
