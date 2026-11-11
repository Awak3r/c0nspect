"""Fast, read-only checks of local changes; no builds, services, or network."""

import argparse
import ast
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import warnings


class PreflightError(Exception):
    pass


def run(args, cwd, data=None):
    return subprocess.run(
        args, cwd=cwd, input=data, stdin=subprocess.DEVNULL if data is None else None,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=False,
    )


def git(root, *args):
    return run(["git", "--no-pager", "--no-optional-locks",
                "-c", "diff.autoRefreshIndex=false", *args], root)


def checked_git(root, *args):
    result = git(root, *args)
    if result.returncode:
        raise PreflightError("Git inspection failed (diagnostics withheld)")
    return result.stdout


def baseline(root, ref):
    target = ref if ref is not None else "@{upstream}"
    result = git(root, "rev-parse", "--verify", "--end-of-options", target + "^{commit}")
    if result.returncode == 0:
        return result.stdout.strip().decode("ascii")
    if ref is not None:
        raise PreflightError("Invalid --base: expected a locally resolvable commit")
    print("NOTE: No local upstream commit; using HEAD. Use --base REF to check outgoing changes.")
    return checked_git(root, "rev-parse", "--verify", "--end-of-options", "HEAD^{commit}").strip().decode("ascii")


def changes(root, args):
    fields = checked_git(root, "diff", "--raw", "--no-abbrev", "-z", "--no-renames",
                         "--no-ext-diff", "--no-textconv", "--diff-filter=ACMT", *args, "--").split(b"\0")
    for header, path in zip(fields[0:-1:2], fields[1:-1:2]):
        _, mode, old_oid, oid, _ = header.split()
        # With refresh disabled, stat-only worktree changes can appear in --raw.
        # Compare against the index blob without refreshing/writing the index.
        yield path, mode, old_oid if not args else oid


def blobs(root, oids):
    """Batch by object ID: paths never enter cat-file's line-based protocol."""
    if not oids:
        return {}
    result = run(["git", "--no-pager", "--no-optional-locks", "cat-file", "--batch"], root,
                 b"".join(oid + b"\n" for oid in sorted(oids)))
    if result.returncode:
        raise PreflightError("Git blob inspection failed (diagnostics withheld)")
    contents, offset = {}, 0
    for expected in sorted(oids):
        end = result.stdout.find(b"\n", offset)
        header = result.stdout[offset:end].split() if end >= 0 else []
        if len(header) != 3:
            raise PreflightError("Git blob inspection returned an incomplete object")
        oid, kind, size = header
        if oid != expected or kind != b"blob" or not size.isdigit():
            raise PreflightError("Git blob inspection returned an unexpected object")
        offset = end + 1
        end = offset + int(size)
        if end >= len(result.stdout) or result.stdout[end:end + 1] != b"\n":
            raise PreflightError("Git blob inspection returned incomplete contents")
        contents[oid] = result.stdout[offset:end]
        offset = end + 1
    return contents


def validate(root, suffix, data):
    try:
        if suffix == ".py":
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                ast.parse(data, filename="<preflight>")
        elif suffix == ".json":
            json.loads(data)
        else:
            try:
                result = run(["gofmt"], root, data)
            except FileNotFoundError:
                return "gofmt missing; install Go or add gofmt to PATH and rerun"
            if result.returncode:
                return "gofmt rejected input (diagnostics withheld)"
            if result.stdout != data:
                return "not gofmt-formatted; format the file and rerun"
    except (SyntaxError, ValueError, UnicodeError, RecursionError):
        return "invalid syntax (diagnostics withheld)"
    return None


def preflight(root, ref=None):
    base = baseline(root, ref)
    jobs, failed = [], False
    for version, args in (("HEAD", [base, "HEAD"]), ("index", ["--cached"]), ("worktree", [])):
        result = git(root, "diff", "--check", "--no-ext-diff", "--no-textconv", "--no-renames", *args, "--")
        print(f"{'FAIL' if result.returncode else 'PASS'} [git diff --check] {version}")
        failed |= bool(result.returncode)
        jobs.extend((version, *change) for change in changes(root, args))
    untracked = checked_git(root, "ls-files", "--others", "--exclude-standard", "-z")
    jobs.extend(("worktree", path, b"100644", None) for path in untracked.split(b"\0") if path)
    jobs = [(version, path, mode, oid) for version, path, mode, oid in jobs
            if Path(os.fsdecode(path)).suffix in {".go", ".py", ".json"}]
    contents = blobs(root, {oid for _, _, mode, oid in jobs
                            if oid and oid != b"0" * 40 and mode in {b"100644", b"100755"}})
    cache = {}
    for version, raw_path, mode, oid in jobs:
        name = os.fsdecode(raw_path)
        suffix = Path(name).suffix
        check = {".go": "Go formatting", ".py": "Python AST", ".json": "JSON"}[suffix]
        label = f"[{check}] {ascii(name)} ({version})"
        if version == "worktree":
            path = root / name
            try:
                mode_bits = path.lstat().st_mode
                if stat.S_ISLNK(mode_bits):
                    print(f"SKIP {label}: symlink")
                    continue
                if not path.resolve().is_relative_to(root) or not stat.S_ISREG(mode_bits):
                    raise OSError("unsafe path")
                data = path.read_bytes()
                if oid in contents and data == contents[oid]:
                    continue
            except (OSError, RuntimeError):
                print(f"FAIL {label}: unreadable or unsafe path")
                failed = True
                continue
        elif mode not in {b"100644", b"100755"}:
            print(f"SKIP {label}: non-regular Git entry")
            continue
        else:
            data = contents[oid]
        key = (suffix, data)
        if key not in cache:
            cache[key] = validate(root, suffix, data)
        error = cache[key]
        print(f"FAIL {label}: {error}" if error else f"PASS {label}")
        failed |= error is not None
    return int(failed)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", metavar="REF", help="local commit baseline (default: local upstream)")
    args = parser.parse_args(argv)
    try:
        root = Path(os.fsdecode(checked_git(Path.cwd(), "rev-parse", "--show-toplevel")).removesuffix("\n")).resolve()
        return preflight(root, args.base)
    except (PreflightError, OSError, subprocess.SubprocessError) as error:
        # Neither parser exceptions nor subprocess stderr may expose source or secrets.
        message = str(error) if isinstance(error, PreflightError) else "Local tool unavailable, failed, or timed out (diagnostics withheld)"
        print(f"FAIL [preflight] {message}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
