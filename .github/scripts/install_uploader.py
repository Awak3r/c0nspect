"""Install the conspect-upload HTTP client on a new machine (stdlib only).

Usage: python3 .github/scripts/install_uploader.py --files-root PATH
           [--url URL] [--key-file PATH] [--bin-dir PATH] [--config-dir PATH]
           [--check-project-id ID --check-path PATH] [--replace]

Builds ./cmd/conspect-upload from this checkout with the local Go toolchain and
installs the binary into ~/.local/bin. Writes a private config file
(<config-dir>/conspect/upload.json) that carries NO secret: url, files_root and
a key_file path. The API key itself comes from --key-file, an existing key file
in the config directory, or a hidden prompt; it is validated and stored as
<config-dir>/conspect/api-key with mode 0600. Secrets are never accepted as
command-line arguments and never printed. Existing binary/config/key files are
replaced only with --replace; the config and key directories must lie outside
this Git checkout.

On Windows, chmod is a no-op: restrict the NTFS ACLs of the key and config
files to the owning account. The Zed remote MCP block is documented in
docs/MCP.md and does not require this script.
"""

import argparse
import getpass
from pathlib import Path
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from urllib import parse

DEFAULT_ORIGIN = "https://conspect.awak3r.ru"
MAX_KEY_BYTES = 4096


class InstallError(Exception):
    """Only fixed, secret-free diagnostics may be passed to this exception."""


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's normal diagnostics echo arbitrary input; keep arguments secret-free.
        raise InstallError("Invalid CLI arguments; use --help for usage.")


def valid_origin(raw):
    invalid = "URL must be an HTTPS origin (HTTP only for localhost or a loopback IP), optionally ending in /api/v1."
    if not isinstance(raw, str) or not raw or any(ord(c) <= 32 or ord(c) >= 127 for c in raw) or any(c in raw for c in "?#\\%"):
        raise InstallError(invalid)
    url = parse.urlsplit(raw)
    try:
        if url.username is not None or url.password is not None or not url.hostname:
            raise ValueError
        port = url.port
        if port is not None and not 1 <= port <= 65535:
            raise ValueError
    except ValueError:
        raise InstallError(invalid) from None
    if url.scheme not in ("https", "http") or url.path not in ("", "/", "/api/v1", "/api/v1/"):
        raise InstallError(invalid)
    if url.scheme == "http":
        hostname = url.hostname.lower()
        loopback = hostname == "localhost" or hostname in ("::1", "[::1]")
        if not loopback and not (hostname.startswith("127.") and hostname.count(".") == 3):
            raise InstallError(invalid)
    return raw.rstrip("/")


def valid_key(key):
    if not isinstance(key, str) or len(key) <= len("csp_") or len(key) > MAX_KEY_BYTES or not key.startswith("csp_"):
        raise InstallError("Expected a Conspect API key starting with csp_ (content not echoed).")
    if any(not 33 <= ord(c) <= 126 for c in key):
        raise InstallError("The API key must be printable without whitespace; it was not echoed.")
    return key


def read_key_file(path):
    try:
        info = os.lstat(path)
    except OSError:
        raise InstallError("Key file must be an existing regular file.") from None
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_KEY_BYTES:
        raise InstallError("Key file must be a regular file of at most 4 KiB.")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as stream:
            data = stream.read(MAX_KEY_BYTES + 1)
    except OSError:
        raise InstallError("Key file could not be read (symlinks are refused).") from None
    try:
        key = data.decode("utf-8").strip()
    except UnicodeError:
        raise InstallError("Key file must be UTF-8; it was not echoed.") from None
    return valid_key(key)


def private_write(path, data):
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags, 0o600)
        with os.fdopen(fd, "wb") as stream:
            if os.name != "nt":
                os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        raise InstallError("Could not write a private file (symlinks are refused).") from None


def resolve_target(raw, what):
    path = Path(os.path.abspath(os.path.expanduser(str(raw))))
    if what == "root" and (not path.is_absolute() or not path.is_dir()):
        raise InstallError("--files-root must be an existing absolute directory (a narrow local root).")
    return path


def outside_checkout(paths):
    repo = Path(__file__).resolve().parents[2]
    return all(repo not in path.parents for path in paths)


def plan_key(args, key_path):
    """Return (key, needs_write) without printing or changing anything."""
    if args.key_file:
        key = read_key_file(resolve_target(args.key_file, "key"))
        if key_path.exists() and not args.replace:
            raise InstallError("A key file already exists; rerun with --replace to replace it.")
        return key, True
    if key_path.exists():
        try:
            return read_key_file(key_path), False
        except InstallError:
            raise InstallError("The existing key file is invalid; rerun with --replace and --key-file.") from None
    try:
        entered = getpass.getpass("Conspect API key (input hidden, starts with csp_): ")
    except (EOFError, KeyboardInterrupt):
        raise InstallError("No key entered; nothing was changed.") from None
    if not entered:
        raise InstallError("No key entered; nothing was changed.")
    return valid_key(entered), True


def build_binary(repo, bin_dir, go, replace, runner):
    bin_path = bin_dir / "conspect-upload"
    if bin_path.exists() and not replace:
        raise InstallError("The uploader binary already exists; rerun with --replace to update it.")
    if shutil.which(go) is None:
        raise InstallError("Go was not found; install Go 1.26 or newer and rerun, or set --go.")
    fd, temporary = tempfile.mkstemp(prefix="conspect-upload.", suffix=".tmp", dir=bin_dir)
    os.close(fd)
    try:
        result = runner([go, "build", "-o", temporary, "./cmd/conspect-upload"], cwd=str(repo))
        if result.returncode != 0:
            detail = (result.stderr or b"").decode("utf-8", "replace").strip()
            raise InstallError("go build failed" + (": " + detail[-800:] if detail else "; run it manually for diagnostics."))
        os.replace(temporary, bin_path)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return bin_path


def install(args, runner=None):
    runner = runner or subprocess.run
    repo = Path(__file__).resolve().parents[2]
    if not (repo / "cmd" / "conspect-upload").is_dir():
        raise InstallError("Run this script from a Conspect repository checkout.")

    files_root = resolve_target(args.files_root, "root")
    origin = valid_origin(args.url)
    bin_dir = resolve_target(args.bin_dir, "dir")
    config_home = resolve_target(args.config_dir, "dir")
    config_dir = config_home / "conspect"
    config_path, key_path = config_dir / "upload.json", config_dir / "api-key"
    if not outside_checkout((config_dir,)):
        raise InstallError("The private key and config must live outside the Git checkout.")

    bin_dir.mkdir(parents=True, exist_ok=True)
    config_dir.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        os.chmod(config_dir, 0o700)

    key, write_key = plan_key(args, key_path)
    if write_key:
        private_write(key_path, (key + "\n").encode("utf-8"))

    if config_path.exists() and not args.replace:
        raise InstallError("A config file already exists; rerun with --replace to rewrite it.")
    payload = {"url": origin, "files_root": str(files_root), "key_file": str(key_path)}
    private_write(config_path, (json.dumps(payload, ensure_ascii=True) + "\n").encode("utf-8"))

    bin_path = build_binary(repo, bin_dir, args.go, args.replace, runner)

    print("installed: " + str(bin_path))
    print("config: " + str(config_path) + " (no secret inside)")
    print("key file: " + str(key_path) + " (private)")
    if os.name == "nt":
        print("note: chmod is a no-op on Windows; restrict the NTFS ACLs to your account")
    if args.check_project_id and args.check_path:
        result = runner([str(bin_path), "--config", str(config_path), "--check",
                         "--project-id", args.check_project_id, "--path", args.check_path])
        if result.returncode != 0:
            raise InstallError("The offline --check failed; fix the arguments and rerun with --check-project-id/--check-path.")
        print("check: " + (result.stdout or b"").decode("utf-8", "replace").strip())
    print("next: conspect-upload --project-id ID --path path/ready.md --check")
    print("zed: see docs/MCP.md for the remote context server block")


def main(argv=None):
    parser = SafeParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--files-root", required=True, help="Narrow local root of your Markdown files")
    parser.add_argument("--url", default=DEFAULT_ORIGIN, help="Conspect origin (default: " + DEFAULT_ORIGIN + ")")
    parser.add_argument("--key-file", help="Existing file with the csp_ key; copied into the config directory")
    parser.add_argument("--bin-dir", default=os.path.join("~", ".local", "bin"), help="Binary directory (default: ~/.local/bin)")
    parser.add_argument("--config-dir", default=None, help="Config home; default follows the platform convention")
    parser.add_argument("--go", default="go", help="Go executable to build with")
    parser.add_argument("--check-project-id", help="Optional offline --check with this project ID")
    parser.add_argument("--check-path", help="Optional offline --check with this path")
    parser.add_argument("--replace", action="store_true", help="Replace existing binary, config or key files")
    try:
        args = parser.parse_args(argv)
        if args.config_dir is None:
            if os.name == "nt":
                base = os.environ.get("APPDATA") or os.path.expanduser("~")
            else:
                base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
            args.config_dir = base
        install(args)
        return 0
    except InstallError as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        print("ERROR: Installation failed (details withheld); inspect local state before retrying.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
