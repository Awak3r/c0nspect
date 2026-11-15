#!/usr/bin/env python3
"""Configure Actions access to an ALREADY installed production server.

Usage: configure_production.py {plan,apply} --host HOST --user {root,ubuntu}
       --known-hosts /absolute/trusted_known_hosts [options] [--yes]

plan is offline/read-only. apply needs --yes, POSIX private-file permissions,
OpenSSH ssh/ssh-keygen, and gh authenticated with access to environment management,
Actions secrets and variables in the selected repository. The server needs Python 3,
existing root public-key SSH access, and (for ubuntu) existing sudo -n python3.
No installation, deployment, workflow dispatch, SSH policy or sudoers changes.
Known hosts MUST already be independently trusted; this tool never discovers trust.
GitHub writes are individually retryable, not transactional; existing environment
protection rules are preserved. The dedicated unencrypted deploy key stays private
in the state directory; only that generated key is uploaded, never --identity-file.
"""

import argparse
import base64
from contextlib import contextmanager
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import stat
import struct
import subprocess
import sys
import tempfile
from urllib.parse import quote


CHECKOUT = Path(__file__).resolve().parents[2]
MARKER = "conspect-actions-deploy-v1"
TIMEOUT = 60
LIMIT = 65536


class ConfigError(Exception):
    pass


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise ConfigError("Invalid arguments; use --help. Do not put secrets in arguments.")


def local_path(raw):
    path = Path(raw)
    if (not path.is_absolute() or any(p in (".", "..") for p in re.split(r"[/\\]", raw))
            or any(ord(c) < 32 or ord(c) == 127 for c in raw) or any(c in raw for c in "%$")):
        # OpenSSH expands percent tokens/environment variables even without a shell.
        raise ConfigError("Local paths must be absolute, without traversal, control characters or SSH expansion tokens.")
    for part in (*reversed(path.parents), path):
        if part.is_symlink():
            raise ConfigError("Symbolic links in local paths are refused.")
    return path


def regular(path, *, private=False):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > LIMIT
            or private and (info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600)):
        raise ConfigError("Expected a bounded regular single-link file with safe ownership and permissions.")
    return info


def read_file(path, *, private=False):
    regular(path, private=private)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if info != path.lstat():
            raise ConfigError("Local file changed during inspection; refusing it.")
        data = stream.read(LIMIT + 1)
    if len(data) > LIMIT:
        raise ConfigError("Local file exceeds the allowed size.")
    return data


def default_state(args):
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", str(Path.home() / "AppData/Roaming")))
    elif sys.platform == "darwin":
        base = Path.home() / "Library/Application Support"
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config")))
    # IPv6 colons are not portable directory-name characters.
    host = args.host.replace(":", "_")
    return base / "conspect/deploy" / args.repo / args.environment / (host + "-" + str(args.port))


def validate(args):
    try:
        address = ipaddress.ip_address(args.host)
        if "%" in str(address):
            raise ConfigError("Scoped IP addresses are not supported by the Actions transport.")
        args.host = str(address)
    except ValueError:
        if len(args.host) > 253 or not all(re.fullmatch(
                r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label, re.ASCII
        ) for label in args.host.split(".")):
            raise ConfigError("Host must be a bare hostname or IP address, without user, port or URL.") from None
        args.host = args.host.lower()
    if not 1 <= args.port <= 65535:
        raise ConfigError("Port must be between 1 and 65535.")
    if (not re.fullmatch(r"/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+", args.root, re.ASCII)
            or any(p in (".", "..") for p in args.root.split("/"))):
        raise ConfigError("Root must be an absolute normalized non-root server path.")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9_][A-Za-z0-9_.-]*", args.repo, re.ASCII):
        raise ConfigError("Repository must be an owner/name pair.")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,99}", args.environment, re.ASCII):
        raise ConfigError("Environment must be a simple name of at most 100 characters.")
    args.known_hosts = local_path(args.known_hosts)
    if not regular(args.known_hosts).st_size:
        raise ConfigError("Known-hosts file must already contain independently trusted host keys.")
    if args.identity_file:
        args.identity_file = local_path(args.identity_file)
        regular(args.identity_file)
    args.state_dir = local_path(args.state_dir or str(default_state(args)))
    if args.state_dir == CHECKOUT or CHECKOUT in args.state_dir.parents or args.state_dir in CHECKOUT.parents:
        raise ConfigError("State directory must be separate from and outside the checkout.")
    if args.command == "apply" and not args.yes:
        raise ConfigError("Apply requires --yes; review plan first.")
    return args


def run(argv, *, data=None, error="External command failed; details withheld.", check=True):
    try:
        result = subprocess.run(
            argv, input=data, stdin=subprocess.DEVNULL if data is None else None,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=TIMEOUT, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        raise ConfigError(error) from None
    if check and result.returncode:
        raise ConfigError(error)
    return result


def atomic(path, data):
    if os.path.lexists(path):
        regular(path, private=True)
    fd, name = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.lexists(name):
            os.unlink(name)


def state_config(args):
    return {"marker": MARKER, "host": args.host, "port": args.port, "root": args.root,
            "repo": args.repo, "environment": args.environment}


def private_directory(path):
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ConfigError("State directories must be owned by the current user with mode 0700.")


@contextmanager
def locked_state(args):
    # flock releases on process death: no stale lock deletion or unsafe lock takeover.
    if os.name != "posix":
        raise ConfigError("Apply requires POSIX ownership, mode 0700/0600 and flock; use a POSIX client.")
    import fcntl

    state = args.state_dir
    local_path(str(state))
    # An existing directory, even an empty one, is not adopted as managed state.
    if not os.path.lexists(state):
        missing, parent = [], state.parent
        while not parent.exists():
            missing.append(parent)
            parent = parent.parent
        for path in reversed(missing):
            path.mkdir(mode=0o700)
        # Publish a complete marker atomically, before key generation can begin.
        stage = Path(tempfile.mkdtemp(prefix=".conspect-state-", dir=state.parent))
        try:
            atomic(stage / "config.json", json.dumps(state_config(args), sort_keys=True).encode() + b"\n")
            if os.path.lexists(state):
                raise ConfigError("State appeared during initialization; refusing adoption.")
            stage.rename(state)
        finally:
            if stage.exists():
                (stage / "config.json").unlink(missing_ok=True)
                stage.rmdir()
    private_directory(state)
    config = state / "config.json"
    if json.loads(read_file(config, private=True)) != state_config(args):
        raise ConfigError("State is unmanaged or belongs to different inputs; use its original inputs or a fresh directory.")
    lock = state / "lock"
    if os.path.lexists(lock):
        regular(lock, private=True)
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        regular(lock, private=True)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ConfigError("Another apply holds this state lock; wait for it to finish.") from None
        # Pending atomic writes from a killed process contain only managed data.
        allowed = {"config.json", "lock", "deploy_ed25519", "deploy_ed25519.pub", "known_hosts"}
        for path in state.iterdir():
            if path.name not in allowed and not path.name.startswith(".pending-"):
                raise ConfigError("State contains unmanaged files; refusing adoption.")
            if path.name == "deploy_ed25519.pub":
                info = regular(path)
                if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) not in (0o600, 0o644):
                    raise ConfigError("Managed public key has unsafe ownership or permissions.")
            else:
                regular(path, private=True)
        yield state
    finally:
        os.close(fd)


def public_key(data):
    try:
        text = data.decode("ascii").rstrip("\r\n")
        if any(ord(c) < 32 and c != "\t" or ord(c) == 127 for c in text):
            raise ValueError
        fields = text.split(maxsplit=2)
        if len(fields) not in (2, 3) or fields[0] != "ssh-ed25519":
            raise ValueError
        raw = base64.b64decode(fields[1], validate=True)
        expected = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32)
        if len(raw) != 51 or not raw.startswith(expected):
            raise ValueError
        return "ssh-ed25519 " + base64.b64encode(raw).decode("ascii")
    except (ValueError, UnicodeError):
        raise ConfigError("Expected a valid Ed25519 public key; refusing malformed or other key types.") from None


def deployment_key(state):
    key, pub = state / "deploy_ed25519", state / "deploy_ed25519.pub"
    if not os.path.lexists(key):
        if os.path.lexists(pub):
            raise ConfigError("Incomplete key state; refusing to overwrite an orphan public key.")
        run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", MARKER, "-f", str(key)],
            error="Dedicated key generation failed; keep state and inspect it privately before retrying.")
        # ssh-keygen normally creates the PUBLIC half as 0644; it is not a secret.
        regular(pub)
        pub.chmod(0o600)
    private = read_file(key, private=True)
    if not private.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----\n"):
        raise ConfigError("Managed private key is malformed; it will not be overwritten.")
    derived = public_key(run(["ssh-keygen", "-y", "-P", "", "-f", str(key)],
                             error="Managed key must be a valid unencrypted Ed25519 key; it will not be replaced.").stdout)
    if os.path.lexists(pub):
        # Also recover interruption between ssh-keygen and public-file chmod.
        regular(pub)
        if public_key(read_file(pub)) != derived:
            raise ConfigError("Managed public and private keys do not match; refusing replacement.")
        pub.chmod(0o600)
    else:
        atomic(pub, (derived + "\n").encode())
    return private, derived


def ssh(args, command, *, data=None, deployment=False):
    identity = args.state_dir / "deploy_ed25519" if deployment else args.identity_file
    hosts = args.state_dir / "known_hosts" if deployment else args.known_hosts
    argv = ["ssh", "-F", os.devnull, "-T", "-p", str(args.port), "-l", "root" if deployment else args.user]
    if identity:
        argv += ["-i", str(identity), "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none"]
    # -o is parsed as ssh_config syntax, not as shell syntax; quote filenames there too.
    filename = str(hosts).replace("\\", "\\\\").replace('"', '\\"')
    for option in ("BatchMode=yes", "StrictHostKeyChecking=yes", 'UserKnownHostsFile="' + filename + '"',
                   "GlobalKnownHostsFile=" + os.devnull, "UpdateHostKeys=no", "VerifyHostKeyDNS=no",
                   "PasswordAuthentication=no", "KbdInteractiveAuthentication=no", "ForwardAgent=no",
                   "ClearAllForwardings=yes", "ConnectTimeout=15", "ConnectionAttempts=1",
                   "ServerAliveInterval=10", "ServerAliveCountMax=2"):
        argv += ["-o", option]
    if deployment:
        argv += ["-o", "HostKeyAlgorithms=ssh-ed25519"]
    argv += ["--", args.host, command]
    error = ("Root SSH with the dedicated key failed. Existing root public-key policy must allow Actions; "
             "ask the server administrator to review it. No SSH policy bypass or GitHub edits were made."
             if deployment else "Trusted SSH/server check failed. Verify supplied trust, installed files, Python 3 and sudo -n access.")
    return run(argv, data=data, error=error).stdout


# These scripts run through the already-authenticated SSH connection, not a local
# shell. Only the public deploy key is sent on stdin. No .env contents are returned.
REMOTE_COMMON = '''import os, stat, sys
from pathlib import Path

def directory(path):
    for p in (path, *path.parents):
        s = p.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
            raise ValueError("unsafe directory")

def regular(path):
    s = path.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or s.st_nlink != 1 or s.st_mode & 0o022:
        raise ValueError("unsafe file")
    return s

if os.geteuid() != 0:
    raise ValueError("root required")
'''

REMOTE_INSPECT = REMOTE_COMMON + '''root = Path(sys.argv[1])
directory(root)
directory(root / "deploy")
for name in (".env", "deploy/bootstrap.py", "deploy/release.py"):
    s = regular(root / name)
    if not s.st_size or name == ".env" and s.st_mode & 0o077:
        raise ValueError("installation required")
host = Path("/etc/ssh/ssh_host_ed25519_key.pub")
directory(host.parent)
regular(host)
with host.open("rb") as stream:
    data = stream.read(4097)
if len(data) > 4096:
    raise ValueError("invalid public host key")
sys.stdout.buffer.write(data)
'''

REMOTE_AUTHORIZE = REMOTE_COMMON + '''import base64, fcntl, struct
key = sys.stdin.buffer.read(4097).decode("ascii").strip()
fields = key.split()
if len(fields) != 2 or fields[0] != "ssh-ed25519":
    raise ValueError("invalid public key")
blob = base64.b64decode(fields[1], validate=True)
if len(blob) != 51 or not blob.startswith(struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32)):
    raise ValueError("invalid public key")
home = Path("/root")
directory(home)
folder = home / ".ssh"
try:
    folder.mkdir(mode=0o700)
except FileExistsError:
    pass
directory(folder)
target = folder / "authorized_keys"
if os.path.lexists(target):
    regular(target)
fd = os.open(target, os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, "r+b") as stream:
    fcntl.flock(stream, fcntl.LOCK_EX)
    s = regular(target)
    if s.st_ino != os.fstat(stream.fileno()).st_ino or s.st_size > 4 * 1024 * 1024:
        raise ValueError("unsafe authorized_keys")
    old = stream.read()
    entry = ("restrict " + key + " conspect-actions-deploy-v1").encode("ascii")
    if entry not in old.splitlines():
        stream.write((b"" if not old or old.endswith(b"\\n") else b"\\n") + entry + b"\\n")
        stream.flush()
        os.fsync(stream.fileno())
'''


def remote_python(args, code, *arguments):
    prefix = ["sudo", "-n"] if args.user == "ubuntu" else []
    return shlex.join([*prefix, "python3", "-c", code, *arguments])


def environment(args):
    endpoint = "repos/" + args.repo + "/environments/" + quote(args.environment, safe="")
    result = run(["gh", "api", "--method", "GET", "--include", endpoint], check=False)
    if result.returncode:
        if not re.match(rb"HTTP/[0-9.]+ 404(?:\s|$)", result.stdout):
            raise ConfigError("GitHub environment lookup failed; check repository/environment administration permissions.")
        run(["gh", "api", "--method", "PUT", endpoint],
            error="GitHub environment creation failed; check repository administration permissions.")


def apply(args):
    if os.name != "posix":
        raise ConfigError("Apply requires POSIX ownership, mode 0700/0600 and flock; use a POSIX client.")
    run(["gh", "auth", "status"], error="GitHub authentication unavailable; run gh auth login with appropriate repository access.")
    with locked_state(args) as state:
        host_key = public_key(ssh(args, remote_python(args, REMOTE_INSPECT, args.root)))
        private, public = deployment_key(state)
        host = args.host if args.port == 22 else "[" + args.host + "]:" + str(args.port)
        known_hosts = (host + " " + host_key + "\n").encode("ascii")
        atomic(state / "known_hosts", known_hosts)
        ssh(args, remote_python(args, REMOTE_AUTHORIZE), data=(public + "\n").encode("ascii"))
        if ssh(args, shlex.join(["python3", "-c", "import os, sys; sys.exit('not root') if os.geteuid() else print('conspect-root-ok')"]),
               deployment=True) != b"conspect-root-ok\n":
            raise ConfigError("Dedicated root SSH did not prove root execution; GitHub was not changed.")
        environment(args)
        for name, value in (("DEPLOY_SSH_KEY", private), ("DEPLOY_KNOWN_HOSTS", known_hosts)):
            run(["gh", "secret", "set", name, "--repo", args.repo, "--env", args.environment], data=value,
                error="GitHub secret update failed; some settings may be saved. Retry with the same state directory.")
        for name, value in (("DEPLOY_HOST", args.host), ("DEPLOY_USER", "root"),
                            ("DEPLOY_PORT", str(args.port)), ("DEPLOY_PATH", args.root)):
            run(["gh", "variable", "set", name, "--repo", args.repo, "--env", args.environment], data=value.encode(),
                error="GitHub variable update failed; some settings may be saved. Retry with the same state directory.")


def main(argv=None):
    parser = SafeParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=("plan", "apply"))
    parser.add_argument("--host", required=True)
    parser.add_argument("--user", required=True, choices=("root", "ubuntu"))
    parser.add_argument("--known-hosts", required=True, help="Absolute, already independently trusted file; never ssh-keyscan")
    parser.add_argument("--identity-file", help="Absolute existing login identity; never uploaded")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--root", default="/opt/conspect")
    parser.add_argument("--repo", default="Awak3r/c0nspect")
    parser.add_argument("--environment", default="production")
    parser.add_argument("--state-dir", help="Fresh absolute directory outside checkout, or this tool's own retry state")
    parser.add_argument("--yes", action="store_true")
    try:
        args = validate(parser.parse_args(argv))
        if args.command == "plan":
            print("PLAN: offline, read-only; no commands, key generation, network or writes.")
            print("Apply checks gh authentication and the existing root-owned installation over trusted SSH.")
            print("It generates/reuses one private dedicated Ed25519 key outside the checkout, appends restrict authorization,")
            print("then tests root SSH with the authenticated server's Ed25519 public host key and strict checking.")
            print("Only after that: create environment if absent; set DEPLOY_SSH_KEY / DEPLOY_KNOWN_HOSTS secrets")
            print("and DEPLOY_HOST / DEPLOY_USER=root / DEPLOY_PORT / DEPLOY_PATH variables via stdin.")
            print("No root-login enablement, server installation, deployment or workflow dispatch. Apply requires --yes.")
        else:
            apply(args)
            print("Configured Actions environment; dedicated root SSH verified. No deployment or workflow was started.")
        return 0
    except ConfigError as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
    except KeyboardInterrupt:
        print("ERROR: Interrupted; keep the state directory and retry with the same inputs.", file=sys.stderr)
    except (OSError, ValueError, TypeError, UnicodeError, subprocess.SubprocessError):
        print("ERROR: Configuration failed (details withheld); inspect private state and retry with the same inputs.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
