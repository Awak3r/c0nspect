"""Actions-only SSH transport. Production release logic belongs to deploy/release.py."""

import ipaddress
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import subprocess
import sys
import tempfile


IMAGE = "ghcr.io/awak3r/c0nspect"


def checked(name, pattern, default=None):
    value = os.environ.get(name) or default
    if value is None or not re.fullmatch(pattern, value, flags=re.ASCII):
        raise ValueError(f"Invalid or missing {name}")
    return value


class Deployment:
    def __init__(self):
        self.host = checked("DEPLOY_HOST", r"[A-Za-z0-9:][A-Za-z0-9.:-]*")
        try:
            ipaddress.ip_address(self.host)
        except ValueError:
            labels = self.host.split(".")
            if len(self.host) > 253 or any(
                not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                for label in labels
            ):
                raise ValueError("DEPLOY_HOST must be a bare IP address or DNS name") from None
        self.user = checked("DEPLOY_USER", r"root")
        self.port = checked("DEPLOY_PORT", r"[0-9]{1,5}", "22")
        if not 1 <= int(self.port) <= 65535:
            raise ValueError("DEPLOY_PORT must be between 1 and 65535")
        self.root = checked("DEPLOY_PATH", r"/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+", "/opt/conspect")
        if any(part in {".", ".."} for part in self.root.split("/")):
            raise ValueError("DEPLOY_PATH must be an absolute, normalized, non-root path")
        self.revision = checked("GITHUB_SHA", r"[0-9a-f]{40}")
        run = checked("GITHUB_RUN_ID", r"[1-9][0-9]*")
        attempt = checked("GITHUB_RUN_ATTEMPT", r"[1-9][0-9]*")
        self.actor = checked("GITHUB_ACTOR", r"[A-Za-z0-9][A-Za-z0-9\[\]-]*")
        self.digest = checked("IMAGE_DIGEST", r"sha256:[0-9a-f]{64}")
        self.staging = str(PurePosixPath(self.root) / ".releases" / f"{self.revision}-{run}-{attempt}")
        state = os.environ.get("DEPLOY_STATE")
        self.state = Path(state) if state else Path(os.environ["RUNNER_TEMP"]) / "conspect-deploy"
        if not self.state.is_absolute():
            raise ValueError("DEPLOY_STATE must be absolute")

    def configure(self):
        key = os.environ.get("DEPLOY_SSH_KEY", "")
        known_hosts = os.environ.get("DEPLOY_KNOWN_HOSTS", "")
        if not key.strip() or not known_hosts.strip():
            raise ValueError("DEPLOY_SSH_KEY and DEPLOY_KNOWN_HOSTS are required")
        self.state.mkdir(mode=0o700)
        try:
            for name, value in (("identity", key), ("known_hosts", known_hosts)):
                with open(self.state / name, "x", encoding="utf-8", opener=lambda path, flags: os.open(path, flags, 0o600)) as stream:
                    stream.write(value.rstrip("\r\n") + "\n")
            with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
                output.write("configured=true\n")
        except BaseException:
            shutil.rmtree(self.state)
            raise

    def ssh(self, command, *, stdin=None, input=None, timeout=120):
        # SSH still invokes a remote shell: quote EVERY remote argv element.
        argv = [
            "ssh", "-F", "/dev/null", "-T",
            "-i", str(self.state / "identity"), "-p", self.port, "-l", self.user,
            "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
            "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={self.state / 'known_hosts'}",
            "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no",
            "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes",
            "-o", "ConnectTimeout=15", "-o", "ConnectionAttempts=3",
            "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=4",
            "--", self.host, command,
        ]
        if stdin is None and input is None:
            stdin = subprocess.DEVNULL
        subprocess.run(argv, stdin=stdin, input=input, check=True, timeout=timeout)

    def release(self):
        token = os.environ.get("GITHUB_TOKEN", "")
        if not token or "\n" in token or "\r" in token:
            raise ValueError("GITHUB_TOKEN must be a nonempty single line")
        # This archive excludes application source, local secrets and untracked files.
        with tempfile.TemporaryFile() as archive:
            subprocess.run(
                ["git", "archive", "--format=tar", self.revision, "compose.yaml", "deploy"],
                stdout=archive, check=True, timeout=60,
            )
            archive.seek(0)
            releases = str(PurePosixPath(self.staging).parent)
            self.ssh(
                "umask 077; "
                + shlex.join(["test", "!", "-L", releases]) + " && "
                + shlex.join(["mkdir", "-p", "--", releases]) + " && "
                + shlex.join(["mkdir", "--", self.staging])
            )
            # Only remove a directory that this run successfully created.
            (self.state / "staged").touch(exist_ok=False)
            self.ssh(shlex.join(["tar", "-xf", "-", "-C", self.staging]), stdin=archive)
        command = [
            "python3", f"{self.staging}/deploy/release.py",
            "--source", self.staging, "--root", self.root,
            "--image", f"{IMAGE}@{self.digest}",
            "--registry-user", self.actor, "--revision", self.revision,
        ]
        # Never put the registry token in argv, remote files or shell text.
        self.ssh(shlex.join(command), input=(token + "\n").encode(), timeout=1800)

    def cleanup(self):
        try:
            if (self.state / "staged").is_file():
                self.ssh(shlex.join(["rm", "-rf", "--", self.staging]), timeout=60)
        finally:
            shutil.rmtree(self.state, ignore_errors=True)


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in {"configure", "release", "cleanup"}:
        raise SystemExit("usage: deploy.py {configure|release|cleanup}")
    try:
        getattr(Deployment(), sys.argv[1])()
    except (ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        # subprocess exceptions contain argv, but credentials are never in argv.
        print(f"Deployment {sys.argv[1]} failed: {error}", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
