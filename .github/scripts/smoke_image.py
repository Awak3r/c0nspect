#!/usr/bin/env python3
"""Smoke a locally loaded linux/amd64 image with disposable Docker resources."""

import http.client
import json
import os
import secrets
import signal
import subprocess
import sys
import time
from urllib.request import parse_http_list, parse_keqv_list


BASE_URL = "http://127.0.0.1:18080"
RESOURCE_METADATA = BASE_URL + "/.well-known/oauth-protected-resource/mcp"
PLATFORM = "linux/amd64"
POSTGRES_IMAGE = "postgres:17-alpine"
LABEL = "conspect.image-smoke"
WAIT_SECONDS = 90
MAX_RESPONSE_BYTES = 1 << 20


class SmokeError(Exception):
    """A curated diagnostic safe to print in CI."""


def docker(stage, *arguments, timeout=30, environment=None, check=True):
    try:
        result = subprocess.run(
            ["docker", *arguments], stdin=subprocess.DEVNULL,
            capture_output=True, text=True, timeout=timeout,
            env=None if environment is None else dict(os.environ, **environment),
        )
    except subprocess.TimeoutExpired:
        raise SmokeError(f"{stage}: Docker command timed out.") from None
    except (OSError, subprocess.SubprocessError):
        raise SmokeError(f"{stage}: could not run Docker.") from None
    if check and result.returncode:
        # Docker errors can contain argv, environment values or application logs.
        raise SmokeError(f"{stage}: Docker command failed.")
    return result


def request(method, path):
    # HTTPConnection ignores proxy variables and never follows redirects.
    connection = http.client.HTTPConnection("127.0.0.1", 18080, timeout=3)
    try:
        headers = {"Accept": "application/json"}
        body = None
        if method == "POST":
            headers["Content-Type"] = "application/json"
            body = b"{}"
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        data = response.read(MAX_RESPONSE_BYTES + 1)
        if len(data) > MAX_RESPONSE_BYTES:
            raise SmokeError(f"{method} {path}: response exceeds the smoke limit.")
        return response.status, response.headers, data
    except (OSError, http.client.HTTPException):
        raise SmokeError(f"{method} {path}: HTTP request failed.") from None
    finally:
        connection.close()


def wait_until(check, description):
    deadline = time.monotonic() + WAIT_SECONDS
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(min(1, max(0, deadline - time.monotonic())))
    raise SmokeError(f"Timed out waiting for {description}.")


def healthy():
    try:
        return request("GET", "/healthz")[0] == 200
    except SmokeError:
        return False


def discovery(path):
    status, headers, body = request("GET", path)
    if status != 200 or headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
        raise SmokeError(f"GET {path}: expected HTTP 200 JSON metadata.")
    try:
        document = json.loads(body)
    except (ValueError, UnicodeError):
        raise SmokeError(f"GET {path}: invalid JSON metadata.") from None
    if not isinstance(document, dict):
        raise SmokeError(f"GET {path}: expected a metadata object.")
    return document


def check_endpoints():
    resource = discovery("/.well-known/oauth-protected-resource/mcp")
    if (resource.get("resource") != BASE_URL + "/mcp"
            or resource.get("authorization_servers") != [BASE_URL]
            or resource.get("bearer_methods_supported") != ["header"]):
        raise SmokeError("OAuth protected-resource metadata does not match the smoke origin.")
    server = discovery("/.well-known/oauth-authorization-server")
    expected = {
        "issuer": BASE_URL,
        "authorization_endpoint": BASE_URL + "/oauth/authorize",
        "token_endpoint": BASE_URL + "/oauth/token",
        "registration_endpoint": BASE_URL + "/oauth/register",
        "revocation_endpoint": BASE_URL + "/oauth/revoke",
        "code_challenge_methods_supported": ["S256"],
    }
    if any(server.get(key) != value for key, value in expected.items()):
        raise SmokeError("OAuth server metadata has incorrect issuer, endpoints or PKCE S256.")
    status, headers, body = request("POST", "/mcp")
    challenge = headers.get("WWW-Authenticate", "")
    scheme, _, parameters = challenge.partition(" ")
    try:
        items = parse_http_list(parameters)
        fields = parse_keqv_list(items)
    except (ValueError, IndexError):
        fields, items = {}, []
    if (status != 401 or scheme.lower() != "bearer" or len(fields) != len(items)
            or fields.get("resource_metadata") != RESOURCE_METADATA
            or fields.get("error") != "invalid_token"):
        raise SmokeError("POST /mcp: expected HTTP 401 with the canonical OAuth discovery challenge.")


class ImageSmoke:
    def __init__(self, image):
        if not image or image.startswith("-") or any(c.isspace() or ord(c) < 32 for c in image):
            raise SmokeError("Supply one local Docker image reference, not options or whitespace.")
        self.image = image
        self.token = secrets.token_hex(16)
        self.selector = f"{LABEL}={self.token}"
        self.network = f"conspect-smoke-{self.token}"
        self.db = self.network + "-db"
        self.app = self.network + "-app"

    def run(self):
        # Never silently pull a different app image when Buildx load:true is missing.
        docker("Inspect local app image", "image", "inspect", self.image)
        try:
            # An internal-only network can suppress Docker's host port mapping.
            # Use a dedicated bridge; only the app's loopback port is published.
            docker("Create smoke network", "network", "create", "--label", self.selector, self.network)
            password = secrets.token_urlsafe(32)
            docker(
                "Start smoke PostgreSQL", "run", "--detach", "--name", self.db,
                "--label", self.selector, "--network", self.network, "--network-alias", "db",
                "--platform", PLATFORM, "--pull=missing",
                "--tmpfs", "/var/lib/postgresql/data:rw",
                "--env", "POSTGRES_DB", "--env", "POSTGRES_USER", "--env", "POSTGRES_PASSWORD",
                POSTGRES_IMAGE, timeout=180,
                environment={"POSTGRES_DB": "smoke", "POSTGRES_USER": "smoke", "POSTGRES_PASSWORD": password},
            )
            wait_until(
                lambda: docker(
                    "Check smoke PostgreSQL", "exec", self.db, "pg_isready",
                    "--host", "127.0.0.1", "--username", "smoke", "--dbname", "smoke",
                    timeout=5, check=False,
                ).returncode == 0,
                "smoke PostgreSQL TCP readiness",
            )
            environment = {
                "DATABASE_URL": f"postgres://smoke:{password}@db:5432/smoke?sslmode=disable",
                "APP_ADDR": ":8080", "APP_BASE_URL": BASE_URL,
                "APP_SECRET": secrets.token_hex(32), "OWNER_USERNAME": "smoke",
                "OWNER_PASSWORD": secrets.token_urlsafe(32), "DATA_DIR": "/data",
                "MCP_ENABLED": "true", "MCP_API_URL": "http://127.0.0.1:8080", "TRUST_PROXY": "false",
            }
            env_arguments = [argument for name in environment for argument in ("--env", name)]
            docker(
                "Start smoke app", "run", "--detach", "--name", self.app,
                "--label", self.selector, "--network", self.network,
                "--platform", PLATFORM, "--pull=never", "--publish", "127.0.0.1:18080:8080",
                "--read-only", "--tmpfs", "/data/uploads:rw,uid=10001,gid=10001",
                "--tmpfs", "/tmp:rw,noexec,nosuid", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges:true", *env_arguments, self.image,
                environment=environment,
            )
            wait_until(healthy, "smoke app /healthz HTTP 200")
            check_endpoints()
        finally:
            self.cleanup()

    def cleanup(self):
        # Query by our random ownership label: this also finds containers created
        # by a Docker command that failed/timed out before returning its ID.
        failed = False
        for kind, listing, removal in (
            ("containers", ("container", "ls", "--all"), ("container", "rm", "--force", "--volumes")),
            ("networks", ("network", "ls"), ("network", "rm")),
        ):
            try:
                result = docker(
                    f"Find smoke {kind}", *listing, "--filter", "label=" + self.selector,
                    "--format", "{{.ID}}",
                )
            except SmokeError:
                failed = True
                continue
            for identifier in result.stdout.split():
                try:
                    docker(f"Remove smoke {kind}", *removal, identifier)
                except SmokeError:
                    failed = True
        if failed:
            raise SmokeError(f"Cleanup failed; inspect Docker resources with label {self.selector}.")


def interrupted(signum, frame):
    raise SmokeError("Image smoke interrupted.")


def main():
    if len(sys.argv) != 2:
        print("usage: python3 .github/scripts/smoke_image.py IMAGE", file=sys.stderr)
        return 2
    previous = signal.signal(signal.SIGTERM, interrupted)
    try:
        ImageSmoke(sys.argv[1]).run()
    except (SmokeError, KeyboardInterrupt) as error:
        message = str(error) if isinstance(error, SmokeError) else "Image smoke interrupted."
        print(f"Image smoke failed: {message}", file=sys.stderr)
        return 1
    finally:
        signal.signal(signal.SIGTERM, previous)
    print("Image smoke passed: /healthz, OAuth discovery and unauthenticated MCP challenge.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
