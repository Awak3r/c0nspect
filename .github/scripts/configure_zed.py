"""Offline-first migration of one Zed JSONC context server (Python stdlib only).

Usage: python3 .github/scripts/configure_zed.py --settings PATH [--check|--probe|--apply]
Windows drive paths map to /mnt/<drive>/ under WSL. Only the existing Conspect
credential is used; process-environment credentials and other servers are ignored.

--apply stores that SAME secret in settings.json headers, after one read-only MCP
initialize succeeds. Close Zed while applying. The backup contains secrets too:
keep both files private and outside Git. Unix settings must already be private;
new backups use 0600 and replacements preserve the original mode. On Windows/
DrvFS, chmod cannot establish ACL privacy: PowerShell reads Windows ACL metadata
(no ACL changes), requiring a private user-profile directory and matching file
DACLs on the inherited backup/replacement. If this cannot be verified, apply is
refused. A stricter/custom original ACL may need manual migration instead.

Hash/identity checks immediately before replacement detect ordinary concurrent
edits, not a hostile writer racing the final check. This is not a file-locking
protocol with Zed. No OAuth configuration, owner API, tools or Git index is used.
"""

import argparse
import base64
from dataclasses import dataclass, field
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from urllib import error, parse, request


DEFAULT_ORIGIN = "https://conspect.awak3r.ru"
PROTOCOL = "2025-11-25"
MAX_SETTINGS = 4 * 1024 * 1024
MAX_RESPONSE = 65536


class ConfigError(Exception):
    """Only fixed, secret-free diagnostics may be passed to this exception."""


@dataclass(repr=False)
class Node:
    value: object
    start: int
    end: int
    members: dict = field(default_factory=dict)


class JSONC:
    """Small span-aware JSON parser: comments/trailing commas, no duplicate keys."""

    def __init__(self, text):
        self.text = text
        self.pos = 1 if text.startswith("\ufeff") else 0
        self.decoder = json.JSONDecoder(parse_constant=self.invalid)

    @staticmethod
    def invalid(*_):
        raise ConfigError("Invalid or ambiguous JSONC settings; no changes made.")

    def skip(self):
        while self.pos < len(self.text):
            if self.text[self.pos] in " \t\r\n":
                self.pos += 1
            elif self.text.startswith("//", self.pos):
                end = self.text.find("\n", self.pos + 2)
                self.pos = len(self.text) if end < 0 else end
            elif self.text.startswith("/*", self.pos):
                end = self.text.find("*/", self.pos + 2)
                if end < 0:
                    self.invalid()
                self.pos = end + 2
            else:
                break

    def node(self):
        self.skip()
        start = self.pos
        opening = self.text[self.pos:self.pos + 1]
        if opening not in ("{", "["):
            value, self.pos = self.decoder.raw_decode(self.text, self.pos)
            return Node(value, start, self.pos)
        self.pos += 1
        closing = "}" if opening == "{" else "]"
        members, values = {}, []
        self.skip()
        while self.text[self.pos:self.pos + 1] != closing:
            if opening == "{":
                key, self.pos = self.decoder.raw_decode(self.text, self.pos)
                if not isinstance(key, str) or key in members:
                    self.invalid()
                self.skip()
                if self.text[self.pos:self.pos + 1] != ":":
                    self.invalid()
                self.pos += 1
                members[key] = self.node()
            else:
                values.append(self.node().value)
            self.skip()
            if self.text[self.pos:self.pos + 1] == closing:
                break
            if self.text[self.pos:self.pos + 1] != ",":
                self.invalid()
            self.pos += 1
            self.skip()
        self.pos += 1
        value = {key: node.value for key, node in members.items()} if opening == "{" else values
        return Node(value, start, self.pos, members)

    def parse(self):
        try:
            node = self.node()
            self.skip()
            if self.pos != len(self.text):
                self.invalid()
            return node
        except (ValueError, IndexError, RecursionError):
            self.invalid()


def local_path(raw):
    if not isinstance(raw, str) or not raw or any(ord(c) < 32 for c in raw):
        raise ConfigError("Invalid local path; no changes made.")
    if re.match(r"^[A-Za-z]:[\\/]", raw) and os.name != "nt":
        raw = "/mnt/" + raw[0].lower() + "/" + raw[3:].replace("\\", "/")
    elif "\\" in raw and os.name != "nt":
        raise ConfigError("Unsupported Windows path; use an absolute drive path.")
    return Path(os.path.abspath(raw))


def check_path(path):
    # Check ancestors too: resolve() alone would silently follow a symlink/junction.
    for part in (*reversed(path.parents), path):
        info = part.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ConfigError("Symlink or reparse-point paths are refused.")


def read_regular(path, limit):
    check_path(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit:
        raise ConfigError("Expected a bounded, regular, non-linked local file.")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not os.path.samestat(before, info):
            raise ConfigError("Local file changed while reading; retry after closing Zed.")
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ConfigError("Local file exceeds the supported size.")
    return data, info


def endpoint(raw, remote=False):
    invalid = "Conspect URL must be a plain HTTPS origin (or its canonical MCP URL)."
    if not isinstance(raw, str) or any(ord(c) <= 32 or ord(c) >= 127 for c in raw) or any(c in raw for c in "?#\\%"):
        raise ConfigError(invalid)
    try:
        url = parse.urlsplit(raw)
        if url.scheme != "https" or not url.hostname or url.username is not None or url.password is not None:
            raise ValueError
        host = url.hostname.lower()
        try:
            ip = ipaddress.ip_address(host)
            host = "[" + ip.compressed + "]" if ip.version == 6 else ip.compressed
        except ValueError:
            if len(host) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in host.split(".")):
                raise ValueError from None
        port = url.port
        if url.netloc.endswith(":") or port is not None and not 1 <= port <= 65535:
            raise ValueError
        allowed = ("/mcp",) if remote else ("", "/", "/api/v1", "/api/v1/")
        if url.path not in allowed:
            raise ValueError
        return "https://" + host + (":" + str(port) if port not in (None, 443) else "") + "/mcp"
    except ValueError:
        raise ConfigError(invalid) from None


def valid_key(key):
    if not isinstance(key, str) or not 4 < len(key) <= 4096 or not key.startswith("csp_") or any(not 33 <= ord(c) <= 126 for c in key):
        raise ConfigError("Expected exactly one existing, valid Conspect API key.")
    return key


@dataclass(repr=False)
class Plan:
    path: Path
    original: bytes
    info: object
    updated: bytes
    url: str
    key: str
    root: str
    source: str
    remote: bool


def prepare(path):
    original, info = read_regular(path, MAX_SETTINGS)
    try:
        text = original.decode("utf-8")
    except UnicodeError:
        raise ConfigError("Settings must be UTF-8 JSONC.") from None
    doc = JSONC(text).parse()
    try:
        server = doc.members["context_servers"].members["conspect"]
    except KeyError:
        raise ConfigError("Expected exactly context_servers.conspect in settings.") from None
    cfg = server.value
    if not isinstance(cfg, dict):
        raise ConfigError("context_servers.conspect must be an object.")
    env, headers = cfg.get("env", {}), cfg.get("headers", {})
    if not isinstance(env, dict) or not isinstance(headers, dict):
        raise ConfigError("Conspect env and headers must be objects.")
    remote = "url" in cfg
    if remote and ("command" in cfg or "CONSPECT_URL" in env):
        raise ConfigError("Ambiguous local/remote Conspect configuration.")
    if not remote and (not isinstance(cfg.get("command"), str) or not cfg["command"]):
        raise ConfigError("Expected an existing local command or remote URL.")
    url = endpoint(cfg["url"] if remote else env.get("CONSPECT_URL", DEFAULT_ORIGIN), remote)
    sources = [(name, env[name]) for name in ("CONSPECT_API_KEY_FILE", "CONSPECT_API_KEY") if name in env]
    for name, value in headers.items():
        if name.lower() in ("authorization", "x-api-key"):
            sources.append((name.lower(), value))
    if len(sources) != 1:
        raise ConfigError("Expected exactly one existing Conspect credential source.")
    source, key = sources[0]
    if source == "CONSPECT_API_KEY_FILE":
        key_path = local_path(key)
        if not re.match(r"^[A-Za-z]:[\\/]", key) and not Path(key).is_absolute():
            raise ConfigError("The existing API key file path must be absolute.")
        data, _ = read_regular(key_path, 4096)
        try:
            key = data.decode("utf-8").strip()
        except UnicodeError:
            raise ConfigError("API key file must contain a valid Conspect key.") from None
    elif source == "authorization":
        if not isinstance(key, str) or not key.startswith("Bearer "):
            raise ConfigError("Existing Authorization must use a Conspect Bearer key.")
        key = key[7:]
    key = valid_key(key)
    root = env.get("CONSPECT_FILES_ROOT", "")
    if not isinstance(root, str) or any(ord(c) < 32 for c in root):
        raise ConfigError("Invalid CONSPECT_FILES_ROOT path.")
    value = json.dumps({"url": url, "headers": {"Authorization": "Bearer " + key}}, ensure_ascii=True)
    updated = (text[:server.start] + value + text[server.end:]).encode("utf-8")
    return Plan(path, original, info, updated, url, key, root, source, remote)


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def probe(plan):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": PROTOCOL, "capabilities": {},
        "clientInfo": {"name": "conspect-configure-zed", "version": "1"},
    }}).encode("utf-8")
    req = request.Request(plan.url, data=body, method="POST", headers={
        "Authorization": "Bearer " + plan.key, "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream", "MCP-Protocol-Version": PROTOCOL,
    })
    # No redirects, cookies, ambient HTTP auth, proxy credentials or follow-up RPCs.
    opener = request.build_opener(request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(req, timeout=20) as response:
            if response.status != 200 or response.geturl() != plan.url:
                raise ConfigError("MCP initialize was not accepted; settings unchanged.")
            content_type = response.headers.get_content_type()
            if content_type != "application/json":
                raise ConfigError("MCP initialize did not return JSON; settings unchanged.")
            raw = response.read(MAX_RESPONSE + 1)
            if len(raw) > MAX_RESPONSE:
                raise ConfigError("MCP initialize response exceeded the limit; settings unchanged.")
            reply = json.loads(raw)
        if not isinstance(reply, dict):
            raise ConfigError("MCP initialize returned an invalid result; settings unchanged.")
        result = reply.get("result")
        if (reply.get("jsonrpc") != "2.0" or type(reply.get("id")) is not int or reply["id"] != 1
                or "error" in reply or not isinstance(result, dict)
                or result.get("protocolVersion") != PROTOCOL
                or not isinstance(result.get("capabilities"), dict)
                or not isinstance(result.get("serverInfo"), dict)):
            raise ConfigError("MCP initialize returned an invalid result; settings unchanged.")
    except error.HTTPError as exc:
        code = exc.code
        exc.close()
        if code in (401, 403):
            raise ConfigError("MCP authorization refused. The server may not yet accept csp_ keys; wait for deployment. Settings unchanged.") from None
        raise ConfigError("MCP initialize failed (HTTP response withheld); settings unchanged.") from None
    except (OSError, ValueError, error.URLError, http.client.HTTPException):
        raise ConfigError("MCP initialize unavailable or invalid; settings unchanged.") from None


def windows_path(path):
    if os.name == "nt":
        return str(path)
    match = re.fullmatch(r"/mnt/([a-z])/(.+)", str(path))
    return match[1].upper() + ":\\" + match[2].replace("/", "\\") if match else None


# Windows metadata only. No ACL mutations; neither settings nor key contents enter
# PowerShell. SID comparisons work on localized Windows installations.
ACL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$p = [IO.Path]::GetFullPath($env:CONSPECT_ZED_ACL_PATH)
$profile = [Environment]::GetFolderPath('UserProfile').TrimEnd('\') + '\'
$me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$acl = Get-Acl -LiteralPath $p
$ok = $p.StartsWith($profile, [StringComparison]::OrdinalIgnoreCase)
$trusted = @($me, 'S-1-5-18', 'S-1-5-32-544', 'S-1-3-0')
$ok = $ok -and ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -in $trusted)
foreach ($r in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    if ($r.AccessControlType -eq 'Allow' -and $r.IdentityReference.Value -notin $trusted) { $ok = $false }
}
@{private=$ok; dacl=$acl.GetSecurityDescriptorSddlForm([Security.AccessControl.AccessControlSections]::Access)} | ConvertTo-Json -Compress
"""


def windows_acl(path):
    executable = shutil.which("powershell.exe")
    if not executable:
        raise ConfigError("Cannot verify Windows ACLs: PowerShell interop is required; no ACLs were changed.")
    env = dict(os.environ, CONSPECT_ZED_ACL_PATH=windows_path(path))
    if os.name != "nt":
        # WSL does not forward arbitrary Linux environment values to Win32.
        variables = [item for item in env.get("WSLENV", "").split(":")
                     if item and item.split("/", 1)[0] != "CONSPECT_ZED_ACL_PATH"]
        env["WSLENV"] = ":".join([*variables, "CONSPECT_ZED_ACL_PATH"])
    try:
        result = subprocess.run(
            [executable, "-NoProfile", "-NonInteractive", "-EncodedCommand",
             base64.b64encode(ACL_SCRIPT.encode("utf-16le")).decode("ascii")],
            env=env, stdin=subprocess.DEVNULL, capture_output=True, timeout=10, check=False,
        )
        meta = json.loads(result.stdout.decode("utf-8-sig"))
        if result.returncode or meta.get("private") is not True or not isinstance(meta.get("dacl"), str) or not meta["dacl"]:
            raise ValueError
        return meta["dacl"]
    except (OSError, ValueError, subprocess.SubprocessError):
        raise ConfigError("Windows user-profile ACL privacy could not be verified; no ACLs were changed.") from None


def permissions(plan):
    repo = Path(__file__).resolve().parents[2]
    if plan.path == repo or repo in plan.path.parents:
        raise ConfigError("Apply requires settings and secret backups outside the checkout.")
    if windows_path(plan.path):
        windows_acl(plan.path.parent)
        return windows_acl(plan.path)
    if (plan.info.st_mode & 0o077 or plan.info.st_uid != os.getuid()
            or plan.path.parent.stat().st_mode & 0o022):
        raise ConfigError("Apply requires already-private settings and a non-writable-by-others directory.")
    return None


def unchanged(plan):
    data, info = read_regular(plan.path, MAX_SETTINGS)
    if (not os.path.samestat(info, plan.info) or stat.S_IMODE(info.st_mode) != stat.S_IMODE(plan.info.st_mode)
            or hashlib.sha256(data).digest() != hashlib.sha256(plan.original).digest()):
        raise ConfigError("Settings changed since inspection; close Zed and retry. Nothing replaced.")


def apply(plan):
    acl = permissions(plan)
    probe(plan)
    unchanged(plan)
    backup = temporary = None
    replaced = False
    try:
        for is_backup, data in ((True, plan.original), (False, plan.updated)):
            fd, name = tempfile.mkstemp(prefix=plan.path.name + ".conspect-", suffix=".bak" if is_backup else ".tmp", dir=plan.path.parent)
            path = Path(name)
            if is_backup:
                backup = path
            else:
                temporary = path
            with os.fdopen(fd, "wb") as stream:
                if acl is not None and windows_acl(path) != acl:
                    raise ConfigError("Inherited Windows file ACL differs from settings; refusing replacement without ACL changes.")
                if acl is None:
                    os.fchmod(stream.fileno(), 0o600 if is_backup else stat.S_IMODE(plan.info.st_mode))
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            if acl is not None and windows_acl(path) != acl:
                raise ConfigError("Inherited Windows file ACL differs from settings; refusing replacement without ACL changes.")
        if acl is not None and permissions(plan) != acl:
            raise ConfigError("Windows ACL changed since inspection; nothing replaced.")
        unchanged(plan)
        os.replace(temporary, plan.path)
        replaced = True
    finally:
        for path in (temporary, backup if not replaced else None):
            if path is not None:
                path.unlink(missing_ok=True)


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's normal diagnostics echo arbitrary input, possibly a secret.
        raise ConfigError("Invalid CLI arguments; use --help for usage.")


def main(argv=None):
    parser = SafeParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--settings", required=True, help="Existing settings.json path (outside checkout)")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--check", action="store_true", help="Offline inspection only (default)")
    modes.add_argument("--probe", action="store_true", help="One authenticated HTTPS initialize; no local writes")
    modes.add_argument("--apply", action="store_true", help="Probe, private backup, then atomic replacement")
    try:
        args = parser.parse_args(argv)
        plan = prepare(local_path(args.settings))
        mode = "apply" if args.apply else "probe" if args.probe else "inspect"
        print("mode: " + mode)
        print("url: " + plan.url)
        print("credential field: " + plan.source)
        print("replacement fields: url, headers.Authorization")
        print("local files root (removed from remote config): " + json.dumps(plan.root, ensure_ascii=True))
        if args.apply:
            apply(plan)
            print("mode: applied; private sibling backup retained; local file access is no longer configured")
        elif args.probe:
            probe(plan)
            print("mode: probe accepted; settings unchanged")
        else:
            print("mode: offline; settings unchanged; apply will embed the existing key in headers")
        return 0
    except ConfigError as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
    except (OSError, ValueError, TypeError, RecursionError, subprocess.SubprocessError):
        print("ERROR: Local configuration operation failed (details withheld); inspect file state before retrying.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
