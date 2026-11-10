"""Static docs/route checks; no private env files, database, or Docker needed."""

import json
import os
import re
import shutil
import subprocess
import unittest
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}


def normalized_route(method, path):
    return method.upper(), re.sub(r"\{[^}]+\}", "{}", path)


class ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = json.loads((ROOT / "internal" / "web" / "openapi.json").read_text(encoding="utf-8"))

    def test_effective_openapi_routes_match_go_router(self):
        source = (ROOT / "internal" / "web" / "app.go").read_text(encoding="utf-8")
        actual = {
            normalized_route(method, path)
            for method, path in re.findall(r'm\.HandleFunc\("([A-Z]+) ([^"]+)"', source)
            if path.startswith("/api/v1/") or path == "/healthz"
        }
        effective = set()
        operation_ids = set()
        for path, item in self.document["paths"].items():
            for method, operation in item.items():
                if method not in HTTP_METHODS:
                    continue
                self.assertNotIn(operation["operationId"], operation_ids)
                operation_ids.add(operation["operationId"])
                servers = operation.get("servers", item.get("servers", self.document["servers"]))
                for server in servers:
                    # OpenAPI appends path keys to server URLs; urljoin would
                    # incorrectly discard /api/v1 when a path begins with '/'.
                    full_path = urlsplit(server["url"]).path.rstrip("/") + path
                    effective.add(normalized_route(method, full_path))
        self.assertEqual(effective, actual)
        self.assertIn(("GET", "/api/v1/openapi.json"), effective)
        self.assertIn(("GET", "/healthz"), effective)
        self.assertEqual(self.document["paths"]["/openapi.json"]["get"]["security"], [])

    def test_schema_references_resolve_locally(self):
        def walk(value):
            if isinstance(value, dict):
                if "$ref" in value:
                    reference = value["$ref"]
                    self.assertTrue(reference.startswith("#/"), reference)
                    target = self.document
                    for part in reference[2:].split("/"):
                        target = target[part.replace("~1", "/").replace("~0", "~")]
                for child in value.values():
                    walk(child)
            elif isinstance(value, list):
                for child in value:
                    walk(child)
        walk(self.document)

    def test_caddy_preserves_app_referrer_policy(self):
        config = (ROOT / "deploy" / "Caddyfile").read_text(encoding="utf-8")
        active = "\n".join(line.split("#", 1)[0] for line in config.splitlines())
        self.assertNotRegex(
            active, r"(?i)\bReferrer-Policy\b",
            "Caddy must preserve the app's route-specific referrer policy.",
        )

    def test_readme_shell_blocks_parse_without_execution(self):
        bash = shutil.which("bash")
        if not bash:
            self.skipTest("bash is required for README shell syntax checks")
        fence = "`" * 3
        pattern = r"^[ \t]*" + fence + r"(?:sh|bash)\n(.*?)^[ \t]*" + fence
        blocks = re.findall(pattern, (ROOT / "README.md").read_text(encoding="utf-8"), re.MULTILINE | re.DOTALL)
        self.assertTrue(blocks, "No shell blocks found")
        for index, block in enumerate(blocks, 1):
            with self.subTest(block=index):
                result = subprocess.run(
                    [bash, "--noprofile", "--norc", "-n"], input=block, text=True,
                    capture_output=True, timeout=10, env={"PATH": os.defpath}, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
