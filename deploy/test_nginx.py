"""Host-nginx and local contracts. Compose checks use only a synthetic env file."""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def active_config(name):
    content = (ROOT / "deploy" / name).read_text(encoding="utf-8")
    return "\n".join(line.split("#", 1)[0] for line in content.splitlines())


class NginxSnippetTests(unittest.TestCase):
    def test_bootstrap_serves_only_acme_and_503_without_certificates(self):
        config = active_config("nginx.bootstrap.conf")
        self.assertEqual(config.count("server {"), 1)
        self.assertIn("listen 80;", config)
        self.assertIn("server_name notes.example.com;", config)
        self.assertIn("location ^~ /.well-known/acme-challenge/", config)
        self.assertIn("root /var/lib/conspect-acme;", config)
        self.assertIn("try_files $uri =404;", config)
        self.assertRegex(config, r"location /\s*\{[^}]*return 503")
        self.assertNotIn("proxy_pass", config)
        self.assertNotIn("ssl_certificate", config)
        self.assertIn("access_log off;", config)
        self.assertIn("error_log /dev/null crit;", config)
        self.assertNotRegex(config, r"(?i)\bReferrer-Policy\b")

    def test_tls_uses_separate_servers_single_proxy_and_private_logs(self):
        config = active_config("nginx.tls.conf").strip()
        self.assertEqual(config.count("server {"), 2)
        http, tls = config.split("\nserver {", 1)
        self.assertIn("location ^~ /.well-known/acme-challenge/", http)
        self.assertIn("root /var/lib/conspect-acme;", http)
        self.assertIn("return 308 https://notes.example.com$request_uri;", http)
        self.assertNotIn("proxy_pass", http)
        self.assertIn("listen 443 ssl;", tls)
        self.assertIn("ssl_certificate /etc/letsencrypt/live/notes.example.com/fullchain.pem;", tls)
        self.assertIn("ssl_certificate_key /etc/letsencrypt/live/notes.example.com/privkey.pem;", tls)
        self.assertIn("proxy_pass http://127.0.0.1:8096;", tls)
        self.assertIn("proxy_set_header X-Forwarded-For $remote_addr;", tls)
        self.assertNotIn("$proxy_add_x_forwarded_for", tls)
        self.assertEqual(config.count("access_log off;"), 2)
        self.assertEqual(config.count("error_log /dev/null crit;"), 2)
        self.assertEqual(config.count("client_max_body_size 16m;"), 2)
        self.assertNotRegex(config, r"(?i)\bReferrer-Policy\b")


class NginxComposeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        docker = shutil.which("docker")
        if not docker:
            raise unittest.SkipTest("Docker Compose CLI is not installed")
        temporary = tempfile.TemporaryDirectory(prefix="conspect-nginx-config-")
        cls.addClassCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        cls.environment = {
            "PATH": os.defpath,
            "HOME": str(directory),
            "DOCKER_CONFIG": str(directory / "docker"),
            "COMPOSE_DISABLE_ENV_FILE": "true",
        }
        version = subprocess.run(
            [docker, "compose", "version"], env=cls.environment,
            capture_output=True, timeout=10, check=False,
        )
        if version.returncode:
            raise unittest.SkipTest("Docker Compose plugin is not installed")
        env_file = directory / "synthetic.env"
        env_file.write_text(
            "APP_BASE_URL=https://notes.example.com\n"
            + "APP_SECRET=" + "ab" * 32 + "\n"
            "POSTGRES_DB=conspect\nPOSTGRES_USER=conspect\n"
            "POSTGRES_PASSWORD=test-only-db-password\n"
            "DATABASE_URL=postgres://conspect:test-only-db-password@db:5432/conspect?sslmode=disable\n"
            "OWNER_PASSWORD=test-only-owner-password\n",
            encoding="utf-8",
        )
        env_file.chmod(0o600)
        cls.command = [
            docker, "compose", "--project-directory", str(ROOT), "--project-name", "conspect",
            "--env-file", str(env_file), "-f", str(ROOT / "compose.yaml"),
        ]

    def config(self, *, local=False, all_profiles=False, **overrides):
        overlay = "compose.local.yaml" if local else "compose.nginx.yaml"
        command = self.command + ["-f", str(ROOT / "deploy" / overlay)]
        if all_profiles:
            command += ["--profile", "*"]
        result = subprocess.run(
            command + ["config", "--format", "json"], cwd=ROOT,
            env=dict(self.environment, **overrides), capture_output=True, text=True,
            timeout=20, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_default_services_and_ports_are_app_db_and_loopback_only(self):
        services = self.config(all_profiles=True)["services"]
        self.assertEqual(set(services), {"app", "db"})
        self.assertEqual(services["app"]["image"], "conspect:local")
        ports = services["app"]["ports"]
        self.assertEqual(len(ports), 1)
        self.assertEqual(ports[0]["host_ip"], "127.0.0.1")
        self.assertEqual(str(ports[0]["published"]), "8096")
        self.assertEqual(ports[0]["target"], 8080)
        self.assertFalse(services["db"].get("ports"))
        self.assertEqual(services["app"]["environment"]["TRUST_PROXY"], "true")

    def test_remote_mcp_defaults_to_production_only_and_can_be_disabled(self):
        production = self.config()["services"]["app"]["environment"]
        self.assertEqual(production["MCP_ENABLED"], "true")
        self.assertEqual(production["MCP_API_URL"], "http://127.0.0.1:8080")
        self.assertEqual(self.config(local=True)["services"]["app"]["environment"]["MCP_ENABLED"], "false")
        disabled = self.config(MCP_ENABLED="false")["services"]["app"]["environment"]
        self.assertEqual(disabled["MCP_ENABLED"], "false")

    def test_resource_limits_and_postgresql_settings(self):
        services = self.config()["services"]
        self.assertEqual(int(services["app"]["mem_limit"]), 256 * 1024 * 1024)
        self.assertEqual(int(services["db"]["mem_limit"]), 256 * 1024 * 1024)
        self.assertEqual(services["app"]["environment"]["GOMEMLIMIT"], "192MiB")
        self.assertEqual(services["app"]["environment"]["GOMAXPROCS"], "1")
        self.assertEqual(services["db"]["image"], "postgres:17-alpine")
        self.assertEqual(services["db"]["command"], [
            "postgres", "-c", "shared_buffers=64MB", "-c", "max_connections=30",
            "-c", "work_mem=2MB", "-c", "maintenance_work_mem=32MB",
        ])
        self.assertEqual(services["db"]["volumes"][0]["target"], "/var/lib/postgresql/data")

    def test_all_profiles_still_expose_only_app_and_db(self):
        for local in (False, True):
            with self.subTest(local=local):
                services = self.config(local=local, all_profiles=True)["services"]
                self.assertEqual(set(services), {"app", "db"})
                self.assertFalse(any(service.get("profiles") for service in services.values()))

    def test_local_ports_and_trust_are_loopback_development_only(self):
        config = self.config(local=True, all_profiles=True)
        services = config["services"]
        self.assertEqual(set(services), {"app", "db"})
        for service, port in (("app", 8080), ("db", 5432)):
            with self.subTest(service=service):
                ports = services[service]["ports"]
                self.assertEqual(len(ports), 1)
                self.assertEqual(ports[0]["host_ip"], "127.0.0.1")
                self.assertEqual(str(ports[0]["published"]), str(port))
                self.assertEqual(ports[0]["target"], port)
        environment = services["app"]["environment"]
        self.assertEqual(environment["APP_BASE_URL"], "http://localhost:8080")
        self.assertEqual(environment["TRUST_PROXY"], "false")
        self.assertNotIn("GOMEMLIMIT", environment)
        self.assertNotIn("GOMAXPROCS", environment)
        self.assertNotIn("mem_limit", services["app"])
        self.assertIsNone(services["db"].get("command"))

    def test_local_ignores_production_image_and_port_overrides(self):
        services = self.config(
            local=True, all_profiles=True, CONSPECT_IMAGE="conspect:production-only", CONSPECT_HTTP_PORT="18096",
        )["services"]
        self.assertEqual(services["app"]["image"], "conspect:local")
        self.assertEqual(services["app"]["build"]["context"], str(ROOT))
        self.assertEqual(str(services["app"]["ports"][0]["published"]), "8080")
        self.assertEqual(str(services["db"]["ports"][0]["published"]), "5432")

    def test_both_overlays_preserve_project_volumes_and_networks(self):
        for local in (False, True):
            with self.subTest(local=local):
                config = self.config(local=local, all_profiles=True)
                self.assertEqual(config["name"], "conspect")
                self.assertEqual(set(config["volumes"]), {"uploads", "db_data"})
                for name, volume in config["volumes"].items():
                    self.assertEqual(volume["name"], "conspect_" + name)
                self.assertEqual(set(config["networks"]), {"frontend", "backend"})
                for name, network in config["networks"].items():
                    self.assertEqual(network["name"], "conspect_" + name)
                self.assertTrue(config["networks"]["backend"]["internal"])
                self.assertEqual(config["services"]["app"]["volumes"][0]["source"], "uploads")
                self.assertEqual(config["services"]["db"]["volumes"][0]["source"], "db_data")

    def test_image_and_port_overrides_do_not_publish_database(self):
        services = self.config(all_profiles=True, CONSPECT_IMAGE="conspect:nginx-test", CONSPECT_HTTP_PORT="18096")["services"]
        self.assertEqual(services["app"]["image"], "conspect:nginx-test")
        self.assertEqual(services["app"]["ports"][0]["host_ip"], "127.0.0.1")
        self.assertEqual(str(services["app"]["ports"][0]["published"]), "18096")
        self.assertFalse(services["db"].get("ports"))


if __name__ == "__main__":
    unittest.main()
