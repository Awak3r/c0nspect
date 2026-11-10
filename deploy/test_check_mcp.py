"""Public MCP acceptance contracts: synthetic HTTPS only, no live host or credentials.

Safety regressions are not marked expectedFailure: failures must remain visible.
"""

from contextlib import redirect_stdout
from email.message import Message
import http.client
import io
import json
import ssl
import traceback
import unittest
from unittest.mock import Mock, call, patch

import check_mcp
from operations import OperationError


BASE_URL = "https://notes.example.com"
RESOURCE_PATH = "/.well-known/oauth-protected-resource/mcp"
SERVER_PATH = "/.well-known/oauth-authorization-server"
PRIVATE = "synthetic-private-diagnostics-never-log"


def json_response(document, status=200):
    return status, {"Content-Type": "application/json; charset=utf-8"}, json.dumps(document).encode()


class CheckMCPTests(unittest.TestCase):
    def setUp(self):
        self.requests = []
        self.connections = []
        self.output = io.StringIO()
        self.configure_origin(BASE_URL)
        for manager in (
            redirect_stdout(self.output),
            patch("check_mcp.http.client.HTTPConnection", side_effect=AssertionError("Unexpected plain HTTP")),
        ):
            manager.__enter__()
            self.addCleanup(manager.__exit__, None, None, None)
        manager = patch("check_mcp.http.client.HTTPSConnection", side_effect=self.connect)
        self.https = manager.start()
        self.addCleanup(manager.stop)

    def configure_origin(self, base_url):
        self.resource = {
            "resource": base_url + "/mcp", "authorization_servers": [base_url],
            "bearer_methods_supported": ["header"],
        }
        self.server = {
            "issuer": base_url,
            "authorization_endpoint": base_url + "/oauth/authorize",
            "token_endpoint": base_url + "/oauth/token",
            "registration_endpoint": base_url + "/oauth/register",
            "revocation_endpoint": base_url + "/oauth/revoke",
            "code_challenge_methods_supported": ["S256"],
        }
        self.challenge = f'Bearer resource_metadata="{base_url + RESOURCE_PATH}", error="invalid_token"'
        self.responses = {
            "/healthz": (200, {}, b""),
            RESOURCE_PATH: json_response(self.resource),
            SERVER_PATH: json_response(self.server),
            "/mcp": (401, {"WWW-Authenticate": self.challenge}, b'{"error":"invalid_token"}'),
        }

    def connect(self, host, port, timeout):
        connection = Mock(spec=["request", "getresponse", "close", "set_tunnel"])
        response = Mock(spec=["status", "headers", "read"])

        def send(method, path, **kwargs):
            self.requests.append((method, path, kwargs))
            status, values, data = self.responses[path]
            response.status = status
            response.headers = Message()
            for key, value in values.items():
                response.headers[key] = value
            response.read.side_effect = lambda limit: data[:limit]

        connection.request.side_effect = send
        connection.getresponse.return_value = response
        self.connections.append((connection, response))
        return connection

    def assert_rejected(self, base_url=BASE_URL):
        with self.assertRaises(OperationError) as caught:
            check_mcp.check_mcp(base_url)
        diagnostic = "".join(traceback.format_exception(caught.exception))
        self.assertNotIn(PRIVATE, diagnostic)
        self.assertNotIn(base_url, diagnostic)
        self.assertNotIn("Remote MCP verified", self.output.getvalue())
        for connection, _ in self.connections:
            connection.close.assert_called_once()
        return caught.exception

    def test_successful_https_checks_without_credentials_proxy_or_redirects(self):
        with patch.dict("os.environ", {
            "HTTPS_PROXY": "http://proxy.invalid:3128", "HTTP_PROXY": "http://proxy.invalid:3128",
            "ALL_PROXY": "http://proxy.invalid:3128", "NO_PROXY": "",
        }):
            check_mcp.check_mcp(BASE_URL)
        self.assertEqual(self.https.call_args_list, [call("notes.example.com", None, timeout=10)] * 4)
        self.assertEqual([(method, path) for method, path, _ in self.requests], [
            ("GET", "/healthz"), ("GET", RESOURCE_PATH), ("GET", SERVER_PATH), ("POST", "/mcp"),
        ])
        for method, _, kwargs in self.requests:
            expected_headers = {"Accept": "application/json"}
            if method == "POST":
                expected_headers["Content-Type"] = "application/json"
            self.assertEqual(kwargs, {"body": b"{}" if method == "POST" else None, "headers": expected_headers})
        for connection, response in self.connections:
            response.read.assert_called_once_with(check_mcp.MAX_RESPONSE_BYTES + 1)
            connection.close.assert_called_once()
            connection.set_tunnel.assert_not_called()
        self.assertIn("Remote MCP verified", self.output.getvalue())

    def test_explicit_https_port_and_ipv6_origin(self):
        for base_url, host in (("https://notes.example.com:8443", "notes.example.com"), ("https://[::1]:8443", "::1")):
            with self.subTest(origin=base_url):
                self.configure_origin(base_url)
                self.https.reset_mock()
                check_mcp.check_mcp(base_url)
                self.assertEqual(self.https.call_args_list, [call(host, 8443, timeout=10)] * 4)

    def test_trailing_slash_is_normalized_like_the_application(self):
        check_mcp.check_mcp(BASE_URL + "/")
        self.assertIn("Remote MCP verified", self.output.getvalue())

    def test_mcp_config_preserves_explicit_disable_and_validates_flags(self):
        for flag in (False, "false", "FALSE", "False", "0", "f", "F"):
            with self.subTest(flag=flag):
                self.assertIsNone(check_mcp.mcp_base_url({"MCP_ENABLED": flag}))
        self.assertIsNone(check_mcp.mcp_base_url({}))
        for flag in (True, "true", "TRUE", "True", "1", "t", "T"):
            with self.subTest(flag=flag):
                self.assertEqual(check_mcp.mcp_base_url({"MCP_ENABLED": flag, "APP_BASE_URL": BASE_URL + "/"}), BASE_URL)
        for flag in ("", "yes", "TrUe", " false ", None):
            with self.subTest(flag=flag), self.assertRaises(OperationError):
                check_mcp.mcp_base_url({"MCP_ENABLED": flag, "APP_BASE_URL": BASE_URL})
        with self.assertRaises(OperationError):
            check_mcp.mcp_base_url({"MCP_ENABLED": "true"})
        self.https.assert_not_called()

    def test_invalid_origins_are_rejected_before_http(self):
        for base_url in (
            "", None, "notes.example.com", "//notes.example.com", "http://notes.example.com",
            "https://", "https://user:password@notes.example.com", "https://user@notes.example.com",
            BASE_URL + "//", BASE_URL + "/path", BASE_URL + "?token=" + PRIVATE,
            BASE_URL + "#" + PRIVATE, BASE_URL + ":0", BASE_URL + ":65536",
            BASE_URL + ":not-a-port", "https://[broken",
        ):
            with self.subTest(origin=base_url):
                with self.assertRaisesRegex(OperationError, "canonical HTTPS") as caught:
                    check_mcp.check_mcp(base_url)
                self.assertNotIn(PRIVATE, str(caught.exception))
                self.https.assert_not_called()

    def test_health_failure_stops_before_discovery(self):
        for status in (204, 301, 302, 401, 503):
            with self.subTest(status=status):
                self.requests.clear()
                self.responses["/healthz"] = (status, {"Location": "https://redirect.invalid/" + PRIVATE}, PRIVATE.encode())
                self.assert_rejected()
                self.assertEqual([(method, path) for method, path, _ in self.requests], [("GET", "/healthz")])

    def test_discovery_requires_http_200_json_without_redirects(self):
        for path in (RESOURCE_PATH, SERVER_PATH):
            original = self.responses[path]
            for status, content_type in (
                (204, "application/json"), (302, "application/json"), (307, "application/json"),
                (401, "application/json"), (503, "application/json"),
                (200, "text/html"), (200, "application/jsonp"), (200, ""),
            ):
                with self.subTest(path=path, status=status, content_type=content_type):
                    self.requests.clear()
                    self.responses[path] = (status, {"Content-Type": content_type, "Location": "https://redirect.invalid/" + PRIVATE}, original[2])
                    self.assert_rejected()
                    self.assertEqual(self.requests[-1][1], path)
                    self.assertFalse(any("redirect.invalid" in requested for _, requested, _ in self.requests))
            self.responses[path] = original

    def test_metadata_body_must_be_one_json_object(self):
        for path in (RESOURCE_PATH, SERVER_PATH):
            original = self.responses[path]
            for body in (b"", PRIVATE.encode(), b"{", b"\xff", b"{} {}", b"[]", b"null", b"true", b"42", b'"text"'):
                with self.subTest(path=path, body=body):
                    self.responses[path] = (200, {"Content-Type": "application/json"}, body)
                    self.assert_rejected()
            self.responses[path] = original

    def test_json_content_type_is_case_insensitive_with_parameters(self):
        for path in (RESOURCE_PATH, SERVER_PATH):
            status, _, data = self.responses[path]
            self.responses[path] = (status, {"content-type": " Application/JSON ; charset=utf-8"}, data)
        check_mcp.check_mcp(BASE_URL)

    def test_resource_binding_and_bearer_method_are_required(self):
        for key, values in {
            "resource": (None, "https://wrong.invalid/mcp", BASE_URL + "/other"),
            "authorization_servers": (None, BASE_URL, [], ["https://wrong.invalid"], [BASE_URL, "https://other.invalid"]),
            "bearer_methods_supported": (None, [], ["query"], ["header", "query"]),
        }.items():
            for value in values:
                with self.subTest(field=key, value=value):
                    document = dict(self.resource)
                    if value is None:
                        del document[key]
                    else:
                        document[key] = value
                    self.responses[RESOURCE_PATH] = json_response(document)
                    self.assert_rejected()

    def test_issuer_and_every_oauth_endpoint_are_required_and_origin_bound(self):
        for key in ("issuer", "authorization_endpoint", "token_endpoint", "registration_endpoint", "revocation_endpoint"):
            for value in (None, "https://wrong.invalid/" + PRIVATE, self.server[key] + "/wrong"):
                with self.subTest(field=key, value=value):
                    document = dict(self.server)
                    if value is None:
                        del document[key]
                    else:
                        document[key] = value
                    self.responses[SERVER_PATH] = json_response(document)
                    self.assert_rejected()

    def test_pkce_requires_only_s256(self):
        for value in (None, [], "S256", ["plain"], ["S256", "plain"], ["s256"]):
            with self.subTest(value=value):
                document = dict(self.server)
                if value is None:
                    del document["code_challenge_methods_supported"]
                else:
                    document["code_challenge_methods_supported"] = value
                self.responses[SERVER_PATH] = json_response(document)
                self.assert_rejected()

    def test_mcp_requires_401_and_canonical_bearer_challenge(self):
        for status, challenge in (
            (200, self.challenge), (302, self.challenge), (403, self.challenge), (503, self.challenge),
            (401, ""), (401, "Bearer malformed"), (401, self.challenge.replace("Bearer", "Basic")),
            (401, self.challenge.replace(BASE_URL, "https://wrong.invalid")),
            (401, self.challenge.replace(RESOURCE_PATH, "/.well-known/other")),
            (401, self.challenge.replace("invalid_token", "invalid_request")),
            (401, f'Bearer resource_metadata="{BASE_URL + RESOURCE_PATH}"'),
            (401, 'Bearer error="invalid_token"'),
            (401, self.challenge + ', error="invalid_token"'),
            (401, self.challenge + f', resource_metadata="{BASE_URL + RESOURCE_PATH}"'),
        ):
            with self.subTest(status=status, challenge=challenge):
                self.responses["/mcp"] = (status, {"WWW-Authenticate": challenge}, PRIVATE.encode())
                self.assert_rejected()

    def test_challenge_allows_reordering_scheme_case_and_extra_parameters(self):
        self.responses["/mcp"] = (401, {"www-authenticate": (
            f'bEaReR error="invalid_token", realm="test, realm", resource_metadata="{BASE_URL + RESOURCE_PATH}"'
        )}, b"not used as metadata")
        check_mcp.check_mcp(BASE_URL)

    def test_oversized_body_is_rejected_on_every_endpoint(self):
        for path in ("/healthz", RESOURCE_PATH, SERVER_PATH, "/mcp"):
            with self.subTest(path=path):
                original = self.responses[path]
                self.responses[path] = (original[0], original[1], PRIVATE.encode() + b"x" * check_mcp.MAX_RESPONSE_BYTES)
                error = self.assert_rejected()
                self.assertIn("size limit", str(error))
                self.connections[-1][1].read.assert_called_once_with(check_mcp.MAX_RESPONSE_BYTES + 1)
                self.responses[path] = original

    def test_request_accepts_bodies_at_the_limit_and_closes_connections(self):
        for size in (check_mcp.MAX_RESPONSE_BYTES - 1, check_mcp.MAX_RESPONSE_BYTES):
            with self.subTest(size=size):
                data = b"x" * size
                self.responses["/healthz"] = (200, {}, data)
                self.assertEqual(check_mcp.request(BASE_URL, "GET", "/healthz")[2], data)
                connection, response = self.connections[-1]
                response.read.assert_called_once_with(check_mcp.MAX_RESPONSE_BYTES + 1)
                connection.close.assert_called_once()

    def test_tls_http_and_socket_failures_are_safe_and_close_connections(self):
        for phase in ("request", "getresponse", "read"):
            for error in (
                ssl.SSLCertVerificationError(1, PRIVATE + " " + BASE_URL),
                ssl.SSLError(PRIVATE), TimeoutError(PRIVATE), OSError(PRIVATE),
                http.client.BadStatusLine(PRIVATE), http.client.RemoteDisconnected(PRIVATE),
                http.client.IncompleteRead(PRIVATE.encode(), 100),
            ):
                with self.subTest(phase=phase, error=type(error).__name__):
                    connection = Mock()
                    response = connection.getresponse.return_value
                    getattr(response if phase == "read" else connection, phase).side_effect = error
                    with patch("check_mcp.http.client.HTTPSConnection", return_value=connection):
                        with self.assertRaisesRegex(OperationError, "HTTPS check failed") as caught:
                            check_mcp.check_mcp(BASE_URL)
                    diagnostic = "".join(traceback.format_exception(caught.exception))
                    self.assertNotIn(PRIVATE, diagnostic)
                    self.assertNotIn(BASE_URL, diagnostic)
                    self.assertTrue(caught.exception.__suppress_context__)
                    connection.close.assert_called_once()
                    self.assertNotIn("Remote MCP verified", self.output.getvalue())

    def test_invalid_hostname_constructor_error_is_sanitized(self):
        base_url = "https://bad host.example"
        # HTTPSConnection rejects this host before making any network request.
        with patch("check_mcp.http.client.HTTPSConnection", side_effect=http.client.InvalidURL(base_url)):
            with self.assertRaisesRegex(OperationError, "canonical HTTPS|HTTPS check failed") as caught:
                check_mcp.check_mcp(base_url)
        self.assertNotIn(base_url, "".join(traceback.format_exception(caught.exception)))

    def test_tls_connection_setup_error_is_sanitized(self):
        with patch("check_mcp.http.client.HTTPSConnection", side_effect=ssl.SSLError(PRIVATE + " " + BASE_URL)):
            with self.assertRaisesRegex(OperationError, "HTTPS check failed") as caught:
                check_mcp.check_mcp(BASE_URL)
        diagnostic = "".join(traceback.format_exception(caught.exception))
        self.assertNotIn(PRIVATE, diagnostic)
        self.assertNotIn(BASE_URL, diagnostic)


if __name__ == "__main__":
    unittest.main()
