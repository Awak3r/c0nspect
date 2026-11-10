"""Public HTTPS acceptance checks for remote MCP; never use owner credentials."""

import http.client
import json
from urllib.parse import urlsplit
from urllib.request import parse_http_list, parse_keqv_list

from operations import OperationError

MAX_RESPONSE_BYTES = 65536


def request(base_url, method, path):
    origin = urlsplit(base_url)
    connection = None
    try:
        connection = http.client.HTTPSConnection(origin.hostname, origin.port, timeout=10)
        headers = {"Accept": "application/json"}
        body = None
        if method == "POST":
            headers["Content-Type"] = "application/json"
            body = b"{}"
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        data = response.read(MAX_RESPONSE_BYTES + 1)
        if len(data) > MAX_RESPONSE_BYTES:
            raise OperationError("Remote MCP check response exceeds the size limit.")
        return response.status, response.headers, data
    except (OSError, http.client.HTTPException):
        # Never log response bodies, redirects or URL/config values from the host.
        raise OperationError("Remote MCP HTTPS check failed; inspect TLS, nginx and APP_BASE_URL.") from None
    finally:
        if connection is not None:
            connection.close()


def metadata(base_url, path):
    status, headers, body = request(base_url, "GET", path)
    if status != 200 or headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
        raise OperationError("Remote MCP discovery must return HTTP 200 JSON without redirects.")
    try:
        document = json.loads(body)
    except (ValueError, UnicodeError):
        raise OperationError("Remote MCP discovery returned invalid JSON.") from None
    if not isinstance(document, dict):
        raise OperationError("Remote MCP discovery must return a metadata object.")
    return document


def canonical_origin(base_url):
    try:
        origin = urlsplit(base_url)
        valid = (isinstance(base_url, str) and origin.scheme == "https" and origin.hostname
                 and origin.username is None and origin.password is None
                 and origin.path in {"", "/"} and not origin.query and not origin.fragment
                 and origin.port != 0 and not any(character.isspace() or ord(character) < 32 for character in base_url))
    except (ValueError, TypeError):
        valid = False
    if not valid:
        raise OperationError("Production remote MCP requires a canonical HTTPS APP_BASE_URL origin.")
    return base_url.rstrip("/")


def mcp_base_url(environment):
    flag = str(environment.get("MCP_ENABLED", "false"))
    if flag in {"0", "f", "F", "FALSE", "false", "False"}:
        return None
    if flag not in {"1", "t", "T", "TRUE", "true", "True"}:
        raise OperationError("MCP_ENABLED must be true or false.")
    return canonical_origin(environment.get("APP_BASE_URL"))


def check_mcp(base_url):
    base_url = canonical_origin(base_url)
    if request(base_url, "GET", "/healthz")[0] != 200:
        raise OperationError("Public application readiness check failed.")
    resource = metadata(base_url, "/.well-known/oauth-protected-resource/mcp")
    if (resource.get("resource") != base_url + "/mcp"
            or resource.get("authorization_servers") != [base_url]
            or resource.get("bearer_methods_supported") != ["header"]):
        raise OperationError("Remote MCP resource metadata does not match APP_BASE_URL.")
    server = metadata(base_url, "/.well-known/oauth-authorization-server")
    expected = {
        "issuer": base_url,
        "authorization_endpoint": base_url + "/oauth/authorize",
        "token_endpoint": base_url + "/oauth/token",
        "registration_endpoint": base_url + "/oauth/register",
        "revocation_endpoint": base_url + "/oauth/revoke",
        "code_challenge_methods_supported": ["S256"],
    }
    if any(server.get(key) != value for key, value in expected.items()):
        raise OperationError("Remote MCP OAuth issuer, endpoints or PKCE S256 metadata is invalid.")
    status, headers, _ = request(base_url, "POST", "/mcp")
    scheme, _, parameters = headers.get("WWW-Authenticate", "").partition(" ")
    try:
        items = parse_http_list(parameters)
        fields = parse_keqv_list(items)
    except (ValueError, IndexError):
        items, fields = [], {}
    if (status != 401 or scheme.lower() != "bearer" or len(fields) != len(items)
            or fields.get("resource_metadata") != base_url + "/.well-known/oauth-protected-resource/mcp"
            or fields.get("error") != "invalid_token"):
        raise OperationError("Unauthenticated MCP must return HTTP 401 with the canonical OAuth challenge.")
    print("Remote MCP verified: public HTTPS readiness, OAuth discovery, S256 and unauthenticated 401.", flush=True)
