package web

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestOAuthInputSecurity(t *testing.T) {
	for _, uri := range []string{"https://chatgpt.com/connector_platform_oauth_redirect", "https://chatgpt.com/connector/oauth/abc-123_def"} {
		if !validOAuthRedirect(uri) {
			t.Errorf("valid callback rejected: %s", uri)
		}
	}
	for _, uri := range []string{"http://chatgpt.com/connector_platform_oauth_redirect", "https://evil.test/callback", "https://chatgpt.com.evil.test/connector_platform_oauth_redirect", "https://user@chatgpt.com/connector_platform_oauth_redirect", "https://chatgpt.com:443/connector_platform_oauth_redirect", "https://chatgpt.com/connector_platform_oauth_redirect?next=evil", "https://chatgpt.com/connector/oauth/../evil", "https://chatgpt.com/connector/oauth/%61bc", "https://chatgpt.com/connector_platform_oauth_redirect#fragment"} {
		if validOAuthRedirect(uri) {
			t.Errorf("unsafe callback accepted: %s", uri)
		}
	}
	for _, next := range []string{"https://evil.test", "//evil.test", "/projects", "/oauth/authorize?x=1#fragment"} {
		if oauthLoginNext(next) != "" {
			t.Error("unsafe login destination accepted")
		}
	}
	a := &App{cfg: Config{Secret: bytes.Repeat([]byte{1}, 32)}}
	request := oauthAuthorization{Session: "session-one", Expires: time.Now().Add(time.Minute).Unix(), Resource: "https://localhost/mcp"}
	signed := a.signOAuthConsent(request)
	if _, ok := a.readOAuthConsent(signed, request.Session); !ok {
		t.Fatal("valid consent rejected")
	}
	for _, input := range []struct{ token, session string }{{signed + "x", request.Session}, {signed, "another-session"}, {strings.Repeat("x", 17000), request.Session}} {
		if _, ok := a.readOAuthConsent(input.token, input.session); ok {
			t.Error("tampered or wrong-session consent accepted")
		}
	}
	request.Expires = time.Now().Add(-time.Minute).Unix()
	if _, ok := a.readOAuthConsent(a.signOAuthConsent(request), request.Session); ok {
		t.Error("expired consent accepted")
	}
}

func TestRemoteMCPOAuthFlow(t *testing.T) {
	for _, method := range []string{"none", "client_secret_post", "client_secret_basic"} {
		t.Run(method, func(t *testing.T) {
			base, db := newTestApp(t)
			if err := db.InitOAuth(t.Context()); err != nil {
				t.Fatal(err)
			}
			if err := db.InitOAuth(t.Context()); err != nil {
				t.Fatal("OAuth initialization not idempotent:", err)
			}
			cfg := base.cfg
			cfg.MCPEnabled = true
			app, err := New(db, cfg)
			if err != nil {
				t.Fatal(err)
			}
			api := httptest.NewServer(app.Handler())
			t.Cleanup(api.Close)
			app.cfg.MCPAPIURL = api.URL
			owner := browserTestOwner(t, app, db)
			public := &browserTestClient{app: app, db: db}
			project := owner.createProject(t, "Selected project", "")
			other := owner.createProject(t, "PRIVATE other project", "")
			note := owner.importNotes(t, project.ID, browserTestMarkdown("selected.md", "# Selected\n\nAllowed reference."))[0]
			private := owner.importNotes(t, other.ID, browserTestMarkdown("private.md", "# SECRET_UNGRANTED_CONTENT"))[0]

			anonymous := public.request(t, "POST", "/mcp", strings.NewReader(`{}`), map[string]string{"Content-Type": "application/json"})
			browserTestStatus(t, anonymous, 401)
			if !strings.Contains(anonymous.Header().Get("WWW-Authenticate"), "/.well-known/oauth-protected-resource/mcp") {
				t.Fatal("missing OAuth discovery challenge")
			}
			for _, path := range []string{"/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-authorization-server"} {
				browserTestStatus(t, public.request(t, "GET", path, nil, nil), 200)
			}
			var registration struct {
				ID     string `json:"client_id"`
				Secret string `json:"client_secret"`
			}
			body, _ := json.Marshal(map[string]any{"client_name": "ChatGPT test", "redirect_uris": []string{"https://chatgpt.com/connector_platform_oauth_redirect"}, "token_endpoint_auth_method": method, "grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"}})
			registered := public.request(t, "POST", "/oauth/register", bytes.NewReader(body), map[string]string{"Content-Type": "application/json"})
			browserTestStatus(t, registered, 201)
			if json.Unmarshal(registered.Body.Bytes(), &registration) != nil || registration.ID == "" {
				t.Fatal("invalid registration response")
			}
			verifier := strings.Repeat("v", 64)
			sum := sha256.Sum256([]byte(verifier))
			query := url.Values{"client_id": {registration.ID}, "redirect_uri": {"https://chatgpt.com/connector_platform_oauth_redirect"}, "response_type": {"code"}, "state": {"state-with-special-&-value"}, "scope": {"notes:read"}, "resource": {app.oauthResource()}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}}
			authorizePath := "/oauth/authorize?" + query.Encode()
			login := public.request(t, "GET", authorizePath, nil, nil)
			browserTestStatus(t, login, 303)
			loginURL, _ := url.Parse(login.Header().Get("Location"))
			if loginURL.Path != "/login" || loginURL.Query().Get("next") != authorizePath {
				t.Fatal("OAuth authorization request lost during login redirect")
			}
			consent := owner.request(t, "GET", authorizePath, nil, nil)
			browserTestStatus(t, consent, 200)
			if !strings.Contains(consent.Header().Get("Content-Security-Policy"), "form-action 'self' https://chatgpt.com/connector_platform_oauth_redirect") {
				t.Fatal("consent CSP would block the callback")
			}
			form := browserTestForm(t, browserTestDocument(t, consent), "/oauth/authorize")
			request := browserTestInput(t, form, "request")
			fields := url.Values{"request": {request}, "decision": {"allow"}, "scopes": {"notes:read"}, "projects": {project.ID}}
			tampered := owner.fields(fields)
			tampered.Set("scopes", "notes:write")
			browserTestStatus(t, owner.form(t, "/oauth/authorize", tampered), 400)
			badCSRF := owner.fields(fields)
			badCSRF.Set("csrf", "wrong")
			browserTestStatus(t, owner.form(t, "/oauth/authorize", badCSRF), 403)
			approved := owner.form(t, "/oauth/authorize", fields)
			browserTestStatus(t, approved, 303)
			callback, err := url.Parse(approved.Header().Get("Location"))
			if err != nil || callback.Query().Get("iss") != app.cfg.BaseURL || callback.Query().Get("state") != query.Get("state") || callback.Query().Get("code") == "" {
				t.Fatal("invalid OAuth callback binding")
			}
			tokenRequest := func(values url.Values) *httptest.ResponseRecorder {
				t.Helper()
				values.Set("client_id", registration.ID)
				headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
				if method == "client_secret_post" {
					values.Set("client_secret", registration.Secret)
				} else if method == "client_secret_basic" {
					headers["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(registration.ID+":"+registration.Secret))
				}
				return public.request(t, "POST", "/oauth/token", strings.NewReader(values.Encode()), headers)
			}
			exchange := url.Values{"grant_type": {"authorization_code"}, "code": {callback.Query().Get("code")}, "redirect_uri": {query.Get("redirect_uri")}, "code_verifier": {strings.Repeat("x", 64)}, "resource": {app.oauthResource()}}
			browserTestStatus(t, tokenRequest(exchange), 400)
			exchange.Set("code_verifier", verifier)
			issued := tokenRequest(exchange)
			browserTestStatus(t, issued, 200)
			var tokens struct {
				Access  string `json:"access_token"`
				Refresh string `json:"refresh_token"`
				Scope   string `json:"scope"`
			}
			if json.Unmarshal(issued.Body.Bytes(), &tokens) != nil || tokens.Access == "" || tokens.Refresh == "" || tokens.Scope != "notes:read" {
				t.Fatal("invalid token response")
			}
			browserTestStatus(t, tokenRequest(exchange), 400)
			rpc := func(access, method string, params any) *httptest.ResponseRecorder {
				t.Helper()
				body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
				return public.request(t, "POST", "/mcp", bytes.NewReader(body), map[string]string{"Authorization": "Bearer " + access, "Content-Type": "application/json", "Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-11-25"})
			}
			initialized := rpc(tokens.Access, "initialize", map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "test", "version": "1"}})
			browserTestStatus(t, initialized, 200)
			tools := rpc(tokens.Access, "tools/list", map[string]any{})
			browserTestStatus(t, tools, 200)
			for _, forbidden := range []string{"conspect_upload_image", "conspect_upload_markdown", "conspect_update_note", "conspect_create_note", "source_path"} {
				if strings.Contains(tools.Body.String(), `"`+forbidden+`"`) {
					t.Errorf("read-only remote server exposes %s", forbidden)
				}
			}
			projects := rpc(tokens.Access, "tools/call", map[string]any{"name": "conspect_list_projects", "arguments": map[string]any{}})
			browserTestStatus(t, projects, 200)
			if !strings.Contains(projects.Body.String(), project.ID) || strings.Contains(projects.Body.String(), other.ID) {
				t.Fatal("remote MCP project isolation failed")
			}
			read := rpc(tokens.Access, "tools/call", map[string]any{"name": "conspect_get_note", "arguments": map[string]any{"note_id": note.ID}})
			browserTestStatus(t, read, 200)
			if !strings.Contains(read.Body.String(), "Allowed reference") || !strings.Contains(read.Body.String(), "http://localhost/notes/") || strings.Contains(read.Body.String(), api.URL) {
				t.Fatal("note content or public citation URL incorrect")
			}
			denied := rpc(tokens.Access, "tools/call", map[string]any{"name": "conspect_get_note", "arguments": map[string]any{"note_id": private.ID}})
			browserTestStatus(t, denied, 200)
			if strings.Contains(denied.Body.String(), "SECRET_UNGRANTED_CONTENT") || !strings.Contains(denied.Body.String(), `"isError":true`) {
				t.Fatal("remote MCP exposed an ungranted note")
			}
			refresh := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tokens.Refresh}, "resource": {app.oauthResource()}, "scope": {"notes:read"}}
			rotated := tokenRequest(refresh)
			browserTestStatus(t, rotated, 200)
			var replacement struct {
				Access string `json:"access_token"`
			}
			_ = json.Unmarshal(rotated.Body.Bytes(), &replacement)
			browserTestStatus(t, rpc(tokens.Access, "tools/list", map[string]any{}), 401)
			browserTestStatus(t, rpc(replacement.Access, "tools/list", map[string]any{}), 200)
			// Reuse of an already consumed refresh token revokes its successor too.
			browserTestStatus(t, tokenRequest(refresh), 400)
			browserTestStatus(t, rpc(replacement.Access, "tools/list", map[string]any{}), 401)
			keys, err := db.APIKeys(t.Context())
			if err != nil || len(keys) != 1 || keys[0].RevokedAt == nil || !slices.Equal(keys[0].ProjectIDs, []string{project.ID}) {
				t.Fatal("OAuth grant revocation or scope snapshot incorrect")
			}
		})
	}
}
