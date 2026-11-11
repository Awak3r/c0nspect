package web

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"conspect/internal/store"

	"golang.org/x/net/html"
)

func keyAccessHasAttr(node *html.Node, name string) bool {
	for _, attr := range node.Attr {
		if attr.Key == name {
			return true
		}
	}
	return false
}

func keyAccessCheckbox(t *testing.T, form *html.Node, name, value string, checked bool) {
	t.Helper()
	count := 0
	for _, input := range browserTestElements(form, "input") {
		if browserTestAttr(input, "name") != name || browserTestAttr(input, "value") != value {
			continue
		}
		count++
		if browserTestAttr(input, "type") != "checkbox" || keyAccessHasAttr(input, "checked") != checked {
			t.Errorf("checkbox %s=%s: checked = %v, want %v", name, value, keyAccessHasAttr(input, "checked"), checked)
		}
	}
	if count != 1 {
		t.Errorf("checkbox %s=%s: found %d, want exactly one", name, value, count)
	}
}

func TestKeyResourceAccessStrictParsing(t *testing.T) {
	for _, tc := range []struct {
		name, body, query string
		all, invalid      bool
	}{
		{name: "absent", body: "projects=p"},
		{name: "explicit opt in", body: "all_projects=1", all: true},
		{name: "all and explicit", body: "all_projects=1&projects=p&notes=n", all: true},
		{name: "no resources", invalid: true},
		{name: "query cannot opt in", query: "all_projects=1", invalid: true},
		{name: "query does not broaden", body: "projects=p", query: "all_projects=1"},
		{name: "empty", body: "projects=p&all_projects=", invalid: true},
		{name: "zero", body: "projects=p&all_projects=0", invalid: true},
		{name: "true", body: "projects=p&all_projects=true", invalid: true},
		{name: "on", body: "projects=p&all_projects=on", invalid: true},
		{name: "whitespace", body: "projects=p&all_projects=+1", invalid: true},
		{name: "duplicate true", body: "all_projects=1&all_projects=1", invalid: true},
		{name: "conflicting values", body: "all_projects=0&all_projects=1", invalid: true},
		{name: "blank project", body: "all_projects=1&projects=", invalid: true},
		{name: "blank note", body: "all_projects=1&notes=+", invalid: true},
		{name: "256 explicit IDs", body: strings.Repeat("projects=p&", 256)},
		{name: "257 explicit IDs", body: "all_projects=1&" + strings.Repeat("projects=p&", 257), invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/?"+tc.query, strings.NewReader(tc.body))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			all, _, _, err := keyResourceAccess(r)
			if tc.invalid {
				var httpErr *HTTPError
				if !errors.As(err, &httpErr) || httpErr.Status != 422 {
					t.Fatalf("error = %v, want HTTP 422", err)
				}
				return
			}
			if err != nil || all != tc.all {
				t.Fatalf("allProjects = %v, err = %v; want %v", all, err, tc.all)
			}
		})
	}
}

func TestKeyAccessTemplates(t *testing.T) {
	app, err := New(nil, Config{BaseURL: "http://localhost", Secret: make([]byte, 32), DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	past, future := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	data := pageData{
		Projects: []store.Project{{ID: "p", Name: "Selected project"}, {ID: "other", Name: "Other"}},
		Notes:    []store.Note{{ID: "n", Title: "Selected note"}, {ID: "other-note", Title: "Other note"}},
		Keys: []store.APIKey{
			{ID: "selected", Name: "Selected", ProjectIDs: []string{"p"}, NoteIDs: []string{"n"}, Scopes: []string{"notes:read"}, TokenHash: "private-key-hash", ExpiresAt: &future},
			{ID: "all", Name: "All", AllProjects: true},
			{ID: "expired", Name: "Expired", ExpiresAt: &past},
			{ID: "revoked", Name: "Revoked", RevokedAt: &past},
		},
	}
	response := httptest.NewRecorder()
	app.page(response, httptest.NewRequest("GET", "/settings/api-keys", nil), 200, "keys", data)
	browserTestStatus(t, response, 200)
	doc := browserTestDocument(t, response)
	keyAccessCheckbox(t, browserTestForm(t, doc, "/settings/api-keys"), "all_projects", "1", false)
	selected := browserTestForm(t, doc, "/settings/api-keys/selected/access")
	keyAccessCheckbox(t, selected, "all_projects", "1", false)
	keyAccessCheckbox(t, selected, "projects", "p", true)
	keyAccessCheckbox(t, selected, "projects", "other", false)
	keyAccessCheckbox(t, selected, "notes", "n", true)
	keyAccessCheckbox(t, selected, "notes", "other-note", false)
	keyAccessCheckbox(t, browserTestForm(t, doc, "/settings/api-keys/all/access"), "all_projects", "1", true)
	for _, form := range browserTestElements(doc, "form") {
		action := browserTestAttr(form, "action")
		if action == "/settings/api-keys/expired/access" || action == "/settings/api-keys/revoked/access" {
			t.Error("inactive key has an access edit form")
		}
		if !strings.HasSuffix(action, "/access") {
			continue
		}
		insideDisclosure := false
		for parent := form.Parent; parent != nil; parent = parent.Parent {
			insideDisclosure = insideDisclosure || parent.Data == "details"
		}
		if !insideDisclosure {
			t.Error("access form is outside a disclosure")
		}
		for _, input := range browserTestElements(form, "input") {
			if name := browserTestAttr(input, "name"); name != "csrf" && name != "all_projects" && name != "projects" && name != "notes" {
				t.Errorf("resource edit form contains unexpected field %q", name)
			}
		}
	}
	apiTestNoSecrets(t, response, data.Keys[0].TokenHash)
}

func TestBrowserKeyAccessUpdateAndNarrow(t *testing.T) {
	app, db := newTestApp(t)
	owner := browserTestOwner(t, app, db)
	project := apiTestProject(t, db, "Original project")
	note := apiTestNote(t, db, project.ID, "Original note")
	key, token := apiTestKey(t, db, store.APIKey{Scopes: []string{"notes:read"}, ProjectIDs: []string{project.ID}, NoteIDs: []string{note.ID}})
	path := "/settings/api-keys/" + key.ID + "/access"
	page := owner.request(t, "GET", "/settings/api-keys", nil, nil)
	browserTestStatus(t, page, 200)
	form := browserTestForm(t, browserTestDocument(t, page), path)
	if browserTestInput(t, form, "csrf") != owner.csrf {
		t.Fatal("access form is not bound to owner CSRF token")
	}
	keyAccessCheckbox(t, form, "projects", project.ID, true)
	keyAccessCheckbox(t, form, "notes", note.ID, true)
	apiTestNoSecrets(t, page, token, key.TokenHash)

	updated := owner.form(t, path, url.Values{"all_projects": {"1"}, "scopes": {"notes:write"}})
	browserTestRedirect(t, updated, "/settings/api-keys")
	apiTestNoSecrets(t, updated, token, key.TokenHash)
	stored, err := db.APIKeyByHash(t.Context(), tokenHash(token))
	if err != nil || stored.ID != key.ID || stored.TokenHash != key.TokenHash || !stored.AllProjects || !slices.Equal(stored.Scopes, key.Scopes) || !stored.CreatedAt.Equal(key.CreatedAt) {
		t.Fatalf("resource update changed key identity/scopes or lost all-projects: %+v, %v", stored, err)
	}
	future := apiTestProject(t, db, "Future project")
	futureNote := apiTestNote(t, db, future.ID, "Future note")
	sibling := apiTestNote(t, db, future.ID, "Sibling note")
	projects := apiTestRequest(app, "GET", "/api/v1/projects", token, nil, nil)
	apiTestStatus(t, projects, 200)
	if !strings.Contains(projects.Body.String(), future.ID) {
		t.Error("old bearer token cannot see a future project after all-projects opt-in")
	}
	apiTestStatus(t, apiTestRequest(app, "GET", "/api/v1/notes/"+futureNote.ID, token, nil, nil), 200)
	apiTestStatus(t, apiTestRequest(app, "POST", "/api/v1/projects/"+future.ID+"/notes", token, strings.NewReader(`{"title":"No write grant","markdown":"private"}`), nil), 403)

	browserTestRedirect(t, owner.form(t, path, url.Values{"notes": {futureNote.ID}}), "/settings/api-keys")
	stored, err = db.APIKeyByHash(t.Context(), tokenHash(token))
	if err != nil || stored.AllProjects || len(stored.ProjectIDs) != 0 || !slices.Equal(stored.NoteIDs, []string{futureNote.ID}) || !slices.Equal(stored.Scopes, key.Scopes) {
		t.Fatalf("key was not narrowed to the selected note: %+v, %v", stored, err)
	}
	apiTestStatus(t, apiTestRequest(app, "GET", "/api/v1/notes/"+futureNote.ID, token, nil, nil), 200)
	apiTestStatus(t, apiTestRequest(app, "GET", "/api/v1/notes/"+sibling.ID, token, nil, nil), 404)
	apiTestStatus(t, apiTestRequest(app, "GET", "/api/v1/notes/"+note.ID, token, nil, nil), 404)
	page = owner.request(t, "GET", "/settings/api-keys", nil, nil)
	browserTestStatus(t, page, 200)
	keyAccessCheckbox(t, browserTestForm(t, browserTestDocument(t, page), path), "all_projects", "1", false)
	apiTestNoSecrets(t, page, token, key.TokenHash)
}

func TestBrowserKeyAccessRejectsInvalidChanges(t *testing.T) {
	app, db := newTestApp(t)
	owner := browserTestOwner(t, app, db)
	public := &browserTestClient{app: app, db: db}
	project := apiTestProject(t, db, "Granted project")
	key, token := apiTestKey(t, db, store.APIKey{Scopes: []string{"notes:read"}, ProjectIDs: []string{project.ID}})
	path := "/settings/api-keys/" + key.ID + "/access"
	for _, tc := range []struct {
		name   string
		fields url.Values
		status int
	}{
		{"empty", url.Values{}, 422},
		{"false value", url.Values{"all_projects": {"0"}, "projects": {project.ID}}, 422},
		{"duplicate", url.Values{"all_projects": {"1", "1"}}, 422},
		{"unknown project", url.Values{"projects": {"missing-project"}}, 404},
		{"unknown note even with all", url.Values{"all_projects": {"1"}, "notes": {"missing-note"}}, 404},
		{"blank project", url.Values{"all_projects": {"1"}, "projects": {""}}, 422},
		{"too many IDs", url.Values{"all_projects": {"1"}, "projects": slices.Repeat([]string{project.ID}, 257)}, 422},
		{"bad CSRF", url.Values{"all_projects": {"1"}, "csrf": {"wrong"}}, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := owner.form(t, path, tc.fields)
			browserTestStatus(t, response, tc.status)
			apiTestNoSecrets(t, response, token, key.TokenHash)
		})
	}
	browserTestStatus(t, owner.form(t, path+"?all_projects=1", url.Values{}), 422)
	browserTestStatus(t, public.form(t, path, url.Values{"all_projects": {"1"}}), 401)
	browserTestStatus(t, owner.request(t, "POST", path, strings.NewReader(owner.fields(url.Values{"all_projects": {"1"}}).Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded", "Origin": "https://evil.test"}), 403)
	browserTestStatus(t, owner.form(t, "/settings/api-keys/missing-key/access", url.Values{"all_projects": {"1"}}), 404)
	stored, err := db.APIKeyByHash(t.Context(), tokenHash(token))
	if err != nil || stored.AllProjects || !slices.Equal(stored.ProjectIDs, key.ProjectIDs) || !slices.Equal(stored.Scopes, key.Scopes) {
		t.Fatalf("rejected requests changed grants: %+v, %v", stored, err)
	}
	past := time.Now().Add(-time.Hour)
	expired, _ := apiTestKey(t, db, store.APIKey{Scopes: key.Scopes, ProjectIDs: key.ProjectIDs, ExpiresAt: &past})
	browserTestStatus(t, owner.form(t, "/settings/api-keys/"+expired.ID+"/access", url.Values{"all_projects": {"1"}}), 403)
	browserTestRedirect(t, owner.form(t, "/settings/api-keys/"+key.ID+"/revoke", nil), "/settings/api-keys")
	browserTestStatus(t, owner.form(t, path, url.Values{"all_projects": {"1"}}), 403)
	keys, err := db.APIKeys(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, stored := range keys {
		if stored.AllProjects {
			t.Error("inactive key was broadened")
		}
	}
	page := owner.request(t, "GET", "/settings/api-keys?show_revoked=1", nil, nil)
	browserTestStatus(t, page, 200)
	for _, form := range browserTestElements(browserTestDocument(t, page), "form") {
		if strings.HasSuffix(browserTestAttr(form, "action"), "/access") {
			t.Error("expired/revoked key has an edit form")
		}
	}
	apiTestNoSecrets(t, page, token, key.TokenHash)
}

func TestBrowserKeyCreationAllProjectsOptIn(t *testing.T) {
	app, db := newTestApp(t)
	owner := browserTestOwner(t, app, db)
	fields := url.Values{"name": {"All-projects key"}, "scopes": {"notes:read"}}
	browserTestStatus(t, owner.form(t, "/settings/api-keys", fields), 422)
	browserTestStatus(t, owner.form(t, "/settings/api-keys?all_projects=1", fields), 422)
	for _, values := range [][]string{{""}, {"0"}, {"true"}, {"1", "1"}, {"0", "1"}} {
		invalid := owner.fields(fields)
		invalid["all_projects"] = values
		browserTestStatus(t, owner.form(t, "/settings/api-keys", invalid), 422)
	}
	project := apiTestProject(t, db, "Explicit-only project")
	explicit := owner.fields(fields)
	explicit.Set("projects", project.ID)
	browserTestStatus(t, owner.form(t, "/settings/api-keys", explicit), 201)
	keys, err := db.APIKeys(t.Context())
	if err != nil || len(keys) != 1 || keys[0].AllProjects || !slices.Equal(keys[0].ProjectIDs, []string{project.ID}) {
		t.Fatalf("unchecked creation broadened access: %+v, %v", keys, err)
	}
	fields.Set("all_projects", "1")
	invalidResource := owner.fields(fields)
	invalidResource.Set("projects", "missing-project")
	browserTestStatus(t, owner.form(t, "/settings/api-keys", invalidResource), 404)
	missingScope := owner.fields(fields)
	missingScope.Del("scopes")
	browserTestStatus(t, owner.form(t, "/settings/api-keys", missingScope), 422)
	created := owner.form(t, "/settings/api-keys", fields)
	browserTestStatus(t, created, 201)
	doc := browserTestDocument(t, created)
	secret := browserTestInputID(doc, "key-secret")
	if secret == nil {
		t.Fatal("new key secret was not shown once")
	}
	token := browserTestAttr(secret, "value")
	key, err := db.APIKeyByHash(t.Context(), tokenHash(token))
	if err != nil || !key.AllProjects || len(key.ProjectIDs)+len(key.NoteIDs) != 0 || !slices.Equal(key.Scopes, []string{"notes:read"}) {
		t.Fatalf("all-projects key creation failed: %+v, %v", key, err)
	}
	keyAccessCheckbox(t, browserTestForm(t, doc, "/settings/api-keys"), "all_projects", "1", false)
	page := owner.request(t, "GET", "/settings/api-keys", nil, nil)
	browserTestStatus(t, page, 200)
	apiTestNoSecrets(t, page, token, key.TokenHash)
}

func TestOAuthAllProjectsConsent(t *testing.T) {
	base, db := newTestApp(t)
	if err := db.InitOAuth(t.Context()); err != nil {
		t.Fatal(err)
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
	project := apiTestProject(t, db, "Retained OAuth project")
	note := apiTestNote(t, db, project.ID, "RETAINED_OAUTH_NOTE")
	other := apiTestProject(t, db, "Other OAuth project")
	private := apiTestNote(t, db, other.ID, "PRIVATE_BEFORE_NARROWING")
	client, err := db.CreateOAuthClient(t.Context(), store.OAuthClient{Name: "All-projects consent", AuthMethod: "none", RedirectURIs: []string{"https://chatgpt.com/connector_platform_oauth_redirect"}})
	if err != nil {
		t.Fatal(err)
	}
	verifier := strings.Repeat("v", 64)
	sum := sha256.Sum256([]byte(verifier))
	query := url.Values{"client_id": {client.ID}, "redirect_uri": {client.RedirectURIs[0]}, "response_type": {"code"}, "scope": {"notes:read"}, "resource": {app.oauthResource()}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}}
	consent := owner.request(t, "GET", "/oauth/authorize?"+query.Encode(), nil, nil)
	browserTestStatus(t, consent, 200)
	form := browserTestForm(t, browserTestDocument(t, consent), "/oauth/authorize")
	keyAccessCheckbox(t, form, "all_projects", "1", false)
	fields := url.Values{"request": {browserTestInput(t, form, "request")}, "decision": {"allow"}, "scopes": {"notes:read"}}
	browserTestStatus(t, owner.form(t, "/oauth/authorize", fields), 422)
	browserTestStatus(t, owner.form(t, "/oauth/authorize?all_projects=1", fields), 422)
	for _, values := range [][]string{{""}, {"true"}, {"1", "1"}, {"0", "1"}} {
		invalid := owner.fields(fields)
		invalid["all_projects"] = values
		browserTestStatus(t, owner.form(t, "/oauth/authorize", invalid), 422)
	}
	fields.Set("all_projects", "1")
	missingScope := owner.fields(fields)
	missingScope.Del("scopes")
	browserTestStatus(t, owner.form(t, "/oauth/authorize", missingScope), 422)
	unrequestedScope := owner.fields(fields)
	unrequestedScope.Set("scopes", "notes:write")
	browserTestStatus(t, owner.form(t, "/oauth/authorize", unrequestedScope), 400)
	approved := owner.form(t, "/oauth/authorize", fields)
	browserTestStatus(t, approved, 303)
	callback, err := url.Parse(approved.Header().Get("Location"))
	if err != nil || callback.Query().Get("code") == "" {
		t.Fatal("missing OAuth authorization code")
	}
	keys, err := db.APIKeys(t.Context())
	if err != nil || len(keys) != 1 || !keys[0].AllProjects || len(keys[0].ProjectIDs)+len(keys[0].NoteIDs) != 0 || !slices.Equal(keys[0].Scopes, []string{"notes:read"}) {
		t.Fatalf("OAuth consent did not preserve explicit opt-in and requested scopes: %+v, %v", keys, err)
	}
	page := owner.request(t, "GET", "/settings/api-keys", nil, nil)
	browserTestStatus(t, page, 200)
	apiTestNoSecrets(t, page, keys[0].TokenHash)
	keyAccessCheckbox(t, browserTestForm(t, browserTestDocument(t, page), "/settings/api-keys/"+keys[0].ID+"/access"), "all_projects", "1", true)

	exchange := url.Values{"grant_type": {"authorization_code"}, "client_id": {client.ID}, "code": {callback.Query().Get("code")}, "redirect_uri": {client.RedirectURIs[0]}, "code_verifier": {verifier}, "resource": {app.oauthResource()}}
	issued := public.request(t, "POST", "/oauth/token", strings.NewReader(exchange.Encode()), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	browserTestStatus(t, issued, 200)
	tokens := apiTestDecode[struct {
		Access  string `json:"access_token"`
		Refresh string `json:"refresh_token"`
		Scope   string `json:"scope"`
	}](t, issued)
	if tokens.Access == "" || tokens.Refresh == "" || tokens.Scope != "notes:read" {
		t.Fatal("invalid public-client OAuth token response")
	}
	grant, err := db.OAuthGrantByAccess(t.Context(), tokenHash(tokens.Access), app.oauthResource())
	if err != nil || grant.KeyID != keys[0].ID {
		t.Fatalf("access token is not bound to the consent key: %v", err)
	}
	apiSecret := app.oauthAPIKey(grant.ID)
	if tokenHash(apiSecret) != keys[0].TokenHash {
		t.Fatal("OAuth API secret does not match the consent key")
	}
	rpc := func(method string, params any) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
		if err != nil {
			t.Fatal(err)
		}
		response := public.request(t, "POST", "/mcp", bytes.NewReader(body), map[string]string{"Authorization": "Bearer " + tokens.Access, "Content-Type": "application/json", "Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-11-25"})
		browserTestStatus(t, response, 200)
		envelope := apiTestDecode[struct {
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}](t, response)
		if len(envelope.Error) != 0 || len(envelope.Result) == 0 {
			t.Fatalf("MCP %s failed: %s", method, response.Body.String())
		}
		apiTestNoSecrets(t, response, tokens.Access, tokens.Refresh, apiSecret, keys[0].TokenHash)
		return response
	}
	call := func(name string, arguments map[string]any, wantError bool) *httptest.ResponseRecorder {
		t.Helper()
		response := rpc("tools/call", map[string]any{"name": name, "arguments": arguments})
		envelope := apiTestDecode[struct {
			Result struct {
				IsError bool `json:"isError"`
			} `json:"result"`
		}](t, response)
		if envelope.Result.IsError != wantError {
			t.Fatalf("MCP %s isError = %v, want %v: %s", name, envelope.Result.IsError, wantError, response.Body.String())
		}
		return response
	}
	listProjects := func() []string {
		t.Helper()
		response := call("conspect_list_projects", map[string]any{}, false)
		envelope := apiTestDecode[struct {
			Result struct {
				StructuredContent struct {
					Projects []store.Project `json:"projects"`
				} `json:"structuredContent"`
			} `json:"result"`
		}](t, response)
		var ids []string
		for _, project := range envelope.Result.StructuredContent.Projects {
			ids = append(ids, project.ID)
		}
		return ids
	}
	assertReadOnlyTools := func() {
		t.Helper()
		response := rpc("tools/list", map[string]any{})
		envelope := apiTestDecode[struct {
			Result struct {
				Tools []struct {
					Name string `json:"name"`
				} `json:"tools"`
			} `json:"result"`
		}](t, response)
		var names []string
		for _, tool := range envelope.Result.Tools {
			names = append(names, tool.Name)
		}
		for _, required := range []string{"conspect_list_projects", "conspect_get_note"} {
			if !slices.Contains(names, required) {
				t.Errorf("read-only OAuth token is missing tool %s", required)
			}
		}
		for _, forbidden := range []string{"conspect_upload_image", "conspect_upload_markdown", "conspect_update_note", "conspect_create_note"} {
			if slices.Contains(names, forbidden) {
				t.Errorf("read-only OAuth token exposes write tool %s", forbidden)
			}
		}
	}
	rpc("initialize", map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "all-projects-test", "version": "1"}})
	initial := listProjects()
	if len(initial) != 2 || !slices.Contains(initial, project.ID) || !slices.Contains(initial, other.ID) {
		t.Fatalf("OAuth all-projects grant cannot list existing projects: %v", initial)
	}
	assertReadOnlyTools()
	call("conspect_get_note", map[string]any{"note_id": private.ID}, false)

	future := apiTestProject(t, db, "Created after OAuth issuance and first MCP call")
	futureNote := apiTestNote(t, db, future.ID, "PRIVATE_FUTURE_OAUTH_NOTE")
	visible := listProjects()
	if len(visible) != 3 || !slices.Contains(visible, project.ID) || !slices.Contains(visible, other.ID) || !slices.Contains(visible, future.ID) {
		t.Fatalf("unchanged OAuth access token cannot see a future project: %v", visible)
	}
	call("conspect_get_note", map[string]any{"note_id": futureNote.ID}, false)

	path := "/settings/api-keys/" + keys[0].ID + "/access"
	updated := owner.form(t, path, url.Values{"projects": {project.ID}, "scopes": {"notes:write"}})
	browserTestRedirect(t, updated, "/settings/api-keys")
	apiTestNoSecrets(t, updated, apiSecret, keys[0].TokenHash, tokens.Access, tokens.Refresh)
	stored, err := db.APIKeyByHash(t.Context(), tokenHash(apiSecret))
	if err != nil || stored.ID != keys[0].ID || stored.TokenHash != keys[0].TokenHash || stored.AllProjects || !slices.Equal(stored.ProjectIDs, []string{project.ID}) || len(stored.NoteIDs) != 0 || !slices.Equal(stored.Scopes, keys[0].Scopes) {
		t.Fatalf("owner resource update changed the OAuth secret/scopes or failed to narrow grants: %v", err)
	}
	visible = listProjects()
	if !slices.Equal(visible, []string{project.ID}) {
		t.Fatalf("unchanged OAuth access token still lists ungranted projects: %v", visible)
	}
	read := call("conspect_get_note", map[string]any{"note_id": note.ID}, false)
	if !strings.Contains(read.Body.String(), note.Title) {
		t.Fatal("narrowed OAuth access token cannot read the retained project's note")
	}
	for _, hidden := range []store.Note{private, futureNote} {
		denied := call("conspect_get_note", map[string]any{"note_id": hidden.ID}, true)
		if strings.Contains(denied.Body.String(), hidden.Title) {
			t.Error("narrowed OAuth access token exposed an ungranted note")
		}
	}
	assertReadOnlyTools()
	page = owner.request(t, "GET", "/settings/api-keys", nil, nil)
	browserTestStatus(t, page, 200)
	apiTestNoSecrets(t, page, apiSecret, keys[0].TokenHash, tokens.Access, tokens.Refresh)
	edit := browserTestForm(t, browserTestDocument(t, page), path)
	keyAccessCheckbox(t, edit, "all_projects", "1", false)
	keyAccessCheckbox(t, edit, "projects", project.ID, true)
	keyAccessCheckbox(t, edit, "projects", other.ID, false)
	keyAccessCheckbox(t, edit, "projects", future.ID, false)
}
