package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"conspect/internal/conspectclient"
	"conspect/internal/store"
)

func newMCPAPIKeyTestApp(t *testing.T) (*App, *store.Store) {
	t.Helper()
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
	return app, db
}

func mcpAPIKeyRPC(t *testing.T, app *App, token, method string, params any) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if err != nil {
		t.Fatal(err)
	}
	response := apiTestRequest(app, http.MethodPost, app.cfg.BaseURL+"/mcp", token, bytes.NewReader(body), map[string]string{
		"Accept": "application/json, text/event-stream", "MCP-Protocol-Version": "2025-11-25",
	})
	browserTestStatus(t, response, http.StatusOK)
	if !strings.HasPrefix(response.Header().Get("Content-Type"), "application/json") || response.Header().Get("Mcp-Session-Id") != "" {
		t.Fatal("MCP must return stateless JSON without a session ID")
	}
	apiTestNoSecrets(t, response, token, tokenHash(token))
	return response
}

func mcpAPIKeyResult[T any](t *testing.T, response *httptest.ResponseRecorder) T {
	t.Helper()
	envelope := apiTestDecode[struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      int             `json:"id"`
		Result  T               `json:"result"`
		Error   json.RawMessage `json:"error"`
	}](t, response)
	if envelope.JSONRPC != "2.0" || envelope.ID != 1 || len(envelope.Error) != 0 {
		t.Fatalf("invalid RPC result: %s", response.Body.String())
	}
	return envelope.Result
}

func mcpAPIKeyCall(t *testing.T, app *App, token, name string, arguments any, wantError bool) *httptest.ResponseRecorder {
	t.Helper()
	response := mcpAPIKeyRPC(t, app, token, "tools/call", map[string]any{"name": name, "arguments": arguments})
	result := mcpAPIKeyResult[struct {
		IsError bool `json:"isError"`
	}](t, response)
	if result.IsError != wantError {
		t.Fatalf("%s isError = %v, want %v: %s", name, result.IsError, wantError, response.Body.String())
	}
	return response
}

func mcpAPIKeyNote(t *testing.T, response *httptest.ResponseRecorder) conspectclient.Note {
	t.Helper()
	return mcpAPIKeyResult[struct {
		Note conspectclient.Note `json:"structuredContent"`
	}](t, response).Note
}

func mcpAPIKeyUnknownTool(t *testing.T, app *App, token, name string, args any) {
	t.Helper()
	response := mcpAPIKeyRPC(t, app, token, "tools/call", map[string]any{"name": name, "arguments": args})
	envelope := apiTestDecode[struct {
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
	}](t, response)
	if envelope.Error == nil || envelope.Error.Code != -32602 {
		t.Fatalf("hidden tool %s remains callable: %s", name, response.Body.String())
	}
}

func TestRemoteMCPAPIKeyReadAndWrite(t *testing.T) {
	app, db := newMCPAPIKeyTestApp(t)
	project := apiTestProject(t, db, "Synthetic selected project")
	note := apiTestNote(t, db, project.ID, "Synthetic reference")
	_, token := apiTestKey(t, db, store.APIKey{
		Scopes: []string{"notes:read", "notes:write", "attachments:read", "attachments:write"}, ProjectIDs: []string{project.ID},
	})
	var calls atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.Header.Values("Authorization")) != 1 || r.Header.Get("Authorization") != "Bearer "+token || !strings.HasPrefix(r.URL.Path, "/api/v1/") {
			t.Error("MCP did not delegate to REST with the exact original bearer key")
		}
		calls.Add(1)
		app.Handler().ServeHTTP(w, r)
	}))
	t.Cleanup(api.Close)
	app.cfg.MCPAPIURL = api.URL

	for range 2 {
		initialized := mcpAPIKeyResult[struct {
			Protocol string `json:"protocolVersion"`
		}](t, mcpAPIKeyRPC(t, app, token, "initialize", map[string]any{
			"protocolVersion": "2025-11-25", "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "Zed test", "version": "1"},
		}))
		if initialized.Protocol != "2025-11-25" {
			t.Fatal("initialize did not negotiate the requested protocol")
		}
	}
	tools := mcpAPIKeyRPC(t, app, token, "tools/list", map[string]any{})
	for _, forbidden := range []string{"conspect_upload_markdown", "conspect_upload_image", "source_path"} {
		if strings.Contains(tools.Body.String(), `"`+forbidden+`"`) {
			t.Errorf("remote tools expose filesystem input %s", forbidden)
		}
	}
	for _, name := range []string{"conspect_upload_markdown", "conspect_upload_image"} {
		mcpAPIKeyUnknownTool(t, app, token, name, map[string]any{"path": "/etc/passwd"})
	}
	mcpAPIKeyCall(t, app, token, "conspect_prepare_note", map[string]any{"source_path": "/etc/passwd"}, true)
	mcpAPIKeyCall(t, app, token, "conspect_prepare_note", map[string]any{"source_text": "Synthetic source", "source_path": "/etc/passwd"}, true)
	mcpAPIKeyCall(t, app, token, "conspect_prepare_note", map[string]any{"source_text": "Synthetic source"}, false)
	if calls.Load() != 0 {
		t.Fatal("initialize, tools/list or prepare unexpectedly called REST")
	}

	for _, tc := range []struct {
		name string
		args map[string]any
		want string
	}{
		{"conspect_list_projects", map[string]any{}, project.ID},
		{"conspect_list_notes", map[string]any{"project_id": project.ID}, note.ID},
		{"conspect_get_note", map[string]any{"note_id": note.ID}, "Private text"},
		{"conspect_search_docs", map[string]any{"query": "Synthetic", "project_id": project.ID}, note.ID},
		{"conspect_docs_outline", map[string]any{"note_id": note.ID}, "Synthetic reference"},
		{"conspect_read_docs", map[string]any{"note_id": note.ID}, "Private text"},
	} {
		response := mcpAPIKeyCall(t, app, token, tc.name, tc.args, false)
		if !strings.Contains(response.Body.String(), tc.want) || strings.Contains(response.Body.String(), api.URL) {
			t.Fatalf("%s returned incorrect content or a loopback citation", tc.name)
		}
	}
	if calls.Load() == 0 {
		t.Fatal("MCP reads did not reach the real REST API")
	}
	read := mcpAPIKeyNote(t, mcpAPIKeyCall(t, app, token, "conspect_get_note", map[string]any{"note_id": note.ID}, false))
	if read.URL != app.cfg.BaseURL+"/notes/"+note.ID || read.ETag != `"v1"` {
		t.Fatal("get_note lost the public citation or current ETag")
	}
	markdown := "# Synthetic note\n\n$x_i$\n\n```go\nreturn 42\n```"
	created := mcpAPIKeyNote(t, mcpAPIKeyCall(t, app, token, "conspect_create_note", map[string]any{
		"project_id": project.ID, "title": "Synthetic created", "markdown": markdown,
	}, false))
	if created.ID == "" || created.ProjectID != project.ID || created.Markdown != markdown || created.ETag != `"v1"` || created.Shared {
		t.Fatal("create_note returned incorrect content, ETag or sharing state")
	}
	updated := mcpAPIKeyNote(t, mcpAPIKeyCall(t, app, token, "conspect_update_note", map[string]any{
		"note_id": created.ID, "title": "Synthetic updated", "markdown": markdown + "\nUpdated.", "etag": created.ETag,
	}, false))
	if updated.ID != created.ID || updated.ETag != `"v2"` || updated.Markdown != markdown+"\nUpdated." {
		t.Fatal("update_note lost content or the new ETag")
	}
	mcpAPIKeyCall(t, app, token, "conspect_update_note", map[string]any{
		"note_id": created.ID, "title": "Stale", "markdown": "Stale", "etag": created.ETag,
	}, true)
	stored, err := db.Note(t.Context(), created.ID)
	if err != nil || stored.Title != updated.Title || stored.Markdown != updated.Markdown || stored.Version != 2 || stored.Shared {
		t.Fatalf("REST writes were not persisted correctly: %v", err)
	}
}

func TestRemoteMCPAPIKeyScopes(t *testing.T) {
	app, db := newMCPAPIKeyTestApp(t)
	project := apiTestProject(t, db, "Synthetic scope project")

	readTools := []string{"conspect_list_projects", "conspect_list_notes", "conspect_get_note", "conspect_search_docs", "conspect_docs_outline", "conspect_read_docs"}
	writeTools := []string{"conspect_create_note", "conspect_update_note"}
	for _, tc := range []struct {
		name   string
		scopes []string
		read   bool
		write  bool
	}{
		{name: "no scopes"},
		{name: "attachments only", scopes: []string{"attachments:read", "attachments:write"}},
		{name: "read only", scopes: []string{"notes:read"}, read: true},
		{name: "write only", scopes: []string{"notes:write"}, write: true},
		{name: "read and write", scopes: []string{"notes:read", "notes:write"}, read: true, write: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			note := apiTestNote(t, db, project.ID, "Synthetic scope note")
			_, token := apiTestKey(t, db, store.APIKey{Scopes: tc.scopes, ProjectIDs: []string{project.ID}})
			listed := mcpAPIKeyResult[struct {
				Tools []struct{ Name string } `json:"tools"`
			}](t, mcpAPIKeyRPC(t, app, token, "tools/list", map[string]any{}))
			want := []string{"conspect_prepare_note"}
			if tc.read {
				want = append(want, readTools...)
			}
			if tc.write {
				want = append(want, writeTools...)
			}
			var got []string
			for _, tool := range listed.Tools {
				got = append(got, tool.Name)
			}
			slices.Sort(got)
			slices.Sort(want)
			if !slices.Equal(got, want) {
				t.Fatalf("tools = %v, want %v", got, want)
			}
			for _, name := range append(slices.Clone(readTools), writeTools...) {
				if !slices.Contains(want, name) {
					mcpAPIKeyUnknownTool(t, app, token, name, map[string]any{})
				}
			}
			if tc.read {
				mcpAPIKeyCall(t, app, token, "conspect_get_note", map[string]any{"note_id": note.ID}, false)
			}
			if tc.write {
				mcpAPIKeyCall(t, app, token, "conspect_create_note", map[string]any{
					"project_id": project.ID, "title": "Synthetic write-only creation", "markdown": "Text",
				}, false)
				mcpAPIKeyCall(t, app, token, "conspect_update_note", map[string]any{
					"note_id": note.ID, "title": note.Title, "markdown": note.Markdown, "etag": `"v1"`,
				}, false)

			}
		})
	}
}

func TestRemoteMCPAPIKeyCurrentResourceGrants(t *testing.T) {
	app, db := newMCPAPIKeyTestApp(t)
	project := apiTestProject(t, db, "Synthetic allowed project")
	other := apiTestProject(t, db, "Synthetic other project")
	note := apiTestNote(t, db, project.ID, "Synthetic granted note")
	sibling := apiTestNote(t, db, project.ID, "SYNTHETIC_UNGRANTED_SIBLING")
	private := apiTestNote(t, db, other.ID, "SYNTHETIC_UNGRANTED_OTHER")
	key, token := apiTestKey(t, db, store.APIKey{Scopes: []string{"notes:read", "notes:write"}, NoteIDs: []string{note.ID}})
	for _, tc := range []struct {
		name     string
		all      bool
		projects []string
		notes    []string
		visible  []bool
		create   bool
	}{
		{"note only", false, nil, []string{note.ID}, []bool{true, false, false}, false},
		{"project", false, []string{project.ID}, nil, []bool{true, true, false}, true},
		{"all projects", true, nil, nil, []bool{true, true, true}, true},
		{"narrowed to other note", false, nil, []string{private.ID}, []bool{false, false, true}, false},
		{"no resources", false, nil, nil, []bool{false, false, false}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := db.UpdateAPIKeyAccess(t.Context(), key.ID, tc.all, tc.projects, tc.notes); err != nil {
				t.Fatal(err)
			}
			for i, resource := range []store.Note{note, sibling, private} {
				read := mcpAPIKeyCall(t, app, token, "conspect_get_note", map[string]any{"note_id": resource.ID}, !tc.visible[i])
				rest := apiTestRequest(app, http.MethodGet, "/api/v1/notes/"+resource.ID, token, nil, nil)
				status := http.StatusNotFound
				if tc.visible[i] {
					status = http.StatusOK
				}
				apiTestStatus(t, rest, status)
				if !tc.visible[i] && strings.Contains(read.Body.String(), resource.Title) {
					t.Fatal("ungranted note content escaped through MCP")
				}
				current, err := db.Note(t.Context(), resource.ID)
				if err != nil {
					t.Fatal(err)
				}
				mcpAPIKeyCall(t, app, token, "conspect_update_note", map[string]any{
					"note_id": resource.ID, "title": resource.Title, "markdown": resource.Markdown, "etag": fmt.Sprintf(`"v%d"`, current.Version),
				}, !tc.visible[i])
			}
			listed := mcpAPIKeyCall(t, app, token, "conspect_list_notes", map[string]any{"project_id": project.ID}, !tc.visible[0])
			searched := mcpAPIKeyCall(t, app, token, "conspect_search_docs", map[string]any{"query": "SYNTHETIC_UNGRANTED"}, false)
			for i, resource := range []store.Note{note, sibling, private} {
				if !tc.visible[i] && (strings.Contains(listed.Body.String(), resource.ID) || strings.Contains(searched.Body.String(), resource.ID)) {
					t.Fatal("listing or documentation search escaped current grants")
				}
			}
			mcpAPIKeyCall(t, app, token, "conspect_create_note", map[string]any{
				"project_id": project.ID, "title": "Synthetic current-grant creation", "markdown": "Text",
			}, !tc.create)
			projects := mcpAPIKeyCall(t, app, token, "conspect_list_projects", map[string]any{}, false)
			if strings.Contains(projects.Body.String(), project.ID) != tc.visible[0] || strings.Contains(projects.Body.String(), other.ID) != tc.visible[2] {
				t.Fatal("project listing does not reflect the key's current grants")
			}
			if tc.all {
				future := apiTestProject(t, db, "Synthetic future project")
				futureNote := apiTestNote(t, db, future.ID, "Synthetic future note")
				mcpAPIKeyCall(t, app, token, "conspect_get_note", map[string]any{"note_id": futureNote.ID}, false)
				mcpAPIKeyCall(t, app, token, "conspect_create_note", map[string]any{"project_id": future.ID, "title": "Synthetic future creation", "markdown": "Text"}, false)
			}
		})
	}
}

func TestRemoteMCPAPIKeyAuthentication(t *testing.T) {
	app, db := newMCPAPIKeyTestApp(t)
	key, revoked := apiTestKey(t, db, store.APIKey{Scopes: []string{"notes:read"}, AllProjects: true})
	_, token := apiTestKey(t, db, store.APIKey{Scopes: key.Scopes, AllProjects: true})
	past := time.Now().Add(-time.Minute)
	_, expired := apiTestKey(t, db, store.APIKey{Scopes: key.Scopes, AllProjects: true, ExpiresAt: &past})
	owner := browserTestOwner(t, app, db)
	// A successful request must not cache authorization past revocation.
	mcpAPIKeyRPC(t, app, revoked, "tools/list", map[string]any{})
	if err := db.RevokeAPIKey(t.Context(), key.ID); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		headers []string
		cookie  bool
	}{
		{name: "missing"},
		{name: "owner session is not a bearer", cookie: true},
		{name: "key cookie is not a bearer"},
		{name: "invalid", headers: []string{"Bearer csp_not-a-real-key"}},
		{name: "unknown OAuth", headers: []string{"Bearer csa_not-a-real-grant"}},
		{name: "expired", headers: []string{"Bearer " + expired}},
		{name: "revoked", headers: []string{"Bearer " + revoked}},
		{name: "wrong scheme", headers: []string{"Basic " + token}},
		{name: "wrong prefix", headers: []string{"Bearer cspx_" + strings.Repeat("x", 64)}},
		{name: "overlong", headers: []string{"Bearer csp_" + strings.Repeat("x", 125)}},
		{name: "duplicate", headers: []string{"Bearer " + token, "Bearer " + token}},
		{name: "comma joined", headers: []string{"Bearer " + token + ", Bearer " + token}},
		{name: "leading whitespace", headers: []string{" Bearer " + token}},
		{name: "trailing whitespace", headers: []string{"Bearer " + token + " "}},
		{name: "tab separator", headers: []string{"Bearer\t" + token}},
		{name: "extra separator", headers: []string{"Bearer  " + token}},
		{name: "embedded whitespace", headers: []string{"Bearer csp_invalid token"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, app.cfg.BaseURL+"/mcp", strings.NewReader(`{}`))
			for _, header := range tc.headers {
				r.Header.Add("Authorization", header)
			}
			if tc.cookie {
				r.AddCookie(owner.cookie)
			} else {
				r.AddCookie(&http.Cookie{Name: "access_token", Value: token})
			}
			response := httptest.NewRecorder()
			app.Handler().ServeHTTP(response, r)
			browserTestStatus(t, response, http.StatusUnauthorized)
			if response.Header().Get("WWW-Authenticate") != `Bearer resource_metadata="`+app.cfg.BaseURL+`/.well-known/oauth-protected-resource/mcp", error="invalid_token"` || response.Body.String() != "{\"error\":\"invalid_token\"}\n" {
				t.Fatal("authentication failure did not use the common OAuth challenge")
			}
			apiTestNoSecrets(t, response, token, revoked, expired, key.TokenHash)
		})
	}
}

func TestRemoteMCPAPIKeyHTTPGuards(t *testing.T) {
	app, db := newMCPAPIKeyTestApp(t)
	_, token := apiTestKey(t, db, store.APIKey{Scopes: []string{"notes:read"}, AllProjects: true})
	for _, tc := range []struct {
		name, method, path, origin, host string
		status                           int
	}{
		{"host", "POST", "/mcp", "", "evil.invalid", 403},
		{"origin", "POST", "/mcp", "https://evil.invalid", "", 403},
		{"null origin", "POST", "/mcp", "null", "", 403},
		{"query", "POST", "/mcp?access_token=" + token, "", "", 400},
		{"other query", "POST", "/mcp?unrelated=1", "", "", 400},
		{"get", "GET", "/mcp", "", "", 405},
		{"delete", "DELETE", "/mcp", "", "", 405},
		{"put", "PUT", "/mcp", "", "", 405},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, app.cfg.BaseURL+tc.path, strings.NewReader(`{}`))
			r.Header.Set("Authorization", "Bearer "+token)
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			if tc.host != "" {
				r.Host = tc.host
			}
			response := httptest.NewRecorder()
			app.Handler().ServeHTTP(response, r)
			browserTestStatus(t, response, tc.status)
			if tc.status == 405 && response.Header().Get("Allow") != "POST" {
				t.Fatal("non-POST MCP request lost its Allow header")
			}
			apiTestNoSecrets(t, response, token)
		})
	}
	// Query credentials cannot authenticate even without an Authorization header.
	browserTestStatus(t, apiTestRequest(app, "POST", app.cfg.BaseURL+"/mcp?access_token="+token, "", strings.NewReader(`{}`), nil), 400)
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`
	accepted := apiTestRequest(app, "POST", app.cfg.BaseURL+"/mcp", token, strings.NewReader(body), map[string]string{
		"Origin": app.cfg.BaseURL, "Accept": "application/json, text/event-stream", "Authorization": "bEaReR " + token,
	})
	browserTestStatus(t, accepted, 200)

	app.cfg.MaxMarkdownBytes = 1
	oversized := apiTestRequest(app, "POST", app.cfg.BaseURL+"/mcp", token, strings.NewReader(body+strings.Repeat(" ", 65543)), map[string]string{"Accept": "application/json, text/event-stream"})
	browserTestStatus(t, oversized, http.StatusRequestEntityTooLarge)
	r := httptest.NewRequest("POST", app.cfg.BaseURL+"/mcp", nil)
	for range 240 {
		app.limits.allow("oauth:mcp:"+app.clientIP(r), 240, time.Minute)
	}
	limited := apiTestRequest(app, "POST", app.cfg.BaseURL+"/mcp", token, strings.NewReader(body), nil)
	browserTestStatus(t, limited, http.StatusTooManyRequests)
	if limited.Header().Get("Retry-After") != "60" {
		t.Fatal("MCP rate limit lost its retry hint")
	}
}
