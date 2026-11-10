package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"conspect/internal/store"
)

type apiTestNoteResult struct {
	store.Note
	Attachments json.RawMessage `json:"attachments"`
}

type apiTestProjectList struct {
	Projects []store.Project `json:"projects"`
}

type apiTestNoteList struct {
	Notes []apiTestNoteResult `json:"notes"`
}

type apiTestUploadResult struct {
	Attachment store.Attachment `json:"attachment"`
	Markdown   string           `json:"markdown"`
}

func TestAPISchemaAndBearerAuthentication(t *testing.T) {
	app, db := newTestApp(t)
	project := apiTestProject(t, db, "Private project")
	note := apiTestNote(t, db, project.ID, "Private note")
	_, token := apiTestKey(t, db, store.APIKey{
		Scopes: []string{"notes:read", "notes:write", "attachments:read", "attachments:write"}, ProjectIDs: []string{project.ID},
	})
	schema := apiTestRequest(app, "GET", "/api/v1/openapi.json", "", nil, nil)
	apiTestStatus(t, schema, 200)
	document := apiTestDecode[map[string]json.RawMessage](t, schema)
	if string(document["openapi"]) != `"3.1.0"` || len(document["paths"]) == 0 {
		t.Fatalf("not an OpenAPI document: %s", schema.Body.String())
	}
	if !strings.HasPrefix(schema.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("schema Content-Type = %q", schema.Header().Get("Content-Type"))
	}
	for _, route := range []struct{ method, path string }{
		{"GET", "/api/v1/projects"},
		{"GET", "/api/v1/projects/" + project.ID + "/notes"},
		{"GET", "/api/v1/notes/" + note.ID},
		{"POST", "/api/v1/projects/" + project.ID + "/notes"},
		{"PUT", "/api/v1/notes/" + note.ID},
		{"POST", "/api/v1/notes/" + note.ID + "/attachments"},
		{"GET", "/api/v1/notes/" + note.ID + "/attachments/" + store.NewID() + "/content"},
	} {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			response := apiTestRequest(app, route.method, route.path, "", strings.NewReader(`{"title":"x","markdown":""}`), nil)
			apiTestStatus(t, response, 401)
			if response.Header().Get("Location") != "" {
				t.Fatal("API authentication redirected to browser login")
			}
			apiTestNoSecrets(t, response, project.ID, note.ID, app.cfg.DataDir)
		})
	}

	sessionToken := randomToken("sess_")
	if err := db.CreateSession(t.Context(), store.Session{TokenHash: tokenHash(sessionToken), CSRFToken: "test-csrf", ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	shareToken := app.shareToken(store.NewID())
	for _, tc := range []struct {
		name, query string
		headers     map[string]string
	}{
		{name: "unknown key", headers: map[string]string{"Authorization": "Bearer csp_nonexistent"}},
		{name: "wrong scheme", headers: map[string]string{"Authorization": "Basic " + token}},
		{name: "extra credential", headers: map[string]string{"Authorization": "Bearer " + token + " extra"}},
		{name: "owner cookie", headers: map[string]string{"Cookie": sessionCookie + "=" + sessionToken}},
		{name: "key in cookie", headers: map[string]string{"Cookie": sessionCookie + "=" + token}},
		{name: "key in query", query: "?api_key=" + token + "&access_token=" + token},
		{name: "public share token", headers: map[string]string{"Authorization": "Bearer " + shareToken}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := apiTestRequest(app, "GET", "/api/v1/notes/"+note.ID+tc.query, "", nil, tc.headers)
			apiTestStatus(t, response, 401)
			apiTestNoSecrets(t, response, token, sessionToken, shareToken, app.cfg.DataDir)
		})
	}
	response := apiTestRequest(app, "GET", "/api/v1/notes/"+note.ID, "", nil, map[string]string{"Authorization": "bEaReR " + token})
	apiTestStatus(t, response, 200)
}

func TestAPIListsFilterResourcesSearchAndSort(t *testing.T) {
	app, db := newTestApp(t)
	alpha := apiTestProject(t, db, "Alpha")
	beta := apiTestProject(t, db, "Beta")
	empty := apiTestProject(t, db, "Empty")
	hidden := apiTestProject(t, db, "Hidden")
	zulu := apiTestNote(t, db, alpha.ID, "Zulu")
	neighbor := apiTestNote(t, db, alpha.ID, "Alpha neighbor secret")
	other := apiTestNote(t, db, beta.ID, "Beta note")
	hiddenNote := apiTestNote(t, db, hidden.ID, "Hidden note")
	var err error
	zulu, err = db.UpdateNote(t.Context(), zulu.ID, zulu.Title, zulu.Markdown, zulu.SourceName, zulu.Version, store.Actor{Owner: true})
	if err != nil {
		t.Fatal(err)
	}
	_, noteToken := apiTestKey(t, db, store.APIKey{Scopes: []string{"notes:read"}, NoteIDs: []string{zulu.ID}})
	_, mixedToken := apiTestKey(t, db, store.APIKey{Scopes: []string{"notes:read", "attachments:read"}, ProjectIDs: []string{beta.ID}, NoteIDs: []string{zulu.ID}})
	_, projectToken := apiTestKey(t, db, store.APIKey{Scopes: []string{"notes:read"}, ProjectIDs: []string{alpha.ID, empty.ID}})
	_, noResources := apiTestKey(t, db, store.APIKey{Scopes: []string{"notes:read"}})
	_, noRead := apiTestKey(t, db, store.APIKey{Scopes: []string{"notes:write", "attachments:read"}, ProjectIDs: []string{alpha.ID}})

	for _, tc := range []struct {
		name, token string
		want        []string
	}{
		{"note parent only", noteToken, []string{alpha.ID}},
		{"mixed grants", mixedToken, []string{alpha.ID, beta.ID}},
		{"project grants including empty", projectToken, []string{alpha.ID, empty.ID}},
		{"no implicit wildcard", noResources, []string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := apiTestRequest(app, "GET", "/api/v1/projects", tc.token, nil, nil)
			apiTestStatus(t, response, 200)
			result := apiTestDecode[apiTestProjectList](t, response)
			got := make([]string, 0, len(result.Projects))
			for _, project := range result.Projects {
				got = append(got, project.ID)
			}
			if result.Projects == nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("projects = %v, want %v (non-null array); body: %s", got, tc.want, response.Body.String())
			}
			apiTestNoSecrets(t, response, tc.token, hidden.ID, hiddenNote.ID)
		})
	}

	for _, tc := range []struct {
		name, token, project, query string
		status                      int
		want                        []string
	}{
		{"note grant excludes neighbor", noteToken, alpha.ID, "", 200, []string{zulu.ID}},
		{"query cannot expose neighbor", noteToken, alpha.ID, "?q=" + url.QueryEscape(neighbor.Title), 200, []string{}},
		{"query cannot hide parent grant", noteToken, alpha.ID, "?q=does-not-match", 200, []string{}},
		{"body search stays scoped", noteToken, alpha.ID, "?q=PRIVATE+TEXT", 200, []string{zulu.ID}},
		{"mixed note grant", mixedToken, alpha.ID, "", 200, []string{zulu.ID}},
		{"mixed project grant", mixedToken, beta.ID, "", 200, []string{other.ID}},
		{"default modified", projectToken, alpha.ID, "", 200, []string{zulu.ID, neighbor.ID}},
		{"title order", projectToken, alpha.ID, "?sort=title", 200, []string{neighbor.ID, zulu.ID}},
		{"unknown sort is modified", projectToken, alpha.ID, "?sort=title%20DESC", 200, []string{zulu.ID, neighbor.ID}},
		{"empty project", projectToken, empty.ID, "", 200, []string{}},
		{"outside existing project", noteToken, beta.ID, "", 404, nil},
		{"outside empty project", noteToken, empty.ID, "?q=Zulu", 404, nil},
		{"hidden project query", mixedToken, hidden.ID, "?q=Hidden&sort=title", 404, nil},
		{"missing project", mixedToken, store.NewID(), "", 404, nil},
		{"no resource selection", noResources, alpha.ID, "", 404, nil},
		{"scope absent", noRead, alpha.ID, "", 403, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := apiTestRequest(app, "GET", "/api/v1/projects/"+tc.project+"/notes"+tc.query, tc.token, nil, nil)
			apiTestStatus(t, response, tc.status)
			if tc.status != 200 {
				apiTestNoSecrets(t, response, tc.project, neighbor.ID, hidden.ID, hiddenNote.ID)
				return
			}
			result := apiTestDecode[apiTestNoteList](t, response)
			got := make([]string, 0, len(result.Notes))
			for _, note := range result.Notes {
				got = append(got, note.ID)
				if note.Title == "" || note.Markdown == "" || note.SourceName != "source.md" || note.Version < 1 || note.CreatedAt.IsZero() || note.UpdatedAt.IsZero() {
					t.Errorf("incomplete note metadata: %+v", note)
				}
				if tc.token == mixedToken {
					if string(note.Attachments) != "[]" {
						t.Errorf("empty readable attachments = %s, want []", note.Attachments)
					}
				} else if len(note.Attachments) != 0 {
					t.Error("attachment metadata exposed without attachments:read")
				}
			}
			if result.Notes == nil || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("notes = %v, want %v (non-null array); body: %s", got, tc.want, response.Body.String())
			}
			apiTestNoSecrets(t, response, tc.token, hidden.ID, hiddenNote.ID)
		})
	}
	apiTestStatus(t, apiTestRequest(app, "GET", "/api/v1/projects", noRead, nil, nil), 403)
}

func TestAPIGetNoteMetadataAttachmentsAndSecrets(t *testing.T) {
	app, db := newTestApp(t)
	project := apiTestProject(t, db, "Project")
	note := apiTestNote(t, db, project.ID, "Shared note")
	emptyNote := apiTestNote(t, db, project.ID, "No images")
	otherProject := apiTestProject(t, db, "Other")
	_, token := apiTestKey(t, db, store.APIKey{Scopes: []string{"notes:read", "attachments:read", "attachments:write"}, NoteIDs: []string{note.ID, emptyNote.ID}})
	_, readOnly := apiTestKey(t, db, store.APIKey{Scopes: []string{"notes:read", "attachments:write"}, NoteIDs: []string{note.ID}})
	_, imageOnly := apiTestKey(t, db, store.APIKey{Scopes: []string{"attachments:read"}, NoteIDs: []string{note.ID}})
	_, outside := apiTestKey(t, db, store.APIKey{Scopes: []string{"notes:read", "attachments:read"}, ProjectIDs: []string{otherProject.ID}})
	shareID := store.NewID()
	shareToken := app.shareToken(shareID)
	share, err := db.ReplaceShare(t.Context(), store.ShareLink{ID: shareID, NoteID: note.ID, TokenHash: tokenHash(shareToken)})
	if err != nil {
		t.Fatal(err)
	}
	image := apiTestPNG(t)
	upload := apiTestUpload(t, app, note.ID, token, "figure.png", image)
	apiTestStatus(t, upload, 201)
	attachment := apiTestDecode[apiTestUploadResult](t, upload).Attachment
	stored, err := db.Attachment(t.Context(), note.ID, attachment.ID)
	if err != nil {
		t.Fatal(err)
	}
	response := apiTestRequest(app, "GET", "/api/v1/notes/"+note.ID, token, nil, nil)
	apiTestStatus(t, response, 200)
	result := apiTestDecode[apiTestNoteResult](t, response)
	if result.ID != note.ID || result.ProjectID != note.ProjectID || result.Title != note.Title || result.Markdown != note.Markdown || result.SourceName != note.SourceName || result.Version != note.Version || !result.Shared || !result.CreatedAt.Equal(note.CreatedAt) || !result.UpdatedAt.Equal(note.UpdatedAt) {
		t.Fatalf("note metadata changed or missing: %+v", result)
	}
	if response.Header().Get("ETag") != etag(note.Version) {
		t.Fatalf("ETag = %q", response.Header().Get("ETag"))
	}
	var attachments []store.Attachment
	if err := json.Unmarshal(result.Attachments, &attachments); err != nil || len(attachments) != 1 || attachments[0].ID != attachment.ID || attachments[0].NoteID != note.ID || attachments[0].Size != int64(len(image)) {
		t.Fatalf("attachment metadata = %s, err=%v", result.Attachments, err)
	}
	apiTestNoSecrets(t, response, token, tokenHash(token), shareToken, share.TokenHash, share.ID, stored.StorageKey, app.cfg.DataDir, string(app.cfg.Secret))
	list := apiTestRequest(app, "GET", "/api/v1/projects/"+project.ID+"/notes", token, nil, nil)
	apiTestStatus(t, list, 200)
	apiTestNoSecrets(t, list, token, tokenHash(token), shareToken, share.TokenHash, share.ID, stored.StorageKey, app.cfg.DataDir)

	response = apiTestRequest(app, "GET", "/api/v1/notes/"+note.ID, readOnly, nil, nil)
	apiTestStatus(t, response, 200)
	if len(apiTestDecode[apiTestNoteResult](t, response).Attachments) != 0 {
		t.Fatal("attachments:write must not imply attachments:read")
	}
	response = apiTestRequest(app, "GET", "/api/v1/notes/"+emptyNote.ID, token, nil, nil)
	apiTestStatus(t, response, 200)
	if string(apiTestDecode[apiTestNoteResult](t, response).Attachments) != "[]" {
		t.Fatal("empty readable attachment array must be []")
	}
	apiTestStatus(t, apiTestRequest(app, "GET", "/api/v1/notes/"+note.ID, imageOnly, nil, nil), 403)
	content := apiTestRequest(app, "GET", "/api/v1/notes/"+note.ID+"/attachments/"+attachment.ID+"/content", imageOnly, nil, nil)
	apiTestStatus(t, content, 200)
	if !bytes.Equal(content.Body.Bytes(), image) || content.Header().Get("Content-Type") != "image/png" {
		t.Fatal("attachment read scope should independently allow original image content")
	}
	for _, id := range []string{note.ID, store.NewID()} {
		response := apiTestRequest(app, "GET", "/api/v1/notes/"+id, outside, nil, nil)
		apiTestStatus(t, response, 404)
		apiTestNoSecrets(t, response, id, note.ID, token, shareToken)
	}
}

func TestAPICreateNoteRequiresProjectGrant(t *testing.T) {
	app, db := newTestApp(t)
	project := apiTestProject(t, db, "Project")
	other := apiTestProject(t, db, "Other")
	existing := apiTestNote(t, db, project.ID, "Existing")
	_, writer := apiTestKey(t, db, store.APIKey{Scopes: []string{"notes:write", "attachments:read"}, ProjectIDs: []string{project.ID}})
	_, noteWriter := apiTestKey(t, db, store.APIKey{Scopes: []string{"notes:write"}, NoteIDs: []string{existing.ID}})
	_, reader := apiTestKey(t, db, store.APIKey{Scopes: []string{"notes:read"}, ProjectIDs: []string{project.ID}})
	body := `{"title":"API title","markdown":"# Markdown\n\n$A^{-1}A=I$"}`
	response := apiTestRequest(app, "POST", "/api/v1/projects/"+project.ID+"/notes", writer, strings.NewReader(body), nil)
	apiTestStatus(t, response, 201)
	created := apiTestDecode[apiTestNoteResult](t, response)
	if created.ID == "" || created.ProjectID != project.ID || created.Title != "API title" || created.Markdown != "# Markdown\n\n$A^{-1}A=I$" || created.SourceName != "" || created.Version != 1 || created.Shared || created.CreatedAt.IsZero() || created.UpdatedAt.IsZero() || string(created.Attachments) != "[]" {
		t.Fatalf("created note = %+v", created)
	}
	if response.Header().Get("Location") != "/api/v1/notes/"+created.ID || response.Header().Get("ETag") != `"v1"` {
		t.Fatalf("creation headers = %v", response.Header())
	}
	apiTestNoSecrets(t, response, writer, tokenHash(writer), app.cfg.DataDir)
	stored, err := db.Note(t.Context(), created.ID)
	if err != nil || !reflect.DeepEqual(stored, created.Note) {
		t.Fatalf("persisted note = %+v, err=%v", stored, err)
	}
	apiTestStatus(t, apiTestRequest(app, "GET", response.Header().Get("Location"), writer, nil, nil), 403)
	for _, tc := range []struct {
		name, token, project string
		status               int
	}{
		{"note grant cannot create neighbors", noteWriter, project.ID, 404},
		{"project outside access", writer, other.ID, 404},
		{"missing project", writer, store.NewID(), 404},
		{"read does not imply write", reader, project.ID, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := apiTestRequest(app, "POST", "/api/v1/projects/"+tc.project+"/notes", tc.token, strings.NewReader(body), nil)
			apiTestStatus(t, response, tc.status)
			apiTestNoSecrets(t, response, tc.project, tc.token)
		})
	}
	missingID := store.NewID()
	_, missingGrant := apiTestKey(t, db, store.APIKey{Scopes: []string{"notes:write"}, ProjectIDs: []string{missingID}})
	apiTestStatus(t, apiTestRequest(app, "POST", "/api/v1/projects/"+missingID+"/notes", missingGrant, strings.NewReader(body), nil), 404)
	projects, err := db.Projects(t.Context())
	if err != nil || len(projects) != 2 {
		t.Fatalf("API implicitly registered a project: %+v, %v", projects, err)
	}
	notes, err := db.Notes(t.Context(), project.ID, "", "modified")
	if err != nil || len(notes) != 2 {
		t.Fatalf("denied creation persisted a note: %+v, %v", notes, err)
	}
	if _, err := db.Owner(t.Context()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("API implicitly registered an owner, err=%v", err)
	}
}

func TestAPIStrictJSONAndByteLimits(t *testing.T) {
	app, db := newTestApp(t)
	app.cfg.MaxMarkdownBytes = 64
	project := apiTestProject(t, db, "Project")
	note := apiTestNote(t, db, project.ID, "Original")
	_, token := apiTestKey(t, db, store.APIKey{Scopes: []string{"notes:write"}, ProjectIDs: []string{project.ID}})
	valid := `{"title":"Title","markdown":""}`
	wireMax := int(app.cfg.MaxMarkdownBytes*6 + 8192)
	for _, tc := range []struct {
		name, body, contentType string
		status                  int
	}{
		{"unknown field", `{"title":"Title","markdown":"","secret-field-name":"secret-field-value"}`, "application/json", 400},
		{"source name is not writable", `{"title":"Title","markdown":"","source_name":"new.md"}`, "application/json", 400},
		{"project is not writable", `{"title":"Title","markdown":"","project_id":"other"}`, "application/json", 400},
		{"sharing is not writable", `{"title":"Title","markdown":"","shared":true}`, "application/json", 400},
		{"two objects", valid + valid, "application/json", 400},
		{"trailing null", valid + " null", "application/json", 400},
		{"trailing garbage", valid + " garbage", "application/json", 400},
		{"array", "[]", "application/json", 400},
		{"null", "null", "application/json", 400},
		{"string", `"text"`, "application/json", 400},
		{"empty body", "", "application/json", 400},
		{"syntax", `{"title":"Title","markdown":`, "application/json", 400},
		{"wrong title type", `{"title":10,"markdown":""}`, "application/json", 400},
		{"wrong markdown type", `{"title":"Title","markdown":{}}`, "application/json", 400},
		{"missing title", `{"markdown":""}`, "application/json", 422},
		{"missing markdown", `{"title":"Title"}`, "application/json", 422},
		{"null title", `{"title":null,"markdown":""}`, "application/json", 422},
		{"null markdown", `{"title":"Title","markdown":null}`, "application/json", 422},
		{"blank title", `{"title":" \t\n\u00a0","markdown":""}`, "application/json", 422},
		{"overlong title", `{"title":"` + strings.Repeat("界", 301) + `","markdown":""}`, "application/json", 422},
		{"NUL title", `{"title":"bad\u0000title","markdown":""}`, "application/json", 422},
		{"NUL markdown", `{"title":"Title","markdown":"bad\u0000body"}`, "application/json", 422},
		{"invalid UTF8 title", "{\"title\":\"\xff\",\"markdown\":\"\"}", "application/json", 422},
		{"invalid UTF8 markdown", "{\"title\":\"Title\",\"markdown\":\"\xff\"}", "application/json", 422},
		{"markdown byte limit", `{"title":"Title","markdown":"` + strings.Repeat("a", 65) + `"}`, "application/json", 413},
		{"markdown UTF8 byte limit", `{"title":"Title","markdown":"` + strings.Repeat("я", 33) + `"}`, "application/json", 413},
		{"wire limit", strings.Repeat(" ", wireMax) + valid, "application/json", 413},
		{"trailing whitespace wire limit", valid + strings.Repeat(" ", wireMax), "application/json", 413},
		{"plain text", valid, "text/plain", 415},
		{"absent content type", valid, "", 415},
		{"JSON prefix is not JSON", valid, "application/jsonp", 415},
		{"malformed media type", valid, "application/json; charset", 415},
	} {
		for _, endpoint := range []struct{ method, path string }{
			{"POST", "/api/v1/projects/" + project.ID + "/notes"},
			{"PUT", "/api/v1/notes/" + note.ID},
		} {
			t.Run(endpoint.method+"/"+tc.name, func(t *testing.T) {
				response := apiTestRequest(app, endpoint.method, endpoint.path, token, strings.NewReader(tc.body), map[string]string{
					"Content-Type": tc.contentType, "If-Match": etag(note.Version),
				})
				apiTestStatus(t, response, tc.status)
				apiTestNoSecrets(t, response, token, "secret-field-name", "secret-field-value", app.cfg.DataDir)
			})
		}
	}
	current, err := db.Note(t.Context(), note.ID)
	if err != nil || !reflect.DeepEqual(current, note) {
		t.Fatalf("invalid request changed original note: %+v, %v", current, err)
	}
	notes, err := db.Notes(t.Context(), project.ID, "", "modified")
	if err != nil || len(notes) != 1 {
		t.Fatalf("invalid request created a note: %+v, %v", notes, err)
	}
	// The JSON wire allowance permits six-byte escapes; the Markdown limit is
	// checked on decoded UTF-8 bytes, while the title limit counts runes.
	body := " \n" + `{"title":"` + strings.Repeat("界", 300) + `","markdown":"` + strings.Repeat(`\u0061`, 64) + `"}` + "\n\t"
	response := apiTestRequest(app, "POST", "/api/v1/projects/"+project.ID+"/notes", token, strings.NewReader(body), map[string]string{"Content-Type": "Application/JSON; charset=utf-8"})
	apiTestStatus(t, response, 201)
	created := apiTestDecode[apiTestNoteResult](t, response)
	if created.Title != strings.Repeat("界", 300) || created.Markdown != strings.Repeat("a", 64) || len(created.Attachments) != 0 {
		t.Fatalf("valid boundary input was changed: %+v", created)
	}
}

func TestAPIOptimisticVersionsAndParallelUpdates(t *testing.T) {
	app, db := newTestApp(t)
	project := apiTestProject(t, db, "Project")
	note := apiTestNote(t, db, project.ID, "Original")
	_, token := apiTestKey(t, db, store.APIKey{Scopes: []string{"notes:read", "notes:write"}, NoteIDs: []string{note.ID}})
	shareID := store.NewID()
	if _, err := db.ReplaceShare(t.Context(), store.ShareLink{ID: shareID, NoteID: note.ID, TokenHash: tokenHash(app.shareToken(shareID))}); err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/notes/" + note.ID
	body := `{"title":"Updated","markdown":""}`
	for _, tc := range []struct {
		name, condition string
		status          int
	}{
		{"missing", "", 428},
		{"wildcard", "*", 400},
		{"weak", `W/"v1"`, 400},
		{"unquoted", "v1", 400},
		{"wrong prefix", `"1"`, 400},
		{"zero", `"v0"`, 400},
		{"negative", `"v-1"`, 400},
		{"leading zero", `"v01"`, 400},
		{"plus sign", `"v+1"`, 400},
		{"space", ` "v1" `, 400},
		{"list", `"v1", "v2"`, 400},
		{"overflow", `"v9223372036854775808"`, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			headers := map[string]string{}
			if tc.condition != "" {
				headers["If-Match"] = tc.condition
			}
			apiTestStatus(t, apiTestRequest(app, "PUT", path, token, strings.NewReader(body), headers), tc.status)
		})
	}
	request := httptest.NewRequest("PUT", path, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Add("If-Match", `"v1"`)
	request.Header.Add("If-Match", `"v1"`)
	duplicate := httptest.NewRecorder()
	app.Handler().ServeHTTP(duplicate, request)
	apiTestStatus(t, duplicate, 400)
	before, err := db.Note(t.Context(), note.ID)
	if err != nil || before.Version != 1 || before.Title != note.Title || before.Markdown != note.Markdown {
		t.Fatalf("invalid condition changed note: %+v, %v", before, err)
	}
	response := apiTestRequest(app, "PUT", path, token, strings.NewReader(body), map[string]string{"If-Match": `"v1"`})
	apiTestStatus(t, response, 200)
	updated := apiTestDecode[apiTestNoteResult](t, response)
	if updated.Version != 2 || updated.Title != "Updated" || updated.Markdown != "" || updated.SourceName != note.SourceName || !updated.Shared || len(updated.Attachments) != 0 || response.Header().Get("ETag") != `"v2"` {
		t.Fatalf("updated note = %+v; headers: %v", updated, response.Header())
	}
	stale := apiTestRequest(app, "PUT", path, token, strings.NewReader(`{"title":"Stale","markdown":"lost update"}`), map[string]string{"If-Match": `"v1"`})
	apiTestStatus(t, stale, 412)
	current := apiTestRequest(app, "GET", path, token, nil, nil)
	apiTestStatus(t, current, 200)
	if current.Header().Get("ETag") != `"v2"` || apiTestDecode[apiTestNoteResult](t, current).Title != "Updated" {
		t.Fatal("stale request overwrote the note")
	}

	start := make(chan struct{})
	results := make(chan *httptest.ResponseRecorder, 2)
	for _, title := range []string{"Winner A", "Winner B"} {
		payload, err := json.Marshal(map[string]string{"title": title, "markdown": title + " body"})
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			<-start
			results <- apiTestRequest(app, "PUT", path, token, bytes.NewReader(payload), map[string]string{"If-Match": `"v2"`})
		}()
	}
	close(start)
	var winner apiTestNoteResult
	successes, conflicts := 0, 0
	for range 2 {
		response := <-results
		switch response.Code {
		case 200:
			successes++
			winner = apiTestDecode[apiTestNoteResult](t, response)
			if response.Header().Get("ETag") != `"v3"` {
				t.Errorf("parallel update ETag = %q", response.Header().Get("ETag"))
			}
		case 412:
			conflicts++
			apiTestStatus(t, response, 412)
		default:
			t.Errorf("parallel status = %d: %s", response.Code, response.Body.String())
		}
	}
	stored, err := db.Note(t.Context(), note.ID)
	if successes != 1 || conflicts != 1 || err != nil || stored.Version != 3 || stored.Title != winner.Title || stored.Markdown != winner.Markdown || stored.SourceName != note.SourceName || !stored.Shared {
		t.Fatalf("parallel update: %d successes, %d conflicts, stored=%+v, err=%v", successes, conflicts, stored, err)
	}
}

func TestAPIAttachmentsAreNoteBoundAndDoNotMutateText(t *testing.T) {
	app, db := newTestApp(t)
	project := apiTestProject(t, db, "Project")
	otherProject := apiTestProject(t, db, "Other")
	note := apiTestNote(t, db, project.ID, "Original")
	neighbor := apiTestNote(t, db, project.ID, "Neighbor")
	other := apiTestNote(t, db, otherProject.ID, "Other note")
	_, uploadOnly := apiTestKey(t, db, store.APIKey{Scopes: []string{"attachments:write"}, NoteIDs: []string{note.ID}})
	_, imageOnly := apiTestKey(t, db, store.APIKey{Scopes: []string{"attachments:read"}, NoteIDs: []string{note.ID}})
	_, notesOnly := apiTestKey(t, db, store.APIKey{Scopes: []string{"notes:read", "notes:write"}, NoteIDs: []string{note.ID}})
	_, broad := apiTestKey(t, db, store.APIKey{Scopes: []string{"attachments:read", "attachments:write"}, ProjectIDs: []string{project.ID, otherProject.ID}})
	image := apiTestPNG(t)
	response := apiTestUpload(t, app, note.ID, uploadOnly, "figure[1].png", image)
	apiTestStatus(t, response, 201)
	upload := apiTestDecode[apiTestUploadResult](t, response)
	attachment := upload.Attachment
	if attachment.ID == "" || attachment.NoteID != note.ID || attachment.Name != "figure[1].png" || attachment.MIME != "image/png" || attachment.Size != int64(len(image)) || attachment.CreatedAt.IsZero() || upload.Markdown != `![figure\[1\].png](attachment:`+attachment.ID+`)` {
		t.Fatalf("upload = %+v", upload)
	}
	apiTestNoSecrets(t, response, uploadOnly, tokenHash(uploadOnly), app.cfg.DataDir, attachment.ID+".png")
	stored, err := db.Note(t.Context(), note.ID)
	if err != nil || !reflect.DeepEqual(stored, note) {
		t.Fatalf("upload modified note text, metadata or version: %+v, %v", stored, err)
	}
	for _, token := range []string{imageOnly, notesOnly} {
		apiTestStatus(t, apiTestUpload(t, app, note.ID, token, "no.png", image), 403)
	}
	for _, target := range []string{neighbor.ID, other.ID, store.NewID()} {
		response := apiTestUpload(t, app, target, uploadOnly, "no.png", image)
		apiTestStatus(t, response, 404)
		apiTestNoSecrets(t, response, target, note.ID)
	}
	assets := map[string]string{note.ID: attachment.ID}
	for _, target := range []store.Note{neighbor, other} {
		response := apiTestUpload(t, app, target.ID, broad, "image.png", image)
		apiTestStatus(t, response, 201)
		assets[target.ID] = apiTestDecode[apiTestUploadResult](t, response).Attachment.ID
	}
	for _, tc := range []struct {
		name, token, noteID, attachmentID string
		status                            int
	}{
		{"allowed image only", imageOnly, note.ID, attachment.ID, 200},
		{"write is not read", uploadOnly, note.ID, attachment.ID, 403},
		{"notes are not images", notesOnly, note.ID, attachment.ID, 403},
		{"neighbor outside grant", imageOnly, neighbor.ID, assets[neighbor.ID], 404},
		{"other project outside grant", imageOnly, other.ID, assets[other.ID], 404},
		{"neighbor ID under allowed note", imageOnly, note.ID, assets[neighbor.ID], 404},
		{"cross project ID under allowed note", imageOnly, note.ID, assets[other.ID], 404},
		{"both notes allowed still bound", broad, note.ID, assets[neighbor.ID], 404},
		{"both projects allowed still bound", broad, note.ID, assets[other.ID], 404},
		{"missing attachment", imageOnly, note.ID, store.NewID(), 404},
		{"missing note", imageOnly, store.NewID(), attachment.ID, 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := "/api/v1/notes/" + tc.noteID + "/attachments/" + tc.attachmentID + "/content?noteID=" + note.ID
			response := apiTestRequest(app, "GET", path, tc.token, nil, nil)
			apiTestStatus(t, response, tc.status)
			if tc.status == 200 {
				if !bytes.Equal(response.Body.Bytes(), image) || response.Header().Get("Content-Type") != "image/png" {
					t.Fatal("content response did not contain the original PNG")
				}
			} else {
				apiTestNoSecrets(t, response, tc.noteID, tc.attachmentID, app.cfg.DataDir)
			}
		})
	}
	beforeFiles, err := os.ReadDir(filepath.Join(app.cfg.DataDir, "uploads"))
	if err != nil {
		t.Fatal(err)
	}
	apiTestStatus(t, apiTestUpload(t, app, note.ID, uploadOnly, "bad.svg", []byte(`<svg xmlns="http://www.w3.org/2000/svg"/>`)), 415)
	apiTestStatus(t, apiTestRequest(app, "POST", "/api/v1/notes/"+note.ID+"/attachments", uploadOnly, strings.NewReader(`{}`), nil), 415)
	app.cfg.MaxImageBytes = int64(len(image) - 1)
	apiTestStatus(t, apiTestUpload(t, app, note.ID, uploadOnly, "too-big.png", image), 413)
	app.cfg.MaxImageBytes = 10 << 20
	app.cfg.MaxStorageBytes = 1
	apiTestStatus(t, apiTestUpload(t, app, note.ID, uploadOnly, "over-quota.png", image), 413)
	afterFiles, err := os.ReadDir(filepath.Join(app.cfg.DataDir, "uploads"))
	if err != nil || len(beforeFiles) != len(afterFiles) {
		t.Fatalf("failed upload leaked a file: before=%d after=%d err=%v", len(beforeFiles), len(afterFiles), err)
	}
	stored, err = db.Note(t.Context(), note.ID)
	if err != nil || !reflect.DeepEqual(stored, note) {
		t.Fatalf("failed upload modified note: %+v, %v", stored, err)
	}
}

func TestAPIKeysRevocationExpiryAndMoves(t *testing.T) {
	app, db := newTestApp(t)
	project := apiTestProject(t, db, "Old project")
	destination := apiTestProject(t, db, "New project")
	note := apiTestNote(t, db, project.ID, "Moving note")
	neighbor := apiTestNote(t, db, destination.ID, "Hidden neighbor")
	scopes := []string{"notes:read", "notes:write", "attachments:read", "attachments:write"}
	projectKey, projectToken := apiTestKey(t, db, store.APIKey{Scopes: scopes, ProjectIDs: []string{project.ID}})
	_, noteToken := apiTestKey(t, db, store.APIKey{Scopes: scopes, NoteIDs: []string{note.ID}})
	past := time.Now().Add(-time.Hour)
	_, expired := apiTestKey(t, db, store.APIKey{Scopes: scopes, ProjectIDs: []string{project.ID}, ExpiresAt: &past})
	revokedKey, revoked := apiTestKey(t, db, store.APIKey{Scopes: scopes, ProjectIDs: []string{project.ID}})
	apiTestStatus(t, apiTestRequest(app, "GET", "/api/v1/notes/"+note.ID, revoked, nil, nil), 200)
	if err := db.RevokeAPIKey(t.Context(), revokedKey.ID); err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{expired, revoked} {
		for _, route := range []struct{ method, path string }{
			{"GET", "/api/v1/projects"},
			{"GET", "/api/v1/projects/" + project.ID + "/notes"},
			{"GET", "/api/v1/notes/" + note.ID},
			{"PUT", "/api/v1/notes/" + note.ID},
			{"POST", "/api/v1/projects/" + project.ID + "/notes"},
			{"POST", "/api/v1/notes/" + note.ID + "/attachments"},
			{"GET", "/api/v1/notes/" + note.ID + "/attachments/missing/content"},
		} {
			response := apiTestRequest(app, route.method, route.path, token, strings.NewReader(`{"title":"No","markdown":""}`), map[string]string{"If-Match": `"v1"`})
			apiTestStatus(t, response, 401)
			apiTestNoSecrets(t, response, token, tokenHash(token), project.ID, note.ID)
		}
	}
	image := apiTestPNG(t)
	upload := apiTestUpload(t, app, note.ID, projectToken, "image.png", image)
	apiTestStatus(t, upload, 201)
	attachment := apiTestDecode[apiTestUploadResult](t, upload).Attachment
	moved, err := db.SetNoteMetadata(t.Context(), note.ID, note.Title, destination.ID, note.Version)
	if err != nil {
		t.Fatal(err)
	}
	path := "/api/v1/notes/" + note.ID
	apiTestStatus(t, apiTestRequest(app, "GET", path, projectToken, nil, nil), 404)
	apiTestStatus(t, apiTestRequest(app, "PUT", path, projectToken, strings.NewReader(`{"title":"No","markdown":""}`), nil), 404)
	apiTestStatus(t, apiTestUpload(t, app, note.ID, projectToken, "no.png", image), 404)
	contentPath := path + "/attachments/" + attachment.ID + "/content"
	apiTestStatus(t, apiTestRequest(app, "GET", contentPath, projectToken, nil, nil), 404)
	apiTestStatus(t, apiTestRequest(app, "GET", "/api/v1/projects/"+destination.ID+"/notes?q=Moving", projectToken, nil, nil), 404)
	oldList := apiTestRequest(app, "GET", "/api/v1/projects/"+project.ID+"/notes", projectToken, nil, nil)
	apiTestStatus(t, oldList, 200)
	if notes := apiTestDecode[apiTestNoteList](t, oldList).Notes; notes == nil || len(notes) != 0 {
		t.Fatalf("moved note remains visible through old project: %s", oldList.Body.String())
	}
	parents := apiTestRequest(app, "GET", "/api/v1/projects", noteToken, nil, nil)
	apiTestStatus(t, parents, 200)
	projects := apiTestDecode[apiTestProjectList](t, parents).Projects
	if len(projects) != 1 || projects[0].ID != destination.ID {
		t.Fatalf("note grant did not follow its parent: %s", parents.Body.String())
	}
	apiTestStatus(t, apiTestRequest(app, "GET", "/api/v1/projects/"+project.ID+"/notes", noteToken, nil, nil), 404)
	newList := apiTestRequest(app, "GET", "/api/v1/projects/"+destination.ID+"/notes", noteToken, nil, nil)
	apiTestStatus(t, newList, 200)
	notes := apiTestDecode[apiTestNoteList](t, newList).Notes
	if len(notes) != 1 || notes[0].ID != note.ID {
		t.Fatalf("note grant exposed new neighbors: %s", newList.Body.String())
	}
	apiTestNoSecrets(t, newList, neighbor.ID)
	apiTestStatus(t, apiTestRequest(app, "GET", contentPath, noteToken, nil, nil), 200)
	response := apiTestRequest(app, "GET", path, noteToken, nil, nil)
	apiTestStatus(t, response, 200)
	if response.Header().Get("ETag") != etag(moved.Version) {
		t.Fatal("move did not update the API ETag")
	}
	apiTestStatus(t, apiTestRequest(app, "PUT", path, noteToken, strings.NewReader(`{"title":"Moved","markdown":""}`), map[string]string{"If-Match": etag(note.Version)}), 412)
	response = apiTestRequest(app, "PUT", path, noteToken, strings.NewReader(`{"title":"Moved","markdown":""}`), map[string]string{"If-Match": etag(moved.Version)})
	apiTestStatus(t, response, 200)
	updated := apiTestDecode[apiTestNoteResult](t, response)
	if updated.ProjectID != destination.ID || updated.Version != moved.Version+1 || updated.SourceName != note.SourceName {
		t.Fatalf("note-scoped write after move = %+v", updated)
	}
	if _, err := db.DeleteNote(t.Context(), note.ID, updated.Version); err != nil {
		t.Fatal(err)
	}
	parents = apiTestRequest(app, "GET", "/api/v1/projects", noteToken, nil, nil)
	apiTestStatus(t, parents, 200)
	projects = apiTestDecode[apiTestProjectList](t, parents).Projects
	if projects == nil || len(projects) != 0 {
		t.Fatal("deleted note grant must not reveal the old parent")
	}
	apiTestStatus(t, apiTestRequest(app, "GET", "/api/v1/projects/"+destination.ID+"/notes", noteToken, nil, nil), 404)
	if err := db.RevokeAPIKey(t.Context(), projectKey.ID); err != nil {
		t.Fatal(err)
	}
	apiTestStatus(t, apiTestRequest(app, "GET", "/api/v1/projects", projectToken, nil, nil), 401)
}

// These hooks change real PostgreSQL state after HTTP authorization but before
// the real store write. They expose any accidental Owner actor or cached-key
// authorization without replacing the store's transactional implementation.
type apiBeforeWriteRepository struct {
	store.Repository
	before func() error
}

func (s apiBeforeWriteRepository) CreateNote(ctx context.Context, note store.Note, actor store.Actor) (store.Note, error) {
	if err := s.before(); err != nil {
		return store.Note{}, err
	}
	return s.Repository.CreateNote(ctx, note, actor)
}

func (s apiBeforeWriteRepository) UpdateNote(ctx context.Context, id, title, markdown, source string, version int64, actor store.Actor) (store.Note, error) {
	if err := s.before(); err != nil {
		return store.Note{}, err
	}
	return s.Repository.UpdateNote(ctx, id, title, markdown, source, version, actor)
}

func (s apiBeforeWriteRepository) CreateAttachment(ctx context.Context, attachment store.Attachment, actor store.Actor, quota int64) (store.Attachment, error) {
	if err := s.before(); err != nil {
		return store.Attachment{}, err
	}
	return s.Repository.CreateAttachment(ctx, attachment, actor, quota)
}

func TestAPIWritesReauthorizeRevokedKeysAndMovedNotes(t *testing.T) {
	for _, operation := range []string{"create", "update", "upload"} {
		for _, change := range []string{"revoke", "move"} {
			if operation == "create" && change == "move" {
				continue
			}
			t.Run(operation+"/"+change, func(t *testing.T) {
				app, db := newTestApp(t)
				project := apiTestProject(t, db, "Project")
				destination := apiTestProject(t, db, "Other")
				note := apiTestNote(t, db, project.ID, "Original")
				key, token := apiTestKey(t, db, store.APIKey{Scopes: []string{"notes:write", "attachments:write"}, ProjectIDs: []string{project.ID}})
				want := 401
				before := func() error { return db.RevokeAPIKey(t.Context(), key.ID) }
				if change == "move" {
					want = 404
					before = func() error {
						_, err := db.SetNoteMetadata(t.Context(), note.ID, note.Title, destination.ID, note.Version)
						return err
					}
				}
				app.db = apiBeforeWriteRepository{Repository: db, before: before}
				var response *httptest.ResponseRecorder
				switch operation {
				case "create":
					response = apiTestRequest(app, "POST", "/api/v1/projects/"+project.ID+"/notes", token, strings.NewReader(`{"title":"Denied","markdown":"new text"}`), nil)
				case "update":
					response = apiTestRequest(app, "PUT", "/api/v1/notes/"+note.ID, token, strings.NewReader(`{"title":"Denied","markdown":"new text"}`), map[string]string{"If-Match": etag(note.Version)})
				case "upload":
					response = apiTestUpload(t, app, note.ID, token, "denied.png", apiTestPNG(t))
				}
				apiTestStatus(t, response, want)
				apiTestNoSecrets(t, response, key.TokenHash, token, note.ID, project.ID, destination.ID, app.cfg.DataDir)
				stored, err := db.Note(t.Context(), note.ID)
				if err != nil || stored.Title != note.Title || stored.Markdown != note.Markdown || stored.SourceName != note.SourceName {
					t.Fatalf("unauthorized write persisted: %+v, %v", stored, err)
				}
				if change == "move" && (stored.ProjectID != destination.ID || stored.Version != note.Version+1) {
					t.Fatalf("failed API write changed the owner's move: %+v", stored)
				}
				if change == "revoke" && stored.Version != note.Version {
					t.Fatal("revoked write changed the version")
				}
				notes, err := db.Notes(t.Context(), "", "", "modified")
				if err != nil || len(notes) != 1 {
					t.Fatalf("unauthorized create persisted: %+v, %v", notes, err)
				}
				attachments, err := db.Attachments(t.Context(), note.ID)
				if err != nil || len(attachments) != 0 {
					t.Fatalf("unauthorized attachment persisted: %+v, %v", attachments, err)
				}
				files, err := os.ReadDir(filepath.Join(app.cfg.DataDir, "uploads"))
				if err != nil || len(files) != 0 {
					t.Fatalf("unauthorized upload left files: %v, %v", files, err)
				}
			})
		}
	}
}

func TestAPINoDeleteShareOrAdministration(t *testing.T) {
	app, db := newTestApp(t)
	project := apiTestProject(t, db, "Project")
	note := apiTestNote(t, db, project.ID, "Original")
	_, token := apiTestKey(t, db, store.APIKey{Scopes: []string{"notes:read", "notes:write", "attachments:read", "attachments:write"}, ProjectIDs: []string{project.ID}})
	for _, route := range []struct{ method, path string }{
		{"DELETE", "/api/v1/notes/" + note.ID},
		{"DELETE", "/api/v1/projects/" + project.ID},
		{"POST", "/api/v1/projects"},
		{"POST", "/api/v1/notes/" + note.ID + "/share"},
		{"POST", "/api/v1/settings/api-keys"},
		{"GET", "/api/v1/settings/api-keys"},
		{"POST", "/api/v1/owner"},
	} {
		response := apiTestRequest(app, route.method, route.path, token, strings.NewReader(`{"title":"No","markdown":""}`), nil)
		if response.Code != 404 && response.Code != 405 {
			t.Errorf("unexpected admin/delete/share route %s %s: %d %s", route.method, route.path, response.Code, response.Body.String())
		}
		apiTestNoSecrets(t, response, token, tokenHash(token))
	}
	stored, err := db.Note(t.Context(), note.ID)
	if err != nil || !reflect.DeepEqual(stored, note) {
		t.Fatalf("unsupported API operation mutated note: %+v, %v", stored, err)
	}
}

type apiFailingProjectsRepository struct {
	store.Repository
	err error
}

func (s apiFailingProjectsRepository) Projects(context.Context) ([]store.Project, error) {
	return nil, s.err
}

func TestAPIInternalErrorsDoNotExposeSecrets(t *testing.T) {
	app, db := newTestApp(t)
	_, token := apiTestKey(t, db, store.APIKey{Scopes: []string{"notes:read"}})
	secret := "private-database-error-detail"
	app.db = apiFailingProjectsRepository{Repository: db, err: errors.New(secret + ": " + token + ": " + app.cfg.DataDir)}
	response := apiTestRequest(app, "GET", "/api/v1/projects", token, nil, nil)
	apiTestStatus(t, response, 500)
	apiTestNoSecrets(t, response, secret, token, tokenHash(token), app.cfg.DataDir, string(app.cfg.Secret))
}

func TestAPIIntegrationSchemasAreIsolated(t *testing.T) {
	_, first := newTestApp(t)
	_, second := newTestApp(t)
	apiTestProject(t, first, "Only in first schema")
	projects, err := second.Projects(t.Context())
	if err != nil || len(projects) != 0 {
		t.Fatalf("test stores share schema state: %+v, %v", projects, err)
	}
}
