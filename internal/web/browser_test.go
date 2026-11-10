package web

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"conspect/internal/store"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/html"
)

const (
	browserTestUsername = "browser-owner"
	browserTestPassword = "browser-test-only-password"
)

type browserTestClient struct {
	app    *App
	db     *store.Store
	cookie *http.Cookie
	csrf   string
}

type browserTestUpload struct {
	field, name string
	data        []byte
}

// Exercise the complete handler without listeners, redirect following, or a
// forged session context. Cookies and form tokens come from actual responses.
func (b *browserTestClient) request(t *testing.T, method, path string, body io.Reader, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	r := httptest.NewRequestWithContext(ctx, method, b.app.cfg.BaseURL+path, body)
	if b.cookie != nil {
		r.AddCookie(b.cookie)
	}
	for key, value := range headers {
		r.Header.Set(key, value)
	}
	response := httptest.NewRecorder()
	b.app.Handler().ServeHTTP(response, r)
	if err := ctx.Err(); err != nil {
		t.Fatalf("%s %s exceeded request deadline: %v", method, path, err)
	}
	return response
}

func browserTestStatus(t *testing.T, response *httptest.ResponseRecorder, want int) {
	t.Helper()
	if response.Code != want {
		body := response.Body.String()
		if len(body) > 2000 {
			body = body[:2000] + "…"
		}
		t.Fatalf("HTTP status = %d, want %d; body: %s", response.Code, want, body)
	}
}

func browserTestRedirect(t *testing.T, response *httptest.ResponseRecorder, path string) {
	t.Helper()
	browserTestStatus(t, response, http.StatusSeeOther)
	if got := response.Header().Get("Location"); got != path {
		t.Fatalf("redirect = %q, want %q", got, path)
	}
}

func browserTestDocument(t *testing.T, response *httptest.ResponseRecorder) *html.Node {
	t.Helper()
	if got := response.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/html; charset=utf-8") {
		t.Fatalf("HTML Content-Type = %q", got)
	}
	doc, err := html.Parse(bytes.NewReader(response.Body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func browserTestWalk(node *html.Node, visit func(*html.Node)) {
	visit(node)
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		browserTestWalk(child, visit)
	}
}

func browserTestElements(doc *html.Node, tag string) []*html.Node {
	var result []*html.Node
	browserTestWalk(doc, func(node *html.Node) {
		if node.Type == html.ElementNode && node.Data == tag {
			result = append(result, node)
		}
	})
	return result
}

func browserTestAttr(node *html.Node, name string) string {
	for _, attr := range node.Attr {
		if attr.Key == name {
			return attr.Val
		}
	}
	return ""
}

func browserTestText(doc *html.Node) string {
	var text strings.Builder
	browserTestWalk(doc, func(node *html.Node) {
		if node.Type == html.TextNode {
			text.WriteString(node.Data)
		}
	})
	return text.String()
}

func browserTestForm(t *testing.T, doc *html.Node, action string) *html.Node {
	t.Helper()
	for _, form := range browserTestElements(doc, "form") {
		if browserTestAttr(form, "action") == action && strings.EqualFold(browserTestAttr(form, "method"), "post") {
			return form
		}
	}
	t.Fatalf("missing POST form for %q", action)
	return nil
}

func browserTestInput(t *testing.T, doc *html.Node, name string) string {
	t.Helper()
	for _, input := range browserTestElements(doc, "input") {
		if browserTestAttr(input, "name") == name {
			return browserTestAttr(input, "value")
		}
	}
	t.Fatalf("missing input %q", name)
	return ""
}

func browserTestInputID(doc *html.Node, id string) *html.Node {
	for _, input := range browserTestElements(doc, "input") {
		if browserTestAttr(input, "id") == id {
			return input
		}
	}
	return nil
}

func browserTestHasLink(doc *html.Node, path string) bool {
	for _, link := range browserTestElements(doc, "a") {
		if browserTestAttr(link, "href") == path {
			return true
		}
	}
	return false
}

func browserTestSecurity(t *testing.T, response *httptest.ResponseRecorder, referrerPolicy ...string) {
	t.Helper()
	policy := "same-origin"
	if len(referrerPolicy) > 0 {
		policy = referrerPolicy[0]
	}
	for key, want := range map[string]string{
		"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
		"Referrer-Policy": policy, "X-Robots-Tag": "noindex, nofollow",
	} {
		if got := response.Header().Get(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	csp := response.Header().Get("Content-Security-Policy")
	for _, directive := range []string{"default-src 'self'", "script-src 'self'", "img-src 'self'", "connect-src 'none'", "form-action 'self'", "frame-ancestors 'none'"} {
		if !slices.Contains(strings.Split(csp, "; "), directive) {
			t.Errorf("missing CSP directive %q: %q", directive, csp)
		}
	}
	if response.Header().Get("X-Request-ID") == "" {
		t.Error("missing request ID")
	}
}

func browserTestReferrerMeta(t *testing.T, doc *html.Node, want string) {
	t.Helper()
	var policies []string
	for _, meta := range browserTestElements(doc, "meta") {
		if strings.EqualFold(browserTestAttr(meta, "name"), "referrer") {
			if meta.Parent == nil || meta.Parent.Data != "head" {
				t.Error("referrer meta is outside the document head")
			}
			policies = append(policies, browserTestAttr(meta, "content"))
		}
	}
	if !reflect.DeepEqual(policies, []string{want}) {
		t.Errorf("referrer meta policies = %v, want exactly [%s]", policies, want)
	}
}

func browserTestManagementNote(t *testing.T, doc *html.Node, noteID string) *html.Node {
	t.Helper()
	for _, article := range browserTestElements(doc, "article") {
		if browserTestAttr(article, "aria-labelledby") == "note-"+noteID+"-title" {
			return article
		}
	}
	t.Fatalf("management page omitted note %s", noteID)
	return nil
}

func browserTestShareActions(t *testing.T, doc *html.Node, noteID, csrf string) []string {
	t.Helper()
	var actions []string
	for _, form := range browserTestElements(doc, "form") {
		if browserTestAttr(form, "action") != "/notes/"+noteID+"/share" {
			continue
		}
		if browserTestAttr(form, "method") != "post" || browserTestInput(t, form, "csrf") != csrf {
			t.Error("share control has incorrect method or session CSRF token")
		}
		buttons := browserTestElements(form, "button")
		if len(buttons) != 1 || browserTestAttr(buttons[0], "type") != "submit" || strings.TrimSpace(browserTestText(buttons[0])) == "" {
			t.Error("share control omitted its submit button")
		}
		browserTestWalk(form, func(node *html.Node) {
			for _, attr := range node.Attr {
				if attr.Key == "hidden" || attr.Key == "disabled" {
					t.Error("share control is hidden or disabled")
				}
			}
		})
		actions = append(actions, browserTestInput(t, form, "action"))
	}
	slices.Sort(actions)
	return actions
}

func browserTestNoPrivateValues(t *testing.T, response *httptest.ResponseRecorder, values ...string) {
	t.Helper()
	for _, value := range values {
		if value != "" && strings.Contains(response.Body.String(), value) {
			t.Error("response exposes a private value")
		}
	}
}

func browserTestOwner(t *testing.T, app *App, db *store.Store) *browserTestClient {
	t.Helper()
	// Login still uses real bcrypt; reducing the fixture cost keeps the race
	// suite fast. The bootstrap test also exercises a production-cost hash.
	hash, err := bcrypt.GenerateFromPassword([]byte(browserTestPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureOwner(t.Context(), browserTestUsername, string(hash)); err != nil {
		t.Fatal(err)
	}
	b := &browserTestClient{app: app, db: db}
	b.login(t, browserTestUsername, browserTestPassword)
	return b
}

func (b *browserTestClient) login(t *testing.T, username, password string) *httptest.ResponseRecorder {
	t.Helper()
	response := b.request(t, "POST", "/login", strings.NewReader(url.Values{"username": {username}, "password": {password}}.Encode()), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded", "Origin": b.app.cfg.BaseURL,
	})
	browserTestRedirect(t, response, "/projects")
	result := response.Result()
	defer result.Body.Close()
	cookies := result.Cookies()
	if len(cookies) != 1 || cookies[0].Name != sessionCookie || cookies[0].Value == "" {
		t.Fatalf("login did not issue exactly one session cookie: %v", cookies)
	}
	b.cookie = cookies[0]
	page := b.request(t, "GET", "/projects", nil, nil)
	browserTestStatus(t, page, 200)
	b.csrf = browserTestInput(t, browserTestForm(t, browserTestDocument(t, page), "/projects"), "csrf")
	if b.csrf == "" {
		t.Fatal("authenticated form has no CSRF token")
	}
	return response
}

func (b *browserTestClient) fields(values url.Values) url.Values {
	fields := make(url.Values, len(values)+1)
	for key, values := range values {
		fields[key] = slices.Clone(values)
	}
	if !fields.Has("csrf") {
		fields.Set("csrf", b.csrf)
	}
	return fields
}

func (b *browserTestClient) form(t *testing.T, path string, values url.Values) *httptest.ResponseRecorder {
	t.Helper()
	return b.request(t, "POST", path, strings.NewReader(b.fields(values).Encode()), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded", "Origin": b.app.cfg.BaseURL,
	})
}

func (b *browserTestClient) api(t *testing.T, method, path, token string, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()
	response := b.request(t, method, path, body, map[string]string{"Authorization": "Bearer " + token, "Content-Type": "application/json"})
	browserTestSecurity(t, response, "no-referrer")
	return response
}

func (b *browserTestClient) multipart(t *testing.T, path string, values url.Values, files ...browserTestUpload) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for key, values := range b.fields(values) {
		for _, value := range values {
			if err := writer.WriteField(key, value); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, file := range files {
		part, err := writer.CreateFormFile(file.field, file.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write(file.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return b.request(t, "POST", path, &body, map[string]string{"Content-Type": writer.FormDataContentType(), "Origin": b.app.cfg.BaseURL})
}

func (b *browserTestClient) createProject(t *testing.T, name, description string) store.Project {
	t.Helper()
	response := b.form(t, "/projects", url.Values{"name": {name}, "description": {description}})
	browserTestStatus(t, response, 303)
	path := response.Header().Get("Location")
	if !strings.HasPrefix(path, "/projects/") || !strings.HasSuffix(path, "/manage") {
		t.Fatalf("unexpected project redirect %q", path)
	}
	id := strings.TrimSuffix(strings.TrimPrefix(path, "/projects/"), "/manage")
	project, err := b.db.Project(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	if project.Name != strings.TrimSpace(name) || project.Description != description {
		t.Fatalf("project fields not persisted: %+v", project)
	}
	return project
}

func (b *browserTestClient) notes(t *testing.T, projectID string) []store.Note {
	t.Helper()
	notes, err := b.db.Notes(t.Context(), projectID, "", "title")
	if err != nil {
		t.Fatal(err)
	}
	return notes
}

func (b *browserTestClient) note(t *testing.T, id string) store.Note {
	t.Helper()
	note, err := b.db.Note(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	return note
}

func (b *browserTestClient) importNotes(t *testing.T, projectID string, files ...browserTestUpload) []store.Note {
	t.Helper()
	before := make(map[string]bool)
	for _, note := range b.notes(t, projectID) {
		before[note.ID] = true
	}
	response := b.multipart(t, "/projects/"+projectID+"/notes", nil, files...)
	browserTestRedirect(t, response, "/projects/"+projectID+"/manage")
	var imported []store.Note
	for _, note := range b.notes(t, projectID) {
		if !before[note.ID] {
			imported = append(imported, note)
		}
	}
	if len(imported) != len(files) {
		t.Fatalf("imported %d notes for %d files", len(imported), len(files))
	}
	return imported
}

func browserTestMarkdown(name, source string) browserTestUpload {
	return browserTestUpload{field: "files", name: name, data: []byte(source)}
}

func (b *browserTestClient) version(t *testing.T, note store.Note, action string) string {
	t.Helper()
	page := b.request(t, "GET", "/notes/"+note.ID+"/manage", nil, nil)
	browserTestStatus(t, page, 200)
	form := browserTestForm(t, browserTestDocument(t, page), "/notes/"+note.ID+"/"+action)
	if csrf := browserTestInput(t, form, "csrf"); csrf != b.csrf {
		t.Fatal("management form has wrong session CSRF token")
	}
	version := browserTestInput(t, form, "version")
	if version != strconv.FormatInt(note.Version, 10) {
		t.Fatalf("form version = %q, stored version = %d", version, note.Version)
	}
	return version
}

func (b *browserTestClient) uploadImage(t *testing.T, note store.Note, name string) store.Attachment {
	t.Helper()
	before, err := b.db.Attachments(t.Context(), note.ID)
	if err != nil {
		t.Fatal(err)
	}
	response := b.multipart(t, "/notes/"+note.ID+"/attachments", nil, browserTestUpload{field: "file", name: name, data: apiTestPNG(t)})
	browserTestRedirect(t, response, "/notes/"+note.ID+"/manage")
	after, err := b.db.Attachments(t.Context(), note.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before)+1 {
		t.Fatal("image upload did not add exactly one attachment")
	}
	if current := b.note(t, note.ID); !reflect.DeepEqual(current, note) {
		t.Error("upload changed note source or version")
	}
	page := b.request(t, "GET", "/notes/"+note.ID+"/manage", nil, nil)
	browserTestStatus(t, page, 200)
	doc := browserTestDocument(t, page)
	for _, file := range after {
		if slices.ContainsFunc(before, func(old store.Attachment) bool { return old.ID == file.ID }) {
			continue
		}
		input := browserTestInputID(doc, "markdown-"+file.ID)
		if input == nil || browserTestAttr(input, "value") != imageMarkdown(file) || !browserTestHasLink(doc, "/notes/"+note.ID+"/attachments/"+file.ID) {
			t.Fatal("management page omitted attachment URL or Markdown snippet")
		}
		data, err := os.ReadFile(filepath.Join(b.app.cfg.DataDir, "uploads", file.StorageKey))
		if err != nil || !bytes.Equal(data, apiTestPNG(t)) {
			t.Fatalf("uploaded bytes not persisted: %v", err)
		}
		return file
	}
	t.Fatal("new attachment not found")
	return store.Attachment{}
}

func (b *browserTestClient) shareURL(t *testing.T, noteID string) string {
	t.Helper()
	page := b.request(t, "GET", "/notes/"+noteID+"/share", nil, nil)
	browserTestStatus(t, page, 200)
	input := browserTestInputID(browserTestDocument(t, page), "share-url")
	if input == nil {
		t.Fatal("share administration page omitted active URL")
	}
	value := browserTestAttr(input, "value")
	u, err := url.Parse(value)
	if err != nil || u.Scheme+"://"+u.Host != b.app.cfg.BaseURL || !strings.HasPrefix(u.Path, "/s/") || u.RawQuery != "" || u.Fragment != "" {
		t.Fatalf("invalid share URL %q", value)
	}
	token, err := hex.DecodeString(strings.TrimPrefix(u.Path, "/s/"))
	if err != nil || len(token) != 32 {
		t.Fatal("share URL does not contain a 256-bit opaque token")
	}
	if !slices.ContainsFunc(input.Attr, func(attr html.Attribute) bool { return attr.Key == "readonly" }) {
		t.Fatal("share URL input is not read-only")
	}
	return u.Path
}

func (b *browserTestClient) changeShare(t *testing.T, noteID, action string) {
	t.Helper()
	response := b.form(t, "/notes/"+noteID+"/share", url.Values{"action": {action}})
	browserTestRedirect(t, response, "/notes/"+noteID+"/share")
}

func TestBrowserBootstrapLoginSessionAndLogout(t *testing.T) {
	app, db := newTestApp(t)
	b := &browserTestClient{app: app, db: db}
	if _, err := db.Owner(t.Context()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("new schema unexpectedly has an owner: %v", err)
	}
	login := b.request(t, "GET", "/login", nil, nil)
	browserTestStatus(t, login, 200)
	browserTestSecurity(t, login)
	passwordInput := browserTestInputID(browserTestDocument(t, login), "password")
	if passwordInput == nil || browserTestAttr(passwordInput, "type") != "password" || browserTestAttr(passwordInput, "autocomplete") != "current-password" || browserTestAttr(passwordInput, "value") != "" {
		t.Fatal("login form does not use an empty password input")
	}
	browserTestRedirect(t, b.request(t, "GET", "/projects", nil, nil), "/login")

	hash, err := bcrypt.GenerateFromPassword([]byte(browserTestPassword), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureOwner(t.Context(), browserTestUsername, string(hash)); err != nil {
		t.Fatal(err)
	}
	replacementHash, err := bcrypt.GenerateFromPassword([]byte("changed-bootstrap-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.EnsureOwner(t.Context(), "replacement-owner", string(replacementHash)); err != nil {
		t.Fatal(err)
	}
	owner, err := db.Owner(t.Context())
	if err != nil || owner.Username != browserTestUsername || owner.PasswordHash != string(hash) || bcrypt.CompareHashAndPassword([]byte(owner.PasswordHash), []byte(browserTestPassword)) != nil {
		t.Fatalf("bootstrap was not insert-only or lost password hash: %v", err)
	}

	var failureText string
	for _, credentials := range []struct{ username, password string }{
		{browserTestUsername, "wrong-password"}, {"unknown-owner", browserTestPassword}, {"replacement-owner", "changed-bootstrap-password"},
	} {
		response := b.form(t, "/login", url.Values{"username": {credentials.username}, "password": {credentials.password}})
		browserTestStatus(t, response, 401)
		if len(response.Result().Cookies()) != 0 {
			t.Error("failed login issued a cookie")
		}
		text := browserTestText(browserTestDocument(t, response))
		if failureText != "" && failureText != text {
			t.Error("login errors disclose whether username exists")
		}
		failureText = text
		browserTestNoPrivateValues(t, response, credentials.password, string(hash), string(replacementHash))
	}

	before := time.Now()
	response := b.login(t, browserTestUsername, browserTestPassword)
	after := time.Now()
	cookie := b.cookie
	if cookie.Path != "/" || cookie.Domain != "" || !cookie.HttpOnly || cookie.Secure || cookie.SameSite != http.SameSiteLaxMode || cookie.MaxAge != 43200 {
		t.Fatalf("insecure/incorrect HTTP session cookie attributes: %+v", cookie)
	}
	if cookie.Expires.Before(before.Add(12*time.Hour-time.Second)) || cookie.Expires.After(after.Add(12*time.Hour+time.Second)) {
		t.Errorf("cookie expiry = %s, want 12 hours from login", cookie.Expires)
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(cookie.Value, "sess_"))
	if !strings.HasPrefix(cookie.Value, "sess_") || err != nil || len(raw) != 32 {
		t.Fatal("session cookie does not contain a random 256-bit token")
	}
	session, err := db.Session(t.Context(), tokenHash(cookie.Value))
	if err != nil || session.CSRFToken != b.csrf || session.TokenHash == cookie.Value || !strings.HasPrefix(session.CSRFToken, "csrf_") || session.ExpiresAt.Before(before.Add(12*time.Hour)) || session.ExpiresAt.After(after.Add(12*time.Hour)) {
		t.Fatalf("stored session does not match login response: %v", err)
	}
	if _, err := db.Session(t.Context(), cookie.Value); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("session accepted unhashed bearer token as database lookup: %v", err)
	}
	browserTestSecurity(t, response)
	browserTestNoPrivateValues(t, response, browserTestPassword, string(hash), session.TokenHash)

	second := &browserTestClient{app: app, db: db}
	second.login(t, browserTestUsername, browserTestPassword)
	if second.cookie.Value == cookie.Value || second.csrf == b.csrf {
		t.Error("independent logins reused session or CSRF tokens")
	}

	logout := b.form(t, "/logout", nil)
	browserTestRedirect(t, logout, "/login")
	cleared := logout.Result().Cookies()
	if len(cleared) != 1 || cleared[0].Name != sessionCookie || cleared[0].Value != "" || cleared[0].Path != "/" || cleared[0].MaxAge != -1 || !cleared[0].Expires.Before(before) || !cleared[0].HttpOnly || cleared[0].Secure || cleared[0].SameSite != http.SameSiteLaxMode {
		t.Fatalf("logout did not clear the session cookie safely: %+v", cleared)
	}
	if _, err := db.Session(t.Context(), session.TokenHash); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("logout left an active session: %v", err)
	}
	browserTestRedirect(t, b.request(t, "GET", "/projects", nil, nil), "/login")
	browserTestStatus(t, second.request(t, "GET", "/projects", nil, nil), 200)

	// Expire a genuinely issued session deterministically; no sleeps or clock
	// overrides, and the client deliberately keeps its still-unexpired cookie.
	expired, err := db.Session(t.Context(), tokenHash(second.cookie.Value))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteSession(t.Context(), expired.TokenHash); err != nil {
		t.Fatal(err)
	}
	expired.ExpiresAt = time.Now().Add(-time.Minute)
	if err := db.CreateSession(t.Context(), expired); err != nil {
		t.Fatal(err)
	}
	browserTestRedirect(t, second.request(t, "GET", "/projects", nil, nil), "/login")
	browserTestRedirect(t, second.form(t, "/projects", url.Values{"name": {"must not exist"}}), "/login")
	forged := &browserTestClient{app: app, db: db, cookie: &http.Cookie{Name: sessionCookie, Value: "sess_forged"}}
	browserTestRedirect(t, forged.request(t, "GET", "/settings/api-keys", nil, nil), "/login")
	if len(b.notes(t, "")) != 0 {
		t.Error("authentication tests unexpectedly created notes")
	}
	projects, err := db.Projects(t.Context())
	if err != nil || len(projects) != 0 {
		t.Fatalf("expired session mutated projects: %v", err)
	}

	t.Run("HTTPS cookie and logout", func(t *testing.T) {
		cfg := app.cfg
		cfg.BaseURL = "https://localhost"
		secureApp, err := New(db, cfg)
		if err != nil {
			t.Fatal(err)
		}
		secure := &browserTestClient{app: secureApp, db: db}
		login := secure.login(t, browserTestUsername, browserTestPassword)
		if !secure.cookie.Secure || !secure.cookie.HttpOnly || secure.cookie.SameSite != http.SameSiteLaxMode || login.Header().Get("Strict-Transport-Security") != "max-age=31536000" {
			t.Error("HTTPS login omitted Secure cookie or HSTS")
		}
		logout := secure.form(t, "/logout", nil)
		browserTestRedirect(t, logout, "/login")
		cookies := logout.Result().Cookies()
		if len(cookies) != 1 || !cookies[0].Secure || cookies[0].MaxAge != -1 {
			t.Error("HTTPS logout did not clear the Secure cookie")
		}
	})
}

func TestBrowserFormPagesPreserveSameOriginReferrerPolicy(t *testing.T) {
	app, db := newTestApp(t)
	b := browserTestOwner(t, app, db)
	anonymous := &browserTestClient{app: app, db: db}
	project := b.createProject(t, "Native forms", "")
	note := b.importNotes(t, project.ID, browserTestMarkdown("forms.md", "# Form policy"))[0]
	for _, tc := range []struct {
		path   string
		client *browserTestClient
	}{
		{"/login", anonymous}, {"/projects", b}, {"/projects/" + project.ID, b},
		{"/projects/" + project.ID + "/manage", b}, {"/notes/" + note.ID + "/manage", b}, {"/notes/" + note.ID + "/share", b}, {"/settings/api-keys", b},
	} {
		t.Run(tc.path, func(t *testing.T) {
			response := tc.client.request(t, "GET", tc.path, nil, nil)
			browserTestStatus(t, response, 200)
			browserTestSecurity(t, response)
			doc := browserTestDocument(t, response)
			// A no-referrer meta can override a compatible response header and
			// make a browser's native form POST send Origin: null.
			browserTestReferrerMeta(t, doc, "same-origin")
			posts := 0
			for _, form := range browserTestElements(doc, "form") {
				if !strings.EqualFold(browserTestAttr(form, "method"), "post") {
					continue
				}
				posts++
				action := browserTestAttr(form, "action")
				u, err := url.Parse(action)
				if err != nil || !strings.HasPrefix(action, "/") || strings.HasPrefix(action, "//") || u.IsAbs() || u.Host != "" {
					t.Fatalf("native POST form is not same-origin: %q", action)
				}
				if action != "/login" && browserTestInput(t, form, "csrf") != b.csrf {
					t.Error("native management form omitted its session CSRF token")
				}
			}
			if posts == 0 {
				t.Error("form page contains no native POST forms")
			}
		})
	}
	anonymous.login(t, browserTestUsername, browserTestPassword)
	page := b.request(t, "GET", "/projects/"+project.ID+"/manage", nil, nil)
	browserTestStatus(t, page, 200)
	action := "/projects/" + project.ID + "/edit"
	form := browserTestForm(t, browserTestDocument(t, page), action)
	browserTestRedirect(t, b.form(t, browserTestAttr(form, "action"), url.Values{
		"csrf": {browserTestInput(t, form, "csrf")}, "name": {"Native form edit"}, "description": {"Submitted without JavaScript"},
	}), "/projects/"+project.ID+"/manage")
	updated, err := db.Project(t.Context(), project.ID)
	if err != nil || updated.Name != "Native form edit" || updated.Description != "Submitted without JavaScript" {
		t.Fatalf("same-origin native form submission failed: %v", err)
	}
}

func TestBrowserCSRFRequiresOriginAndSessionToken(t *testing.T) {
	app, db := newTestApp(t)
	b := browserTestOwner(t, app, db)
	other := &browserTestClient{app: app, db: db}
	other.login(t, browserTestUsername, browserTestPassword)
	anonymous := &browserTestClient{app: app, db: db}
	browserTestStatus(t, anonymous.form(t, "/projects", url.Values{"name": {"anonymous"}}), 401)

	for _, tc := range []struct{ name, origin, csrf string }{
		{"missing origin", "", b.csrf}, {"cross origin", "https://evil.example", b.csrf},
		{"null origin", "null", b.csrf}, {"origin with path", app.cfg.BaseURL + "/", b.csrf},
		{"missing token", app.cfg.BaseURL, ""}, {"incorrect token", app.cfg.BaseURL, "csrf_forged"},
		{"different session token", app.cfg.BaseURL, other.csrf},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := b.request(t, "POST", "/projects", strings.NewReader(url.Values{"name": {"must not exist"}, "csrf": {tc.csrf}}.Encode()), map[string]string{
				"Content-Type": "application/x-www-form-urlencoded", "Origin": tc.origin, "Referer": app.cfg.BaseURL + "/projects",
			})
			browserTestStatus(t, response, 403)
			projects, err := db.Projects(t.Context())
			if err != nil || len(projects) != 0 {
				t.Fatalf("rejected CSRF request changed projects: %v", err)
			}
		})
	}
	for _, origin := range []string{"", "null", "https://evil.example"} {
		response := anonymous.request(t, "POST", "/login", strings.NewReader(url.Values{"username": {browserTestUsername}, "password": {browserTestPassword}}.Encode()), map[string]string{
			"Content-Type": "application/x-www-form-urlencoded", "Origin": origin, "Referer": app.cfg.BaseURL + "/login",
		})
		browserTestStatus(t, response, 403)
		if len(response.Result().Cookies()) != 0 {
			t.Error("cross-origin login issued a session")
		}
	}
	browserTestStatus(t, b.form(t, "/logout", url.Values{"csrf": {other.csrf}}), 403)
	browserTestStatus(t, b.request(t, "GET", "/projects", nil, nil), 200)

	project := b.createProject(t, "CSRF project", "")
	file := browserTestMarkdown("source.md", "# Must not import")
	for _, csrf := range []string{"", "csrf_wrong", other.csrf} {
		browserTestStatus(t, b.multipart(t, "/projects/"+project.ID+"/notes", url.Values{"csrf": {csrf}}, file), 403)
		if len(b.notes(t, project.ID)) != 0 {
			t.Fatal("rejected multipart CSRF request imported a note")
		}
	}
	b.importNotes(t, project.ID, browserTestMarkdown("valid.md", "# Valid multipart CSRF"))
}

func TestBrowserProjectsAndMarkdownImports(t *testing.T) {
	app, db := newTestApp(t)
	b := browserTestOwner(t, app, db)
	project := b.createProject(t, "  Математика <основы>  ", "Описание <script>not executable</script>")
	managePath := "/projects/" + project.ID + "/manage"
	page := b.request(t, "GET", managePath, nil, nil)
	browserTestStatus(t, page, 200)
	doc := browserTestDocument(t, page)
	for _, action := range []string{"/projects/" + project.ID + "/edit", "/projects/" + project.ID + "/notes", "/projects/" + project.ID + "/delete"} {
		form := browserTestForm(t, doc, action)
		if browserTestAttr(form, "method") != "post" || browserTestInput(t, form, "csrf") != b.csrf {
			t.Errorf("management form %q has incorrect method or CSRF", action)
		}
	}
	if len(browserTestElements(doc, "script")) != 0 || !strings.Contains(browserTestText(doc), project.Description) {
		t.Error("project description was not escaped as text")
	}
	browserTestRedirect(t, b.form(t, "/projects/"+project.ID+"/edit", url.Values{"name": {"Изменённый проект"}, "description": {"Новое описание"}}), managePath)
	updatedProject, err := db.Project(t.Context(), project.ID)
	if err != nil || updatedProject.Name != "Изменённый проект" || updatedProject.Description != "Новое описание" || !updatedProject.CreatedAt.Equal(project.CreatedAt) {
		t.Fatalf("project edit was not persisted correctly: %v", err)
	}
	for _, fields := range []url.Values{
		{"name": {"  "}}, {"name": {strings.Repeat("я", 301)}}, {"name": {"valid"}, "description": {strings.Repeat("x", 4001)}},
	} {
		browserTestStatus(t, b.form(t, "/projects/"+project.ID+"/edit", fields), 422)
		actual, err := db.Project(t.Context(), project.ID)
		if err != nil || !reflect.DeepEqual(actual, updatedProject) {
			t.Fatalf("invalid project edit changed persisted state: %v", err)
		}
	}

	files := []browserTestUpload{
		browserTestMarkdown("heading.md", "```md\n# Fenced fake title\n```\n\n    # Indented fake title\n\n## Smaller heading\n\n# Настоящий заголовок\n\nТекст с уникальнымсловом и UTF-8: λ, 日本語.\n"),
		browserTestMarkdown("Запасное имя.MD", "~~~md\n# Another fake title\n~~~\n\n    # Also code\n\nТекст без заголовка первого уровня.\n"),
		browserTestMarkdown("setext.md", "Сетекст\n=======\n\nСодержимое.\n"),
	}
	imported := b.importNotes(t, project.ID, files...)
	bySource := make(map[string]store.Note)
	for _, note := range imported {
		bySource[note.SourceName] = note
		if note.ProjectID != project.ID || note.Version != 1 || note.CreatedAt.IsZero() || note.UpdatedAt.IsZero() {
			t.Errorf("incomplete imported note metadata: %+v", note)
		}
	}
	for i, title := range []string{"Настоящий заголовок", "Запасное имя", "Сетекст"} {
		note, ok := bySource[files[i].name]
		if !ok || note.Title != title || note.Markdown != string(files[i].data) {
			t.Errorf("import %q did not preserve UTF-8 source or derive title %q: %+v", files[i].name, title, note)
		}
	}
	duplicate := b.importNotes(t, project.ID, files[0])[0]
	if duplicate.ID == bySource[files[0].name].ID || duplicate.Version != 1 || len(b.notes(t, project.ID)) != 4 {
		t.Fatal("same filename overwrote an existing note")
	}
	if actual := b.note(t, bySource[files[0].name].ID); !reflect.DeepEqual(actual, bySource[files[0].name]) {
		t.Error("duplicate import modified original note")
	}
	page = b.request(t, "GET", "/projects/"+project.ID, nil, nil)
	browserTestStatus(t, page, 200)
	doc = browserTestDocument(t, page)
	if !browserTestHasLink(doc, managePath) {
		t.Error("project page omitted separate management link")
	}
	for _, note := range b.notes(t, project.ID) {
		if !browserTestHasLink(doc, "/notes/"+note.ID) {
			t.Errorf("project table of contents omitted note %s", note.ID)
		}
	}
	for _, path := range []string{"/projects?q=уникальнымсловом", "/projects/" + project.ID + "?q=уникальнымсловом&sort=title"} {
		page := b.request(t, "GET", path, nil, nil)
		browserTestStatus(t, page, 200)
		doc := browserTestDocument(t, page)
		if !browserTestHasLink(doc, "/notes/"+duplicate.ID) || browserTestHasLink(doc, "/notes/"+bySource["setext.md"].ID) {
			t.Error("browser search did not filter by source text")
		}
	}

	tooMany := make([]browserTestUpload, 33)
	for i := range tooMany {
		tooMany[i] = browserTestMarkdown(strconv.Itoa(i)+".md", "# Too many")
	}
	for _, tc := range []struct {
		name   string
		status int
		files  []browserTestUpload
	}{
		{"missing file", 422, nil},
		{"extension", 415, []browserTestUpload{browserTestMarkdown("bad.txt", "# Bad extension")}},
		{"invalid UTF-8", 422, []browserTestUpload{{field: "files", name: "bad.md", data: []byte{'#', ' ', 0xff, 0xfe}}}},
		{"NUL byte", 422, []browserTestUpload{browserTestMarkdown("bad.md", "# Title\n\x00")}},
		{"oversized", 413, []browserTestUpload{browserTestMarkdown("large.md", strings.Repeat("x", int(app.cfg.MaxMarkdownBytes)+1))}},
		{"long heading", 422, []browserTestUpload{browserTestMarkdown("bad.md", "# "+strings.Repeat("я", 301))}},
		{"empty derived title", 422, []browserTestUpload{browserTestMarkdown(".md", "No heading")}},
		{"too many files", 422, tooMany},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := b.notes(t, project.ID)
			files := tc.files
			// A valid first file must not be saved before a later invalid file
			// has been validated. Keep the empty and count-limit cases exact.
			if len(files) == 1 {
				files = append([]browserTestUpload{browserTestMarkdown("valid-first.md", "# Must not partially import")}, files...)
			}
			browserTestStatus(t, b.multipart(t, "/projects/"+project.ID+"/notes", nil, files...), tc.status)
			if after := b.notes(t, project.ID); !reflect.DeepEqual(after, before) {
				t.Error("invalid import created or changed notes")
			}
		})
	}
}

func TestBrowserRootSearchSortsByTitle(t *testing.T) {
	app, db := newTestApp(t)
	b := browserTestOwner(t, app, db)
	first := b.createProject(t, "First search project", "")
	second := b.createProject(t, "Second search project", "")
	query := "root-search-regression"
	alpha := b.importNotes(t, first.ID, browserTestMarkdown("alpha.md", "# Alpha lesson\n\n"+query))[0]
	zulu := b.importNotes(t, second.ID, browserTestMarkdown("zulu.md", "# Zulu lesson\n\n"+query))[0]
	b.importNotes(t, first.ID, browserTestMarkdown("hidden.md", "# Not a search result"))
	for _, tc := range []struct {
		name, sort, selected string
		want                 []string
	}{
		{"default modified order", "", "updated", []string{zulu.ID, alpha.ID}},
		{"title order across projects", "title", "title", []string{alpha.ID, zulu.ID}},
		{"explicit modified order", "updated", "updated", []string{zulu.ID, alpha.ID}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			values := url.Values{"q": {query}}
			if tc.sort != "" {
				values.Set("sort", tc.sort)
			}
			response := b.request(t, "GET", "/projects?"+values.Encode(), nil, nil)
			browserTestStatus(t, response, 200)
			doc := browserTestDocument(t, response)
			var got []string
			for _, link := range browserTestElements(doc, "a") {
				if id, ok := strings.CutPrefix(browserTestAttr(link, "href"), "/notes/"); ok {
					got = append(got, id)
				}
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("root search results = %v, want %v", got, tc.want)
			}
			var selected []string
			for _, selectNode := range browserTestElements(doc, "select") {
				if browserTestAttr(selectNode, "id") != "search-sort" {
					continue
				}
				for _, option := range browserTestElements(selectNode, "option") {
					if slices.ContainsFunc(option.Attr, func(attr html.Attribute) bool { return attr.Key == "selected" }) {
						selected = append(selected, browserTestAttr(option, "value"))
					}
				}
			}
			if !reflect.DeepEqual(selected, []string{tc.selected}) {
				t.Errorf("search sort control = %v, want [%s]", selected, tc.selected)
			}
			if browserTestInput(t, doc, "q") != query {
				t.Error("root search lost the query in its native form")
			}
		})
	}
}

func TestBrowserReplacementAndMetadataPreserveIdentityShareAndAssets(t *testing.T) {
	app, db := newTestApp(t)
	b := browserTestOwner(t, app, db)
	project := b.createProject(t, "Original project", "")
	destination := b.createProject(t, "Destination project", "")
	note := b.importNotes(t, project.ID, browserTestMarkdown("original.md", "# Original title\n\nOld body."))[0]
	image := b.uploadImage(t, note, "diagram.png")
	checkSharedWarning := func(shared bool) {
		t.Helper()
		page := b.request(t, "GET", "/notes/"+note.ID+"/manage", nil, nil)
		browserTestStatus(t, page, 200)
		entry := browserTestManagementNote(t, browserTestDocument(t, page), note.ID)
		replace := browserTestForm(t, entry, "/notes/"+note.ID+"/replace")
		seenWarning := false
		browserTestWalk(entry, func(node *html.Node) {
			if node.Type == html.ElementNode && node.Data == "p" && strings.HasPrefix(browserTestText(node), "Доступен по ссылке.") {
				seenWarning = true
				if !strings.Contains(browserTestText(node), "Замена файла и правки через MCP сразу станут видны читателям.") {
					t.Error("shared-note warning omitted the immediate publication risk")
				}
			}
			if node == replace && shared && !seenWarning {
				t.Error("shared-note warning does not precede the replacement form")
			}
		})
		if seenWarning != shared || strings.Contains(browserTestText(entry), "Публичный доступ закрыт.") == shared {
			t.Error("management warning does not reflect the note's sharing state")
		}
	}
	checkSharedWarning(false)
	b.changeShare(t, note.ID, "create")
	sharePath := b.shareURL(t, note.ID)
	note = b.note(t, note.ID)
	checkSharedWarning(true)
	version := b.version(t, note, "replace")
	source := "# A different heading must not rename the note\n\nНовый текст.\n\n![diagram](attachment:" + image.ID + ")\n"
	response := b.multipart(t, "/notes/"+note.ID+"/replace", url.Values{"version": {version}}, browserTestUpload{field: "file", name: "replacement.MD", data: []byte(source)})
	browserTestRedirect(t, response, "/notes/"+note.ID+"/manage")
	replaced := b.note(t, note.ID)
	if replaced.ID != note.ID || replaced.Title != note.Title || replaced.ProjectID != note.ProjectID || replaced.Markdown != source || replaced.SourceName != "replacement.MD" || replaced.Version != note.Version+1 || !replaced.CreatedAt.Equal(note.CreatedAt) || !replaced.Shared {
		t.Fatalf("replacement lost note identity, metadata, share, or new source: %+v", replaced)
	}
	if b.shareURL(t, note.ID) != sharePath {
		t.Error("replacement changed public share URL")
	}
	storedImage, err := db.Attachment(t.Context(), note.ID, image.ID)
	if err != nil || !reflect.DeepEqual(storedImage, image) {
		t.Fatalf("replacement changed attachment metadata: %v", err)
	}
	public := &browserTestClient{app: app, db: db}
	page := public.request(t, "GET", sharePath, nil, nil)
	browserTestStatus(t, page, 200)
	if !strings.Contains(browserTestText(browserTestDocument(t, page)), "Новый текст.") {
		t.Error("share page did not render replacement source")
	}
	browserTestStatus(t, public.request(t, "GET", sharePath+"/attachments/"+image.ID, nil, nil), 200)

	stale := b.multipart(t, "/notes/"+note.ID+"/replace", url.Values{"version": {version}}, browserTestUpload{field: "file", name: "stale.md", data: []byte("# Lost update")})
	browserTestStatus(t, stale, 412)
	for _, invalid := range []string{"", "0", "-1", "not-a-number"} {
		browserTestStatus(t, b.multipart(t, "/notes/"+note.ID+"/replace", url.Values{"version": {invalid}}, browserTestUpload{field: "file", name: "invalid.md", data: []byte("# Not saved")}), 400)
	}
	browserTestStatus(t, b.multipart(t, "/notes/"+note.ID+"/replace", url.Values{"version": {strconv.FormatInt(replaced.Version, 10)}}, browserTestUpload{field: "file", name: "bad.md", data: []byte{0xff}}), 422)
	if current := b.note(t, note.ID); !reflect.DeepEqual(current, replaced) {
		t.Error("failed or stale replacement changed note")
	}

	metadataVersion := b.version(t, replaced, "metadata")
	response = b.form(t, "/notes/"+note.ID+"/metadata", url.Values{"version": {metadataVersion}, "title": {"Переименованный конспект"}, "project_id": {destination.ID}})
	browserTestRedirect(t, response, "/notes/"+note.ID+"/manage")
	moved := b.note(t, note.ID)
	if moved.ID != note.ID || moved.ProjectID != destination.ID || moved.Title != "Переименованный конспект" || moved.Version != replaced.Version+1 || moved.Markdown != source || moved.SourceName != replaced.SourceName || !moved.CreatedAt.Equal(note.CreatedAt) || !moved.Shared {
		t.Fatalf("metadata move lost content or identity: %+v", moved)
	}
	browserTestStatus(t, b.form(t, "/notes/"+note.ID+"/metadata", url.Values{"version": {metadataVersion}, "title": {"Stale title"}, "project_id": {project.ID}}), 412)
	if current := b.note(t, note.ID); !reflect.DeepEqual(current, moved) || b.shareURL(t, note.ID) != sharePath {
		t.Error("stale metadata write or move changed note identity/share")
	}
	for _, project := range []store.Project{project, destination} {
		page := b.request(t, "GET", "/projects/"+project.ID, nil, nil)
		browserTestStatus(t, page, 200)
		if got := browserTestHasLink(browserTestDocument(t, page), "/notes/"+note.ID); got != (project.ID == destination.ID) {
			t.Errorf("moved note visibility incorrect in project %s", project.ID)
		}
	}
	browserTestStatus(t, public.request(t, "GET", sharePath, nil, nil), 200)
	browserTestStatus(t, public.request(t, "GET", sharePath+"/attachments/"+image.ID, nil, nil), 200)
}

func browserTestReadOnly(t *testing.T, response *httptest.ResponseRecorder, public bool) *html.Node {
	t.Helper()
	browserTestStatus(t, response, 200)
	browserTestSecurity(t, response, "no-referrer")
	doc := browserTestDocument(t, response)
	browserTestReferrerMeta(t, doc, "no-referrer")
	for _, tag := range []string{"button", "form", "input", "textarea", "select", "iframe", "object", "embed", "svg", "video", "audio"} {
		if len(browserTestElements(doc, tag)) != 0 {
			t.Errorf("reader contains forbidden %s element", tag)
		}
	}
	browserTestWalk(doc, func(node *html.Node) {
		if node.Type != html.ElementNode {
			return
		}
		for _, attr := range node.Attr {
			if strings.HasPrefix(attr.Key, "on") || attr.Key == "srcset" || attr.Key == "style" || attr.Key == "contenteditable" && attr.Val != "false" {
				t.Errorf("reader contains active attribute %q on %s", attr.Key, node.Data)
			}
		}
		if role := browserTestAttr(node, "role"); role == "button" || role == "textbox" {
			t.Errorf("reader contains interactive role %q", role)
		}
		for _, class := range strings.Fields(browserTestAttr(node, "class")) {
			if slices.Contains([]string{"editor", "cm-editor", "CodeMirror", "monaco-editor"}, class) {
				t.Errorf("reader contains editor class %q", class)
			}
		}
	})
	for _, link := range browserTestElements(doc, "a") {
		href := browserTestAttr(link, "href")
		u, err := url.Parse(href)
		if err != nil || u.Scheme != "" && u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "mailto" {
			t.Errorf("unsafe reader link %q", href)
			continue
		}
		if u.Host == "" {
			if strings.HasPrefix(u.Path, "/settings") || u.Path == "/logout" || strings.HasSuffix(u.Path, "/manage") || strings.HasSuffix(u.Path, "/share") || strings.HasSuffix(u.Path, "/delete") || strings.HasSuffix(u.Path, "/replace") || strings.HasSuffix(u.Path, "/metadata") {
				t.Errorf("reader exposes management link %q", href)
			}
			if public && (strings.HasPrefix(u.Path, "/projects") || strings.HasPrefix(u.Path, "/notes") || u.Path == "/login") {
				t.Errorf("public reader exposes private navigation %q", href)
			}
		}
	}
	for _, script := range browserTestElements(doc, "script") {
		if !slices.Contains([]string{readerAsset("katex.min.js"), readerAsset("reader.js")}, browserTestAttr(script, "src")) || strings.TrimSpace(browserTestText(script)) != "" {
			t.Error("reader contains remote or inline script")
		}
	}
	return doc
}

func TestBrowserReadersSharingAndAttachmentAuthorization(t *testing.T) {
	app, db := newTestApp(t)
	b := browserTestOwner(t, app, db)
	anonymous := &browserTestClient{app: app, db: db}
	project := b.createProject(t, "Parent project must stay private", "Private parent description")
	otherProject := b.createProject(t, "Another private project", "")
	note := b.importNotes(t, project.ID, browserTestMarkdown("shared.md", "# Shared lesson"))[0]
	neighbor := b.importNotes(t, project.ID, browserTestMarkdown("neighbor.md", "# Secret neighboring lesson\n\nConfidential neighboring body."))[0]
	otherNote := b.importNotes(t, otherProject.ID, browserTestMarkdown("other.md", "# Secret other lesson"))[0]
	image := b.uploadImage(t, note, "local.png")
	neighborImage := b.uploadImage(t, neighbor, "neighbor.png")
	otherImage := b.uploadImage(t, otherNote, "other.png")

	var fetches atomic.Int64
	canary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte("unexpected remote fetch"))
	}))
	t.Cleanup(canary.Close)
	inline := `x_1+\frac{a}{b}`
	block := "\n\\sum_{i=1}^{n} i\n"
	source := "# Shared lesson\n\nInline $" + inline + "$ math.\n\n$$" + block + "$$\n\n" +
		"```go\n// $literal$ stays code\nfmt.Println(\"<safe>\")\n```\n\n`$also_literal$`\n\n" +
		"- [x] done\n- [ ] pending\n\n[Ordinary link](https://example.test/reading)\n\n" +
		"![local](attachment:" + image.ID + ")\n![foreign](attachment:" + neighborImage.ID + ")\n![other](attachment:" + otherImage.ID + ")\n![missing](attachment:missing_id)\n\n" +
		"![tracker](" + canary.URL + "/tracker.png)\n![protocol-relative](//example.test/tracker.png)\n![local-file](images/private.png)\n![data](data:image/png;base64,AAAA)\n\n" +
		"<script src=\"" + canary.URL + "/evil.js\">alert('bad')</script>\n\n" +
		"<form action=\"/logout\"><input name=\"csrf\"><button>Bad action</button></form>\n\n" +
		"<iframe src=\"" + canary.URL + "/frame\"></iframe>\n\n" +
		"<img src=\"" + canary.URL + "/raw.png\" onerror=\"alert(1)\">\n\n" +
		"[unsafe](javascript:alert%281%29)\n"
	browserTestRedirect(t, b.multipart(t, "/notes/"+note.ID+"/replace", url.Values{"version": {b.version(t, note, "replace")}}, browserTestUpload{field: "file", name: "reader.md", data: []byte(source)}), "/notes/"+note.ID+"/manage")
	note = b.note(t, note.ID)

	admin := b.request(t, "GET", "/notes/"+note.ID+"/share", nil, nil)
	browserTestStatus(t, admin, 200)
	adminDoc := browserTestDocument(t, admin)
	if browserTestInputID(adminDoc, "share-url") != nil || browserTestInput(t, browserTestForm(t, adminDoc, "/notes/"+note.ID+"/share"), "action") != "create" {
		t.Error("unshared note's administration UI is incorrect")
	}
	browserTestRedirect(t, anonymous.request(t, "GET", "/notes/"+note.ID+"/share", nil, nil), "/login")
	browserTestStatus(t, anonymous.form(t, "/notes/"+note.ID+"/share", url.Values{"action": {"create"}}), 401)
	b.changeShare(t, note.ID, "create")
	sharePath := b.shareURL(t, note.ID)
	b.changeShare(t, note.ID, "create")
	if b.shareURL(t, note.ID) != sharePath {
		t.Error("creating an existing share rotated it unexpectedly")
	}
	admin = b.request(t, "GET", "/notes/"+note.ID+"/share", nil, nil)
	adminDoc = browserTestDocument(t, admin)
	var actions []string
	for _, form := range browserTestElements(adminDoc, "form") {
		if browserTestAttr(form, "action") == "/notes/"+note.ID+"/share" {
			actions = append(actions, browserTestInput(t, form, "action"))
			if browserTestInput(t, form, "csrf") != b.csrf {
				t.Error("share administration form omitted session CSRF")
			}
		}
	}
	if !slices.Contains(actions, "rotate") || !slices.Contains(actions, "revoke") {
		t.Error("share controls are missing from the separate administration page")
	}
	activeShare, err := db.ActiveShare(t.Context(), note.ID)
	if err != nil || activeShare.TokenHash != tokenHash(strings.TrimPrefix(sharePath, "/s/")) {
		t.Fatalf("share URL does not match stored token hash: %v", err)
	}

	for _, tc := range []struct {
		name   string
		client *browserTestClient
		path   string
		public bool
	}{
		{"owner reader", b, "/notes/" + note.ID, false},
		{"public reader", anonymous, sharePath, true},
		{"public URL with owner cookie", b, sharePath, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := tc.client.request(t, "GET", tc.path, nil, nil)
			doc := browserTestReadOnly(t, response, tc.public)
			if !tc.public && (!browserTestHasLink(doc, "/projects") || !browserTestHasLink(doc, "/projects/"+project.ID)) {
				t.Error("owner reader omitted permitted table-of-contents navigation")
			}
			browserTestNoPrivateValues(t, response, b.csrf, b.cookie.Value, activeShare.TokenHash, app.cfg.DataDir, canary.URL)
			if tc.public {
				browserTestNoPrivateValues(t, response, project.ID, project.Name, project.Description, otherProject.ID, otherProject.Name, browserTestUsername, neighbor.ID, neighbor.Title, "Confidential neighboring body.", otherNote.ID, otherNote.Title, neighborImage.ID, otherImage.ID)
			}
			var formulas []*html.Node
			var highlighted bool
			browserTestWalk(doc, func(node *html.Node) {
				if browserTestAttr(node, "data-math") != "" {
					formulas = append(formulas, node)
				}
				if node.Data == "pre" && browserTestAttr(node, "class") == "syntax-chroma" {
					highlighted = len(browserTestElements(node, "span")) > 0 && strings.Contains(browserTestText(node), "$literal$")
				}
			})
			if len(formulas) != 2 || browserTestAttr(formulas[0], "data-math") != "inline" || browserTestAttr(formulas[0], "data-tex") != inline || browserTestAttr(formulas[1], "data-math") != "block" || browserTestAttr(formulas[1], "data-tex") != block {
				t.Error("reader did not preserve inline/display math, or parsed math inside code")
			}
			if !highlighted || !strings.Contains(browserTestText(doc), "$also_literal$") {
				t.Error("reader omitted highlighted code or changed literal code math")
			}
			images := browserTestElements(doc, "img")
			prefix := "/notes/" + note.ID
			if tc.public {
				prefix = sharePath
			}
			if len(images) != 1 || browserTestAttr(images[0], "src") != prefix+"/attachments/"+image.ID || browserTestAttr(images[0], "loading") != "lazy" || browserTestAttr(images[0], "referrerpolicy") != "no-referrer" {
				t.Error("reader allowed remote/foreign images or emitted an incorrectly scoped image URL")
			}
			var assets []string
			for _, link := range browserTestElements(doc, "link") {
				assets = append(assets, browserTestAttr(link, "href"))
			}
			for _, script := range browserTestElements(doc, "script") {
				assets = append(assets, browserTestAttr(script, "src"))
			}
			want := []string{stylesheetURL(), readerAsset("katex.min.css"), readerAsset("syntax.css"), readerAsset("katex.min.js"), readerAsset("reader.js")}
			if !reflect.DeepEqual(assets, want) {
				t.Errorf("reader assets = %v, want only local math/code assets %v", assets, want)
			}
		})
	}

	for _, path := range []string{stylesheetURL(), readerAsset("katex.min.css"), readerAsset("syntax.css"), readerAsset("katex.min.js"), readerAsset("reader.js"), "/assets/app.css", "/assets/reader/katex.min.css", "/assets/reader/syntax.css", "/assets/reader/katex.min.js", "/assets/reader/reader.js"} {
		asset := anonymous.request(t, "GET", path, nil, nil)
		browserTestStatus(t, asset, 200)
		if asset.Body.Len() == 0 || strings.HasPrefix(asset.Header().Get("Content-Type"), "text/html") {
			t.Errorf("asset %s is empty or an HTML error", path)
		}
		if path == readerAsset("katex.min.css") || path == "/assets/reader/katex.min.css" {
			urls := regexp.MustCompile(`url\(([^)]+)\)`).FindAllStringSubmatch(asset.Body.String(), -1)
			if len(urls) == 0 {
				t.Fatal("KaTeX CSS has no font assets")
			}
			base := &url.URL{Path: path}
			for _, match := range urls {
				u, err := url.Parse(strings.Trim(match[1], `"'`))
				if err != nil || u.IsAbs() || u.Host != "" {
					t.Fatalf("KaTeX CSS uses a remote/invalid font URL: %q", match[1])
				}
				font := base.ResolveReference(u).Path
				if !strings.HasPrefix(font, strings.TrimSuffix(path, "katex.min.css")+"fonts/") {
					t.Fatalf("KaTeX font is outside local assets: %q", font)
				}
				response := anonymous.request(t, "GET", font, nil, nil)
				browserTestStatus(t, response, 200)
				if response.Body.Len() == 0 {
					t.Errorf("empty KaTeX font %s", font)
				}
			}
		}
	}
	if fetches.Load() != 0 {
		t.Errorf("rendering fetched remote images/HTML %d times", fetches.Load())
	}

	for _, tc := range []struct {
		name, method, path string
		client             *browserTestClient
		status             int
	}{
		{"owner image", "GET", "/notes/" + note.ID + "/attachments/" + image.ID, b, 200},
		{"owner image HEAD", "HEAD", "/notes/" + note.ID + "/attachments/" + image.ID, b, 200},
		{"owner same-project foreign image", "GET", "/notes/" + note.ID + "/attachments/" + neighborImage.ID, b, 404},
		{"owner cross-project foreign image", "GET", "/notes/" + note.ID + "/attachments/" + otherImage.ID, b, 404},
		{"owner reverse mismatch", "GET", "/notes/" + neighbor.ID + "/attachments/" + image.ID, b, 404},
		{"owner image without login", "GET", "/notes/" + note.ID + "/attachments/" + image.ID, anonymous, 303},
		{"shared image", "GET", sharePath + "/attachments/" + image.ID, anonymous, 200},
		{"shared image HEAD", "HEAD", sharePath + "/attachments/" + image.ID, anonymous, 200},
		{"shared image with owner cookie", "GET", sharePath + "/attachments/" + image.ID, b, 200},
		{"share same-project foreign image", "GET", sharePath + "/attachments/" + neighborImage.ID, anonymous, 404},
		{"share cross-project foreign image", "GET", sharePath + "/attachments/" + otherImage.ID, anonymous, 404},
		{"owner cookie cannot widen share", "GET", sharePath + "/attachments/" + otherImage.ID, b, 404},
		{"missing attachment", "GET", sharePath + "/attachments/missing_id", anonymous, 404},
		{"unknown share image", "GET", "/s/unknown-token/attachments/" + image.ID, b, 404},
		{"uploads are not public", "GET", "/uploads/" + image.StorageKey, anonymous, 404},
		{"public URL cannot write", "POST", sharePath, anonymous, 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := tc.client.request(t, tc.method, tc.path, nil, nil)
			browserTestStatus(t, response, tc.status)
			if tc.status == 200 {
				if response.Header().Get("Content-Type") != "image/png" || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Content-Type-Options") != "nosniff" {
					t.Error("attachment has unsafe content/cache headers")
				}
				if tc.method == "GET" && !bytes.Equal(response.Body.Bytes(), apiTestPNG(t)) {
					t.Error("attachment response has incorrect bytes")
				}
				if tc.method == "HEAD" && response.Body.Len() != 0 {
					t.Error("attachment HEAD returned a body")
				}
			} else if tc.status == 404 {
				browserTestNoPrivateValues(t, response, project.Name, project.Description, neighbor.Title, otherNote.Title, image.StorageKey, app.cfg.DataDir)
			}
		})
	}
	rangeResponse := anonymous.request(t, "GET", sharePath+"/attachments/"+image.ID, nil, map[string]string{"Range": "bytes=0-7"})
	browserTestStatus(t, rangeResponse, 206)
	if !bytes.Equal(rangeResponse.Body.Bytes(), apiTestPNG(t)[:8]) {
		t.Error("authorized range request returned wrong image bytes")
	}

	browserTestStatus(t, b.form(t, "/notes/"+note.ID+"/share", url.Values{"action": {"rotate"}, "csrf": {"wrong"}}), 403)
	if b.shareURL(t, note.ID) != sharePath {
		t.Fatal("CSRF-rejected request rotated the share")
	}
	b.changeShare(t, note.ID, "rotate")
	rotatedPath := b.shareURL(t, note.ID)
	if rotatedPath == sharePath {
		t.Fatal("rotation reused the old share token")
	}
	for _, client := range []*browserTestClient{anonymous, b} {
		for _, suffix := range []string{"", "/attachments/" + image.ID} {
			browserTestStatus(t, client.request(t, "GET", sharePath+suffix, nil, nil), 404)
			browserTestStatus(t, client.request(t, "GET", rotatedPath+suffix, nil, nil), 200)
		}
	}
	b.changeShare(t, note.ID, "revoke")
	unknown := anonymous.request(t, "GET", "/s/unknown-token", nil, nil)
	browserTestStatus(t, unknown, 404)
	for _, client := range []*browserTestClient{anonymous, b} {
		for _, suffix := range []string{"", "/attachments/" + image.ID} {
			response := client.request(t, "GET", rotatedPath+suffix, nil, map[string]string{"Range": "bytes=0-7", "If-Modified-Since": time.Now().Add(time.Hour).UTC().Format(http.TimeFormat)})
			browserTestStatus(t, response, 404)
			browserTestSecurity(t, response, "no-referrer")
			if !bytes.Equal(response.Body.Bytes(), unknown.Body.Bytes()) {
				t.Error("revoked/unknown shares return distinguishable error pages or expose owner controls")
			}
			browserTestStatus(t, client.request(t, "HEAD", rotatedPath+suffix, nil, nil), 404)
		}
	}
	page := b.request(t, "GET", "/notes/"+note.ID+"/share", nil, nil)
	browserTestStatus(t, page, 200)
	if browserTestInputID(browserTestDocument(t, page), "share-url") != nil {
		t.Error("revoked share remains visible as active in administration UI")
	}
	b.changeShare(t, note.ID, "create")
	recreatedPath := b.shareURL(t, note.ID)
	if recreatedPath == sharePath || recreatedPath == rotatedPath {
		t.Error("recreating revoked access reused a token")
	}
	browserTestStatus(t, anonymous.request(t, "GET", recreatedPath, nil, nil), 200)
	browserTestStatus(t, anonymous.request(t, "GET", recreatedPath+"/attachments/"+image.ID, nil, nil), 200)
	current := b.note(t, note.ID)
	if current.Version != note.Version || current.Markdown != note.Markdown || current.ID != note.ID {
		t.Error("sharing controls changed note content or version")
	}
}

func TestBrowserShareControlsRecoverAfterAppSecretChange(t *testing.T) {
	for _, action := range []string{"revoke", "rotate"} {
		t.Run(action, func(t *testing.T) {
			app, db := newTestApp(t)
			owner := browserTestOwner(t, app, db)
			project := owner.createProject(t, "Secret rotation recovery", "")
			note := owner.importNotes(t, project.ID, browserTestMarkdown("shared.md", "# Existing shared note"))[0]
			image := owner.uploadImage(t, note, "existing.png")
			owner.changeShare(t, note.ID, "create")
			oldPath := owner.shareURL(t, note.ID)
			note = owner.note(t, note.ID)
			oldShare, err := db.ActiveShare(t.Context(), note.ID)
			if err != nil {
				t.Fatal(err)
			}

			cfg := app.cfg
			cfg.Secret = bytes.Repeat([]byte{0x72}, 32)
			changedApp, err := New(db, cfg)
			if err != nil {
				t.Fatal(err)
			}
			// A restart keeps database sessions; changing APP_SECRET must not
			// strand an authenticated owner behind an unrecoverable share page.
			changed := &browserTestClient{app: changedApp, db: db, cookie: owner.cookie, csrf: owner.csrf}
			public := &browserTestClient{app: changedApp, db: db}
			shareAdmin := "/notes/" + note.ID + "/share"
			page := changed.request(t, "GET", shareAdmin, nil, nil)
			browserTestStatus(t, page, 200)
			browserTestSecurity(t, page)
			doc := browserTestDocument(t, page)
			browserTestReferrerMeta(t, doc, "same-origin")
			if browserTestInputID(doc, "share-url") != nil {
				t.Error("changed APP_SECRET exposed an unusable reconstructed share URL")
			}
			text := browserTestText(doc)
			if !strings.Contains(text, "APP_SECRET изменён") || !strings.Contains(text, "прежняя ссылка всё ещё действует") {
				t.Error("changed-secret share page omitted the still-active-share warning")
			}
			if got := browserTestShareActions(t, doc, note.ID, changed.csrf); !reflect.DeepEqual(got, []string{"revoke", "rotate"}) {
				t.Errorf("changed-secret share actions = %v, want revoke and rotate without create", got)
			}
			reconstructed := "/s/" + changedApp.shareToken(oldShare.ID)
			browserTestNoPrivateValues(t, page, oldPath, reconstructed, oldShare.TokenHash)
			browserTestStatus(t, public.request(t, "GET", reconstructed, nil, nil), 404)
			current, err := db.ActiveShare(t.Context(), note.ID)
			if err != nil || !reflect.DeepEqual(current, oldShare) || !changed.note(t, note.ID).Shared {
				t.Fatalf("viewing a changed-secret share page invalidated the old share: %v", err)
			}
			for _, client := range []*browserTestClient{public, changed} {
				browserTestReadOnly(t, client.request(t, "GET", oldPath, nil, nil), true)
				browserTestStatus(t, client.request(t, "GET", oldPath+"/attachments/"+image.ID, nil, nil), 200)
			}

			changed.changeShare(t, note.ID, action)
			for _, client := range []*browserTestClient{public, changed, owner} {
				for _, suffix := range []string{"", "/attachments/" + image.ID} {
					response := client.request(t, "GET", oldPath+suffix, nil, nil)
					browserTestStatus(t, response, 404)
					browserTestSecurity(t, response, "no-referrer")
				}
			}
			if action == "revoke" {
				page := changed.request(t, "GET", shareAdmin, nil, nil)
				browserTestStatus(t, page, 200)
				doc := browserTestDocument(t, page)
				if browserTestInputID(doc, "share-url") != nil || strings.Contains(browserTestText(doc), "APP_SECRET изменён") {
					t.Error("revocation left an active URL or changed-secret warning")
				}
				if got := browserTestShareActions(t, doc, note.ID, changed.csrf); !reflect.DeepEqual(got, []string{"create"}) {
					t.Errorf("revoked-share actions = %v, want create", got)
				}
				if _, err := db.ActiveShare(t.Context(), note.ID); !errors.Is(err, store.ErrNotFound) || changed.note(t, note.ID).Shared {
					t.Fatalf("changed-secret revocation left an active share: %v", err)
				}
				changed.changeShare(t, note.ID, "create")
			}
			newPath := changed.shareURL(t, note.ID)
			if newPath == oldPath || newPath == reconstructed {
				t.Error("share recovery reused an old or incorrectly reconstructed token")
			}
			page = changed.request(t, "GET", shareAdmin, nil, nil)
			browserTestStatus(t, page, 200)
			if strings.Contains(browserTestText(browserTestDocument(t, page)), "APP_SECRET изменён") {
				t.Error("successful share recovery did not clear the warning")
			}
			for _, client := range []*browserTestClient{public, changed, owner} {
				browserTestReadOnly(t, client.request(t, "GET", newPath, nil, nil), true)
				browserTestStatus(t, client.request(t, "GET", newPath+"/attachments/"+image.ID, nil, nil), 200)
				browserTestStatus(t, client.request(t, "GET", oldPath, nil, nil), 404)
			}
			if after := changed.note(t, note.ID); !reflect.DeepEqual(after, note) {
				t.Error("changed-secret share recovery changed the note or its version")
			}
			storedImage, err := db.Attachment(t.Context(), note.ID, image.ID)
			if err != nil || !reflect.DeepEqual(storedImage, image) {
				t.Fatalf("share recovery changed attachment metadata: %v", err)
			}
		})
	}
}

func TestBrowserImageWarningsOnlyAppearInManagement(t *testing.T) {
	app, db := newTestApp(t)
	b := browserTestOwner(t, app, db)
	public := &browserTestClient{app: app, db: db}
	project := b.createProject(t, "Image diagnostics", "")
	note := b.importNotes(t, project.ID, browserTestMarkdown("images.md", "# Image warnings"))[0]
	quiet := b.importNotes(t, project.ID, browserTestMarkdown("quiet.md", "# No broken images"))[0]
	image := b.uploadImage(t, note, "available.png")
	var fetches atomic.Int64
	canary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(canary.Close)
	relative := "images/not-uploaded.png"
	unknown := "attachment:unknown_image"
	external := canary.URL + "/tracker.png"
	source := "# Image warnings\n\n![available](attachment:" + image.ID + ")\n\n" +
		"![missing relative](" + relative + ")\n\n![unknown attachment](" + unknown + ")\n\n![external](" + external + ")\n\n" +
		"![duplicate](" + relative + ")\n\n![reference duplicate][tracker]\n\n[tracker]: " + external + "\n\n" +
		"```md\n![code example](images/code-example.png)\n```\n"
	browserTestRedirect(t, b.multipart(t, "/notes/"+note.ID+"/replace", url.Values{"version": {b.version(t, note, "replace")}}, browserTestUpload{field: "file", name: "warnings.md", data: []byte(source)}), "/notes/"+note.ID+"/manage")
	page := b.request(t, "GET", "/notes/"+note.ID+"/manage", nil, nil)
	browserTestStatus(t, page, 200)
	browserTestSecurity(t, page)
	doc := browserTestDocument(t, page)
	entry := browserTestManagementNote(t, doc, note.ID)
	var panels []*html.Node
	for _, div := range browserTestElements(entry, "div") {
		if browserTestAttr(div, "role") == "status" && slices.Contains(strings.Fields(browserTestAttr(div, "class")), "notice-error") {
			panels = append(panels, div)
		}
	}
	if len(panels) != 1 || !strings.Contains(browserTestText(panels[0]), "Не все изображения доступны:") {
		t.Fatal("management page omitted the note-scoped image warning panel")
	}
	var warnings []string
	for _, item := range browserTestElements(panels[0], "li") {
		warnings = append(warnings, browserTestText(item))
	}
	want := []string{
		"Изображение не связано с конспектом: " + relative,
		"Изображение не связано с конспектом: " + unknown,
		"Внешнее изображение отключено; загрузите файл в сервис: " + external,
	}
	if !reflect.DeepEqual(warnings, want) {
		t.Errorf("image warnings = %v, want %v; valid attachments, duplicates, and code examples must not add warnings", warnings, want)
	}
	quietPage := b.request(t, "GET", "/notes/"+quiet.ID+"/manage", nil, nil)
	browserTestStatus(t, quietPage, 200)
	if strings.Contains(browserTestText(browserTestManagementNote(t, browserTestDocument(t, quietPage), quiet.ID)), "Не все изображения доступны:") {
		t.Error("one note's diagnostics leaked into another management page")
	}

	b.changeShare(t, note.ID, "create")
	sharePath := b.shareURL(t, note.ID)
	note = b.note(t, note.ID)
	for _, tc := range []struct {
		name, path string
		client     *browserTestClient
		public     bool
	}{
		{"owner reader", "/notes/" + note.ID, b, false},
		{"public reader", sharePath, public, true},
		{"public reader with owner cookie", sharePath, b, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := tc.client.request(t, "GET", tc.path, nil, nil)
			doc := browserTestReadOnly(t, response, tc.public)
			browserTestNoPrivateValues(t, response, "Не все изображения доступны:", "Изображение не связано с конспектом:", "Внешнее изображение отключено; загрузите файл в сервис:", relative, unknown, external, "Доступен по ссылке.")
			images := browserTestElements(doc, "img")
			if len(images) != 1 || browserTestAttr(images[0], "src") != tc.path+"/attachments/"+image.ID {
				t.Error("reader diagnostics changed authorized image rendering")
			}
			if !strings.Contains(browserTestText(doc), "![code example](images/code-example.png)") {
				t.Error("image diagnostics consumed a literal code example")
			}
		})
	}
	for _, path := range []string{"/projects/" + project.ID, "/projects/" + project.ID + "/manage", "/projects?q=Image", "/notes/" + note.ID + "/share"} {
		page := b.request(t, "GET", path, nil, nil)
		browserTestStatus(t, page, 200)
		browserTestNoPrivateValues(t, page, "Не все изображения доступны:", relative, unknown, external)
	}
	if fetches.Load() != 0 {
		t.Errorf("management/reader image diagnostics fetched external images %d times", fetches.Load())
	}
	if after := b.note(t, note.ID); !reflect.DeepEqual(after, note) {
		t.Error("viewing image warnings changed note content or version")
	}
	files, err := db.Attachments(t.Context(), note.ID)
	if err != nil || !reflect.DeepEqual(files, []store.Attachment{image}) {
		t.Fatalf("image diagnostics changed attachment metadata: %v", err)
	}
}

func TestBrowserDeletesCleanUploadsAndPreserveOtherNotes(t *testing.T) {
	for _, kind := range []string{"attachment", "note", "project"} {
		t.Run(kind, func(t *testing.T) {
			app, db := newTestApp(t)
			b := browserTestOwner(t, app, db)
			anonymous := &browserTestClient{app: app, db: db}
			project := b.createProject(t, "Delete target", "")
			otherProject := b.createProject(t, "Keep project", "")
			note := b.importNotes(t, project.ID, browserTestMarkdown("target.md", "# Target"))[0]
			sibling := b.importNotes(t, project.ID, browserTestMarkdown("sibling.md", "# Sibling"))[0]
			protected := b.importNotes(t, otherProject.ID, browserTestMarkdown("keep.md", "# Keep"))[0]
			image := b.uploadImage(t, note, "target.png")
			siblingImage := b.uploadImage(t, sibling, "sibling.png")
			protectedImage := b.uploadImage(t, protected, "keep.png")
			b.changeShare(t, note.ID, "create")
			sharePath := b.shareURL(t, note.ID)
			note = b.note(t, note.ID)
			path := "/notes/" + note.ID + "/attachments/" + image.ID + "/delete"
			fields := url.Values{}
			redirect := "/notes/" + note.ID + "/manage"
			switch kind {
			case "note":
				redirect = "/projects/" + project.ID + "/manage"
				path = "/notes/" + note.ID + "/delete"
				fields.Set("version", b.version(t, note, "delete"))
			case "project":
				path = "/projects/" + project.ID + "/delete"
				redirect = "/projects"
			}
			for _, confirmation := range []string{"", "delete"} {
				fields.Set("confirm", confirmation)
				browserTestStatus(t, b.form(t, path, fields), 422)
			}
			fields.Set("confirm", "DELETE")
			if kind == "note" {
				stale := b.fields(fields)
				stale.Set("version", strconv.FormatInt(note.Version+1, 10))
				browserTestStatus(t, b.form(t, path, stale), 412)
			}
			if kind == "attachment" {
				browserTestStatus(t, b.form(t, "/notes/"+sibling.ID+"/attachments/"+image.ID+"/delete", fields), 404)
			}
			if _, err := os.Stat(filepath.Join(app.cfg.DataDir, "uploads", image.StorageKey)); err != nil {
				t.Fatalf("rejected delete removed uploaded file: %v", err)
			}
			browserTestStatus(t, anonymous.request(t, "GET", sharePath+"/attachments/"+image.ID, nil, nil), 200)
			browserTestRedirect(t, b.form(t, path, fields), redirect)

			if _, err := os.Stat(filepath.Join(app.cfg.DataDir, "uploads", image.StorageKey)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("deleted upload remains on disk: %v", err)
			}
			if _, err := db.Attachment(t.Context(), note.ID, image.ID); !errors.Is(err, store.ErrNotFound) {
				t.Errorf("deleted attachment remains in database: %v", err)
			}
			browserTestStatus(t, b.request(t, "GET", "/notes/"+note.ID+"/attachments/"+image.ID, nil, nil), 404)
			browserTestStatus(t, anonymous.request(t, "GET", sharePath+"/attachments/"+image.ID, nil, nil), 404)
			if kind == "attachment" {
				browserTestStatus(t, anonymous.request(t, "GET", sharePath, nil, nil), 200)
				if current := b.note(t, note.ID); !reflect.DeepEqual(current, note) {
					t.Error("attachment deletion changed note content/version")
				}
			} else {
				if _, err := db.Note(t.Context(), note.ID); !errors.Is(err, store.ErrNotFound) {
					t.Errorf("deleted note remains in database: %v", err)
				}
				if _, err := db.ActiveShare(t.Context(), note.ID); !errors.Is(err, store.ErrNotFound) {
					t.Errorf("deleted note retains share metadata: %v", err)
				}
				browserTestStatus(t, anonymous.request(t, "GET", sharePath, nil, nil), 404)
			}
			if kind == "project" {
				if _, err := db.Project(t.Context(), project.ID); !errors.Is(err, store.ErrNotFound) {
					t.Errorf("deleted project remains in database: %v", err)
				}
				if _, err := db.Note(t.Context(), sibling.ID); !errors.Is(err, store.ErrNotFound) {
					t.Errorf("project deletion did not cascade to sibling note: %v", err)
				}
				if _, err := os.Stat(filepath.Join(app.cfg.DataDir, "uploads", siblingImage.StorageKey)); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("project deletion left sibling upload on disk: %v", err)
				}
			} else {
				if current := b.note(t, sibling.ID); !reflect.DeepEqual(current, sibling) {
					t.Error("deletion changed unrelated sibling note")
				}
				browserTestStatus(t, b.request(t, "GET", "/notes/"+sibling.ID+"/attachments/"+siblingImage.ID, nil, nil), 200)
			}
			if current := b.note(t, protected.ID); !reflect.DeepEqual(current, protected) {
				t.Error("deletion changed note in another project")
			}
			browserTestStatus(t, b.request(t, "GET", "/notes/"+protected.ID+"/attachments/"+protectedImage.ID, nil, nil), 200)
			entries, err := os.ReadDir(filepath.Join(app.cfg.DataDir, "uploads"))
			want := 2
			if kind == "project" {
				want = 1
			}
			if err != nil || len(entries) != want {
				t.Errorf("upload cleanup left %d files, want %d: %v", len(entries), want, err)
			}
		})
	}
}

func TestBrowserInvalidImagesLeaveNoUploads(t *testing.T) {
	app, db := newTestApp(t)
	b := browserTestOwner(t, app, db)
	project := b.createProject(t, "Image validation", "")
	note := b.importNotes(t, project.ID, browserTestMarkdown("images.md", "# Images"))[0]
	png := apiTestPNG(t)
	for _, tc := range []struct {
		name   string
		files  []browserTestUpload
		status int
	}{
		{"missing", nil, 422},
		{"SVG disguised as PNG", []browserTestUpload{{field: "file", name: "bad.png", data: []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`)}}, 415},
		{"truncated PNG", []browserTestUpload{{field: "file", name: "bad.png", data: png[:8]}}, 415},
		{"multiple images", []browserTestUpload{{field: "file", name: "one.png", data: png}, {field: "file", name: "two.png", data: png}}, 422},
		{"unexpected file field", []browserTestUpload{{field: "file", name: "one.png", data: png}, {field: "extra", name: "two.png", data: png}}, 422},
	} {
		t.Run(tc.name, func(t *testing.T) {
			browserTestStatus(t, b.multipart(t, "/notes/"+note.ID+"/attachments", nil, tc.files...), tc.status)
			files, err := db.Attachments(t.Context(), note.ID)
			if err != nil || len(files) != 0 {
				t.Fatalf("invalid upload persisted attachment metadata: %v", err)
			}
			entries, err := os.ReadDir(filepath.Join(app.cfg.DataDir, "uploads"))
			if err != nil || len(entries) != 0 {
				t.Fatalf("invalid upload left files on disk: %v", err)
			}
			if current := b.note(t, note.ID); !reflect.DeepEqual(current, note) {
				t.Error("invalid upload changed note source/version")
			}
		})
	}
	// A quota failure occurs after the file has been written, so it also tests
	// rollback of the on-disk upload rather than just early MIME rejection.
	app.cfg.MaxStorageBytes = int64(len(png) - 1)
	browserTestStatus(t, b.multipart(t, "/notes/"+note.ID+"/attachments", nil, browserTestUpload{field: "file", name: "over-quota.png", data: png}), 413)
	entries, err := os.ReadDir(filepath.Join(app.cfg.DataDir, "uploads"))
	files, dbErr := db.Attachments(t.Context(), note.ID)
	if err != nil || dbErr != nil || len(entries) != 0 || len(files) != 0 {
		t.Fatalf("quota failure left files or metadata: filesystem=%v, database=%v", err, dbErr)
	}
}

func TestBrowserAPIKeyUISecretScopesExpirationAndRevocation(t *testing.T) {
	app, db := newTestApp(t)
	b := browserTestOwner(t, app, db)
	project := b.createProject(t, "Granted project", "")
	otherProject := b.createProject(t, "Individual grants only", "")
	projectNote := b.importNotes(t, project.ID, browserTestMarkdown("project.md", "# Project note"))[0]
	selected := b.importNotes(t, otherProject.ID, browserTestMarkdown("selected.md", "# Selected note"))[0]
	neighbor := b.importNotes(t, otherProject.ID, browserTestMarkdown("hidden.md", "# Ungranted neighbor"))[0]
	page := b.request(t, "GET", "/settings/api-keys", nil, nil)
	browserTestStatus(t, page, 200)
	if browserTestInput(t, browserTestForm(t, browserTestDocument(t, page), "/settings/api-keys"), "csrf") != b.csrf {
		t.Fatal("API key creation form omitted session CSRF")
	}
	for _, tc := range []struct {
		name   string
		fields url.Values
	}{
		{"no scopes", url.Values{"projects": {project.ID}}},
		{"no grants", url.Values{"scopes": {"notes:read"}}},
		{"unknown scope", url.Values{"projects": {project.ID}, "scopes": {"admin"}}},
		{"past expiration", url.Values{"projects": {project.ID}, "scopes": {"notes:read"}, "expires": {time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02")}}},
		{"invalid expiration", url.Values{"projects": {project.ID}, "scopes": {"notes:read"}, "expires": {"not-a-date"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.fields.Set("name", "Invalid key")
			response := b.form(t, "/settings/api-keys", tc.fields)
			browserTestStatus(t, response, 422)
			if browserTestInputID(browserTestDocument(t, response), "key-secret") != nil {
				t.Error("invalid API key request issued a secret")
			}
			keys, err := db.APIKeys(t.Context())
			if err != nil || len(keys) != 0 {
				t.Fatalf("invalid API key request persisted a key: %v", err)
			}
		})
	}
	expires := time.Now().UTC().AddDate(0, 0, 3).Format("2006-01-02")
	response := b.form(t, "/settings/api-keys", url.Values{
		"name": {"Browser-issued MCP key"}, "scopes": {"notes:read", "notes:read", "attachments:read"},
		"projects": {project.ID, project.ID}, "notes": {selected.ID, selected.ID}, "expires": {expires},
	})
	browserTestStatus(t, response, 201)
	browserTestSecurity(t, response)
	secretInput := browserTestInputID(browserTestDocument(t, response), "key-secret")
	if secretInput == nil {
		t.Fatal("new key response omitted one-time secret")
	}
	secret := browserTestAttr(secretInput, "value")
	decoded, err := hex.DecodeString(strings.TrimPrefix(secret, "csp_"))
	if !strings.HasPrefix(secret, "csp_") || err != nil || len(decoded) != 32 || strings.Count(response.Body.String(), secret) != 1 {
		t.Fatal("API key secret is not a one-time 256-bit bearer token")
	}
	keys, err := db.APIKeys(t.Context())
	if err != nil || len(keys) != 1 {
		t.Fatalf("UI did not persist exactly one API key: %v", err)
	}
	key := keys[0]
	if key.TokenHash != tokenHash(secret) || !reflect.DeepEqual(key.Scopes, []string{"notes:read", "attachments:read"}) || !reflect.DeepEqual(key.ProjectIDs, []string{project.ID}) || !reflect.DeepEqual(key.NoteIDs, []string{selected.ID}) || key.ExpiresAt == nil || key.ExpiresAt.UTC().Format(time.RFC3339) != expires+"T00:00:00Z" {
		t.Error("key metadata did not preserve deduplicated grants/scopes and UTC expiration")
	}
	page = b.request(t, "GET", "/settings/api-keys", nil, nil)
	browserTestStatus(t, page, 200)
	browserTestNoPrivateValues(t, page, secret, key.TokenHash)
	if browserTestInputID(browserTestDocument(t, page), "key-secret") != nil {
		t.Error("key list shows a secret after its creation response")
	}
	revokePath := "/settings/api-keys/" + key.ID + "/revoke"
	browserTestForm(t, browserTestDocument(t, page), revokePath)
	for _, tc := range []struct {
		note   store.Note
		status int
	}{
		{projectNote, 200}, {selected, 200}, {neighbor, 404},
	} {
		apiTestStatus(t, b.api(t, "GET", "/api/v1/notes/"+tc.note.ID, secret, nil), tc.status)
	}
	futureNote := b.importNotes(t, project.ID, browserTestMarkdown("future.md", "# Future project note"))[0]
	apiTestStatus(t, b.api(t, "GET", "/api/v1/notes/"+futureNote.ID, secret, nil), 200)
	apiTestStatus(t, b.api(t, "POST", "/api/v1/projects/"+project.ID+"/notes", secret, strings.NewReader(`{"title":"Forbidden write","markdown":""}`)), 403)
	browserTestStatus(t, b.form(t, revokePath, url.Values{"csrf": {"wrong"}}), 403)
	apiTestStatus(t, b.api(t, "GET", "/api/v1/notes/"+selected.ID, secret, nil), 200)
	browserTestRedirect(t, b.form(t, revokePath, nil), "/settings/api-keys")
	apiTestStatus(t, b.api(t, "GET", "/api/v1/notes/"+selected.ID, secret, nil), 401)
	keys, err = db.APIKeys(t.Context())
	if err != nil || len(keys) != 1 || keys[0].RevokedAt == nil {
		t.Fatalf("UI revocation did not persist revoked key metadata: %v", err)
	}
	page = b.request(t, "GET", "/settings/api-keys", nil, nil)
	browserTestStatus(t, page, 200)
	browserTestNoPrivateValues(t, page, secret, key.TokenHash, key.Name)
	if !browserTestHasLink(browserTestDocument(t, page), "/settings/api-keys?show_revoked=1") {
		t.Error("default key list omitted show-revoked toggle")
	}
	page = b.request(t, "GET", "/settings/api-keys?show_revoked=1", nil, nil)
	browserTestStatus(t, page, 200)
	browserTestNoPrivateValues(t, page, secret, key.TokenHash)
	if !strings.Contains(browserTestText(browserTestDocument(t, page)), key.Name) || !browserTestHasLink(browserTestDocument(t, page), "/settings/api-keys") {
		t.Error("explicit revoked-key view omitted the key or hide toggle")
	}
	for _, form := range browserTestElements(browserTestDocument(t, page), "form") {
		if browserTestAttr(form, "action") == revokePath {
			t.Error("revoked key still has an active revoke control")
		}
	}
}
