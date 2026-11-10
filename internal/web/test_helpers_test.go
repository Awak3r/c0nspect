package web

import (
	"bytes"
	"context"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"conspect/internal/store"

	"github.com/jackc/pgx/v5"
)

// newTestApp(t) (*App, *store.Store) is shared with browser integration tests in
// package web. It requires TEST_DATABASE_URL (otherwise skips), creates and
// migrates a random schema with an isolated search_path, and registers cleanup
// that closes the store and drops ONLY that schema. It never manages containers.
// The app uses http://localhost, a test-only 32-byte secret, temporary uploads,
// and normal default limits. No owner, session, keys, or resources are seeded.
func newTestApp(t *testing.T) (*App, *store.Store) {
	t.Helper()
	baseURL := os.Getenv("TEST_DATABASE_URL")
	if baseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set; use a dedicated PostgreSQL test database")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, baseURL)
	if err != nil {
		t.Fatalf("connect to test database: %v", err)
	}
	schema := "conspect_web_test_" + store.NewID()
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, `CREATE SCHEMA `+identifier); err != nil {
		_ = admin.Close(ctx)
		t.Fatalf("create isolated test schema: %v", err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, `DROP SCHEMA `+identifier+` CASCADE`); err != nil {
			t.Errorf("drop test schema %s: %v", schema, err)
		}
		_ = admin.Close(cleanup)
	})
	databaseURL := baseURL
	if u, err := url.Parse(baseURL); err == nil && (u.Scheme == "postgres" || u.Scheme == "postgresql") {
		query := u.Query()
		query.Set("search_path", schema)
		query.Set("application_name", schema)
		u.RawQuery = query.Encode()
		databaseURL = u.String()
	} else {
		databaseURL += " search_path=" + schema + " application_name=" + schema
	}
	probe, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect to isolated test schema: %v", err)
	}
	var actual string
	err = probe.QueryRow(ctx, `SELECT current_schema()`).Scan(&actual)
	_ = probe.Close(ctx)
	if err != nil || actual != schema {
		t.Fatalf("refusing migrations outside test schema: got %q, want %q, err=%v", actual, schema, err)
	}
	db, err := store.Open(ctx, databaseURL)
	if err != nil {
		t.Fatalf("open isolated test store: %v", err)
	}
	t.Cleanup(db.Close)
	app, err := New(db, Config{
		BaseURL: "http://localhost",
		Secret:  bytes.Repeat([]byte{0x54}, 32),
		DataDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("new test app: %v", err)
	}
	return app, db
}

func apiTestProject(t *testing.T, db *store.Store, name string) store.Project {
	t.Helper()
	project, err := db.CreateProject(t.Context(), name, "Project description")
	if err != nil {
		t.Fatal(err)
	}
	return project
}

func apiTestNote(t *testing.T, db *store.Store, projectID, title string) store.Note {
	t.Helper()
	note, err := db.CreateNote(t.Context(), store.Note{
		ProjectID: projectID, Title: title, Markdown: "# " + title + "\n\nPrivate text", SourceName: "source.md",
	}, store.Actor{Owner: true})
	if err != nil {
		t.Fatal(err)
	}
	return note
}

// apiTestKey returns the stored metadata and the one-time plaintext bearer token.
func apiTestKey(t *testing.T, db *store.Store, input store.APIKey) (store.APIKey, string) {
	t.Helper()
	token := randomToken("csp_")
	input.TokenHash = tokenHash(token)
	if input.Name == "" {
		input.Name = "Integration key"
	}
	key, err := db.CreateAPIKey(t.Context(), input)
	if err != nil {
		t.Fatal(err)
	}
	return key, token
}

// apiTestRequest exercises routing and security middleware without a network
// server. A non-nil body defaults to application/json; headers can override it.
func apiTestRequest(app *App, method, path, token string, body io.Reader, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, body)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	for name, value := range headers {
		r.Header.Set(name, value)
	}
	response := httptest.NewRecorder()
	app.Handler().ServeHTTP(response, r)
	return response
}

func apiTestDecode[T any](t *testing.T, response *httptest.ResponseRecorder) T {
	t.Helper()
	var result T
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode HTTP %d response: %v\n%s", response.Code, err, response.Body.String())
	}
	return result
}

func apiTestStatus(t *testing.T, response *httptest.ResponseRecorder, want int) {
	t.Helper()
	if response.Code != want {
		t.Fatalf("status = %d, want %d; body: %s", response.Code, want, response.Body.String())
	}
	if want < 400 {
		return
	}
	if !strings.HasPrefix(response.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("error Content-Type = %q", response.Header().Get("Content-Type"))
	}
	body := apiTestDecode[struct {
		Error struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			RequestID string `json:"request_id"`
		} `json:"error"`
	}](t, response)
	if body.Error.Code == "" || body.Error.Message == "" || body.Error.RequestID == "" || body.Error.RequestID != response.Header().Get("X-Request-ID") {
		t.Fatalf("incomplete error envelope: %s", response.Body.String())
	}
}

func apiTestNoSecrets(t *testing.T, response *httptest.ResponseRecorder, secrets ...string) {
	t.Helper()
	body := response.Body.String()
	for _, name := range []string{"token_hash", "password_hash", "storage_key", "share_token", "share_url"} {
		if strings.Contains(body, `"`+name+`"`) {
			t.Errorf("response exposes private field %q", name)
		}
	}
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		if strings.Contains(body, secret) {
			t.Errorf("response body exposes a secret")
		}
		for _, values := range response.Header() {
			for _, value := range values {
				if strings.Contains(value, secret) {
					t.Errorf("response header exposes a secret")
				}
			}
		}
	}
}

func apiTestPNG(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	img.Set(0, 0, color.RGBA{R: 255, A: 255})
	var data bytes.Buffer
	if err := png.Encode(&data, img); err != nil {
		t.Fatal(err)
	}
	return data.Bytes()
}

func apiTestMultipart(t *testing.T, name string, data []byte) (*bytes.Buffer, string) {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return &body, writer.FormDataContentType()
}

func apiTestUpload(t *testing.T, app *App, noteID, token, name string, data []byte) *httptest.ResponseRecorder {
	t.Helper()
	body, contentType := apiTestMultipart(t, name, data)
	return apiTestRequest(app, http.MethodPost, "/api/v1/notes/"+noteID+"/attachments", token, body, map[string]string{"Content-Type": contentType})
}
