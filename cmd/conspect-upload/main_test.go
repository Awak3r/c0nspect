package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"conspect/internal/conspectclient"
)

const (
	testProjectID = "11111111111111111111111111111111"
	testNoteID    = "22222222222222222222222222222222"
	testKey       = "csp_private-test-credential"
)

func testConfig(t *testing.T, source string) conspectclient.Config {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "note.md"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	return conspectclient.Config{BaseURL: "http://127.0.0.1:1", APIKey: testKey, FilesRoot: root}
}

func invoke(ctx context.Context, cfg conspectclient.Config, args ...string) (string, error) {
	var out bytes.Buffer
	err := run(ctx, args, func() (conspectclient.Config, error) { return cfg, nil }, &out)
	return out.String(), err
}

func uploadArgs(filename string) []string {
	return []string{"--project-id", testProjectID, "--path", filename}
}

func decodeReceipt(t *testing.T, output string) map[string]any {
	t.Helper()
	if strings.Count(output, "\n") != 1 || !strings.HasSuffix(output, "\n") {
		t.Fatal("receipt must be one compact JSON line")
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(output), &result); err != nil {
		t.Fatal("receipt is not a JSON object:", err)
	}
	return result
}

func assertPrivate(t *testing.T, output string, private ...string) {
	t.Helper()
	for _, value := range private {
		if value != "" && strings.Contains(output, value) {
			t.Fatal("output exposed private data")
		}
	}
}

func respondCreated(w http.ResponseWriter, source string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", `"v1"`)
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"id": testNoteID, "project_id": testProjectID, "title": "untrusted remote title",
		"version": 1, "markdown": source, "etag": "untrusted", "url": "https://untrusted.invalid/share",
	})
}

func TestUploadExactMarkdownAndMetadata(t *testing.T) {
	// Synthetic 51+ KiB fixture only: no user files or production requests.
	source := "# Теорема λ\r\n\r\n$$\\int_0^1 x^2\\,dx=\\frac{1}{3}$$\r\n" +
		"```latex\n\\begin{aligned}α&=β\\\\ γ&=δ\\end{aligned}\n```\n" + strings.Repeat("private body 🧠\n", 3200)
	cfg := testConfig(t, source)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/projects/"+testProjectID+"/notes" {
			t.Error("incorrect method or endpoint")
		}
		if r.URL.RawQuery != "" || r.Header.Get("Authorization") != "Bearer "+testKey || r.Header.Get("Content-Type") != "application/json" {
			t.Error("incorrect authentication, query or content type")
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body) != 2 || body["markdown"] != source || body["title"] != "Теорема λ" {
			t.Error("Markdown bytes or title changed")
		}
		respondCreated(w, source)
	}))
	defer server.Close()
	cfg.BaseURL = server.URL + "/api/v1/"
	output, err := invoke(context.Background(), cfg, uploadArgs(filepath.Join(cfg.FilesRoot, "note.md"))...)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("upload did not perform exactly one POST")
	}
	receipt := decodeReceipt(t, output)
	if len(receipt) != 9 || receipt["id"] != testNoteID || receipt["project_id"] != testProjectID ||
		receipt["title"] != "Теорема λ" || receipt["version"] != float64(1) || receipt["etag"] != `"v1"` ||
		receipt["url"] != server.URL+"/notes/"+testNoteID || receipt["bytes"] != float64(len(source)) ||
		receipt["status"] != "created" {
		t.Fatal("incorrect creation receipt")
	}
	if duration, ok := receipt["duration_ms"].(float64); !ok || duration < 0 || duration > 20000 {
		t.Fatal("invalid duration")
	}
	assertPrivate(t, output, testKey, source, "private body", "markdown", cfg.FilesRoot, "untrusted")
}

func TestCheckIsOfflineAndReadOnly(t *testing.T) {
	source := "# Local title\n\nprivate body \\(α+β\\)\n"
	cfg := testConfig(t, source)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	cfg.BaseURL = server.URL
	for _, filename := range []string{"note.md", filepath.Join(cfg.FilesRoot, "note.md")} {
		output, err := invoke(context.Background(), cfg, append(uploadArgs(filename), "--check")...)
		if err != nil {
			t.Fatal(err)
		}
		receipt := decodeReceipt(t, output)
		if len(receipt) != 3 || receipt["bytes"] != float64(len(source)) || receipt["title"] != "Local title" || receipt["status"] != "ready" {
			t.Fatal("incorrect ready receipt")
		}
		assertPrivate(t, output, testKey, "private body", cfg.FilesRoot, "markdown")
	}
	server.Close()
	// A closed endpoint also succeeds: --check does not test connectivity or grants.
	if _, err := invoke(context.Background(), cfg, append(uploadArgs("note.md"), "--check")...); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatal("--check reached the API")
	}
	data, err := os.ReadFile(filepath.Join(cfg.FilesRoot, "note.md"))
	if err != nil || string(data) != source {
		t.Fatal("check modified the file")
	}
	entries, err := os.ReadDir(cfg.FilesRoot)
	if err != nil || len(entries) != 1 {
		t.Fatal("check saved an extra file")
	}
}

func TestTitles(t *testing.T) {
	for _, tc := range []struct {
		name, source, title, want string
	}{
		{"first H1", "## Skip\n\n# First\n\n# Second\n", "", "First"},
		{"fenced heading", "```md\n# Not a title\n```\n\n# Actual\n", "", "Actual"},
		{"setext H1", "Setext λ\n========\n", "", "Setext λ"},
		{"filename", "No heading\n", "", "note"},
		{"explicit", "# Ignored\n", "  Explicit λ  ", "Explicit λ"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(t, tc.source)
			args := append(uploadArgs("note.md"), "--check")
			if tc.title != "" {
				args = append(args, "--title", tc.title)
			}
			output, err := invoke(context.Background(), cfg, args...)
			if err != nil {
				t.Fatal(err)
			}
			if decodeReceipt(t, output)["title"] != tc.want {
				t.Fatal("incorrect title")
			}
		})
	}
}

func TestInvalidInputsNeverRequestOrEcho(t *testing.T) {
	cfg := testConfig(t, "# Valid\nprivate body\n")
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()
	cfg.BaseURL = server.URL
	for name, content := range map[string]string{
		"note.txt": "private text", "nul.md": "private\x00body", "invalid.md": "\xff",
		"large.md": strings.Repeat("x", (2<<20)+1),
	} {
		if err := os.WriteFile(filepath.Join(cfg.FilesRoot, name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(cfg.FilesRoot, "directory.md"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args []string
		edit func(*conspectclient.Config)
	}{
		{name: "no args"},
		{name: "no project", args: []string{"--path", "note.md"}},
		{name: "no path", args: []string{"--project-id", testProjectID}},
		{name: "invalid ID", args: []string{"--project-id", testKey, "--path", "note.md"}},
		{name: "uppercase ID", args: []string{"--project-id", strings.Repeat("A", 32), "--path", "note.md"}},
		{name: "unknown key flag", args: append(uploadArgs("note.md"), "--api-key="+testKey)},
		{name: "invalid boolean", args: append(uploadArgs("note.md"), "--check="+testKey)},
		{name: "positional credential", args: append(uploadArgs("note.md"), testKey)},
		{name: "missing root", args: uploadArgs("note.md"), edit: func(c *conspectclient.Config) { c.FilesRoot = "" }},
		{name: "missing credentials", args: uploadArgs("note.md"), edit: func(c *conspectclient.Config) { c.APIKey = "" }},
		{name: "both credentials", args: uploadArgs("note.md"), edit: func(c *conspectclient.Config) { c.APIKeyFile = testKey }},
		{name: "invalid URL", args: uploadArgs("note.md"), edit: func(c *conspectclient.Config) { c.BaseURL = "https://example.invalid/?key=" + testKey }},
		{name: "bad title", args: append(uploadArgs("note.md"), "--title", "title\x00"+testKey)},
		{name: "long title", args: append(uploadArgs("note.md"), "--title", strings.Repeat("я", 301))},
		{name: "invalid UTF8 title", args: append(uploadArgs("note.md"), "--title", "\xff")},
		{name: "relative traversal", args: uploadArgs("../note.md")},
		{name: "cleanable traversal", args: uploadArgs("sub/../note.md")},
		{name: "absolute traversal", args: uploadArgs(cfg.FilesRoot + "/sub/../note.md")},
		{name: "outside root", args: uploadArgs(filepath.Join(t.TempDir(), "note.md"))},
		{name: "root prefix sibling", args: uploadArgs(cfg.FilesRoot + "-other/note.md")},
		{name: "backslash", args: uploadArgs(`sub\note.md`)},
		{name: "Windows drive", args: uploadArgs(`C:\private\note.md`)},
		{name: "control path", args: uploadArgs("private\n.md")},
		{name: "txt", args: uploadArgs("note.txt")},
		{name: "missing file", args: uploadArgs("missing.md")},
		{name: "directory", args: uploadArgs("directory.md")},
		{name: "NUL source", args: uploadArgs("nul.md")},
		{name: "invalid UTF8 source", args: uploadArgs("invalid.md")},
		{name: "oversized source", args: uploadArgs("large.md")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, check := range []bool{false, true} {
				config := cfg
				if tc.edit != nil {
					tc.edit(&config)
				}
				args := append([]string{}, tc.args...)
				if check {
					args = append([]string{"--check"}, args...)
				}
				output, err := invoke(context.Background(), config, args...)
				if err == nil || output != "" {
					t.Fatal("invalid input accepted or emitted receipt")
				}
				assertPrivate(t, err.Error(), testKey, "private body", cfg.FilesRoot, "https://example.invalid")
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatal("invalid input reached API")
	}
}

func TestSymlinksRejected(t *testing.T) {
	cfg := testConfig(t, "# Valid\n")
	for name, target := range map[string]string{
		"link.md": "note.md", "nested": cfg.FilesRoot, "escape.md": filepath.Join(t.TempDir(), "secret.md"),
	} {
		if err := os.Symlink(target, filepath.Join(cfg.FilesRoot, name)); err != nil {
			t.Skip("symlink creation unavailable")
		}
	}
	for _, filename := range []string{"link.md", "nested/note.md", "escape.md"} {
		for _, name := range []string{filename, filepath.Join(cfg.FilesRoot, filename)} {
			if output, err := invoke(context.Background(), cfg, append(uploadArgs(name), "--check")...); err == nil || output != "" {
				t.Fatal("symlink path accepted")
			}
		}
	}
	linkRoot := filepath.Join(t.TempDir(), "root")
	if err := os.Symlink(cfg.FilesRoot, linkRoot); err != nil {
		t.Fatal(err)
	}
	cfg.FilesRoot = linkRoot
	if _, err := invoke(context.Background(), cfg, append(uploadArgs("note.md"), "--check")...); err == nil {
		t.Fatal("symlink root accepted")
	}
}

func TestEnvironmentCredentials(t *testing.T) {
	cfg := testConfig(t, "# Environment\n")
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+testKey || r.URL.RawQuery != "" {
			t.Error("credential was not confined to Authorization header")
		}
		respondCreated(w, "")
	}))
	defer server.Close()
	keyFile := filepath.Join(t.TempDir(), "private-key")
	if err := os.WriteFile(keyFile, []byte(testKey+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONSPECT_URL", server.URL)
	t.Setenv("CONSPECT_FILES_ROOT", cfg.FilesRoot)
	for _, file := range []bool{false, true} {
		t.Setenv("CONSPECT_API_KEY", "")
		t.Setenv("CONSPECT_API_KEY_FILE", "")
		if file {
			t.Setenv("CONSPECT_API_KEY_FILE", keyFile)
		} else {
			t.Setenv("CONSPECT_API_KEY", testKey)
		}
		var out bytes.Buffer
		if err := run(context.Background(), uploadArgs("note.md"), conspectclient.ConfigFromEnv, &out); err != nil {
			t.Fatal(err)
		}
		assertPrivate(t, out.String(), testKey, keyFile, cfg.FilesRoot)
	}
	if calls.Load() != 2 {
		t.Fatal("unexpected request count")
	}
}

func TestAPIFailuresSanitizedAndNeverRetried(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{"unauthorized", 401, testKey + " private body"},
		{"server error", 500, testKey + " private body"},
		{"redirect", 307, testKey},
		{"invalid response", 201, "private body " + testKey},
		{"missing metadata", 201, `{"title":"` + testKey + `"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig(t, "# Valid\nprivate body\n")
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Location", "/private?key="+testKey)
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			cfg.BaseURL = server.URL
			output, err := invoke(context.Background(), cfg, uploadArgs("note.md")...)
			if err == nil || output != "" || calls.Load() != 1 {
				t.Fatal("API failure accepted, retried or emitted receipt")
			}
			assertPrivate(t, err.Error(), testKey, "private body", cfg.FilesRoot, server.URL)
			if !strings.Contains(err.Error(), "verify the project's note list") || !strings.Contains(err.Error(), "no retry") {
				t.Fatal("missing uncertain-write guidance")
			}
		})
	}
}

func TestTimeoutNeverRetries(t *testing.T) {
	cfg := testConfig(t, "# Valid\nprivate body\n")
	var calls atomic.Int32
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		<-release
	}))
	defer server.Close()
	defer close(release)
	cfg.BaseURL = server.URL
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	started := time.Now()
	output, err := invoke(ctx, cfg, uploadArgs("note.md")...)
	if err == nil || output != "" || calls.Load() != 1 || time.Since(started) > 2*time.Second {
		t.Fatal("timeout was not bounded or request was retried")
	}
	assertPrivate(t, err.Error(), testKey, "private body", cfg.FilesRoot, server.URL)
	if !strings.Contains(err.Error(), "write outcome may be unknown") || !strings.Contains(err.Error(), "verify the project's note list") {
		t.Fatal("timeout omitted uncertain-write guidance")
	}
}

func TestHelpNeedsNoConfiguration(t *testing.T) {
	var out bytes.Buffer
	err := run(context.Background(), []string{"--help"}, func() (conspectclient.Config, error) {
		t.Fatal("help read configuration")
		return conspectclient.Config{}, nil
	}, &out)
	if err != nil || out.String() != usage {
		t.Fatal("help failed")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New(testKey) }

func TestReceiptFailureDoesNotExposeWriterError(t *testing.T) {
	for _, created := range []bool{false, true} {
		err := writeReceipt(failingWriter{}, readyReceipt{Status: "ready"}, created)
		if err == nil {
			t.Fatal("writer failure ignored")
		}
		assertPrivate(t, err.Error(), testKey)
		if created && !strings.Contains(err.Error(), "do not retry POST") {
			t.Fatal("missing receipt-failure guidance")
		}
	}
}
