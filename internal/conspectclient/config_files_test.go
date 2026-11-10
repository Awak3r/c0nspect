package conspectclient

import (
	"bytes"
	"context"
	"image"
	"image/png"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestOriginValidation(t *testing.T) {
	for _, raw := range []string{
		"https://example.invalid", "https://example.invalid/", "https://example.invalid/api/v1/",
		"http://localhost:8080", "http://127.0.0.2:8080/api/v1", "http://[::1]:8080",
	} {
		if _, err := normalizeOrigin(raw); err != nil {
			t.Fatal("valid origin rejected")
		}
	}
	for _, raw := range []string{
		"http://example.invalid", "http://localhost.evil.invalid", "http://127.0.0.1.evil.invalid",
		"http://0.0.0.0", "http://[::]", "https://user:secret@example.invalid", "https://example.invalid?token=secret",
		"https://example.invalid/#secret", "https://example.invalid/notes", "https://example.invalid/api/v1/../notes",
		"https://example.invalid:70000", "https://example.invalid/%61pi/v1", "//example.invalid", "file:///tmp/key",
	} {
		_, err := normalizeOrigin(raw)
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("invalid origin accepted or exposed")
		}
	}
}

func TestEnvironmentAndKeyFile(t *testing.T) {
	t.Setenv("CONSPECT_URL", "")
	t.Setenv("CONSPECT_API_KEY", testKey)
	t.Setenv("CONSPECT_API_KEY_FILE", "")
	t.Setenv("CONSPECT_FILES_ROOT", "")
	cfg, err := ConfigFromEnv()
	if err != nil || cfg.BaseURL != defaultBaseURL || cfg.APIKey != testKey || cfg.FilesRoot != "" {
		t.Fatal("incorrect environment defaults")
	}
	name := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(name, []byte(testKey+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONSPECT_API_KEY_FILE", name)
	if _, err := ConfigFromEnv(); err == nil {
		t.Fatal("two credential sources accepted")
	}
	t.Setenv("CONSPECT_API_KEY", "")
	cfg, err = ConfigFromEnv()
	if err != nil || cfg.APIKey != "" || cfg.APIKeyFile != name {
		t.Fatal("credential file configuration was not preserved")
	}
	client, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	if runtime.GOOS != "windows" {
		if err := os.Chmod(name, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := ConfigFromEnv(); err == nil || strings.Contains(err.Error(), name) || strings.Contains(err.Error(), testKey) {
			t.Fatal("insecure credential permissions accepted or credentials exposed")
		}
	}
	t.Setenv("CONSPECT_API_KEY_FILE", "")
	if _, err := ConfigFromEnv(); err == nil {
		t.Fatal("missing credentials accepted")
	}
}

func TestLocalFileBoundary(t *testing.T) {
	root := t.TempDir()
	for name, body := range map[string][]byte{
		"source.md": []byte("# Source\n"), "source.txt": []byte("plain text"),
		"nul.md": {'x', 0}, "invalid.md": {0xff}, "large.md": bytes.Repeat([]byte("x"), maxMarkdownBytes+1),
	} {
		if err := os.WriteFile(filepath.Join(root, name), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	client, err := New(Config{APIKey: testKey, FilesRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if source, err := client.ReadMarkdown("source.md"); err != nil || source != "# Source\n" {
		t.Fatal("valid Markdown rejected")
	}
	if source, err := client.ReadSource("source.txt"); err != nil || source != "plain text" {
		t.Fatal("valid text rejected")
	}
	for _, name := range []string{
		"../source.md", "nested/../source.md", "nested/./source.md", "nested//source.md", "/source.md",
		`nested\source.md`, `C:\source.md`, "source.md:stream", "nul.md", "invalid.md", "large.md", "source.txt",
	} {
		if _, err := client.ReadMarkdown(name); err == nil {
			t.Fatal("unsafe or invalid Markdown accepted")
		}
	}
	if err := os.Mkdir(filepath.Join(root, "dir.md"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := client.ReadMarkdown("dir.md"); err == nil {
		t.Fatal("directory accepted as source")
	}
	if runtime.GOOS != "windows" {
		for name, target := range map[string]string{"link.md": "source.md", "outside.md": filepath.Join(t.TempDir(), "secret.md"), "nested": "."} {
			if err := os.Symlink(target, filepath.Join(root, name)); err != nil {
				t.Fatal(err)
			}
		}
		for _, name := range []string{"link.md", "outside.md", "nested/source.md"} {
			if _, err := client.ReadMarkdown(name); err == nil {
				t.Fatal("symlink accepted")
			}
		}
	}
	disabled, err := New(Config{APIKey: testKey})
	if err != nil {
		t.Fatal(err)
	}
	defer disabled.Close()
	if _, err := disabled.ReadMarkdown("source.md"); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatal("file tools must be opt-in")
	}
}

func TestUploadChecksRealImageAndMultipart(t *testing.T) {
	root := t.TempDir()
	var data bytes.Buffer
	if err := png.Encode(&data, image.NewRGBA(image.Rect(0, 0, 1, 1))); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pixel.png"), data.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "fake.png"), []byte("<html>not an image</html>"), 0600); err != nil {
		t.Fatal(err)
	}
	client, err := New(Config{APIKey: testKey, FilesRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	calls := 0
	client.http.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/notes/"+testNoteID+"/attachments" || r.GetBody != nil {
			t.Fatal("incorrect upload request")
		}
		_, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil {
			t.Fatal(err)
		}
		reader := multipart.NewReader(r.Body, params["boundary"])
		part, err := reader.NextPart()
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(part)
		if err != nil || part.FormName() != "file" || part.FileName() != "pixel.png" || part.Header.Get("Content-Type") != "image/png" || !bytes.Equal(body, data.Bytes()) {
			t.Fatal("incorrect multipart image")
		}
		if _, err := reader.NextPart(); err != io.EOF {
			t.Fatal("unexpected additional multipart field")
		}
		return jsonResponse(201, `{"attachment":{"id":"33333333333333333333333333333333","note_id":"`+testNoteID+`","mime_type":"image/png","size":`+strconv.Itoa(data.Len())+`},"markdown":"![pixel.png](attachment:33333333333333333333333333333333)"}`, ""), nil
	})
	if _, err := client.UploadImage(context.Background(), testNoteID, "fake.png"); err == nil || calls != 0 {
		t.Fatal("fake image reached transport")
	}
	result, err := client.UploadImage(context.Background(), testNoteID, "pixel.png")
	if err != nil || result.Markdown == "" || calls != 1 {
		t.Fatal("upload failed or unexpectedly modified the note")
	}
}
