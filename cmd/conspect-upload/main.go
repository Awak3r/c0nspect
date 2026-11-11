// conspect-upload sends one explicitly selected, ready-made Markdown file over HTTP.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"conspect/internal/conspectclient"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/text"
)

const usage = `Usage: conspect-upload --project-id ID --path FILE [--title TITLE] [--check] [--config FILE]

Upload one ready-made .md file without changing its Markdown. This is not an MCP server.
--project-id  Required project ID (32 lowercase hexadecimal characters).
--path        Required relative path or absolute WSL path within CONSPECT_FILES_ROOT.
--title       Optional title; otherwise the first H1 or filename without extension.
--check       Validate configuration and file locally; no network or saving.
--config      Optional config file; default is the platform config directory,
              conspect/upload.json, used only when the file exists.

Environment: CONSPECT_URL, required CONSPECT_FILES_ROOT, and exactly one of
CONSPECT_API_KEY_FILE / CONSPECT_API_KEY. Never pass credentials as arguments.
The config file may provide url, files_root and key_file (a path, never the
secret); a nonempty environment variable overrides the same config field.
Output: one compact JSON metadata receipt. No Markdown or local paths are printed.
Uploads are not retried. After an uncertain write, verify the project's note list
before explicitly retrying POST.
`

type readyReceipt struct {
	Bytes  int    `json:"bytes"`
	Title  string `json:"title"`
	Status string `json:"status"`
}

type createdReceipt struct {
	ID         string `json:"id"`
	ProjectID  string `json:"project_id"`
	Title      string `json:"title"`
	Version    int64  `json:"version"`
	ETag       string `json:"etag"`
	URL        string `json:"url"`
	Bytes      int    `json:"bytes"`
	DurationMS int64  `json:"duration_ms"`
	Status     string `json:"status"`
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], configLoader, os.Stdout)
	cancel()
	if err != nil {
		fmt.Fprintln(os.Stderr, "conspect-upload:", err)
		os.Exit(1)
	}
}

// uploadConfigFile is a private local convenience file. It carries no secret:
// key_file points at a separately protected 0600 key file.
type uploadConfigFile struct {
	URL       string `json:"url"`
	FilesRoot string `json:"files_root"`
	KeyFile   string `json:"key_file"`
}

const maxConfigBytes = 64 * 1024

// configLoader returns the configuration callback for one invocation. An explicit
// --config must exist; the default path is used only when present. Real
// environment variables override values from the file.
func configLoader(explicit string) func() (conspectclient.Config, error) {
	return func() (conspectclient.Config, error) {
		path := explicit
		if path == "" {
			configured, err := os.UserConfigDir()
			if err != nil {
				return conspectclient.ConfigFromEnv()
			}
			path = filepath.Join(configured, "conspect", "upload.json")
		}
		file, err := readUploadConfig(path, explicit != "")
		if err != nil {
			return conspectclient.Config{}, err
		}
		if file == (uploadConfigFile{}) {
			return conspectclient.ConfigFromEnv()
		}
		merged := func(name string) string {
			if value := os.Getenv(name); value != "" {
				return value
			}
			switch name {
			case "CONSPECT_URL":
				return file.URL
			case "CONSPECT_FILES_ROOT":
				return file.FilesRoot
			case "CONSPECT_API_KEY_FILE":
				return file.KeyFile
			}
			return ""
		}
		return conspectclient.ConfigFromLookup(merged)
	}
}

func readUploadConfig(path string, required bool) (uploadConfigFile, error) {
	invalid := errors.New("config file must be a readable regular file of at most 64 KiB with url, files_root and key_file JSON keys")
	before, err := os.Lstat(path)
	if err != nil {
		if required || !errors.Is(err, os.ErrNotExist) {
			if errors.Is(err, os.ErrNotExist) {
				return uploadConfigFile{}, errors.New("--config file does not exist")
			}
			return uploadConfigFile{}, invalid
		}
		return uploadConfigFile{}, nil
	}
	if !before.Mode().IsRegular() || before.Size() > maxConfigBytes {
		return uploadConfigFile{}, invalid
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) > maxConfigBytes {
		return uploadConfigFile{}, invalid
	}
	var file uploadConfigFile
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&file); err != nil {
		return uploadConfigFile{}, errors.New("config file must contain a JSON object with only url, files_root and key_file keys")
	}
	if decoder.More() {
		return uploadConfigFile{}, errors.New("config file must contain exactly one JSON object")
	}
	for _, value := range []string{file.URL, file.FilesRoot, file.KeyFile} {
		if strings.ContainsFunc(value, func(r rune) bool { return r < ' ' || r == '\x7f' }) {
			return uploadConfigFile{}, invalid
		}
	}
	return file, nil
}

func run(ctx context.Context, args []string, newLoader func(configPath string) func() (conspectclient.Config, error), out io.Writer) error {
	started := time.Now()
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	flags := flag.NewFlagSet("conspect-upload", flag.ContinueOnError)
	// flag's default diagnostics echo arguments, which may contain private data.
	flags.SetOutput(io.Discard)
	projectID := flags.String("project-id", "", "")
	filename := flags.String("path", "", "")
	title := flags.String("title", "", "")
	check := flags.Bool("check", false, "")
	configPath := flags.String("config", "", "")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			if _, err := io.WriteString(out, usage); err != nil {
				return errors.New("could not write usage")
			}
			return nil
		}
		return errors.New("invalid arguments; use --help (credentials must not be passed as arguments)")
	}
	if flags.NArg() != 0 || *projectID == "" || *filename == "" {
		return errors.New("--project-id and --path are required; no positional arguments are accepted; use --help")
	}
	if err := ctx.Err(); err != nil {
		return errors.New("operation interrupted before upload; nothing was sent")
	}
	cfg, err := newLoader(*configPath)()
	if err != nil {
		return err
	}
	if strings.TrimSpace(cfg.FilesRoot) == "" {
		return errors.New("CONSPECT_FILES_ROOT is required; no current-directory fallback is allowed")
	}
	root, err := filepath.Abs(cfg.FilesRoot)
	if err != nil {
		return errors.New("could not resolve CONSPECT_FILES_ROOT")
	}
	cfg.FilesRoot = root
	relative, err := relativeMarkdownPath(root, *filename)
	if err != nil {
		return err
	}
	client, err := conspectclient.New(cfg)
	if err != nil {
		return err
	}
	defer client.Close()
	markdown, err := client.ReadMarkdown(relative)
	if err != nil {
		return err
	}
	resolvedTitle := strings.TrimSpace(*title)
	if resolvedTitle == "" {
		resolvedTitle = markdownTitle(markdown, relative)
	}
	if err := validateNote(ctx, client, *projectID, resolvedTitle, markdown); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return errors.New("operation interrupted before upload; nothing was sent")
	}
	if *check {
		return writeReceipt(out, readyReceipt{Bytes: len(markdown), Title: resolvedTitle, Status: "ready"}, false)
	}
	note, err := client.CreateNote(ctx, *projectID, resolvedTitle, markdown)
	if err != nil {
		// Do not propagate network errors, response bodies or remote text. Even a
		// failed response may follow a committed write; never replay this POST.
		var apiError *conspectclient.APIError
		if errors.As(err, &apiError) {
			return fmt.Errorf("upload failed (HTTP %d); write outcome may be unknown; verify the project's note list before explicitly retrying POST; no retry performed", apiError.StatusCode)
		}
		return errors.New("upload failed or was interrupted; write outcome may be unknown; verify the project's note list before explicitly retrying POST; no retry performed")
	}
	return writeReceipt(out, createdReceipt{
		ID: note.ID, ProjectID: note.ProjectID, Title: resolvedTitle,
		Version: note.Version, ETag: note.ETag, URL: note.URL,
		Bytes: len(markdown), DurationMS: time.Since(started).Milliseconds(), Status: "created",
	}, true)
}

func relativeMarkdownPath(root, filename string) (string, error) {
	invalid := errors.New("--path must select a file within CONSPECT_FILES_ROOT without traversal, backslashes or drive prefixes")
	if strings.ContainsAny(filename, "\\:") {
		return "", invalid
	}
	// Reject traversal before Abs/Rel can clean it into an apparently safe path.
	for _, part := range strings.Split(filepath.ToSlash(filename), "/") {
		if part == ".." {
			return "", invalid
		}
	}
	if !filepath.IsAbs(filename) {
		if !fs.ValidPath(filepath.ToSlash(filename)) {
			return "", invalid
		}
		filename = filepath.Join(root, filename)
	}
	absolute, err := filepath.Abs(filename)
	if err != nil {
		return "", invalid
	}
	relative, err := filepath.Rel(root, absolute)
	if err != nil {
		return "", invalid
	}
	relative = filepath.ToSlash(relative)
	if relative == "." || !fs.ValidPath(relative) {
		return "", invalid
	}
	return relative, nil
}

func validateNote(ctx context.Context, client *conspectclient.Client, projectID, title, markdown string) error {
	// The client has no exported input validator. A pre-canceled context lets
	// CreateNote validate ID/title/content with its own rules, but net/http cannot
	// send the request. This also keeps --check entirely offline.
	validationCtx, cancel := context.WithCancel(ctx)
	cancel()
	_, err := client.CreateNote(validationCtx, projectID, title, markdown)
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil
	}
	return err
}

func markdownTitle(source, filename string) string {
	title := strings.TrimSuffix(path.Base(filename), path.Ext(filename))
	data := []byte(source)
	document := goldmark.New().Parser().Parse(text.NewReader(data))
	_ = ast.Walk(document, func(node ast.Node, entering bool) (ast.WalkStatus, error) {
		if heading, ok := node.(*ast.Heading); ok && entering && heading.Level == 1 {
			title = string(heading.Text(data))
			return ast.WalkStop, nil
		}
		return ast.WalkContinue, nil
	})
	return strings.TrimSpace(title)
}

func writeReceipt(out io.Writer, receipt any, created bool) error {
	if err := json.NewEncoder(out).Encode(receipt); err != nil {
		if created {
			return errors.New("note was created but its receipt could not be written; verify the project's note list; do not retry POST")
		}
		return errors.New("could not write validation receipt; nothing was uploaded")
	}
	return nil
}
