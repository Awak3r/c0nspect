package conspectclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const (
	maxMarkdownBytes = 2 << 20
	maxImageBytes    = 10 << 20
	maxResponseBytes = 32 << 20
)

// Client has no publishing, filesystem-writing, URL-fetching or execution tools.
// A Client may be shared by goroutines. Close waits for in-flight operations.
type Client struct {
	mu        sync.RWMutex
	closed    bool
	origin    string
	apiOrigin string
	apiKey    string
	http      *http.Client
	transport *http.Transport
	root      *os.Root
}

// New validates trusted startup configuration and optionally opens FilesRoot.
// It makes no network calls and does not check credentials against the server.
func New(cfg Config) (*Client, error) {
	cfg, key, err := prepareConfig(cfg)
	if err != nil {
		return nil, err
	}
	var root *os.Root
	if cfg.FilesRoot != "" {
		root, err = openFilesRoot(cfg.FilesRoot)
		if err != nil {
			return nil, err
		}
	}
	transport := &http.Transport{
		Proxy:                  http.ProxyFromEnvironment,
		DialContext:            (&net.Dialer{Timeout: 20 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:      true,
		MaxIdleConns:           100,
		IdleConnTimeout:        90 * time.Second,
		TLSHandshakeTimeout:    10 * time.Second,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: 1 << 20,
	}
	return &Client{
		origin:    cfg.BaseURL,
		apiOrigin: cfg.APIBaseURL,
		apiKey:    key,
		root:      root,
		transport: transport,
		http: &http.Client{
			Transport: transport,
			Timeout:   20 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// Close releases the filesystem root and idle HTTP connections. It is idempotent.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	c.apiKey = ""
	c.transport.CloseIdleConnections()
	if c.root != nil {
		if err := c.root.Close(); err != nil {
			return errors.New("could not close the configured files root")
		}
	}
	return nil
}

func (c *Client) ListProjects(ctx context.Context) ([]Project, error) {
	var result struct {
		Projects []Project `json:"projects"`
	}
	if _, err := c.request(ctx, http.MethodGet, "/projects", nil, nil, "", "", http.StatusOK, &result); err != nil {
		return nil, err
	}
	if result.Projects == nil {
		result.Projects = []Project{}
	}
	for _, project := range result.Projects {
		if !validID(project.ID) {
			return nil, errors.New("Conspect API returned an invalid project identifier")
		}
	}
	return result.Projects, nil
}

func (c *Client) ListNotes(ctx context.Context, projectID, query, sort string) ([]NoteSummary, error) {
	if !validID(projectID) {
		return nil, errors.New("project ID must be 32 lowercase hexadecimal characters")
	}
	if !utf8.ValidString(query) || strings.ContainsRune(query, 0) {
		return nil, errors.New("search query must be UTF-8 without NUL bytes")
	}
	// This is the server's documented fallback for all non-title sort values.
	if sort != "title" {
		sort = "modified"
	}
	params := url.Values{"q": {query}, "sort": {sort}}
	var result struct {
		Notes []NoteSummary `json:"notes"`
	}
	if _, err := c.request(ctx, http.MethodGet, "/projects/"+projectID+"/notes", params, nil, "", "", http.StatusOK, &result); err != nil {
		return nil, err
	}
	if result.Notes == nil {
		result.Notes = []NoteSummary{}
	}
	for _, note := range result.Notes {
		if !validID(note.ID) || note.ProjectID != projectID || note.Version < 1 {
			return nil, errors.New("Conspect API returned invalid note metadata")
		}
	}
	return result.Notes, nil
}

func (c *Client) GetNote(ctx context.Context, id string) (Note, error) {
	if !validID(id) {
		return Note{}, errors.New("note ID must be 32 lowercase hexadecimal characters")
	}
	return c.noteRequest(ctx, http.MethodGet, "/notes/"+id, nil, "", id, "", http.StatusOK)
}

func (c *Client) CreateNote(ctx context.Context, projectID, title, markdown string) (Note, error) {
	if !validID(projectID) {
		return Note{}, errors.New("project ID must be 32 lowercase hexadecimal characters")
	}
	body, err := noteBody(title, markdown)
	if err != nil {
		return Note{}, err
	}
	return c.noteRequest(ctx, http.MethodPost, "/projects/"+projectID+"/notes", body, "", "", projectID, http.StatusCreated)
}

// UpdateNote never fetches an ETag or retries a write. The caller must refetch and
// recompute its edit on 412 rather than resending stale Markdown with a new ETag.
func (c *Client) UpdateNote(ctx context.Context, noteID, title, markdown, etag string) (Note, error) {
	if !validID(noteID) {
		return Note{}, errors.New("note ID must be 32 lowercase hexadecimal characters")
	}
	if !validETag(etag) {
		return Note{}, errors.New("update requires one exact strong quoted ETag such as \"v1\" from the latest note response")
	}
	body, err := noteBody(title, markdown)
	if err != nil {
		return Note{}, err
	}
	return c.noteRequest(ctx, http.MethodPut, "/notes/"+noteID, body, etag, noteID, "", http.StatusOK)
}

func (c *Client) noteRequest(ctx context.Context, method, path string, body []byte, etag, noteID, projectID string, status int) (Note, error) {
	var note Note
	headers, err := c.request(ctx, method, path, nil, body, "application/json", etag, status, &note)
	if err != nil {
		return Note{}, err
	}
	etags := headers.Values("ETag")
	if !validID(note.ID) || !validID(note.ProjectID) || note.Version < 1 ||
		(noteID != "" && note.ID != noteID) || (projectID != "" && note.ProjectID != projectID) ||
		len(etags) != 1 || etags[0] != fmt.Sprintf("\"v%d\"", note.Version) {
		return Note{}, uncertainWrite(method, errors.New("Conspect API returned invalid note metadata or a missing/mismatched strong ETag"))
	}
	// Never trust body-supplied URL or ETag fields, or derive a public share URL.
	note.ETag = etags[0]
	note.URL = c.origin + "/notes/" + note.ID
	if note.Attachments == nil {
		note.Attachments = []Attachment{}
	}
	return note, nil
}

func noteBody(title, markdown string) ([]byte, error) {
	if strings.TrimSpace(title) == "" || !utf8.ValidString(title) || strings.ContainsRune(title, 0) || utf8.RuneCountInString(title) > 300 {
		return nil, errors.New("title must be nonblank UTF-8 without NUL and at most 300 Unicode characters")
	}
	if err := validateText(markdown); err != nil {
		return nil, err
	}
	body, err := json.Marshal(struct {
		Title    string `json:"title"`
		Markdown string `json:"markdown"`
	}{title, markdown})
	if err != nil {
		return nil, errors.New("could not encode the note request")
	}
	return body, nil
}

func validID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func validETag(value string) bool {
	if len(value) < 4 || !strings.HasPrefix(value, "\"v") || !strings.HasSuffix(value, "\"") {
		return false
	}
	n, err := strconv.ParseInt(value[2:len(value)-1], 10, 64)
	return err == nil && n > 0 && value == fmt.Sprintf("\"v%d\"", n)
}

// request performs exactly one application-level attempt. In particular, it
// never follows redirects, accepts server-provided URLs, or replays write bodies.
func (c *Client) request(ctx context.Context, method, path string, query url.Values, body []byte, contentType, etag string, status int, result any) (http.Header, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.closed {
		return nil, errors.New("Conspect client is closed")
	}
	if ctx == nil {
		return nil, errors.New("a request context is required")
	}
	origin := c.apiOrigin
	if origin == "" {
		origin = c.origin
	}
	endpoint := origin + "/api/v1" + path
	if len(query) != 0 {
		endpoint += "?" + query.Encode()
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return nil, errors.New("could not construct the Conspect API request")
	}
	// NewRequest recognizes bytes.Reader and otherwise installs a replay hook.
	// Writes have no idempotency contract, so do not expose that hook to Transport.
	req.GetBody = nil
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", contentType)
	}
	if etag != "" {
		req.Header.Set("If-Match", etag)
	}
	response, err := c.http.Do(req)
	if err != nil {
		var failure error = errors.New("Conspect API request failed; check connectivity and TLS configuration")
		if ctx.Err() != nil {
			failure = fmt.Errorf("Conspect API request interrupted: %w", ctx.Err())
		} else if errors.Is(err, context.DeadlineExceeded) {
			failure = fmt.Errorf("Conspect API request timed out: %w", context.DeadlineExceeded)
		}
		return nil, uncertainWrite(method, failure)
	}
	defer response.Body.Close()
	if response.StatusCode != status {
		var failure error = &APIError{StatusCode: response.StatusCode}
		if response.StatusCode < 400 || response.StatusCode >= 500 || response.StatusCode == http.StatusRequestTimeout {
			failure = uncertainWrite(method, failure)
		}
		return nil, failure
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return nil, uncertainWrite(method, errors.New("Conspect API returned a non-JSON response"))
	}
	if response.ContentLength > maxResponseBytes {
		return nil, uncertainWrite(method, errors.New("Conspect API response exceeds the 32 MiB limit"))
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return nil, uncertainWrite(method, errors.New("could not read the Conspect API response"))
	}
	if len(data) > maxResponseBytes {
		return nil, uncertainWrite(method, errors.New("Conspect API response exceeds the 32 MiB limit"))
	}
	trimmed := bytes.TrimSpace(data)
	if !utf8.Valid(data) || len(trimmed) == 0 || trimmed[0] != '{' || json.Unmarshal(data, result) != nil {
		return nil, uncertainWrite(method, errors.New("Conspect API returned an invalid JSON object"))
	}
	return response.Header, nil
}
