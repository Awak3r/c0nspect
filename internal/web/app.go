package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"conspect/internal/render"
	"conspect/internal/store"
)

type Config struct {
	BaseURL          string
	Secret           []byte
	DataDir          string
	TrustProxy       bool
	MaxMarkdownBytes int64
	MaxImageBytes    int64
	MaxStorageBytes  int64
	MCPEnabled       bool
	MCPAPIURL        string
}

type App struct {
	db        store.Repository
	cfg       Config
	renderer  *render.Renderer
	templates *template.Template
	mux       *http.ServeMux
	limits    *limiter
	oauth     store.OAuthRepository
}

type requestKey struct{}
type sessionKey struct{}

type HTTPError struct {
	Status        int
	Code, Message string
}

func (e *HTTPError) Error() string { return e.Message }

func New(db store.Repository, cfg Config) (*App, error) {
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("APP_BASE_URL must be an absolute HTTP(S) origin")
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if len(cfg.Secret) != 32 {
		return nil, errors.New("APP_SECRET must contain 32 bytes")
	}
	if cfg.MaxMarkdownBytes <= 0 {
		cfg.MaxMarkdownBytes = 2 << 20
	}
	if cfg.MaxImageBytes <= 0 {
		cfg.MaxImageBytes = 10 << 20
	}
	if cfg.MaxStorageBytes <= 0 {
		cfg.MaxStorageBytes = 1 << 30
	}
	if cfg.DataDir == "" {
		cfg.DataDir = "data"
	}
	if err := os.MkdirAll(filepath.Join(cfg.DataDir, "uploads"), 0700); err != nil {
		return nil, fmt.Errorf("create uploads directory: %w", err)
	}
	t, err := template.New("pages").Funcs(template.FuncMap{"date": func(t time.Time) string { return t.UTC().Format("02.01.2006 15:04") }, "join": strings.Join, "stylesheet": stylesheetURL, "readerAsset": readerAsset, "now": time.Now}).Parse(pageTemplates)
	if err != nil {
		return nil, err
	}
	a := &App{db: db, cfg: cfg, renderer: render.New(), templates: t, mux: http.NewServeMux(), limits: &limiter{entries: map[string]window{}}}
	if cfg.MCPEnabled {
		var ok bool
		a.oauth, ok = db.(store.OAuthRepository)
		if !ok {
			return nil, errors.New("remote MCP requires an OAuth repository")
		}
		if a.cfg.MCPAPIURL == "" {
			a.cfg.MCPAPIURL = "http://127.0.0.1:8080"
		}
		apiURL, parseErr := url.Parse(a.cfg.MCPAPIURL)
		if parseErr != nil || apiURL.Scheme != "http" || apiURL.User != nil || apiURL.RawQuery != "" || apiURL.Fragment != "" || apiURL.Path != "" || net.ParseIP(apiURL.Hostname()) == nil || !net.ParseIP(apiURL.Hostname()).IsLoopback() {
			return nil, errors.New("MCP_API_URL must be a loopback HTTP origin")
		}
		if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || (net.ParseIP(u.Hostname()) != nil && net.ParseIP(u.Hostname()).IsLoopback()))) {
			return nil, errors.New("remote MCP requires HTTPS outside localhost")
		}
	}
	a.routes()
	return a, nil
}

func (a *App) Handler() http.Handler { return a.security(a.mux) }
func (a *App) routes() {
	m := a.mux
	if a.cfg.MCPEnabled {
		a.oauthRoutes()
	}
	m.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/projects", http.StatusSeeOther) })
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if a.db.Ping(ctx) != nil {
			http.Error(w, "unavailable", 503)
			return
		}
		w.WriteHeader(200)
	})
	m.HandleFunc("GET /login", a.loginPage)
	m.HandleFunc("POST /login", a.login)
	m.HandleFunc("POST /logout", a.owner(a.logout))
	m.HandleFunc("GET /projects", a.owner(a.projects))
	m.HandleFunc("POST /projects", a.owner(a.createProject))
	m.HandleFunc("GET /projects/{projectID}", a.owner(a.project))
	m.HandleFunc("GET /projects/{projectID}/manage", a.owner(a.manageProject))
	m.HandleFunc("POST /projects/{projectID}/edit", a.owner(a.editProject))
	m.HandleFunc("POST /projects/{projectID}/delete", a.owner(a.deleteProject))
	m.HandleFunc("POST /projects/{projectID}/notes", a.owner(a.importNotes))
	m.HandleFunc("GET /notes/{noteID}", a.owner(a.readNote))
	m.HandleFunc("GET /notes/{noteID}/manage", a.owner(a.manageNote))
	m.HandleFunc("POST /notes/{noteID}/replace", a.owner(a.replaceNote))
	m.HandleFunc("POST /notes/{noteID}/metadata", a.owner(a.noteMetadata))
	m.HandleFunc("POST /notes/{noteID}/delete", a.owner(a.deleteNote))
	m.HandleFunc("POST /notes/{noteID}/attachments", a.owner(a.uploadAttachment))
	m.HandleFunc("POST /notes/{noteID}/attachments/{attachmentID}/delete", a.owner(a.deleteAttachment))
	m.HandleFunc("GET /notes/{noteID}/attachments/{attachmentID}", a.owner(a.ownerAttachment))
	m.HandleFunc("GET /notes/{noteID}/share", a.owner(a.sharePage))
	m.HandleFunc("POST /notes/{noteID}/share", a.owner(a.changeShare))
	m.HandleFunc("GET /s/{token}", a.sharedNote)
	m.HandleFunc("GET /s/{token}/attachments/{attachmentID}", a.sharedAttachment)
	m.HandleFunc("GET /settings/api-keys", a.owner(a.keysPage))
	m.HandleFunc("POST /settings/api-keys", a.owner(a.createKey))
	m.HandleFunc("POST /settings/api-keys/{keyID}/revoke", a.owner(a.revokeKey))
	m.HandleFunc("GET /api/v1/projects", a.apiProjects)
	m.HandleFunc("GET /api/v1/projects/{projectID}/notes", a.apiNotes)
	m.HandleFunc("GET /api/v1/notes/{noteID}", a.apiGetNote)
	m.HandleFunc("POST /api/v1/projects/{projectID}/notes", a.apiCreateNote)
	m.HandleFunc("PUT /api/v1/notes/{noteID}", a.apiUpdateNote)
	m.HandleFunc("POST /api/v1/notes/{noteID}/attachments", a.apiUploadAttachment)
	m.HandleFunc("GET /api/v1/notes/{noteID}/attachments/{attachmentID}/content", a.apiAttachment)
	m.HandleFunc("GET /api/v1/openapi.json", a.apiOpenAPI)
	m.HandleFunc("/assets/", serveStaticAsset)
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { a.fail(w, r, store.ErrNotFound) })
}

func randomToken(prefix string) string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return prefix + hex.EncodeToString(b)
}
func etag(v int64) string { return fmt.Sprintf("\"v%d\"", v) }
func validTitle(s string) bool {
	return strings.TrimSpace(s) != "" && utf8.ValidString(s) && utf8.RuneCountInString(s) <= 300 && !strings.ContainsRune(s, 0)
}
func validateMarkdown(s string, max int64) error {
	if int64(len(s)) > max {
		return &HTTPError{413, "too_large", "Markdown превышает допустимый размер"}
	}
	if !utf8.ValidString(s) || strings.ContainsRune(s, 0) {
		return &HTTPError{422, "invalid_markdown", "Нужен текст Markdown в UTF-8 без нулевых байтов"}
	}
	return nil
}
func decodeJSON(w http.ResponseWriter, r *http.Request, v any, max int64) error {
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		return &HTTPError{415, "unsupported_media_type", "Ожидается application/json"}
	}
	r.Body = http.MaxBytesReader(w, r.Body, max)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if err := d.Decode(new(any)); !errors.Is(err, io.EOF) {
		return &HTTPError{400, "invalid_json", "Ожидается один JSON-объект"}
	}
	return nil
}
func (a *App) writeJSON(w http.ResponseWriter, r *http.Request, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Error("write JSON", "request_id", r.Context().Value(requestKey{}))
	}
}
func (a *App) apiError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	a.writeJSON(w, r, status, map[string]any{"error": map[string]any{"code": code, "message": message, "request_id": r.Context().Value(requestKey{})}})
}
func (a *App) fail(w http.ResponseWriter, r *http.Request, err error) {
	status, code, message := 500, "internal_error", "Не удалось выполнить запрос"
	var h *HTTPError
	var max *http.MaxBytesError
	var syntax *json.SyntaxError
	var typ *json.UnmarshalTypeError
	switch {
	case errors.As(err, &h):
		status, code, message = h.Status, h.Code, h.Message
	case errors.Is(err, store.ErrNotFound):
		status, code, message = 404, "not_found", "Материал недоступен"
	case errors.Is(err, store.ErrForbidden):
		status, code, message = 403, "forbidden", "Недостаточно прав"
	case errors.Is(err, store.ErrConflict):
		status, code, message = 412, "version_conflict", "Конспект уже изменён. Получите актуальную версию"
	case errors.Is(err, store.ErrQuota):
		status, code, message = 413, "storage_quota", "Достигнут лимит хранилища"
	case errors.As(err, &max):
		status, code, message = 413, "too_large", "Превышен допустимый размер запроса"
	case errors.As(err, &syntax), errors.As(err, &typ), errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		status, code, message = 400, "invalid_json", "Некорректный JSON"
	}
	if status == 500 {
		slog.Error("request failed", "request_id", r.Context().Value(requestKey{}), "route", r.Pattern, "error_type", fmt.Sprintf("%T", err))
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		a.apiError(w, r, status, code, message)
		return
	}
	a.page(w, r, status, "error", pageData{Title: "Ошибка", Error: message})
}
func (a *App) security(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := store.NewID()
		r = r.WithContext(context.WithValue(r.Context(), requestKey{}, id))
		h := w.Header()
		h.Set("X-Request-ID", id)
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		// Native form submissions need their same-origin Origin header. Readers
		// instead suppress referrers because their URLs can contain access tokens.
		h.Set("Referrer-Policy", "same-origin")
		if strings.HasPrefix(r.URL.Path, "/s/") || strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Referrer-Policy", "no-referrer")
		}
		h.Set("X-Robots-Tag", "noindex, nofollow")
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; style-src-attr 'unsafe-inline'; img-src 'self'; font-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		if strings.HasPrefix(a.cfg.BaseURL, "https://") {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		defer func() {
			if recover() != nil {
				slog.Error("request panic", "request_id", id)
				a.fail(w, r, errors.New("request panic"))
			}
		}()
		next.ServeHTTP(w, r)
	})
}
func (a *App) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if a.cfg.TrustProxy {
		parts := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
		if ip := net.ParseIP(strings.TrimSpace(parts[len(parts)-1])); ip != nil {
			host = ip.String()
		}
	}
	return host
}

type window struct {
	count int
	end   time.Time
}
type limiter struct {
	mu      sync.Mutex
	entries map[string]window
}

func (l *limiter) allow(key string, limit int, duration time.Duration) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if len(l.entries) >= 4096 {
		for k, v := range l.entries {
			if now.After(v.end) {
				delete(l.entries, k)
			}
		}
		if _, ok := l.entries[key]; !ok && len(l.entries) >= 4096 {
			return false
		}
	}
	v := l.entries[key]
	if now.After(v.end) {
		v = window{end: now.Add(duration)}
	}
	v.count++
	l.entries[key] = v
	return v.count <= limit
}
func formVersion(r *http.Request) (int64, error) {
	v, err := strconv.ParseInt(r.FormValue("version"), 10, 64)
	if err != nil || v <= 0 {
		return 0, &HTTPError{400, "invalid_version", "Нужна текущая версия конспекта"}
	}
	return v, nil
}
