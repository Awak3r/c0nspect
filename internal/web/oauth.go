package web

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"conspect/internal/store"
)

var oauthScopes = []string{"notes:read", "notes:write", "attachments:read", "attachments:write"}
var oauthCallbackID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,160}$`)
var oauthVerifier = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)

func (a *App) oauthRoutes() {
	a.mux.HandleFunc("GET /.well-known/oauth-protected-resource", a.oauthResourceMetadata)
	a.mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", a.oauthResourceMetadata)
	a.mux.HandleFunc("GET /.well-known/oauth-authorization-server", a.oauthServerMetadata)
	a.mux.HandleFunc("POST /oauth/register", a.oauthRegister)
	a.mux.HandleFunc("GET /oauth/authorize", a.owner(a.oauthAuthorize))
	a.mux.HandleFunc("POST /oauth/authorize", a.owner(a.oauthApprove))
	a.mux.HandleFunc("POST /oauth/token", a.oauthToken)
	a.mux.HandleFunc("POST /oauth/revoke", a.oauthRevoke)
	a.mux.HandleFunc("/mcp", a.remoteMCP)
}

func (a *App) oauthResource() string { return a.cfg.BaseURL + "/mcp" }

func (a *App) oauthResourceMetadata(w http.ResponseWriter, r *http.Request) {
	a.writeJSON(w, r, 200, map[string]any{"resource": a.oauthResource(), "authorization_servers": []string{a.cfg.BaseURL}, "scopes_supported": oauthScopes, "bearer_methods_supported": []string{"header"}, "resource_name": "Conspect"})
}

func (a *App) oauthServerMetadata(w http.ResponseWriter, r *http.Request) {
	a.writeJSON(w, r, 200, map[string]any{
		"issuer": a.cfg.BaseURL, "authorization_endpoint": a.cfg.BaseURL + "/oauth/authorize",
		"token_endpoint": a.cfg.BaseURL + "/oauth/token", "registration_endpoint": a.cfg.BaseURL + "/oauth/register",
		"revocation_endpoint": a.cfg.BaseURL + "/oauth/revoke", "response_types_supported": []string{"code"},
		"grant_types_supported": []string{"authorization_code", "refresh_token"}, "code_challenge_methods_supported": []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{"none", "client_secret_post", "client_secret_basic"},
		"revocation_endpoint_auth_methods_supported":     []string{"none", "client_secret_post", "client_secret_basic"},
		"authorization_response_iss_parameter_supported": true, "scopes_supported": oauthScopes,
	})
}

func (a *App) oauthError(w http.ResponseWriter, r *http.Request, status int, code string) {
	a.writeJSON(w, r, status, map[string]string{"error": code})
}

func (a *App) oauthLimit(w http.ResponseWriter, r *http.Request, kind string, limit int, period time.Duration) bool {
	if !a.limits.allow("oauth:"+kind+":"+a.clientIP(r), limit, period) {
		w.Header().Set("Retry-After", "60")
		a.oauthError(w, r, 429, "temporarily_unavailable")
		return false
	}
	return true
}

// Only ChatGPT callback destinations are accepted; registration never fetches a
// client-supplied URL. Client names are display text, not authenticated identity.
func validOAuthRedirect(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 2048 || u.Scheme != "https" || u.Host != "chatgpt.com" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.RawPath != "" || u.ForceQuery {
		return false
	}
	if u.Path == "/connector_platform_oauth_redirect" {
		return true
	}
	id, ok := strings.CutPrefix(u.Path, "/connector/oauth/")
	return ok && oauthCallbackID.MatchString(id)
}

func parseOAuthScopes(raw string) ([]string, bool) {
	if len(raw) > 256 {
		return nil, false
	}
	scopes := unique(strings.Fields(raw))
	for _, scope := range scopes {
		if !slices.Contains(oauthScopes, scope) {
			return nil, false
		}
	}
	return scopes, true
}

func (a *App) oauthRegister(w http.ResponseWriter, r *http.Request) {
	if !a.oauthLimit(w, r, "register", 10, time.Hour) {
		return
	}
	if !a.limits.allow("oauth:register:global", 100, time.Hour) {
		a.oauthError(w, r, 429, "temporarily_unavailable")
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || r.URL.RawQuery != "" {
		a.oauthError(w, r, 400, "invalid_client_metadata")
		return
	}
	var input struct {
		Name          string   `json:"client_name"`
		RedirectURIs  []string `json:"redirect_uris"`
		AuthMethod    string   `json:"token_endpoint_auth_method"`
		GrantTypes    []string `json:"grant_types"`
		ResponseTypes []string `json:"response_types"`
		Scope         string   `json:"scope"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16384)
	d := json.NewDecoder(r.Body)
	if d.Decode(&input) != nil || !errors.Is(d.Decode(new(any)), io.EOF) {
		a.oauthError(w, r, 400, "invalid_client_metadata")
		return
	}
	if input.Name == "" {
		input.Name = "ChatGPT"
	}
	if !validTitle(input.Name) || len(input.RedirectURIs) < 1 || len(input.RedirectURIs) > 4 {
		a.oauthError(w, r, 400, "invalid_client_metadata")
		return
	}
	for _, uri := range input.RedirectURIs {
		if !validOAuthRedirect(uri) {
			a.oauthError(w, r, 400, "invalid_redirect_uri")
			return
		}
	}
	for _, grant := range input.GrantTypes {
		if grant != "authorization_code" && grant != "refresh_token" {
			a.oauthError(w, r, 400, "invalid_client_metadata")
			return
		}
	}
	for _, response := range input.ResponseTypes {
		if response != "code" {
			a.oauthError(w, r, 400, "invalid_client_metadata")
			return
		}
	}
	if _, ok := parseOAuthScopes(input.Scope); !ok {
		a.oauthError(w, r, 400, "invalid_scope")
		return
	}
	if input.AuthMethod == "" {
		input.AuthMethod = "client_secret_basic"
	}
	if !slices.Contains([]string{"none", "client_secret_post", "client_secret_basic"}, input.AuthMethod) {
		a.oauthError(w, r, 400, "invalid_client_metadata")
		return
	}
	client := store.OAuthClient{ID: store.NewID(), Name: input.Name, RedirectURIs: unique(input.RedirectURIs), AuthMethod: input.AuthMethod}
	secret := ""
	if client.AuthMethod != "none" {
		secret = randomToken("ocs_")
		client.SecretHash = tokenHash(secret)
	}
	client, err = a.oauth.CreateOAuthClient(r.Context(), client)
	if err != nil {
		if errors.Is(err, store.ErrQuota) {
			a.oauthError(w, r, 429, "temporarily_unavailable")
		} else {
			a.oauthError(w, r, 500, "server_error")
		}
		return
	}
	result := map[string]any{"client_id": client.ID, "client_id_issued_at": client.CreatedAt.Unix(), "client_name": client.Name,
		"redirect_uris": client.RedirectURIs, "token_endpoint_auth_method": client.AuthMethod,
		"grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"}, "scope": strings.Join(oauthScopes, " ")}
	if secret != "" {
		result["client_secret"] = secret
		result["client_secret_expires_at"] = 0
	}
	a.writeJSON(w, r, 201, result)
}

func (a *App) oauthForm(w http.ResponseWriter, r *http.Request) bool {
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/x-www-form-urlencoded" || r.URL.RawQuery != "" {
		a.oauthError(w, r, 400, "invalid_request")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	if r.ParseForm() != nil {
		a.oauthError(w, r, 400, "invalid_request")
		return false
	}
	for _, values := range r.PostForm {
		if len(values) != 1 {
			a.oauthError(w, r, 400, "invalid_request")
			return false
		}
	}
	return true
}

func (a *App) oauthAuthenticateClient(w http.ResponseWriter, r *http.Request) (store.OAuthClient, bool) {
	id, secret := r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	basic := false
	if raw := r.Header.Get("Authorization"); raw != "" {
		var ok bool
		idBasic, secretBasic, valid := r.BasicAuth()
		if valid {
			idBasic, err := url.QueryUnescape(idBasic)
			secretBasic, err2 := url.QueryUnescape(secretBasic)
			ok = err == nil && err2 == nil && (id == "" || id == idBasic) && secret == ""
			if ok {
				id, secret, basic = idBasic, secretBasic, true
			}
		}
		if !ok {
			a.oauthError(w, r, 401, "invalid_client")
			return store.OAuthClient{}, false
		}
	}
	if id == "" || len(id) > 256 || len(secret) > 256 {
		a.oauthError(w, r, 401, "invalid_client")
		return store.OAuthClient{}, false
	}
	client, err := a.oauth.OAuthClient(r.Context(), id)
	valid := err == nil
	if valid {
		switch client.AuthMethod {
		case "none":
			valid = !basic && secret == ""
		case "client_secret_basic":
			valid = basic && secret != "" && hmac.Equal([]byte(client.SecretHash), []byte(tokenHash(secret)))
		case "client_secret_post":
			valid = !basic && secret != "" && hmac.Equal([]byte(client.SecretHash), []byte(tokenHash(secret)))
		default:
			valid = false
		}
	}
	if !valid {
		a.oauthError(w, r, 401, "invalid_client")
		return store.OAuthClient{}, false
	}
	return client, true
}

func (a *App) oauthToken(w http.ResponseWriter, r *http.Request) {
	if !a.oauthLimit(w, r, "token", 120, time.Minute) || !a.oauthForm(w, r) {
		return
	}
	client, ok := a.oauthAuthenticateClient(w, r)
	if !ok {
		return
	}
	resource := r.PostForm.Get("resource")
	if resource != "" && resource != a.oauthResource() {
		a.oauthError(w, r, 400, "invalid_target")
		return
	}
	resource = a.oauthResource()
	access, refresh := randomToken("csa_"), randomToken("csr_")
	now := time.Now()
	var grant store.OAuthGrant
	var err error
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		verifier := r.PostForm.Get("code_verifier")
		code := r.PostForm.Get("code")
		if !oauthVerifier.MatchString(verifier) || len(code) > 128 || !strings.HasPrefix(code, "csc_") {
			a.oauthError(w, r, 400, "invalid_grant")
			return
		}
		sum := sha256.Sum256([]byte(verifier))
		grant, err = a.oauth.ExchangeOAuthCode(r.Context(), tokenHash(code), client.ID, r.PostForm.Get("redirect_uri"), resource,
			base64.RawURLEncoding.EncodeToString(sum[:]), tokenHash(access), tokenHash(refresh), now.Add(time.Hour), now.Add(30*24*time.Hour))
	case "refresh_token":
		old := r.PostForm.Get("refresh_token")
		requestedScopes, validScope := parseOAuthScopes(r.PostForm.Get("scope"))
		if !validScope {
			a.oauthError(w, r, 400, "invalid_scope")
			return
		}
		if len(old) > 128 || !strings.HasPrefix(old, "csr_") {
			a.oauthError(w, r, 400, "invalid_grant")
			return
		}
		grant, err = a.oauth.RefreshOAuthGrant(r.Context(), tokenHash(old), client.ID, resource, tokenHash(access), tokenHash(refresh), strings.Join(requestedScopes, " "), now.Add(time.Hour), now.Add(30*24*time.Hour))
	default:
		a.oauthError(w, r, 400, "unsupported_grant_type")
		return
	}
	if err != nil {
		status, code := 400, "invalid_grant"
		if !errors.Is(err, store.ErrNotFound) {
			status, code = 500, "server_error"
		}
		a.oauthError(w, r, status, code)
		return
	}
	// Derivation binds grants to this installation. A changed APP_SECRET must
	// invalidate old grants, rather than issuing unusable refreshed credentials.
	if _, err := a.db.APIKeyByHash(r.Context(), tokenHash(a.oauthAPIKey(grant.ID))); err != nil {
		_ = a.oauth.RevokeOAuthToken(r.Context(), tokenHash(refresh), client.ID)
		a.oauthError(w, r, 400, "invalid_grant")
		return
	}
	a.writeJSON(w, r, 200, map[string]any{"access_token": access, "token_type": "Bearer", "expires_in": 3600, "refresh_token": refresh, "scope": grant.Scope, "resource": resource})
}

func (a *App) oauthRevoke(w http.ResponseWriter, r *http.Request) {
	if !a.oauthLimit(w, r, "revoke", 60, time.Minute) || !a.oauthForm(w, r) {
		return
	}
	client, ok := a.oauthAuthenticateClient(w, r)
	if !ok {
		return
	}
	token := r.PostForm.Get("token")
	if len(token) > 128 {
		a.oauthError(w, r, 400, "invalid_request")
		return
	}
	if err := a.oauth.RevokeOAuthToken(r.Context(), tokenHash(token), client.ID); err != nil {
		a.oauthError(w, r, 500, "server_error")
		return
	}
	w.WriteHeader(200)
}

func (a *App) oauthAPIKey(grantID string) string {
	mac := hmac.New(sha256.New, a.cfg.Secret)
	mac.Write([]byte("conspect-oauth-upstream-v1:" + grantID))
	return "csp_" + hex.EncodeToString(mac.Sum(nil))
}
