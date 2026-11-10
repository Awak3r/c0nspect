package web

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"conspect/internal/conspectclient"
	"conspect/internal/mcpserver"
	"conspect/internal/store"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func (a *App) mcpUnauthorized(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+a.cfg.BaseURL+`/.well-known/oauth-protected-resource/mcp", error="invalid_token"`)
	a.oauthError(w, r, http.StatusUnauthorized, "invalid_token")
}

func (a *App) remoteMCP(w http.ResponseWriter, r *http.Request) {
	origin, _ := url.Parse(a.cfg.BaseURL)
	if r.Host != origin.Host || (r.Header.Get("Origin") != "" && r.Header.Get("Origin") != a.cfg.BaseURL) {
		a.oauthError(w, r, 403, "invalid_request")
		return
	}
	if r.URL.RawQuery != "" {
		a.oauthError(w, r, 400, "invalid_request")
		return
	}
	if !a.oauthLimit(w, r, "mcp", 240, time.Minute) {
		return
	}
	fields := strings.Fields(r.Header.Get("Authorization"))
	if len(r.Header.Values("Authorization")) != 1 || len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") || !strings.HasPrefix(fields[1], "csa_") || len(fields[1]) > 128 {
		a.mcpUnauthorized(w, r)
		return
	}
	grant, err := a.oauth.OAuthGrantByAccess(r.Context(), tokenHash(fields[1]), a.oauthResource())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			a.mcpUnauthorized(w, r)
		} else {
			a.oauthError(w, r, 503, "temporarily_unavailable")
		}
		return
	}
	apiSecret := a.oauthAPIKey(grant.ID)
	key, err := a.db.APIKeyByHash(r.Context(), tokenHash(apiSecret))
	if err != nil || key.ID != grant.KeyID {
		if err == nil || errors.Is(err, store.ErrNotFound) {
			a.mcpUnauthorized(w, r)
		} else {
			a.oauthError(w, r, 503, "temporarily_unavailable")
		}
		return
	}
	// Stateless HTTP needs no long-lived GET stream or bearer-bound session.
	// Rejecting GET also prevents idle streams from occupying the single VPS CPU.
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	client, err := conspectclient.New(conspectclient.Config{BaseURL: a.cfg.BaseURL, APIBaseURL: a.cfg.MCPAPIURL, APIKey: apiSecret})
	if err != nil {
		a.oauthError(w, r, 503, "temporarily_unavailable")
		return
	}
	defer client.Close()
	server := mcpserver.NewRemote(client, key.Scopes)
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{
		Stateless: true, JSONResponse: true, MaxRequestBodyBytes: 6*a.cfg.MaxMarkdownBytes + 65536,
		PropagateRequestCancellation: true,
	})
	handler.ServeHTTP(w, r)
}
