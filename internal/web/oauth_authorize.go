package web

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"conspect/internal/store"
)

type oauthAuthorization struct {
	ClientID    string `json:"client_id"`
	RedirectURI string `json:"redirect_uri"`
	State       string `json:"state"`
	Scope       string `json:"scope"`
	Resource    string `json:"resource"`
	Challenge   string `json:"challenge"`
	Session     string `json:"session"`
	Expires     int64  `json:"expires"`
}

func oauthLoginNext(raw string) string {
	if len(raw) > 8192 || !strings.HasPrefix(raw, "/oauth/authorize?") {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.IsAbs() || u.Host != "" || u.Path != "/oauth/authorize" || u.Fragment != "" {
		return ""
	}
	return raw
}

func (a *App) loginDestination(r *http.Request) string {
	if a.cfg.MCPEnabled && r.URL.Path == "/oauth/authorize" {
		if next := oauthLoginNext(r.URL.RequestURI()); next != "" {
			return "/login?next=" + url.QueryEscape(next)
		}
	}
	return "/login"
}

func (a *App) oauthConsentMAC(payload string) []byte {
	mac := hmac.New(sha256.New, a.cfg.Secret)
	mac.Write([]byte("conspect-oauth-consent-v1:" + payload))
	return mac.Sum(nil)
}

func (a *App) signOAuthConsent(request oauthAuthorization) string {
	data, _ := json.Marshal(request)
	payload := base64.RawURLEncoding.EncodeToString(data)
	return payload + "." + base64.RawURLEncoding.EncodeToString(a.oauthConsentMAC(payload))
}

func (a *App) readOAuthConsent(raw, session string) (oauthAuthorization, bool) {
	var request oauthAuthorization
	if len(raw) > 16384 {
		return request, false
	}
	payload, signature, found := strings.Cut(raw, ".")
	mac, err := base64.RawURLEncoding.DecodeString(signature)
	if !found || err != nil || !hmac.Equal(mac, a.oauthConsentMAC(payload)) {
		return request, false
	}
	data, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil || json.Unmarshal(data, &request) != nil || request.Session != session || request.Expires <= time.Now().Unix() {
		return oauthAuthorization{}, false
	}
	return request, true
}

func (a *App) oauthAuthorize(w http.ResponseWriter, r *http.Request) {
	if !a.oauthLimit(w, r, "authorize", 60, time.Minute) {
		return
	}
	if len(r.URL.RawQuery) > 8192 {
		a.oauthError(w, r, 400, "invalid_request")
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		a.oauthError(w, r, 400, "invalid_request")
		return
	}
	for _, values := range query {
		if len(values) != 1 {
			a.oauthError(w, r, 400, "invalid_request")
			return
		}
	}
	request := oauthAuthorization{ClientID: query.Get("client_id"), RedirectURI: query.Get("redirect_uri"), State: query.Get("state"), Scope: query.Get("scope"), Resource: query.Get("resource"), Challenge: query.Get("code_challenge")}
	if len(request.ClientID) > 256 || len(request.State) > 2048 || !utf8.ValidString(request.State) || strings.ContainsRune(request.State, 0) {
		a.oauthError(w, r, 400, "invalid_request")
		return
	}
	client, err := a.oauth.OAuthClient(r.Context(), request.ClientID)
	if err != nil || !slices.Contains(client.RedirectURIs, request.RedirectURI) || !validOAuthRedirect(request.RedirectURI) {
		a.oauthError(w, r, 400, "invalid_request")
		return
	}
	if query.Get("response_type") != "code" || query.Get("code_challenge_method") != "S256" {
		a.oauthRedirect(w, r, request, "error", "invalid_request")
		return
	}
	challenge, err := base64.RawURLEncoding.DecodeString(request.Challenge)
	if err != nil || len(challenge) != 32 || base64.RawURLEncoding.EncodeToString(challenge) != request.Challenge {
		a.oauthRedirect(w, r, request, "error", "invalid_request")
		return
	}
	if request.Resource != a.oauthResource() {
		a.oauthRedirect(w, r, request, "error", "invalid_target")
		return
	}
	if request.Scope == "" {
		request.Scope = "notes:read"
	}
	scopes, valid := parseOAuthScopes(request.Scope)
	if !valid || len(scopes) == 0 {
		a.oauthRedirect(w, r, request, "error", "invalid_scope")
		return
	}
	request.Scope = strings.Join(scopes, " ")
	request.Session = r.Context().Value(sessionKey{}).(store.Session).TokenHash
	request.Expires = time.Now().Add(10 * time.Minute).Unix()
	projects, err := a.db.Projects(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	notes, err := a.db.Notes(r.Context(), "", "", "title")
	if err != nil {
		a.fail(w, r, err)
		return
	}
	// Chromium also checks form-action on POST redirects. Permit only this
	// already validated ChatGPT callback, not arbitrary cross-origin forms.
	w.Header().Set("Content-Security-Policy", strings.Replace(w.Header().Get("Content-Security-Policy"), "form-action 'self'", "form-action 'self' "+request.RedirectURI, 1))
	a.page(w, r, 200, "oauth-consent", pageData{Title: "Подключить ChatGPT", OAuthClientName: client.Name, OAuthClientID: client.ID, OAuthRequest: a.signOAuthConsent(request), OAuthScopes: scopes, Projects: projects, Notes: notes})
}

func (a *App) oauthRedirect(w http.ResponseWriter, r *http.Request, request oauthAuthorization, key, value string) {
	u, err := url.Parse(request.RedirectURI)
	if err != nil || !validOAuthRedirect(request.RedirectURI) {
		a.oauthError(w, r, 400, "invalid_request")
		return
	}
	values := u.Query()
	values.Set(key, value)
	values.Set("iss", a.cfg.BaseURL)
	if request.State != "" {
		values.Set("state", request.State)
	}
	u.RawQuery = values.Encode()
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

func (a *App) oauthApprove(w http.ResponseWriter, r *http.Request) {
	if !a.oauthLimit(w, r, "approve", 30, time.Minute) {
		return
	}
	if len(r.PostForm["request"]) != 1 || len(r.PostForm["decision"]) != 1 {
		a.oauthError(w, r, 400, "invalid_request")
		return
	}
	session := r.Context().Value(sessionKey{}).(store.Session)
	request, valid := a.readOAuthConsent(r.PostForm.Get("request"), session.TokenHash)
	if !valid || request.Resource != a.oauthResource() {
		a.oauthError(w, r, 400, "invalid_request")
		return
	}
	client, err := a.oauth.OAuthClient(r.Context(), request.ClientID)
	if err != nil || !slices.Contains(client.RedirectURIs, request.RedirectURI) {
		a.oauthError(w, r, 400, "invalid_request")
		return
	}
	if r.PostForm.Get("decision") == "deny" {
		a.oauthRedirect(w, r, request, "error", "access_denied")
		return
	}
	if r.PostForm.Get("decision") != "allow" {
		a.oauthError(w, r, 400, "invalid_request")
		return
	}
	scopes := unique(r.PostForm["scopes"])
	projects, notes := unique(r.PostForm["projects"]), unique(r.PostForm["notes"])
	requested, _ := parseOAuthScopes(request.Scope)
	if len(scopes) == 0 || len(scopes) > 4 || len(projects)+len(notes) == 0 || len(projects)+len(notes) > 256 {
		a.fail(w, r, &HTTPError{422, "invalid_scope", "Выберите разрешения и хотя бы один проект или конспект"})
		return
	}
	for _, scope := range scopes {
		if !slices.Contains(requested, scope) {
			a.oauthError(w, r, 400, "invalid_scope")
			return
		}
	}
	id, keyID := store.NewID(), store.NewID()
	code := randomToken("csc_")
	grant := store.OAuthGrant{ID: id, ClientID: client.ID, KeyID: keyID, Resource: request.Resource, Scope: strings.Join(scopes, " "), RedirectURI: request.RedirectURI,
		CodeHash: tokenHash(code), CodeChallenge: request.Challenge, CodeExpiresAt: time.Now().Add(5 * time.Minute)}
	name := "ChatGPT · " + client.Name
	if len([]rune(name)) > 300 {
		name = string([]rune(name)[:300])
	}
	key := store.APIKey{ID: keyID, Name: name, TokenHash: tokenHash(a.oauthAPIKey(id)), Scopes: scopes, ProjectIDs: projects, NoteIDs: notes}
	if err := a.oauth.CreateOAuthGrant(r.Context(), grant, key); err != nil {
		if errors.Is(err, store.ErrForbidden) {
			a.oauthError(w, r, 400, "invalid_scope")
		} else {
			a.fail(w, r, err)
		}
		return
	}
	a.oauthRedirect(w, r, request, "code", code)
}
