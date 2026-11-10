package web

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"conspect/internal/store"

	"golang.org/x/crypto/bcrypt"
)

const sessionCookie = "conspect_session"

func tokenHash(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }
func (a *App) owner(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			if r.Method == "GET" {
				http.Redirect(w, r, "/login", 303)
			} else {
				a.fail(w, r, &HTTPError{401, "unauthorized", "Войдите в аккаунт"})
			}
			return
		}
		s, err := a.db.Session(r.Context(), tokenHash(c.Value))
		if errors.Is(err, store.ErrNotFound) {
			http.Redirect(w, r, "/login", 303)
			return
		}
		if err != nil {
			a.fail(w, r, err)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), sessionKey{}, s))
		if r.Method != "GET" && r.Method != "HEAD" {
			if r.Header.Get("Origin") != a.cfg.BaseURL {
				a.fail(w, r, &HTTPError{403, "csrf", "Недопустимый источник запроса"})
				return
			}
			max := a.cfg.MaxImageBytes
			if a.cfg.MaxMarkdownBytes > max {
				max = a.cfg.MaxMarkdownBytes
			}
			r.Body = http.MaxBytesReader(w, r.Body, max+(1<<20))
			if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
				err = r.ParseMultipartForm(1 << 20)
				if r.MultipartForm != nil {
					defer r.MultipartForm.RemoveAll()
				}
			} else {
				err = r.ParseForm()
			}
			if err != nil {
				a.fail(w, r, err)
				return
			}
			if !hmac.Equal([]byte(r.FormValue("csrf")), []byte(s.CSRFToken)) {
				a.fail(w, r, &HTTPError{403, "csrf", "Неверный токен формы. Обновите страницу"})
				return
			}
		}
		next(w, r)
	}
}
func (a *App) loginPage(w http.ResponseWriter, r *http.Request) {
	a.page(w, r, 200, "login", pageData{Title: "Вход"})
}
func (a *App) login(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Origin") != a.cfg.BaseURL {
		a.fail(w, r, &HTTPError{403, "csrf", "Недопустимый источник запроса"})
		return
	}
	if !a.limits.allow("login:"+a.clientIP(r), 10, 15*time.Minute) {
		w.Header().Set("Retry-After", "900")
		a.fail(w, r, &HTTPError{429, "rate_limited", "Слишком много попыток входа. Попробуйте позже"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		a.fail(w, r, err)
		return
	}
	o, err := a.db.Owner(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	passwordOK := bcrypt.CompareHashAndPassword([]byte(o.PasswordHash), []byte(r.FormValue("password"))) == nil
	if r.FormValue("username") != o.Username || !passwordOK {
		a.page(w, r, 401, "login", pageData{Title: "Вход", Error: "Неверный логин или пароль"})
		return
	}
	token := randomToken("sess_")
	s := store.Session{TokenHash: tokenHash(token), CSRFToken: randomToken("csrf_"), ExpiresAt: time.Now().Add(12 * time.Hour)}
	if err := a.db.CreateSession(r.Context(), s); err != nil {
		a.fail(w, r, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/", HttpOnly: true, Secure: strings.HasPrefix(a.cfg.BaseURL, "https://"), SameSite: http.SameSiteLaxMode, MaxAge: 43200, Expires: s.ExpiresAt})
	http.Redirect(w, r, "/projects", 303)
}
func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	s := r.Context().Value(sessionKey{}).(store.Session)
	if err := a.db.DeleteSession(r.Context(), s.TokenHash); err != nil {
		a.fail(w, r, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, Expires: time.Unix(1, 0), HttpOnly: true, Secure: strings.HasPrefix(a.cfg.BaseURL, "https://"), SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, "/login", 303)
}
func (a *App) authorizeAPI(w http.ResponseWriter, r *http.Request, scope string) (store.APIKey, bool) {
	if !a.limits.allow("api-ip:"+a.clientIP(r), 600, time.Minute) {
		w.Header().Set("Retry-After", "60")
		a.apiError(w, r, 429, "rate_limited", "Слишком много запросов")
		return store.APIKey{}, false
	}
	fields := strings.Fields(r.Header.Get("Authorization"))
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") || !strings.HasPrefix(fields[1], "csp_") {
		a.apiError(w, r, 401, "unauthorized", "Нужен действующий API-ключ")
		return store.APIKey{}, false
	}
	k, err := a.db.APIKeyByHash(r.Context(), tokenHash(fields[1]))
	if errors.Is(err, store.ErrNotFound) {
		a.apiError(w, r, 401, "unauthorized", "Нужен действующий API-ключ")
		return store.APIKey{}, false
	}
	if err != nil {
		a.fail(w, r, err)
		return store.APIKey{}, false
	}
	if !k.HasScope(scope) {
		a.apiError(w, r, 403, "forbidden", "Недостаточно прав")
		return store.APIKey{}, false
	}
	if !a.limits.allow("api-key:"+k.ID, 240, time.Minute) {
		w.Header().Set("Retry-After", "60")
		a.apiError(w, r, 429, "rate_limited", "Превышен лимит API-ключа")
		return store.APIKey{}, false
	}
	return k, true
}
func (a *App) shareToken(id string) string {
	mac := hmac.New(sha256.New, a.cfg.Secret)
	mac.Write([]byte("conspect-share-v1:" + id))
	return hex.EncodeToString(mac.Sum(nil))
}
