package web

import (
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"conspect/internal/store"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/text"
)

func projectFields(r *http.Request) (string, string, error) {
	name, description := strings.TrimSpace(r.FormValue("name")), r.FormValue("description")
	if !validTitle(name) || !utf8.ValidString(description) || len(description) > 4000 || strings.ContainsRune(description, 0) {
		return "", "", &HTTPError{422, "invalid_project", "Нужно название до 300 символов и описание до 4000 байт"}
	}
	return name, description, nil
}
func (a *App) projects(w http.ResponseWriter, r *http.Request) {
	projects, err := a.db.Projects(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	sort := "modified"
	if r.URL.Query().Get("sort") == "title" {
		sort = "title"
	}
	data := pageData{Title: "Мои проекты", Projects: projects, Query: r.URL.Query().Get("q"), Sort: sort}
	if data.Query != "" {
		data.Notes, err = a.db.Notes(r.Context(), "", data.Query, sort)
		if err != nil {
			a.fail(w, r, err)
			return
		}
	}
	a.page(w, r, 200, "projects", data)
}
func (a *App) createProject(w http.ResponseWriter, r *http.Request) {
	name, description, err := projectFields(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	p, err := a.db.CreateProject(r.Context(), name, description)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	http.Redirect(w, r, "/projects/"+p.ID+"/manage", 303)
}
func (a *App) project(w http.ResponseWriter, r *http.Request) {
	p, err := a.db.Project(r.Context(), r.PathValue("projectID"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	sort := r.URL.Query().Get("sort")
	if sort != "title" {
		sort = "modified"
	}
	notes, err := a.db.Notes(r.Context(), p.ID, r.URL.Query().Get("q"), sort)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.page(w, r, 200, "project", pageData{Title: p.Name, Project: p, Notes: notes, Query: r.URL.Query().Get("q"), Sort: sort})
}
func (a *App) manageProject(w http.ResponseWriter, r *http.Request) {
	p, err := a.db.Project(r.Context(), r.PathValue("projectID"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	notes, err := a.db.Notes(r.Context(), p.ID, "", "modified")
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.page(w, r, 200, "manage", pageData{Title: "Управление · " + p.Name, Project: p, Notes: notes})
}
func (a *App) manageNote(w http.ResponseWriter, r *http.Request) {
	n, err := a.db.Note(r.Context(), r.PathValue("noteID"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	p, err := a.db.Project(r.Context(), n.ProjectID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	projects, err := a.db.Projects(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	files, err := a.db.Attachments(r.Context(), n.ID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	entry := noteEntry{Note: n, Warnings: imageWarnings(n.Markdown, files)}
	for _, f := range files {
		entry.Attachments = append(entry.Attachments, imageEntry{Attachment: f, Markdown: imageMarkdown(f)})
	}
	a.page(w, r, 200, "manage-note", pageData{Title: "Настройки · " + n.Title, Note: n, Project: p, Projects: projects, Entries: []noteEntry{entry}})
}
func (a *App) editProject(w http.ResponseWriter, r *http.Request) {
	name, description, err := projectFields(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.db.UpdateProject(r.Context(), r.PathValue("projectID"), name, description); err != nil {
		a.fail(w, r, err)
		return
	}
	http.Redirect(w, r, "/projects/"+r.PathValue("projectID")+"/manage", 303)
}
func confirmed(r *http.Request) error {
	if r.FormValue("confirm") != "DELETE" {
		return &HTTPError{422, "confirmation_required", "Подтвердите удаление"}
	}
	return nil
}
func (a *App) deleteProject(w http.ResponseWriter, r *http.Request) {
	if err := confirmed(r); err != nil {
		a.fail(w, r, err)
		return
	}
	files, err := a.db.DeleteProject(r.Context(), r.PathValue("projectID"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.removeFiles(files)
	http.Redirect(w, r, "/projects", 303)
}
func (a *App) uploadedMarkdown(file *multipart.FileHeader) (string, string, error) {
	name := cleanFilename(file.Filename)
	if !strings.EqualFold(filepath.Ext(name), ".md") {
		return "", "", &HTTPError{415, "unsupported_markdown", "Нужен файл с расширением .md"}
	}
	f, err := file.Open()
	if err != nil {
		return "", "", err
	}
	defer f.Close()
	source, err := io.ReadAll(io.LimitReader(f, a.cfg.MaxMarkdownBytes+1))
	if err != nil {
		return "", "", err
	}
	if err := validateMarkdown(string(source), a.cfg.MaxMarkdownBytes); err != nil {
		return "", "", err
	}
	return string(source), name, nil
}
func importedTitle(source, name string) string {
	title := strings.TrimSuffix(name, filepath.Ext(name))
	node := goldmark.New().Parser().Parse(text.NewReader([]byte(source)))
	_ = ast.Walk(node, func(n ast.Node, entering bool) (ast.WalkStatus, error) {
		if heading, ok := n.(*ast.Heading); ok && entering && heading.Level == 1 {
			title = string(heading.Text([]byte(source)))
			return ast.WalkStop, nil
		}
		return ast.WalkContinue, nil
	})
	return strings.TrimSpace(title)
}
func (a *App) importNotes(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("projectID")
	if _, err := a.db.Project(r.Context(), projectID); err != nil {
		a.fail(w, r, err)
		return
	}
	if r.MultipartForm == nil || len(r.MultipartForm.File["files"]) == 0 {
		a.fail(w, r, &HTTPError{422, "invalid_file", "Выберите Markdown-файлы"})
		return
	}
	files := r.MultipartForm.File["files"]
	if len(files) > 32 {
		a.fail(w, r, &HTTPError{422, "too_many_files", "За один раз можно загрузить до 32 файлов"})
		return
	}
	notes := make([]store.Note, 0, len(files))
	for _, f := range files {
		source, name, err := a.uploadedMarkdown(f)
		if err != nil {
			a.fail(w, r, err)
			return
		}
		title := importedTitle(source, name)
		if !validTitle(title) {
			a.fail(w, r, &HTTPError{422, "invalid_title", "Заголовок конспекта должен содержать от 1 до 300 символов"})
			return
		}
		notes = append(notes, store.Note{ID: store.NewID(), ProjectID: projectID, Title: title, Markdown: source, SourceName: name})
	}
	for i, n := range notes {
		if _, err := a.db.CreateNote(r.Context(), n, store.Actor{Owner: true}); err != nil {
			if i > 0 {
				a.fail(w, r, &HTTPError{500, "partial_import", fmt.Sprintf("Импорт прерван: уже сохранено %d конспектов. Проверьте список проекта перед повторной загрузкой", i)})
			} else {
				a.fail(w, r, err)
			}
			return
		}
	}
	http.Redirect(w, r, "/projects/"+projectID+"/manage", 303)
}
func (a *App) replaceNote(w http.ResponseWriter, r *http.Request) {
	version, err := formVersion(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	n, err := a.db.Note(r.Context(), r.PathValue("noteID"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if r.MultipartForm == nil || len(r.MultipartForm.File["file"]) != 1 {
		a.fail(w, r, &HTTPError{422, "invalid_file", "Выберите один Markdown-файл"})
		return
	}
	source, name, err := a.uploadedMarkdown(r.MultipartForm.File["file"][0])
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if _, err = a.db.UpdateNote(r.Context(), n.ID, n.Title, source, name, version, store.Actor{Owner: true}); err != nil {
		a.fail(w, r, err)
		return
	}
	http.Redirect(w, r, "/notes/"+n.ID+"/manage", 303)
}
func (a *App) noteMetadata(w http.ResponseWriter, r *http.Request) {
	version, err := formVersion(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	title := strings.TrimSpace(r.FormValue("title"))
	if !validTitle(title) {
		a.fail(w, r, &HTTPError{422, "invalid_title", "Нужно название от 1 до 300 символов"})
		return
	}
	n, err := a.db.SetNoteMetadata(r.Context(), r.PathValue("noteID"), title, r.FormValue("project_id"), version)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	http.Redirect(w, r, "/notes/"+n.ID+"/manage", 303)
}
func (a *App) deleteNote(w http.ResponseWriter, r *http.Request) {
	if err := confirmed(r); err != nil {
		a.fail(w, r, err)
		return
	}
	version, err := formVersion(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	n, err := a.db.Note(r.Context(), r.PathValue("noteID"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	files, err := a.db.DeleteNote(r.Context(), n.ID, version)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.removeFiles(files)
	http.Redirect(w, r, "/projects/"+n.ProjectID+"/manage", 303)
}
func (a *App) uploadAttachment(w http.ResponseWriter, r *http.Request) {
	n, err := a.db.Note(r.Context(), r.PathValue("noteID"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if _, err := a.receiveImage(w, r, n.ID, store.Actor{Owner: true}); err != nil {
		a.fail(w, r, err)
		return
	}
	http.Redirect(w, r, "/notes/"+n.ID+"/manage", 303)
}
func (a *App) deleteAttachment(w http.ResponseWriter, r *http.Request) {
	if err := confirmed(r); err != nil {
		a.fail(w, r, err)
		return
	}
	n, err := a.db.Note(r.Context(), r.PathValue("noteID"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	f, err := a.db.DeleteAttachment(r.Context(), n.ID, r.PathValue("attachmentID"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.removeFiles([]store.Attachment{f})
	http.Redirect(w, r, "/notes/"+n.ID+"/manage", 303)
}
func (a *App) readNote(w http.ResponseWriter, r *http.Request) {
	n, err := a.db.Note(r.Context(), r.PathValue("noteID"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	p, err := a.db.Project(r.Context(), n.ProjectID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.renderNote(w, r, n, p, "/notes/"+n.ID+"/attachments/")
}
func (a *App) renderNote(w http.ResponseWriter, r *http.Request, n store.Note, p store.Project, prefix string) {
	w.Header().Set("Referrer-Policy", "no-referrer")
	files, err := a.db.Attachments(r.Context(), n.ID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	permitted := make(map[string]bool, len(files))
	for _, f := range files {
		permitted[f.ID] = f.NoteID == n.ID && (f.MIME == "image/png" || f.MIME == "image/jpeg" || f.MIME == "image/webp")
	}
	content, err := a.renderer.Render(n.Markdown, func(id string) string {
		if !permitted[id] {
			return ""
		}
		return prefix + url.PathEscape(id)
	})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.page(w, r, 200, "reader", pageData{Title: n.Title, Note: n, Project: p, Content: content})
}
func (a *App) ownerAttachment(w http.ResponseWriter, r *http.Request) {
	a.attachment(w, r, r.PathValue("noteID"), r.PathValue("attachmentID"))
}
func (a *App) sharedNote(w http.ResponseWriter, r *http.Request) {
	if !a.limits.allow("share:"+a.clientIP(r), 120, time.Minute) {
		a.fail(w, r, &HTTPError{429, "rate_limited", "Слишком много запросов"})
		return
	}
	share, err := a.db.ShareByHash(r.Context(), tokenHash(r.PathValue("token")))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	n, err := a.db.Note(r.Context(), share.NoteID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.renderNote(w, r, n, store.Project{}, "/s/"+url.PathEscape(r.PathValue("token"))+"/attachments/")
}
func (a *App) sharedAttachment(w http.ResponseWriter, r *http.Request) {
	if !a.limits.allow("share-image:"+a.clientIP(r), 600, time.Minute) {
		a.fail(w, r, &HTTPError{429, "rate_limited", "Слишком много запросов"})
		return
	}
	share, err := a.db.ShareByHash(r.Context(), tokenHash(r.PathValue("token")))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.attachment(w, r, share.NoteID, r.PathValue("attachmentID"))
}
func (a *App) sharePage(w http.ResponseWriter, r *http.Request) {
	n, err := a.db.Note(r.Context(), r.PathValue("noteID"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	data := pageData{Title: "Ссылка доступа", Note: n}
	share, err := a.db.ActiveShare(r.Context(), n.ID)
	if err == nil {
		data.ShareActive = true
		token := a.shareToken(share.ID)
		if tokenHash(token) != share.TokenHash {
			data.Message = "APP_SECRET изменён: прежняя ссылка всё ещё действует, но её нельзя восстановить для копирования. Верните исходный секрет, перевыпустите ссылку или отключите доступ ниже."
		} else {
			data.ShareURL = a.cfg.BaseURL + "/s/" + token
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		a.fail(w, r, err)
		return
	}
	a.page(w, r, 200, "share", data)
}
func (a *App) changeShare(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("noteID")
	switch r.FormValue("action") {
	case "revoke":
		if err := a.db.RevokeShare(r.Context(), id); err != nil {
			a.fail(w, r, err)
			return
		}
	case "create", "rotate":
		existing, err := a.db.ActiveShare(r.Context(), id)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			a.fail(w, r, err)
			return
		}
		if r.FormValue("action") == "rotate" || existing.ID == "" {
			shareID := store.NewID()
			if _, err := a.db.ReplaceShare(r.Context(), store.ShareLink{ID: shareID, NoteID: id, TokenHash: tokenHash(a.shareToken(shareID))}); err != nil {
				a.fail(w, r, err)
				return
			}
		}
	default:
		a.fail(w, r, &HTTPError{422, "invalid_action", "Неизвестное действие"})
		return
	}
	http.Redirect(w, r, "/notes/"+id+"/share", 303)
}
func (a *App) keyData(r *http.Request) (pageData, error) {
	keys, err := a.db.APIKeys(r.Context())
	if err != nil {
		return pageData{}, err
	}
	projects, err := a.db.Projects(r.Context())
	if err != nil {
		return pageData{}, err
	}
	notes, err := a.db.Notes(r.Context(), "", "", "title")
	if err != nil {
		return pageData{}, err
	}
	return pageData{Title: "API-ключи для MCP", Keys: keys, Projects: projects, Notes: notes}, nil
}
func (a *App) keysPage(w http.ResponseWriter, r *http.Request) {
	data, err := a.keyData(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.page(w, r, 200, "keys", data)
}
func unique(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, v := range values {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	return result
}
func (a *App) createKey(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.FormValue("name"))
	if !validTitle(name) {
		a.fail(w, r, &HTTPError{422, "invalid_name", "Укажите название клиента до 300 символов"})
		return
	}
	scopes, projects, notes := unique(r.Form["scopes"]), unique(r.Form["projects"]), unique(r.Form["notes"])
	allowed := map[string]bool{"notes:read": true, "notes:write": true, "attachments:read": true, "attachments:write": true}
	if len(scopes) == 0 || len(scopes) > 4 || len(projects)+len(notes) == 0 || len(projects)+len(notes) > 256 {
		a.fail(w, r, &HTTPError{422, "invalid_scope", "Выберите права и хотя бы один проект или конспект (максимум 256)"})
		return
	}
	for _, s := range scopes {
		if !allowed[s] {
			a.fail(w, r, &HTTPError{422, "invalid_scope", "Неизвестное разрешение"})
			return
		}
	}
	for _, id := range projects {
		if _, err := a.db.Project(r.Context(), id); err != nil {
			a.fail(w, r, err)
			return
		}
	}
	for _, id := range notes {
		if _, err := a.db.Note(r.Context(), id); err != nil {
			a.fail(w, r, err)
			return
		}
	}
	var expires *time.Time
	if value := r.FormValue("expires"); value != "" {
		t, err := time.Parse("2006-01-02", value)
		if err != nil || !t.After(time.Now()) {
			a.fail(w, r, &HTTPError{422, "invalid_expiration", "Выберите будущую дату истечения (00:00 UTC)"})
			return
		}
		expires = &t
	}
	token := randomToken("csp_")
	if _, err := a.db.CreateAPIKey(r.Context(), store.APIKey{ID: store.NewID(), Name: name, TokenHash: tokenHash(token), Scopes: scopes, ProjectIDs: projects, NoteIDs: notes, ExpiresAt: expires}); err != nil {
		a.fail(w, r, err)
		return
	}
	data, err := a.keyData(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	data.KeySecret = token
	data.Message = "Сохраните ключ в конфигурации MCP-сервера. Повторно показать секрет нельзя"
	a.page(w, r, 201, "keys", data)
}
func (a *App) revokeKey(w http.ResponseWriter, r *http.Request) {
	if err := a.db.RevokeAPIKey(r.Context(), r.PathValue("keyID")); err != nil {
		a.fail(w, r, err)
		return
	}
	http.Redirect(w, r, "/settings/api-keys", 303)
}
