package web

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"conspect/internal/store"
)

//go:embed openapi.json
var openAPIJSON []byte

type apiNoteResponse struct {
	store.Note
	Attachments *[]store.Attachment `json:"attachments,omitempty"`
}

func (a *App) apiNoteResponse(ctx context.Context, note store.Note, key store.APIKey) (apiNoteResponse, error) {
	result := apiNoteResponse{Note: note}
	if key.AllowsNote(note, "attachments:read") {
		attachments, err := a.db.Attachments(ctx, note.ID)
		if err != nil {
			return apiNoteResponse{}, err
		}
		if attachments == nil {
			attachments = []store.Attachment{}
		}
		result.Attachments = &attachments
	}
	return result, nil
}

// A note grant reveals its current parent project, not that project's other notes.
// Compute visibility independently of search so a nonmatching query still returns [].
func (a *App) apiProjectIDs(ctx context.Context, key store.APIKey) (map[string]bool, error) {
	ids := make(map[string]bool, len(key.ProjectIDs)+len(key.NoteIDs))
	for _, id := range key.ProjectIDs {
		ids[id] = true
	}
	for _, id := range key.NoteIDs {
		note, err := a.db.Note(ctx, id)
		if errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		ids[note.ProjectID] = true
	}
	return ids, nil
}

func (a *App) apiProjects(w http.ResponseWriter, r *http.Request) {
	key, ok := a.authorizeAPI(w, r, "notes:read")
	if !ok {
		return
	}
	var ids map[string]bool
	if !key.AllProjects {
		var err error
		ids, err = a.apiProjectIDs(r.Context(), key)
		if err != nil {
			a.fail(w, r, err)
			return
		}
	}
	projects, err := a.db.Projects(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	visible := make([]store.Project, 0)
	for _, project := range projects {
		if key.AllProjects || ids[project.ID] {
			visible = append(visible, project)
		}
	}
	a.writeJSON(w, r, http.StatusOK, struct {
		Projects []store.Project `json:"projects"`
	}{visible})
}

func (a *App) apiNotes(w http.ResponseWriter, r *http.Request) {
	key, ok := a.authorizeAPI(w, r, "notes:read")
	if !ok {
		return
	}
	projectID := r.PathValue("projectID")
	if !key.AllowsProject(projectID, "notes:read") {
		ids, err := a.apiProjectIDs(r.Context(), key)
		if err != nil {
			a.fail(w, r, err)
			return
		}
		if !ids[projectID] {
			a.fail(w, r, store.ErrNotFound)
			return
		}
	}
	sort := "modified"
	if r.URL.Query().Get("sort") == "title" {
		sort = "title"
	}
	notes, err := a.db.Notes(r.Context(), projectID, r.URL.Query().Get("q"), sort)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	visible := make([]apiNoteResponse, 0)
	for _, note := range notes {
		if !key.AllowsNote(note, "notes:read") {
			continue
		}
		result, err := a.apiNoteResponse(r.Context(), note, key)
		if err != nil {
			a.fail(w, r, err)
			return
		}
		visible = append(visible, result)
	}
	a.writeJSON(w, r, http.StatusOK, struct {
		Notes []apiNoteResponse `json:"notes"`
	}{visible})
}

func (a *App) apiAuthorizedNote(w http.ResponseWriter, r *http.Request, key store.APIKey, scope string) (store.Note, bool) {
	note, err := a.db.Note(r.Context(), r.PathValue("noteID"))
	if err != nil {
		a.fail(w, r, err)
		return store.Note{}, false
	}
	if !key.AllowsNote(note, scope) {
		a.fail(w, r, store.ErrNotFound)
		return store.Note{}, false
	}
	return note, true
}

func (a *App) apiGetNote(w http.ResponseWriter, r *http.Request) {
	key, ok := a.authorizeAPI(w, r, "notes:read")
	if !ok {
		return
	}
	note, ok := a.apiAuthorizedNote(w, r, key, "notes:read")
	if !ok {
		return
	}
	a.apiWriteNote(w, r, http.StatusOK, note, key)
}

func (a *App) apiWriteNote(w http.ResponseWriter, r *http.Request, status int, note store.Note, key store.APIKey) {
	result, err := a.apiNoteResponse(r.Context(), note, key)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if status == http.StatusCreated {
		w.Header().Set("Location", "/api/v1/notes/"+note.ID)
	}
	w.Header().Set("ETag", etag(note.Version))
	a.writeJSON(w, r, status, result)
}

type apiNoteInput struct {
	Title    *string `json:"title"`
	Markdown *string `json:"markdown"`
}

func (a *App) apiDecodeNote(w http.ResponseWriter, r *http.Request) (apiNoteInput, error) {
	var input apiNoteInput
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return input, &HTTPError{415, "unsupported_media_type", "Ожидается application/json"}
	}
	max := a.cfg.MaxMarkdownBytes*6 + 8192
	// encoding/json replaces invalid UTF-8 with U+FFFD. Validate the bounded wire
	// body first so invalid source text cannot silently become a different note.
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, max))
	if err != nil {
		return input, err
	}
	if !utf8.Valid(body) {
		return input, &HTTPError{422, "invalid_utf8", "Нужен текст в UTF-8"}
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return input, &HTTPError{400, "invalid_json", "Ожидается один JSON-объект"}
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	if err := decodeJSON(w, r, &input, max); err != nil {
		var h *HTTPError
		var tooLarge *http.MaxBytesError
		if errors.As(err, &h) || errors.As(err, &tooLarge) {
			return input, err
		}
		// DisallowUnknownFields returns a plain error; never expose it as a 500
		// or echo the caller-controlled field name in the error response.
		return input, &HTTPError{400, "invalid_json", "Некорректный JSON"}
	}
	if input.Title == nil || input.Markdown == nil {
		return input, &HTTPError{422, "invalid_input", "Нужны поля title и markdown"}
	}
	if !validTitle(*input.Title) {
		return input, &HTTPError{422, "invalid_title", "Нужен непустой заголовок до 300 символов"}
	}
	if err := validateMarkdown(*input.Markdown, a.cfg.MaxMarkdownBytes); err != nil {
		return input, err
	}
	return input, nil
}

func (a *App) apiCreateNote(w http.ResponseWriter, r *http.Request) {
	key, ok := a.authorizeAPI(w, r, "notes:write")
	if !ok {
		return
	}
	projectID := r.PathValue("projectID")
	if !key.AllowsProject(projectID, "notes:write") {
		a.fail(w, r, store.ErrNotFound)
		return
	}
	if _, err := a.db.Project(r.Context(), projectID); err != nil {
		a.fail(w, r, err)
		return
	}
	input, err := a.apiDecodeNote(w, r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	note := store.Note{ProjectID: projectID, Title: *input.Title, Markdown: *input.Markdown}
	created, err := a.db.CreateNote(r.Context(), note, store.Actor{KeyID: key.ID})
	if err != nil {
		a.apiFailWrite(w, r, err, key, "notes:write", note)
		return
	}
	a.apiWriteNote(w, r, http.StatusCreated, created, key)
}

func apiIfMatch(r *http.Request) (int64, error) {
	values := r.Header.Values("If-Match")
	if len(values) == 0 || (len(values) == 1 && values[0] == "") {
		return 0, &HTTPError{428, "precondition_required", "Нужен If-Match с текущим ETag конспекта"}
	}
	if len(values) == 1 {
		value := values[0]
		if len(value) >= 4 && strings.HasPrefix(value, "\"v") && strings.HasSuffix(value, "\"") {
			version, err := strconv.ParseInt(value[2:len(value)-1], 10, 64)
			if err == nil && version > 0 && etag(version) == value {
				return version, nil
			}
		}
	}
	return 0, &HTTPError{400, "invalid_if_match", "Нужен один строгий ETag вида \"v1\""}
}

func (a *App) apiUpdateNote(w http.ResponseWriter, r *http.Request) {
	key, ok := a.authorizeAPI(w, r, "notes:write")
	if !ok {
		return
	}
	note, ok := a.apiAuthorizedNote(w, r, key, "notes:write")
	if !ok {
		return
	}
	version, err := apiIfMatch(r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	input, err := a.apiDecodeNote(w, r)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	updated, err := a.db.UpdateNote(r.Context(), note.ID, *input.Title, *input.Markdown, note.SourceName, version, store.Actor{KeyID: key.ID})
	if err != nil {
		a.apiFailWrite(w, r, err, key, "notes:write", note)
		return
	}
	a.apiWriteNote(w, r, http.StatusOK, updated, key)
}

// A key can expire/be revoked or a note can move after the handler's initial
// check. The store rejects that write atomically; translate its generic denial
// without turning lost resource access into an existence-revealing 403.
func (a *App) apiFailWrite(w http.ResponseWriter, r *http.Request, err error, key store.APIKey, scope string, note store.Note) {
	if !errors.Is(err, store.ErrForbidden) {
		a.fail(w, r, err)
		return
	}
	currentKey, err := a.db.APIKeyByHash(r.Context(), key.TokenHash)
	if errors.Is(err, store.ErrNotFound) {
		a.apiError(w, r, 401, "unauthorized", "Нужен действующий API-ключ")
		return
	}
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if !currentKey.HasScope(scope) {
		a.fail(w, r, store.ErrForbidden)
		return
	}
	allowed := currentKey.AllowsProject(note.ProjectID, scope)
	if note.ID != "" {
		current, err := a.db.Note(r.Context(), note.ID)
		if err != nil {
			a.fail(w, r, err)
			return
		}
		allowed = currentKey.AllowsNote(current, scope)
	}
	if !allowed {
		a.fail(w, r, store.ErrNotFound)
		return
	}
	a.fail(w, r, store.ErrForbidden)
}

func (a *App) apiUploadAttachment(w http.ResponseWriter, r *http.Request) {
	key, ok := a.authorizeAPI(w, r, "attachments:write")
	if !ok {
		return
	}
	note, ok := a.apiAuthorizedNote(w, r, key, "attachments:write")
	if !ok {
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/form-data" {
		a.apiError(w, r, 415, "unsupported_media_type", "Ожидается multipart/form-data")
		return
	}
	attachment, err := a.receiveImage(w, r, note.ID, store.Actor{KeyID: key.ID})
	if err != nil {
		a.apiFailWrite(w, r, err, key, "attachments:write", note)
		return
	}
	a.writeJSON(w, r, http.StatusCreated, struct {
		Attachment store.Attachment `json:"attachment"`
		Markdown   string           `json:"markdown"`
	}{attachment, imageMarkdown(attachment)})
}

func (a *App) apiAttachment(w http.ResponseWriter, r *http.Request) {
	key, ok := a.authorizeAPI(w, r, "attachments:read")
	if !ok {
		return
	}
	note, ok := a.apiAuthorizedNote(w, r, key, "attachments:read")
	if !ok {
		return
	}
	a.attachment(w, r, note.ID, r.PathValue("attachmentID"))
}

func (a *App) apiOpenAPI(w http.ResponseWriter, r *http.Request) {
	a.writeJSON(w, r, http.StatusOK, json.RawMessage(openAPIJSON))
}
