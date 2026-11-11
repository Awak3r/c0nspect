package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"slices"
	"time"
)

var (
	ErrNotFound  = errors.New("not found")
	ErrConflict  = errors.New("version conflict")
	ErrForbidden = errors.New("forbidden")
	ErrQuota     = errors.New("storage quota exceeded")
)

func NewID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

type Owner struct {
	Username     string
	PasswordHash string
}

type Session struct {
	TokenHash string
	CSRFToken string
	ExpiresAt time.Time
}

type Project struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type Note struct {
	ID         string    `json:"id"`
	ProjectID  string    `json:"project_id"`
	Title      string    `json:"title"`
	Markdown   string    `json:"markdown"`
	SourceName string    `json:"source_name"`
	Version    int64     `json:"version"`
	Shared     bool      `json:"shared"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type Attachment struct {
	ID         string    `json:"id"`
	NoteID     string    `json:"note_id"`
	Name       string    `json:"name"`
	StorageKey string    `json:"-"`
	MIME       string    `json:"mime_type"`
	Size       int64     `json:"size"`
	CreatedAt  time.Time `json:"created_at"`
}

type ShareLink struct {
	ID        string
	NoteID    string
	TokenHash string
	CreatedAt time.Time
}

type APIKey struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	TokenHash   string     `json:"-"`
	Scopes      []string   `json:"scopes"`
	AllProjects bool       `json:"all_projects"`
	ProjectIDs  []string   `json:"project_ids"`
	NoteIDs     []string   `json:"note_ids"`
	CreatedAt   time.Time  `json:"created_at"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	RevokedAt   *time.Time `json:"revoked_at,omitempty"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
}

func (k APIKey) HasScope(scope string) bool { return slices.Contains(k.Scopes, scope) }
func (k APIKey) AllowsNote(n Note, scope string) bool {
	return k.HasScope(scope) && (k.AllProjects || slices.Contains(k.ProjectIDs, n.ProjectID) || slices.Contains(k.NoteIDs, n.ID))
}
func (k APIKey) AllowsProject(id, scope string) bool {
	return k.HasScope(scope) && (k.AllProjects || slices.Contains(k.ProjectIDs, id))
}

type Actor struct {
	Owner bool
	KeyID string
}

// Repository keeps browser and API writes on the same authorization and version checks.
// API writes must recheck the key under a transaction lock, not trust a cached key.
type Repository interface {
	Ping(context.Context) error
	Owner(context.Context) (Owner, error)
	EnsureOwner(context.Context, string, string) error
	CreateSession(context.Context, Session) error
	Session(context.Context, string) (Session, error)
	DeleteSession(context.Context, string) error
	Projects(context.Context) ([]Project, error)
	Project(context.Context, string) (Project, error)
	CreateProject(context.Context, string, string) (Project, error)
	UpdateProject(context.Context, string, string, string) error
	DeleteProject(context.Context, string) ([]Attachment, error)
	Notes(context.Context, string, string, string) ([]Note, error)
	Note(context.Context, string) (Note, error)
	CreateNote(context.Context, Note, Actor) (Note, error)
	UpdateNote(context.Context, string, string, string, string, int64, Actor) (Note, error)
	SetNoteMetadata(context.Context, string, string, string, int64) (Note, error)
	DeleteNote(context.Context, string, int64) ([]Attachment, error)
	Attachments(context.Context, string) ([]Attachment, error)
	Attachment(context.Context, string, string) (Attachment, error)
	CreateAttachment(context.Context, Attachment, Actor, int64) (Attachment, error)
	DeleteAttachment(context.Context, string, string) (Attachment, error)
	ReplaceShare(context.Context, ShareLink) (ShareLink, error)
	ActiveShare(context.Context, string) (ShareLink, error)
	ShareByHash(context.Context, string) (ShareLink, error)
	RevokeShare(context.Context, string) error
	APIKeys(context.Context) ([]APIKey, error)
	APIKeyByHash(context.Context, string) (APIKey, error)
	CreateAPIKey(context.Context, APIKey) (APIKey, error)
	UpdateAPIKeyAccess(ctx context.Context, id string, allProjects bool, projectIDs, noteIDs []string) error
	RevokeAPIKey(context.Context, string) error
}
