package store

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

type postgresTestDB struct {
	ctx    context.Context
	url    string
	schema string
}

func closeConn(conn *pgx.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = conn.Close(ctx)
}

// Every integration test gets its own generated schema. The supplied database is
// never reset: cleanup can only drop the exact schema this helper just created.
func newPostgresTestDB(t *testing.T) *postgresTestDB {
	t.Helper()
	baseURL := os.Getenv("TEST_DATABASE_URL")
	if baseURL == "" {
		t.Skip("TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	admin, err := pgx.Connect(ctx, baseURL)
	if err != nil {
		t.Fatal(err)
	}
	schema := "conspect_test_" + NewID()
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, `CREATE SCHEMA `+identifier); err != nil {
		_ = admin.Close(context.Background())
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(cleanup, `DROP SCHEMA `+identifier+` CASCADE`); err != nil {
			t.Errorf("clean up temporary schema %s: %v", schema, err)
		}
		_ = admin.Close(cleanup)
	})
	databaseURL := baseURL
	if u, err := url.Parse(baseURL); err == nil && (u.Scheme == "postgres" || u.Scheme == "postgresql") {
		q := u.Query()
		q.Set("search_path", schema)
		q.Set("application_name", schema)
		u.RawQuery = q.Encode()
		databaseURL = u.String()
	} else {
		// The generated identifier is alphanumeric plus underscores, safe in a
		// libpq keyword DSN without escaping or depending on its original quoting.
		databaseURL += " search_path=" + schema + " application_name=" + schema
	}
	probe, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	var actualSchema string
	err = probe.QueryRow(ctx, `SELECT current_schema()`).Scan(&actualSchema)
	closeConn(probe)
	if err != nil || actualSchema != schema {
		t.Fatalf("refusing to run migrations outside temporary schema: got %q, want %q, err=%v", actualSchema, schema, err)
	}
	return &postgresTestDB{ctx: ctx, url: databaseURL, schema: schema}
}

func (db *postgresTestDB) open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(db.ctx, db.url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func (db *postgresTestDB) connect(t *testing.T) *pgx.Conn {
	t.Helper()
	conn, err := pgx.Connect(db.ctx, db.url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { closeConn(conn) })
	return conn
}

func mustProject(t *testing.T, s *Store, ctx context.Context, name string) Project {
	t.Helper()
	p, err := s.CreateProject(ctx, name, "description")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func mustNote(t *testing.T, s *Store, ctx context.Context, projectID, title string) Note {
	t.Helper()
	n, err := s.CreateNote(ctx, Note{ProjectID: projectID, Title: title, Markdown: "private body", SourceName: "notes.md"}, Actor{Owner: true})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func mustKey(t *testing.T, s *Store, ctx context.Context, key APIKey) APIKey {
	t.Helper()
	key.TokenHash = NewID()
	created, err := s.CreateAPIKey(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	return created
}

func testAttachment(noteID string, size int64) Attachment {
	return Attachment{NoteID: noteID, Name: "figure.png", StorageKey: "files/" + NewID(), MIME: "image/png", Size: size}
}

func requireErrorIs(t *testing.T, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("error = %v, want errors.Is(_, %v)", err, target)
	}
}

func TestPostgresMigrationsOwnerAndSessions(t *testing.T) {
	db := newPostgresTestDB(t)
	// Migrations must be safe when multiple service instances start together.
	type opened struct {
		s   *Store
		err error
	}
	results := make(chan opened, 2)
	start := make(chan struct{})
	for range 2 {
		go func() {
			<-start
			s, err := Open(db.ctx, db.url)
			results <- opened{s, err}
		}()
	}
	close(start)
	var s *Store
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Errorf("concurrent Open: %v", result.err)
			continue
		}
		t.Cleanup(result.s.Close)
		s = result.s
	}
	if t.Failed() {
		t.FailNow()
	}
	if err := s.Ping(db.ctx); err != nil {
		t.Fatal(err)
	}
	conn := db.connect(t)
	var migrations int
	if err := conn.QueryRow(db.ctx, `SELECT COUNT(*) FROM schema_migrations WHERE version = 1`).Scan(&migrations); err != nil || migrations != 1 {
		t.Fatalf("migrations = %d, err = %v", migrations, err)
	}
	_, err := s.Owner(db.ctx)
	requireErrorIs(t, err, ErrNotFound)
	if err := s.EnsureOwner(db.ctx, "owner", "original-password-hash"); err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureOwner(db.ctx, "changed", "changed-password-hash"); err != nil {
		t.Fatal(err)
	}
	owner, err := s.Owner(db.ctx)
	if err != nil || owner.Username != "owner" || owner.PasswordHash != "original-password-hash" {
		t.Fatalf("owner was replaced: %+v, %v", owner, err)
	}
	session := Session{TokenHash: NewID(), CSRFToken: NewID(), ExpiresAt: time.Now().Add(time.Hour).Truncate(time.Microsecond)}
	if err := s.CreateSession(db.ctx, session); err != nil {
		t.Fatal(err)
	}
	got, err := s.Session(db.ctx, session.TokenHash)
	if err != nil || got.TokenHash != session.TokenHash || got.CSRFToken != session.CSRFToken || !got.ExpiresAt.Equal(session.ExpiresAt) {
		t.Fatalf("session = %+v, err = %v", got, err)
	}
	expired := Session{TokenHash: NewID(), ExpiresAt: time.Now().Add(-time.Minute)}
	if err := s.CreateSession(db.ctx, expired); err != nil {
		t.Fatal(err)
	}
	_, err = s.Session(db.ctx, expired.TokenHash)
	requireErrorIs(t, err, ErrNotFound)
	_, err = s.Session(db.ctx, "unknown")
	requireErrorIs(t, err, ErrNotFound)
	for range 2 {
		if err := s.DeleteSession(db.ctx, session.TokenHash); err != nil {
			t.Fatal(err)
		}
	}
	_, err = s.Session(db.ctx, session.TokenHash)
	requireErrorIs(t, err, ErrNotFound)
	s.Close()
	s.Close()
	if err := s.Ping(db.ctx); err == nil {
		t.Fatal("Ping on a closed Store succeeded")
	}
}

func TestPostgresOptimisticUpdatesAcrossStores(t *testing.T) {
	db := newPostgresTestDB(t)
	s := db.open(t)
	other := db.open(t)
	p := mustProject(t, s, db.ctx, "A")
	n := mustNote(t, s, db.ctx, p.ID, "Original")
	type updated struct {
		note Note
		err  error
	}
	results := make(chan updated, 2)
	start := make(chan struct{})
	for i, instance := range []*Store{s, other} {
		go func() {
			<-start
			title := []string{"First writer", "Second writer"}[i]
			note, err := instance.UpdateNote(db.ctx, n.ID, title, title, "", n.Version, Actor{Owner: true})
			results <- updated{note, err}
		}()
	}
	close(start)
	var winner Note
	conflicts := 0
	for range 2 {
		result := <-results
		if result.err == nil {
			if winner.ID != "" {
				t.Fatal("two updates with the same expected version committed")
			}
			winner = result.note
		} else {
			requireErrorIs(t, result.err, ErrConflict)
			conflicts++
		}
	}
	if winner.ID == "" || winner.Version != 2 || conflicts != 1 {
		t.Fatalf("winner=%+v conflicts=%d", winner, conflicts)
	}
	persisted, err := s.Note(db.ctx, n.ID)
	if err != nil || persisted.Title != winner.Title || persisted.Version != winner.Version {
		t.Fatalf("persisted winner = %+v, %v", persisted, err)
	}
	var count int
	if err := db.connect(t).QueryRow(db.ctx, `SELECT COUNT(*) FROM audit_events WHERE note_id = $1 AND action = 'note.update'`, n.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("committed update audits = %d, %v", count, err)
	}
}

func TestPostgresCRUDVersionsDeletionAndAudit(t *testing.T) {
	db := newPostgresTestDB(t)
	s := db.open(t)
	ctx := db.ctx
	projects, err := s.Projects(ctx)
	if err != nil || projects == nil || len(projects) != 0 {
		t.Fatalf("empty projects = %v, %v", projects, err)
	}
	p := mustProject(t, s, ctx, "Project")
	if p.ID == "" || p.CreatedAt.IsZero() || p.UpdatedAt.IsZero() {
		t.Fatalf("missing project metadata: %+v", p)
	}
	if err := s.UpdateProject(ctx, p.ID, "Renamed", "new description"); err != nil {
		t.Fatal(err)
	}
	p, err = s.Project(ctx, p.ID)
	if err != nil || p.Name != "Renamed" || p.Description != "new description" {
		t.Fatalf("project = %+v, %v", p, err)
	}
	projects, err = s.Projects(ctx)
	if err != nil || len(projects) != 1 || projects[0].ID != p.ID {
		t.Fatalf("projects = %+v, %v", projects, err)
	}
	owner := Actor{Owner: true}
	n, err := s.CreateNote(ctx, Note{ProjectID: p.ID, Title: "First", Markdown: "private body", Version: 99, Shared: true}, owner)
	if err != nil || n.Version != 1 || n.Shared || n.ID == "" || n.CreatedAt.IsZero() || n.UpdatedAt.IsZero() {
		t.Fatalf("created note = %+v, %v", n, err)
	}
	n, err = s.UpdateNote(ctx, n.ID, "New title", "new private body", "replacement.md", 1, owner)
	if err != nil || n.Version != 2 || n.Title != "New title" || n.Markdown != "new private body" || n.SourceName != "replacement.md" {
		t.Fatalf("updated note = %+v, %v", n, err)
	}
	_, err = s.UpdateNote(ctx, n.ID, "stale", "stale", "", 1, owner)
	requireErrorIs(t, err, ErrConflict)
	_, err = s.SetNoteMetadata(ctx, n.ID, "stale", p.ID, 1)
	requireErrorIs(t, err, ErrConflict)
	_, err = s.DeleteNote(ctx, n.ID, 1)
	requireErrorIs(t, err, ErrConflict)
	n, err = s.SetNoteMetadata(ctx, n.ID, "Metadata title", p.ID, 2)
	if err != nil || n.Version != 3 || n.Title != "Metadata title" || n.Markdown != "new private body" {
		t.Fatalf("metadata update = %+v, %v", n, err)
	}
	unchanged, err := s.SetNoteMetadata(ctx, n.ID, n.Title, n.ProjectID, n.Version)
	if err != nil || unchanged.Version != n.Version {
		t.Fatalf("no-op metadata = %+v, %v", unchanged, err)
	}
	_, err = s.SetNoteMetadata(ctx, n.ID, "bad move", "missing-project", 3)
	requireErrorIs(t, err, ErrNotFound)
	persisted, err := s.Note(ctx, n.ID)
	if err != nil || persisted.Version != 3 || persisted.Title != n.Title {
		t.Fatalf("failed move modified note: %+v, %v", persisted, err)
	}
	asset, err := s.CreateAttachment(ctx, testAttachment(n.ID, 12), owner, 100)
	if err != nil || asset.ID == "" || asset.CreatedAt.IsZero() || asset.Size != 12 {
		t.Fatalf("attachment = %+v, %v", asset, err)
	}
	assets, err := s.Attachments(ctx, n.ID)
	if err != nil || len(assets) != 1 || assets[0].StorageKey != asset.StorageKey {
		t.Fatalf("attachments = %+v, %v", assets, err)
	}
	gotAsset, err := s.Attachment(ctx, n.ID, asset.ID)
	if err != nil || gotAsset.StorageKey != asset.StorageKey {
		t.Fatalf("attachment lookup = %+v, %v", gotAsset, err)
	}
	n2 := mustNote(t, s, ctx, p.ID, "Second")
	_, err = s.Attachment(ctx, n2.ID, asset.ID)
	requireErrorIs(t, err, ErrNotFound)
	_, err = s.DeleteAttachment(ctx, n2.ID, asset.ID)
	requireErrorIs(t, err, ErrNotFound)
	removed, err := s.DeleteAttachment(ctx, n.ID, asset.ID)
	if err != nil || removed.StorageKey != asset.StorageKey {
		t.Fatalf("deleted attachment = %+v, %v", removed, err)
	}
	asset, err = s.CreateAttachment(ctx, testAttachment(n.ID, 12), owner, 100)
	if err != nil {
		t.Fatal(err)
	}
	link, err := s.ReplaceShare(ctx, ShareLink{NoteID: n.ID, TokenHash: NewID()})
	if err != nil {
		t.Fatal(err)
	}
	assets, err = s.DeleteNote(ctx, n.ID, n.Version)
	if err != nil || len(assets) != 1 || assets[0].StorageKey != asset.StorageKey {
		t.Fatalf("deleted note assets = %+v, %v", assets, err)
	}
	_, err = s.Note(ctx, n.ID)
	requireErrorIs(t, err, ErrNotFound)
	_, err = s.Attachment(ctx, n.ID, asset.ID)
	requireErrorIs(t, err, ErrNotFound)
	_, err = s.ShareByHash(ctx, link.TokenHash)
	requireErrorIs(t, err, ErrNotFound)
	asset2, err := s.CreateAttachment(ctx, testAttachment(n2.ID, 5), owner, 100)
	if err != nil {
		t.Fatal(err)
	}
	link2, err := s.ReplaceShare(ctx, ShareLink{NoteID: n2.ID, TokenHash: NewID()})
	if err != nil {
		t.Fatal(err)
	}
	assets, err = s.DeleteProject(ctx, p.ID)
	if err != nil || len(assets) != 1 || assets[0].StorageKey != asset2.StorageKey {
		t.Fatalf("deleted project assets = %+v, %v", assets, err)
	}
	_, err = s.Project(ctx, p.ID)
	requireErrorIs(t, err, ErrNotFound)
	_, err = s.Note(ctx, n2.ID)
	requireErrorIs(t, err, ErrNotFound)
	_, err = s.ShareByHash(ctx, link2.TokenHash)
	requireErrorIs(t, err, ErrNotFound)
	conn := db.connect(t)
	var deleted, updates, remaining int
	if err := conn.QueryRow(ctx, `SELECT COUNT(*) FROM audit_events WHERE action = 'note.delete' AND note_id = ANY($1::text[])`, []string{n.ID, n2.ID}).Scan(&deleted); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, `SELECT COUNT(*) FROM audit_events WHERE note_id = $1 AND action = 'note.update' AND old_version = 1 AND new_version = 2 AND actor_owner`, n.ID).Scan(&updates); err != nil {
		t.Fatal(err)
	}
	if err := conn.QueryRow(ctx, `SELECT (SELECT COUNT(*) FROM attachments) + (SELECT COUNT(*) FROM share_links)`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if deleted != 2 || updates != 1 || remaining != 0 {
		t.Fatalf("audit/delete counts: deleted=%d updates=%d remaining=%d", deleted, updates, remaining)
	}
}

func TestPostgresLiteralSearchAndFixedSorting(t *testing.T) {
	db := newPostgresTestDB(t)
	s := db.open(t)
	p := mustProject(t, s, db.ctx, "A")
	p2 := mustProject(t, s, db.ctx, "B")
	alpha := mustNote(t, s, db.ctx, p.ID, "Alpha")
	beta := mustNote(t, s, db.ctx, p.ID, "beta")
	zeta := mustNote(t, s, db.ctx, p2.ID, "zeta")
	var err error
	beta, err = s.UpdateNote(db.ctx, beta.ID, beta.Title, `NEEDLE 100% literal_under and back\slash`, "", beta.Version, Actor{Owner: true})
	if err != nil {
		t.Fatal(err)
	}
	conn := db.connect(t)
	for i, n := range []Note{alpha, beta, zeta} {
		if _, err := conn.Exec(db.ctx, `UPDATE notes SET updated_at = $2 WHERE id = $1`, n.ID, time.Date(2024, 1, i+1, 0, 0, 0, 0, time.UTC)); err != nil {
			t.Fatal(err)
		}
	}
	for _, test := range []struct {
		name, project, query, sort string
		want                       []string
	}{
		{"title", "", "", "title", []string{alpha.ID, beta.ID, zeta.ID}},
		{"modified", "", "", "modified", []string{zeta.ID, beta.ID, alpha.ID}},
		{"default", "", "", "", []string{zeta.ID, beta.ID, alpha.ID}},
		{"project", p.ID, "", "title", []string{alpha.ID, beta.ID}},
		{"title case", "", "aLP", "", []string{alpha.ID}},
		{"body case", "", "needle", "", []string{beta.ID}},
		{"percent literal", "", "%", "", []string{beta.ID}},
		{"underscore literal", "", "_", "", []string{beta.ID}},
		{"backslash literal", "", `\`, "", []string{beta.ID}},
		{"search injection", "", "' OR true --", "", []string{}},
		{"sort injection", "", "", "title; DROP TABLE notes; --", []string{zeta.ID, beta.ID, alpha.ID}},
		{"project injection", "' OR true --", "", "", nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			notes, err := s.Notes(db.ctx, test.project, test.query, test.sort)
			if test.want == nil {
				requireErrorIs(t, err, ErrNotFound)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			ids := make([]string, 0, len(notes))
			for _, n := range notes {
				ids = append(ids, n.ID)
			}
			if !slices.Equal(ids, test.want) || notes == nil {
				t.Fatalf("ids = %v, want %v (nil slice: %v)", ids, test.want, notes == nil)
			}
		})
	}
}

func TestPostgresAPIWriteAuthorizationAndMoves(t *testing.T) {
	db := newPostgresTestDB(t)
	s := db.open(t)
	ctx := db.ctx
	p := mustProject(t, s, ctx, "A")
	other := mustProject(t, s, ctx, "B")
	n := mustNote(t, s, ctx, p.ID, "Allowed")
	unrelated := mustNote(t, s, ctx, other.ID, "Forbidden")
	projectKey := mustKey(t, s, ctx, APIKey{Name: "project", Scopes: []string{"notes:write", "attachments:write"}, ProjectIDs: []string{p.ID}})
	noteKey := mustKey(t, s, ctx, APIKey{Name: "note", Scopes: []string{"notes:write", "attachments:write"}, NoteIDs: []string{n.ID}})
	readKey := mustKey(t, s, ctx, APIKey{Name: "read", Scopes: []string{"notes:read", "attachments:read"}, ProjectIDs: []string{p.ID}})
	unscoped := mustKey(t, s, ctx, APIKey{Scopes: []string{"notes:write", "attachments:write"}})
	for _, actor := range []Actor{{}, {KeyID: "missing"}, {KeyID: readKey.ID}, {KeyID: unscoped.ID}} {
		_, err := s.CreateNote(ctx, Note{ProjectID: p.ID, Title: "denied"}, actor)
		requireErrorIs(t, err, ErrForbidden)
		_, err = s.UpdateNote(ctx, n.ID, "denied", "denied", "", n.Version, actor)
		requireErrorIs(t, err, ErrForbidden)
		_, err = s.CreateAttachment(ctx, testAttachment(n.ID, 1), actor, 100)
		requireErrorIs(t, err, ErrForbidden)
	}
	_, err := s.CreateNote(ctx, Note{ProjectID: p.ID, Title: "no sibling creation"}, Actor{KeyID: noteKey.ID})
	requireErrorIs(t, err, ErrForbidden)
	_, err = s.UpdateNote(ctx, unrelated.ID, "denied", "", "", unrelated.Version, Actor{KeyID: projectKey.ID})
	requireErrorIs(t, err, ErrForbidden)
	_, err = s.CreateAttachment(ctx, testAttachment(unrelated.ID, 1), Actor{KeyID: noteKey.ID}, 100)
	requireErrorIs(t, err, ErrForbidden)
	n, err = s.UpdateNote(ctx, n.ID, "Note-specific edit", "private updated body", "api.md", n.Version, Actor{KeyID: noteKey.ID})
	if err != nil || n.Version != 2 {
		t.Fatalf("note-scoped edit = %+v, %v", n, err)
	}
	created, err := s.CreateNote(ctx, Note{ProjectID: p.ID, Title: "Project creation"}, Actor{KeyID: projectKey.ID})
	if err != nil || created.Version != 1 {
		t.Fatalf("project-scoped create = %+v, %v", created, err)
	}
	notesOnly := mustKey(t, s, ctx, APIKey{Scopes: []string{"notes:write"}, ProjectIDs: []string{p.ID}})
	_, err = s.CreateAttachment(ctx, testAttachment(n.ID, 1), Actor{KeyID: notesOnly.ID}, 100)
	requireErrorIs(t, err, ErrForbidden)
	attachmentsOnly := mustKey(t, s, ctx, APIKey{Scopes: []string{"attachments:write"}, NoteIDs: []string{n.ID}})
	_, err = s.UpdateNote(ctx, n.ID, "denied", "", "", n.Version, Actor{KeyID: attachmentsOnly.ID})
	requireErrorIs(t, err, ErrForbidden)
	if _, err := s.CreateAttachment(ctx, testAttachment(n.ID, 1), Actor{KeyID: attachmentsOnly.ID}, 100); err != nil {
		t.Fatal(err)
	}
	// Persisted scopes, not a previously fetched key, control the next write.
	conn := db.connect(t)
	if _, err := conn.Exec(ctx, `UPDATE api_keys SET scopes = '{}' WHERE id = $1`, notesOnly.ID); err != nil {
		t.Fatal(err)
	}
	_, err = s.UpdateNote(ctx, n.ID, "denied", "", "", n.Version, Actor{KeyID: notesOnly.ID})
	requireErrorIs(t, err, ErrForbidden)
	n, err = s.SetNoteMetadata(ctx, n.ID, n.Title, other.ID, n.Version)
	if err != nil || n.Version != 3 || n.ProjectID != other.ID {
		t.Fatalf("move = %+v, %v", n, err)
	}
	_, err = s.UpdateNote(ctx, n.ID, "old project denied", "", "", n.Version, Actor{KeyID: projectKey.ID})
	requireErrorIs(t, err, ErrForbidden)
	_, err = s.CreateAttachment(ctx, testAttachment(n.ID, 1), Actor{KeyID: projectKey.ID}, 100)
	requireErrorIs(t, err, ErrForbidden)
	n, err = s.UpdateNote(ctx, n.ID, "Explicit note still allowed", "body", "", n.Version, Actor{KeyID: noteKey.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateAttachment(ctx, testAttachment(n.ID, 1), Actor{KeyID: noteKey.ID}, 100); err != nil {
		t.Fatal(err)
	}
	newProjectKey := mustKey(t, s, ctx, APIKey{Scopes: []string{"notes:write"}, ProjectIDs: []string{other.ID}})
	n, err = s.UpdateNote(ctx, n.ID, "New project allowed", "body", "", n.Version, Actor{KeyID: newProjectKey.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteNote(ctx, n.ID, n.Version); err != nil {
		t.Fatal(err)
	}
	var auditCount int
	if err := conn.QueryRow(ctx, `SELECT COUNT(*) FROM audit_events WHERE note_id = $1 AND actor_key_id = $2 AND NOT actor_owner AND action = 'note.update'`, n.ID, noteKey.ID).Scan(&auditCount); err != nil || auditCount != 2 {
		t.Fatalf("retained API audit count = %d, %v", auditCount, err)
	}
}

func TestPostgresAPIKeyLifecycle(t *testing.T) {
	db := newPostgresTestDB(t)
	s := db.open(t)
	ctx := db.ctx
	p := mustProject(t, s, ctx, "A")
	n := mustNote(t, s, ctx, p.ID, "A")
	future := time.Now().Add(time.Hour).Truncate(time.Microsecond)
	key := mustKey(t, s, ctx, APIKey{Name: "client", Scopes: []string{"notes:write", "attachments:write"}, ProjectIDs: []string{p.ID}, ExpiresAt: &future})
	if key.LastUsedAt != nil || key.RevokedAt != nil || key.ExpiresAt == nil || !key.ExpiresAt.Equal(future) || key.NoteIDs == nil {
		t.Fatalf("created key = %+v", key)
	}
	authenticated, err := s.APIKeyByHash(ctx, key.TokenHash)
	if err != nil || authenticated.ID != key.ID || authenticated.LastUsedAt == nil || !reflect.DeepEqual(authenticated.Scopes, key.Scopes) {
		t.Fatalf("key lookup = %+v, %v", authenticated, err)
	}
	if err := s.RevokeAPIKey(ctx, key.ID); err != nil {
		t.Fatal(err)
	}
	keys, err := s.APIKeys(ctx)
	if err != nil || len(keys) != 1 || keys[0].RevokedAt == nil || keys[0].LastUsedAt == nil {
		t.Fatalf("listed keys = %+v, %v", keys, err)
	}
	firstRevocation := *keys[0].RevokedAt
	if err := s.RevokeAPIKey(ctx, key.ID); err != nil {
		t.Fatal(err)
	}
	keys, err = s.APIKeys(ctx)
	if err != nil || !keys[0].RevokedAt.Equal(firstRevocation) {
		t.Fatalf("repeat revoke changed timestamp: %+v, %v", keys, err)
	}
	past := time.Now().Add(-time.Minute)
	expired := mustKey(t, s, ctx, APIKey{Scopes: key.Scopes, ProjectIDs: key.ProjectIDs, ExpiresAt: &past})
	for _, invalid := range []APIKey{key, expired} {
		_, err := s.APIKeyByHash(ctx, invalid.TokenHash)
		requireErrorIs(t, err, ErrNotFound)
		_, err = s.UpdateNote(ctx, n.ID, "denied", "", "", n.Version, Actor{KeyID: invalid.ID})
		requireErrorIs(t, err, ErrForbidden)
		_, err = s.CreateNote(ctx, Note{ProjectID: p.ID, Title: "denied"}, Actor{KeyID: invalid.ID})
		requireErrorIs(t, err, ErrForbidden)
		_, err = s.CreateAttachment(ctx, testAttachment(n.ID, 1), Actor{KeyID: invalid.ID}, 100)
		requireErrorIs(t, err, ErrForbidden)
	}
	_, err = s.APIKeyByHash(ctx, "unknown")
	requireErrorIs(t, err, ErrNotFound)
	requireErrorIs(t, s.RevokeAPIKey(ctx, "unknown"), ErrNotFound)
	keys, err = s.APIKeys(ctx)
	if err != nil || len(keys) != 2 {
		t.Fatalf("expired/revoked keys missing from listing: %+v, %v", keys, err)
	}
}

func TestPostgresSharesAreAtomicAndUnique(t *testing.T) {
	db := newPostgresTestDB(t)
	s := db.open(t)
	otherStore := db.open(t)
	ctx := db.ctx
	p := mustProject(t, s, ctx, "A")
	n := mustNote(t, s, ctx, p.ID, "A")
	_, err := s.ActiveShare(ctx, n.ID)
	requireErrorIs(t, err, ErrNotFound)
	first, err := s.ReplaceShare(ctx, ShareLink{NoteID: n.ID, TokenHash: NewID()})
	if err != nil || first.ID == "" || first.CreatedAt.IsZero() {
		t.Fatalf("share = %+v, %v", first, err)
	}
	second, err := s.ReplaceShare(ctx, ShareLink{NoteID: n.ID, TokenHash: NewID()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.ShareByHash(ctx, first.TokenHash)
	requireErrorIs(t, err, ErrNotFound)
	if _, err := s.ReplaceShare(ctx, ShareLink{NoteID: n.ID, TokenHash: first.TokenHash}); err == nil {
		t.Fatal("reused historical hash unexpectedly accepted")
	}
	active, err := s.ActiveShare(ctx, n.ID)
	if err != nil || active.ID != second.ID {
		t.Fatalf("failed replacement lost previous share: %+v, %v", active, err)
	}
	n, err = s.Note(ctx, n.ID)
	if err != nil || !n.Shared || n.Version != 1 {
		t.Fatalf("shared note = %+v, %v", n, err)
	}
	p2 := mustProject(t, s, ctx, "B")
	n, err = s.SetNoteMetadata(ctx, n.ID, "Moved", p2.ID, n.Version)
	if err != nil {
		t.Fatal(err)
	}
	if link, err := s.ShareByHash(ctx, second.TokenHash); err != nil || link.NoteID != n.ID {
		t.Fatalf("move lost share: %+v, %v", link, err)
	}
	type replaced struct {
		link ShareLink
		err  error
	}
	results := make(chan replaced, 2)
	start := make(chan struct{})
	for _, instance := range []*Store{s, otherStore} {
		go func() {
			<-start
			link, err := instance.ReplaceShare(ctx, ShareLink{NoteID: n.ID, TokenHash: NewID()})
			results <- replaced{link, err}
		}()
	}
	close(start)
	var issued []ShareLink
	for range 2 {
		result := <-results
		if result.err != nil {
			t.Fatal(result.err)
		}
		issued = append(issued, result.link)
	}
	active, err = s.ActiveShare(ctx, n.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, link := range issued {
		got, err := s.ShareByHash(ctx, link.TokenHash)
		if link.ID == active.ID {
			if err != nil || got.ID != active.ID {
				t.Fatalf("active concurrent share = %+v, %v", got, err)
			}
		} else {
			requireErrorIs(t, err, ErrNotFound)
		}
	}
	conn := db.connect(t)
	var count int
	if err := conn.QueryRow(ctx, `SELECT COUNT(*) FROM share_links WHERE note_id = $1 AND revoked_at IS NULL`, n.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("active share count = %d, %v", count, err)
	}
	for range 2 {
		if err := s.RevokeShare(ctx, n.ID); err != nil {
			t.Fatal(err)
		}
	}
	_, err = s.ShareByHash(ctx, active.TokenHash)
	requireErrorIs(t, err, ErrNotFound)
	n, err = s.Note(ctx, n.ID)
	if err != nil || n.Shared {
		t.Fatalf("revoked note = %+v, %v", n, err)
	}
}

func TestPostgresQuotaIsSerializedAcrossStores(t *testing.T) {
	db := newPostgresTestDB(t)
	s := db.open(t)
	other := db.open(t)
	ctx := db.ctx
	p := mustProject(t, s, ctx, "A")
	notes := []Note{mustNote(t, s, ctx, p.ID, "A"), mustNote(t, s, ctx, p.ID, "B")}
	owner := Actor{Owner: true}
	if _, err := s.CreateAttachment(ctx, testAttachment(notes[0].ID, 0), owner, 0); err != nil {
		t.Fatal(err)
	}
	_, err := s.CreateAttachment(ctx, testAttachment(notes[0].ID, 1), owner, 0)
	requireErrorIs(t, err, ErrQuota)
	if _, err := s.CreateAttachment(ctx, testAttachment(notes[0].ID, -1), owner, 10); err == nil {
		t.Fatal("negative attachment size accepted")
	}
	type inserted struct {
		asset Attachment
		err   error
	}
	results := make(chan inserted, 2)
	start := make(chan struct{})
	for i, instance := range []*Store{s, other} {
		go func() {
			<-start
			asset, err := instance.CreateAttachment(ctx, testAttachment(notes[i].ID, 6), owner, 10)
			results <- inserted{asset, err}
		}()
	}
	close(start)
	var winning Attachment
	for range 2 {
		result := <-results
		if result.err == nil {
			if winning.ID != "" {
				t.Fatal("concurrent uploads exceeded total quota")
			}
			winning = result.asset
		} else {
			requireErrorIs(t, result.err, ErrQuota)
		}
	}
	if winning.ID == "" {
		t.Fatal("neither concurrent upload succeeded")
	}
	if _, err := s.CreateAttachment(ctx, testAttachment(notes[0].ID, 4), owner, 10); err != nil {
		t.Fatal(err)
	}
	_, err = s.CreateAttachment(ctx, testAttachment(notes[1].ID, 1), owner, 10)
	requireErrorIs(t, err, ErrQuota)
	if _, err := s.DeleteAttachment(ctx, winning.NoteID, winning.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateAttachment(ctx, testAttachment(notes[1].ID, 6), owner, 10); err != nil {
		t.Fatalf("deletion did not release quota: %v", err)
	}
	assets, err := s.DeleteProject(ctx, p.ID)
	if err != nil || len(assets) != 3 { // zero + four + six
		t.Fatalf("project cleanup assets = %+v, %v", assets, err)
	}
	p = mustProject(t, s, ctx, "After cleanup")
	n := mustNote(t, s, ctx, p.ID, "Large metadata only")
	if _, err := s.CreateAttachment(ctx, testAttachment(n.ID, math.MaxInt64), owner, math.MaxInt64); err != nil {
		t.Fatalf("quota overflow or deletion accounting error: %v", err)
	}
	_, err = s.CreateAttachment(ctx, testAttachment(n.ID, 1), owner, math.MaxInt64)
	requireErrorIs(t, err, ErrQuota)
}

// Wait for actual PostgreSQL lock waits instead of using scheduling sleeps as
// evidence that a competing operation has reached the intended transaction step.
func waitForBlocked(t *testing.T, db *postgresTestDB, observer *pgx.Conn, count int) {
	t.Helper()
	timer := time.NewTimer(8 * time.Second)
	defer timer.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		var blocked int
		if err := observer.QueryRow(db.ctx, `SELECT COUNT(*) FROM pg_stat_activity
			WHERE datname = current_database() AND application_name = $1 AND wait_event_type = 'Lock'`, db.schema).Scan(&blocked); err != nil {
			t.Fatal(err)
		}
		if blocked >= count {
			return
		}
		select {
		case <-tick.C:
		case <-timer.C:
			t.Fatalf("wanted %d blocked database operations, saw %d", count, blocked)
		case <-db.ctx.Done():
			t.Fatal(db.ctx.Err())
		}
	}
}

func beginTestTx(t *testing.T, db *postgresTestDB) pgx.Tx {
	t.Helper()
	tx, err := db.connect(t).Begin(db.ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	})
	return tx
}

func TestPostgresRevocationOrdering(t *testing.T) {
	t.Run("revocation first prevents cached actor write", func(t *testing.T) {
		db := newPostgresTestDB(t)
		s := db.open(t)
		p := mustProject(t, s, db.ctx, "A")
		n := mustNote(t, s, db.ctx, p.ID, "A")
		key := mustKey(t, s, db.ctx, APIKey{Scopes: []string{"notes:write"}, ProjectIDs: []string{p.ID}})
		tx := beginTestTx(t, db)
		if _, err := tx.Exec(db.ctx, `UPDATE api_keys SET revoked_at = clock_timestamp() WHERE id = $1`, key.ID); err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() {
			_, err := s.UpdateNote(db.ctx, n.ID, "forbidden", "", "", n.Version, Actor{KeyID: key.ID})
			result <- err
		}()
		waitForBlocked(t, db, db.connect(t), 1)
		if err := tx.Commit(db.ctx); err != nil {
			t.Fatal(err)
		}
		requireErrorIs(t, <-result, ErrForbidden)
		got, err := s.Note(db.ctx, n.ID)
		if err != nil || got.Version != n.Version || got.Title != n.Title {
			t.Fatalf("revoked write persisted: %+v, %v", got, err)
		}
	})
	t.Run("write locks key until commit before revocation", func(t *testing.T) {
		db := newPostgresTestDB(t)
		s := db.open(t)
		other := db.open(t)
		p := mustProject(t, s, db.ctx, "A")
		n := mustNote(t, s, db.ctx, p.ID, "A")
		key := mustKey(t, s, db.ctx, APIKey{Scopes: []string{"notes:write"}, ProjectIDs: []string{p.ID}})
		tx := beginTestTx(t, db)
		if _, err := tx.Exec(db.ctx, `SELECT id FROM notes WHERE id = $1 FOR UPDATE`, n.ID); err != nil {
			t.Fatal(err)
		}
		write := make(chan error, 1)
		go func() {
			_, err := s.UpdateNote(db.ctx, n.ID, "committed first", "", "", n.Version, Actor{KeyID: key.ID})
			write <- err
		}()
		observer := db.connect(t)
		waitForBlocked(t, db, observer, 1)
		revoke := make(chan error, 1)
		go func() { revoke <- other.RevokeAPIKey(db.ctx, key.ID) }()
		waitForBlocked(t, db, observer, 2)
		if err := tx.Commit(db.ctx); err != nil {
			t.Fatal(err)
		}
		if err := <-write; err != nil {
			t.Fatalf("write that locked key first failed: %v", err)
		}
		if err := <-revoke; err != nil {
			t.Fatal(err)
		}
		got, err := s.Note(db.ctx, n.ID)
		if err != nil || got.Title != "committed first" || got.Version != n.Version+1 {
			t.Fatalf("ordered write = %+v, %v", got, err)
		}
		_, err = s.APIKeyByHash(db.ctx, key.TokenHash)
		requireErrorIs(t, err, ErrNotFound)
	})
}

func TestPostgresScopeRecheckedAfterConcurrentMove(t *testing.T) {
	for _, operation := range []string{"note", "attachment"} {
		t.Run(operation, func(t *testing.T) {
			db := newPostgresTestDB(t)
			s := db.open(t)
			p := mustProject(t, s, db.ctx, "A")
			p2 := mustProject(t, s, db.ctx, "B")
			n := mustNote(t, s, db.ctx, p.ID, "A")
			key := mustKey(t, s, db.ctx, APIKey{Scopes: []string{"notes:write", "attachments:write"}, ProjectIDs: []string{p.ID}})
			tx := beginTestTx(t, db)
			if _, err := tx.Exec(db.ctx, `SELECT id FROM notes WHERE id = $1 FOR UPDATE`, n.ID); err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() {
				var err error
				if operation == "note" {
					_, err = s.UpdateNote(db.ctx, n.ID, "forbidden", "", "", n.Version, Actor{KeyID: key.ID})
				} else {
					_, err = s.CreateAttachment(db.ctx, testAttachment(n.ID, 1), Actor{KeyID: key.ID}, 100)
				}
				result <- err
			}()
			waitForBlocked(t, db, db.connect(t), 1)
			if _, err := tx.Exec(db.ctx, `UPDATE notes SET project_id = $2, version = version + 1 WHERE id = $1`, n.ID, p2.ID); err != nil {
				t.Fatal(err)
			}
			if err := tx.Commit(db.ctx); err != nil {
				t.Fatal(err)
			}
			requireErrorIs(t, <-result, ErrForbidden)
			assets, err := s.Attachments(db.ctx, n.ID)
			if err != nil || len(assets) != 0 {
				t.Fatalf("forbidden upload persisted: %+v, %v", assets, err)
			}
		})
	}
}

func TestPostgresExpiryWhileWaitingRollsBackWriteAndAudit(t *testing.T) {
	db := newPostgresTestDB(t)
	s := db.open(t)
	p := mustProject(t, s, db.ctx, "A")
	n := mustNote(t, s, db.ctx, p.ID, "A")
	expires := time.Now().Add(3 * time.Second)
	key := mustKey(t, s, db.ctx, APIKey{Scopes: []string{"notes:write"}, ProjectIDs: []string{p.ID}, ExpiresAt: &expires})
	tx := beginTestTx(t, db)
	if _, err := tx.Exec(db.ctx, `SELECT id FROM notes WHERE id = $1 FOR UPDATE`, n.ID); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := s.UpdateNote(db.ctx, n.ID, "must roll back", "", "", n.Version, Actor{KeyID: key.ID})
		result <- err
	}()
	observer := db.connect(t)
	waitForBlocked(t, db, observer, 1)
	// Wait against PostgreSQL's clock, the authority used by the implementation.
	if _, err := observer.Exec(db.ctx, `SELECT pg_sleep(GREATEST(0, EXTRACT(EPOCH FROM ($1::timestamptz - clock_timestamp()))) + 0.02)`, key.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(db.ctx); err != nil {
		t.Fatal(err)
	}
	requireErrorIs(t, <-result, ErrForbidden)
	got, err := s.Note(db.ctx, n.ID)
	if err != nil || got.Version != n.Version || got.Title != n.Title {
		t.Fatalf("expired write persisted: %+v, %v", got, err)
	}
	var auditCount int
	if err := observer.QueryRow(db.ctx, `SELECT COUNT(*) FROM audit_events WHERE actor_key_id = $1`, key.ID).Scan(&auditCount); err != nil || auditCount != 0 {
		t.Fatalf("rolled-back audit count = %d, %v", auditCount, err)
	}
}

func TestPostgresMissingObjects(t *testing.T) {
	db := newPostgresTestDB(t)
	s := db.open(t)
	ctx := db.ctx
	for name, call := range map[string]func() error{
		"project":           func() error { _, err := s.Project(ctx, "missing"); return err },
		"update project":    func() error { return s.UpdateProject(ctx, "missing", "", "") },
		"delete project":    func() error { _, err := s.DeleteProject(ctx, "missing"); return err },
		"note":              func() error { _, err := s.Note(ctx, "missing"); return err },
		"update note":       func() error { _, err := s.UpdateNote(ctx, "missing", "", "", "", 1, Actor{Owner: true}); return err },
		"metadata":          func() error { _, err := s.SetNoteMetadata(ctx, "missing", "", "", 1); return err },
		"delete note":       func() error { _, err := s.DeleteNote(ctx, "missing", 1); return err },
		"create note":       func() error { _, err := s.CreateNote(ctx, Note{ProjectID: "missing"}, Actor{Owner: true}); return err },
		"attachments":       func() error { _, err := s.Attachments(ctx, "missing"); return err },
		"attachment":        func() error { _, err := s.Attachment(ctx, "missing", "missing"); return err },
		"delete attachment": func() error { _, err := s.DeleteAttachment(ctx, "missing", "missing"); return err },
		"create attachment": func() error {
			_, err := s.CreateAttachment(ctx, testAttachment("missing", 1), Actor{Owner: true}, 10)
			return err
		},
		"active share": func() error { _, err := s.ActiveShare(ctx, "missing"); return err },
		"share hash":   func() error { _, err := s.ShareByHash(ctx, "missing"); return err },
		"replace share": func() error {
			_, err := s.ReplaceShare(ctx, ShareLink{NoteID: "missing", TokenHash: NewID()})
			return err
		},
		"revoke share": func() error { return s.RevokeShare(ctx, "missing") },
		"api hash":     func() error { _, err := s.APIKeyByHash(ctx, "missing"); return err },
		"revoke key":   func() error { return s.RevokeAPIKey(ctx, "missing") },
	} {
		t.Run(name, func(t *testing.T) { requireErrorIs(t, call(), ErrNotFound) })
	}
}

func TestJSONDoesNotExposeStoredSecrets(t *testing.T) {
	for name, value := range map[string]any{
		"owner":      Owner{Username: "owner", PasswordHash: "secret-password-hash"},
		"session":    Session{TokenHash: "secret-session-hash", CSRFToken: "csrf"},
		"share":      ShareLink{ID: "share", NoteID: "note", TokenHash: "secret-share-hash"},
		"key":        APIKey{ID: "key", TokenHash: "secret-api-hash"},
		"attachment": Attachment{ID: "attachment", StorageKey: "secret-storage-key"},
	} {
		t.Run(name, func(t *testing.T) {
			data, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(data), "secret-") || strings.Contains(strings.ToLower(string(data)), "hash") {
				t.Fatalf("JSON exposes a stored secret: %s", data)
			}
		})
	}
}
