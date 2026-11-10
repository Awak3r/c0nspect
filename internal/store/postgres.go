package store

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"

	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var schemaSQL string

// Store is a PostgreSQL Repository backed by pgxpool. All cross-process
// coordination lives in PostgreSQL.
type Store struct {
	pool *pgxpool.Pool
}

var _ Repository = (*Store)(nil)

// Open connects to PostgreSQL and applies embedded, versioned migrations in the
// connection's current schema. The URL may set search_path to isolate a schema.
func Open(ctx context.Context, databaseURL string) (*Store, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database configuration: %w", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("create database pool: %w", err)
	}
	s := &Store{pool: pool}
	if err := s.transact(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended(current_schema() || ':conspect:migrations', 0))`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
			version integer PRIMARY KEY CHECK (version > 0),
			applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
		)`); err != nil {
			return err
		}
		var version int
		if err := tx.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&version); err != nil {
			return err
		}
		if version > 1 {
			return fmt.Errorf("database schema version %d is newer than supported version 1", version)
		}
		if version == 0 {
			if _, err := tx.Exec(ctx, schemaSQL); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES (1)`)
			return err
		}
		return nil
	}); err != nil {
		s.Close()
		return nil, fmt.Errorf("migrate database: %w", err)
	}
	return s, nil
}

// Close rejects new work and waits for in-flight calls before returning.
func (s *Store) Close() {
	s.pool.Close()
}

func storeError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" {
		return fmt.Errorf("%w: related object does not exist", ErrNotFound)
	}
	return err
}

func (s *Store) withConn(ctx context.Context, fn func(*pgx.Conn) error) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	return storeError(fn(conn.Conn()))
}

func (s *Store) transact(ctx context.Context, fn func(pgx.Tx) error) error {
	return s.withConn(ctx, func(conn *pgx.Conn) error {
		tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
		if err != nil {
			return err
		}
		defer func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = tx.Rollback(cleanup)
		}()
		if err := fn(tx); err != nil {
			return err
		}
		return tx.Commit(ctx)
	})
}

type scanner interface{ Scan(...any) error }
type queryer interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func queryAll[T any](ctx context.Context, q queryer, sql string, scan func(scanner) (T, error), args ...any) ([]T, error) {
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]T, 0)
	for rows.Next() {
		item, err := scan(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func scanProject(row scanner) (p Project, err error) {
	err = row.Scan(&p.ID, &p.Name, &p.Description, &p.CreatedAt, &p.UpdatedAt)
	return
}

func scanNote(row scanner) (n Note, err error) {
	err = row.Scan(&n.ID, &n.ProjectID, &n.Title, &n.Markdown, &n.SourceName, &n.Version, &n.Shared, &n.CreatedAt, &n.UpdatedAt)
	return
}

func scanAttachment(row scanner) (a Attachment, err error) {
	err = row.Scan(&a.ID, &a.NoteID, &a.Name, &a.StorageKey, &a.MIME, &a.Size, &a.CreatedAt)
	return
}

func scanShare(row scanner) (link ShareLink, err error) {
	err = row.Scan(&link.ID, &link.NoteID, &link.TokenHash, &link.CreatedAt)
	return
}

func scanKey(row scanner) (key APIKey, err error) {
	err = row.Scan(&key.ID, &key.Name, &key.TokenHash, &key.Scopes, &key.ProjectIDs, &key.NoteIDs,
		&key.CreatedAt, &key.ExpiresAt, &key.RevokedAt, &key.LastUsedAt)
	return
}

func (s *Store) Ping(ctx context.Context) error {
	return s.withConn(ctx, func(conn *pgx.Conn) error { return conn.Ping(ctx) })
}

func (s *Store) Owner(ctx context.Context) (owner Owner, err error) {
	err = s.withConn(ctx, func(conn *pgx.Conn) error {
		return conn.QueryRow(ctx, `SELECT username, password_hash FROM owners WHERE singleton`).Scan(&owner.Username, &owner.PasswordHash)
	})
	return
}

// EnsureOwner is insert-only, including when configuration changes on restart.
func (s *Store) EnsureOwner(ctx context.Context, username, passwordHash string) error {
	return s.withConn(ctx, func(conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, `INSERT INTO owners (singleton, username, password_hash)
			VALUES (true, $1, $2) ON CONFLICT (singleton) DO NOTHING`, username, passwordHash)
		return err
	})
}

func (s *Store) CreateSession(ctx context.Context, session Session) error {
	return s.withConn(ctx, func(conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, `INSERT INTO sessions (token_hash, csrf_token, expires_at) VALUES ($1, $2, $3)`,
			session.TokenHash, session.CSRFToken, session.ExpiresAt)
		return err
	})
}

func (s *Store) Session(ctx context.Context, hash string) (session Session, err error) {
	err = s.withConn(ctx, func(conn *pgx.Conn) error {
		return conn.QueryRow(ctx, `SELECT token_hash, csrf_token, expires_at FROM sessions
			WHERE token_hash = $1 AND expires_at > clock_timestamp()`, hash).
			Scan(&session.TokenHash, &session.CSRFToken, &session.ExpiresAt)
	})
	return
}

// DeleteSession is idempotent so repeated logout requests succeed.
func (s *Store) DeleteSession(ctx context.Context, hash string) error {
	return s.withConn(ctx, func(conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, `DELETE FROM sessions WHERE token_hash = $1`, hash)
		return err
	})
}

func (s *Store) Projects(ctx context.Context) (projects []Project, err error) {
	err = s.withConn(ctx, func(conn *pgx.Conn) error {
		projects, err = queryAll(ctx, conn, `SELECT id, name, description, created_at, updated_at FROM projects ORDER BY lower(name), id`, scanProject)
		return err
	})
	return
}

func (s *Store) Project(ctx context.Context, id string) (project Project, err error) {
	err = s.withConn(ctx, func(conn *pgx.Conn) error {
		project, err = scanProject(conn.QueryRow(ctx, `SELECT id, name, description, created_at, updated_at FROM projects WHERE id = $1`, id))
		return err
	})
	return
}

func (s *Store) CreateProject(ctx context.Context, name, description string) (project Project, err error) {
	err = s.withConn(ctx, func(conn *pgx.Conn) error {
		project, err = scanProject(conn.QueryRow(ctx, `INSERT INTO projects (id, name, description) VALUES ($1, $2, $3)
			RETURNING id, name, description, created_at, updated_at`, NewID(), name, description))
		return err
	})
	return
}

func (s *Store) UpdateProject(ctx context.Context, id, name, description string) error {
	return s.withConn(ctx, func(conn *pgx.Conn) error {
		tag, err := conn.Exec(ctx, `UPDATE projects SET name = $2, description = $3, updated_at = clock_timestamp() WHERE id = $1`, id, name, description)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return err
	})
}

// Structural changes share a lock so project deletion cannot miss newly created
// or moved notes, and moves cannot deadlock on a project's cascading deletion.
func lockStructure(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended(current_schema() || ':conspect:project-structure', 0))`)
	return err
}

func audit(ctx context.Context, tx pgx.Tx, actor Actor, noteID, action string, oldVersion, newVersion int64) error {
	keyID := actor.KeyID
	if actor.Owner {
		keyID = ""
	}
	_, err := tx.Exec(ctx, `INSERT INTO audit_events (id, actor_owner, actor_key_id, note_id, action, old_version, new_version)
		VALUES ($1, $2, NULLIF($3, ''), $4, $5, NULLIF($6::bigint, 0), NULLIF($7::bigint, 0))`,
		NewID(), actor.Owner, keyID, noteID, action, oldVersion, newVersion)
	return err
}

func (s *Store) DeleteProject(ctx context.Context, id string) (assets []Attachment, err error) {
	err = s.transact(ctx, func(tx pgx.Tx) error {
		if err := lockStructure(ctx, tx); err != nil {
			return err
		}
		var projectID string
		if err := tx.QueryRow(ctx, `SELECT id FROM projects WHERE id = $1 FOR UPDATE`, id).Scan(&projectID); err != nil {
			return err
		}
		type versionedID struct {
			id      string
			version int64
		}
		notes, err := queryAll(ctx, tx, `SELECT id, version FROM notes WHERE project_id = $1 ORDER BY id FOR UPDATE`,
			func(row scanner) (n versionedID, err error) { err = row.Scan(&n.id, &n.version); return }, id)
		if err != nil {
			return err
		}
		assets, err = queryAll(ctx, tx, `SELECT a.id, a.note_id, a.name, a.storage_key, a.mime_type, a.size, a.created_at
			FROM attachments a JOIN notes n ON n.id = a.note_id WHERE n.project_id = $1 ORDER BY a.id`, scanAttachment, id)
		if err != nil {
			return err
		}
		for _, n := range notes {
			if err := audit(ctx, tx, Actor{Owner: true}, n.id, "note.delete", n.version, 0); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, `DELETE FROM projects WHERE id = $1`, id)
		return err
	})
	if err != nil {
		return nil, err
	}
	return assets, nil
}

// Notes searches literal, case-insensitive substrings. Unknown sort values use
// modified order; neither user input nor an ORDER BY fragment is interpolated.
func (s *Store) Notes(ctx context.Context, projectID, search, sort string) (notes []Note, err error) {
	err = s.withConn(ctx, func(conn *pgx.Conn) error {
		if projectID != "" {
			var id string
			if err := conn.QueryRow(ctx, `SELECT id FROM projects WHERE id = $1`, projectID).Scan(&id); err != nil {
				return err
			}
		}
		notes, err = queryAll(ctx, conn, `SELECT n.id, n.project_id, n.title, n.markdown, n.source_name, n.version,
			EXISTS (SELECT 1 FROM share_links s WHERE s.note_id = n.id AND s.revoked_at IS NULL), n.created_at, n.updated_at
			FROM notes n WHERE ($1::text = '' OR n.project_id = $1)
			AND ($2::text = '' OR strpos(lower(n.title), lower($2)) > 0 OR strpos(lower(n.markdown), lower($2)) > 0)
			ORDER BY CASE WHEN $3::text = 'title' THEN lower(n.title) END, n.updated_at DESC, n.id`, scanNote, projectID, search, sort)
		return err
	})
	return
}

func (s *Store) Note(ctx context.Context, id string) (note Note, err error) {
	err = s.withConn(ctx, func(conn *pgx.Conn) error {
		note, err = scanNote(conn.QueryRow(ctx, `SELECT n.id, n.project_id, n.title, n.markdown, n.source_name, n.version,
			EXISTS (SELECT 1 FROM share_links s WHERE s.note_id = n.id AND s.revoked_at IS NULL), n.created_at, n.updated_at
			FROM notes n WHERE n.id = $1`, id))
		return err
	})
	return
}

func lockedNote(ctx context.Context, tx pgx.Tx, id string) (Note, error) {
	return scanNote(tx.QueryRow(ctx, `SELECT n.id, n.project_id, n.title, n.markdown, n.source_name, n.version,
		EXISTS (SELECT 1 FROM share_links s WHERE s.note_id = n.id AND s.revoked_at IS NULL), n.created_at, n.updated_at
		FROM notes n WHERE n.id = $1 FOR UPDATE OF n`, id))
}

// writeAs locks the key before any note locks. RevokeAPIKey updates that same row,
// so a revocation either follows a committed write or prevents it. Expiry is
// checked after locking and again immediately before commit, including lock waits.
func (s *Store) writeAs(ctx context.Context, actor Actor, fn func(pgx.Tx, APIKey) error) error {
	if !actor.Owner && actor.KeyID == "" {
		return ErrForbidden
	}
	return s.transact(ctx, func(tx pgx.Tx) error {
		var key APIKey
		if !actor.Owner {
			var err error
			key, err = scanKey(tx.QueryRow(ctx, `SELECT id, name, token_hash, scopes, project_ids, note_ids,
				created_at, expires_at, revoked_at, last_used_at FROM api_keys WHERE id = $1 FOR UPDATE`, actor.KeyID))
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrForbidden
			}
			if err != nil {
				return err
			}
			if err := activeActor(ctx, tx, actor.KeyID); err != nil {
				return err
			}
		}
		if err := fn(tx, key); err != nil {
			return err
		}
		if !actor.Owner {
			return activeActor(ctx, tx, actor.KeyID)
		}
		return nil
	})
}

func activeActor(ctx context.Context, tx pgx.Tx, keyID string) error {
	var active bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM api_keys WHERE id = $1 AND revoked_at IS NULL
		AND (expires_at IS NULL OR expires_at > clock_timestamp()))`, keyID).Scan(&active); err != nil {
		return err
	}
	if !active {
		return ErrForbidden
	}
	return nil
}

func (s *Store) CreateNote(ctx context.Context, input Note, actor Actor) (note Note, err error) {
	if input.ID == "" {
		input.ID = NewID()
	}
	err = s.writeAs(ctx, actor, func(tx pgx.Tx, key APIKey) error {
		if !actor.Owner && !key.AllowsProject(input.ProjectID, "notes:write") {
			return ErrForbidden
		}
		if err := lockStructure(ctx, tx); err != nil {
			return err
		}
		note, err = scanNote(tx.QueryRow(ctx, `INSERT INTO notes (id, project_id, title, markdown, source_name)
			VALUES ($1, $2, $3, $4, $5) RETURNING id, project_id, title, markdown, source_name, version, false, created_at, updated_at`,
			input.ID, input.ProjectID, input.Title, input.Markdown, input.SourceName))
		if err != nil {
			return err
		}
		return audit(ctx, tx, actor, note.ID, "note.create", 0, note.Version)
	})
	if err != nil {
		return Note{}, err
	}
	return note, nil
}

// UpdateNote replaces title, Markdown and source filename, including empty values.
func (s *Store) UpdateNote(ctx context.Context, id, title, markdown, sourceName string, version int64, actor Actor) (note Note, err error) {
	err = s.writeAs(ctx, actor, func(tx pgx.Tx, key APIKey) error {
		current, err := lockedNote(ctx, tx, id)
		if err != nil {
			return err
		}
		if !actor.Owner && !key.AllowsNote(current, "notes:write") {
			return ErrForbidden
		}
		if current.Version != version {
			return ErrConflict
		}
		note, err = scanNote(tx.QueryRow(ctx, `UPDATE notes SET title = $2, markdown = $3, source_name = $4,
			version = version + 1, updated_at = clock_timestamp() WHERE id = $1
			RETURNING id, project_id, title, markdown, source_name, version, $5::boolean, created_at, updated_at`,
			id, title, markdown, sourceName, current.Shared))
		if err != nil {
			return err
		}
		return audit(ctx, tx, actor, id, "note.update", current.Version, note.Version)
	})
	if err != nil {
		return Note{}, err
	}
	return note, nil
}

// SetNoteMetadata is owner-only; the caller authenticates the owner. A no-op
// still checks the expected version but does not manufacture a new version.
func (s *Store) SetNoteMetadata(ctx context.Context, id, title, projectID string, version int64) (note Note, err error) {
	err = s.transact(ctx, func(tx pgx.Tx) error {
		if err := lockStructure(ctx, tx); err != nil {
			return err
		}
		current, err := lockedNote(ctx, tx, id)
		if err != nil {
			return err
		}
		if current.Version != version {
			return ErrConflict
		}
		if current.Title == title && current.ProjectID == projectID {
			note = current
			return nil
		}
		note, err = scanNote(tx.QueryRow(ctx, `UPDATE notes SET title = $2, project_id = $3, version = version + 1,
			updated_at = clock_timestamp() WHERE id = $1
			RETURNING id, project_id, title, markdown, source_name, version, $4::boolean, created_at, updated_at`,
			id, title, projectID, current.Shared))
		if err != nil {
			return err
		}
		return audit(ctx, tx, Actor{Owner: true}, id, "note.metadata", current.Version, note.Version)
	})
	if err != nil {
		return Note{}, err
	}
	return note, nil
}

func (s *Store) DeleteNote(ctx context.Context, id string, version int64) (assets []Attachment, err error) {
	err = s.transact(ctx, func(tx pgx.Tx) error {
		note, err := lockedNote(ctx, tx, id)
		if err != nil {
			return err
		}
		if note.Version != version {
			return ErrConflict
		}
		assets, err = queryAll(ctx, tx, `SELECT id, note_id, name, storage_key, mime_type, size, created_at
			FROM attachments WHERE note_id = $1 ORDER BY id`, scanAttachment, id)
		if err != nil {
			return err
		}
		if err := audit(ctx, tx, Actor{Owner: true}, id, "note.delete", note.Version, 0); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `DELETE FROM notes WHERE id = $1`, id)
		return err
	})
	if err != nil {
		return nil, err
	}
	return assets, nil
}

func (s *Store) Attachments(ctx context.Context, noteID string) (assets []Attachment, err error) {
	err = s.withConn(ctx, func(conn *pgx.Conn) error {
		var id string
		if err := conn.QueryRow(ctx, `SELECT id FROM notes WHERE id = $1`, noteID).Scan(&id); err != nil {
			return err
		}
		assets, err = queryAll(ctx, conn, `SELECT id, note_id, name, storage_key, mime_type, size, created_at
			FROM attachments WHERE note_id = $1 ORDER BY created_at, id`, scanAttachment, noteID)
		return err
	})
	return
}

func (s *Store) Attachment(ctx context.Context, noteID, id string) (asset Attachment, err error) {
	err = s.withConn(ctx, func(conn *pgx.Conn) error {
		asset, err = scanAttachment(conn.QueryRow(ctx, `SELECT id, note_id, name, storage_key, mime_type, size, created_at
			FROM attachments WHERE note_id = $1 AND id = $2`, noteID, id))
		return err
	})
	return
}

// maxStorageBytes is a hard cap on total attachment bytes (zero permits only
// zero-byte files). File validation and filesystem writes belong to the caller.
func (s *Store) CreateAttachment(ctx context.Context, input Attachment, actor Actor, maxStorageBytes int64) (asset Attachment, err error) {
	if input.ID == "" {
		input.ID = NewID()
	}
	if input.Size < 0 {
		return Attachment{}, errors.New("attachment size must not be negative")
	}
	err = s.writeAs(ctx, actor, func(tx pgx.Tx, key APIKey) error {
		note, err := lockedNote(ctx, tx, input.NoteID)
		if err != nil {
			return err
		}
		if !actor.Owner && !key.AllowsNote(note, "attachments:write") {
			return ErrForbidden
		}
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended(current_schema() || ':conspect:attachment-quota', 0))`); err != nil {
			return err
		}
		var fits bool
		// SUM(bigint) is numeric, avoiding overflow near the int64 quota limit.
		if err := tx.QueryRow(ctx, `SELECT COALESCE(SUM(size), 0) + $1::numeric <= $2::numeric FROM attachments`, input.Size, maxStorageBytes).Scan(&fits); err != nil {
			return err
		}
		if !fits {
			return ErrQuota
		}
		asset, err = scanAttachment(tx.QueryRow(ctx, `INSERT INTO attachments (id, note_id, name, storage_key, mime_type, size)
			VALUES ($1, $2, $3, $4, $5, $6) RETURNING id, note_id, name, storage_key, mime_type, size, created_at`,
			input.ID, input.NoteID, input.Name, input.StorageKey, input.MIME, input.Size))
		if err != nil {
			return err
		}
		return audit(ctx, tx, actor, note.ID, "attachment.create", note.Version, note.Version)
	})
	if err != nil {
		return Attachment{}, err
	}
	return asset, nil
}

func (s *Store) DeleteAttachment(ctx context.Context, noteID, id string) (asset Attachment, err error) {
	err = s.transact(ctx, func(tx pgx.Tx) error {
		note, err := lockedNote(ctx, tx, noteID)
		if err != nil {
			return err
		}
		asset, err = scanAttachment(tx.QueryRow(ctx, `DELETE FROM attachments WHERE note_id = $1 AND id = $2
			RETURNING id, note_id, name, storage_key, mime_type, size, created_at`, noteID, id))
		if err != nil {
			return err
		}
		return audit(ctx, tx, Actor{Owner: true}, noteID, "attachment.delete", note.Version, note.Version)
	})
	if err != nil {
		return Attachment{}, err
	}
	return asset, nil
}

func (s *Store) ReplaceShare(ctx context.Context, input ShareLink) (link ShareLink, err error) {
	if input.ID == "" {
		input.ID = NewID()
	}
	err = s.transact(ctx, func(tx pgx.Tx) error {
		note, err := lockedNote(ctx, tx, input.NoteID)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE share_links SET revoked_at = clock_timestamp() WHERE note_id = $1 AND revoked_at IS NULL`, input.NoteID); err != nil {
			return err
		}
		link, err = scanShare(tx.QueryRow(ctx, `INSERT INTO share_links (id, note_id, token_hash) VALUES ($1, $2, $3)
			RETURNING id, note_id, token_hash, created_at`, input.ID, input.NoteID, input.TokenHash))
		if err != nil {
			return err
		}
		return audit(ctx, tx, Actor{Owner: true}, note.ID, "share.replace", note.Version, note.Version)
	})
	if err != nil {
		return ShareLink{}, err
	}
	return link, nil
}

func (s *Store) ActiveShare(ctx context.Context, noteID string) (link ShareLink, err error) {
	err = s.withConn(ctx, func(conn *pgx.Conn) error {
		link, err = scanShare(conn.QueryRow(ctx, `SELECT id, note_id, token_hash, created_at FROM share_links WHERE note_id = $1 AND revoked_at IS NULL`, noteID))
		return err
	})
	return
}

func (s *Store) ShareByHash(ctx context.Context, hash string) (link ShareLink, err error) {
	err = s.withConn(ctx, func(conn *pgx.Conn) error {
		link, err = scanShare(conn.QueryRow(ctx, `SELECT id, note_id, token_hash, created_at FROM share_links WHERE token_hash = $1 AND revoked_at IS NULL`, hash))
		return err
	})
	return
}

// RevokeShare is idempotent for an existing note, including an unshared one.
func (s *Store) RevokeShare(ctx context.Context, noteID string) error {
	return s.transact(ctx, func(tx pgx.Tx) error {
		note, err := lockedNote(ctx, tx, noteID)
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE share_links SET revoked_at = clock_timestamp() WHERE note_id = $1 AND revoked_at IS NULL`, noteID)
		if err != nil || tag.RowsAffected() == 0 {
			return err
		}
		return audit(ctx, tx, Actor{Owner: true}, noteID, "share.revoke", note.Version, note.Version)
	})
}

func (s *Store) APIKeys(ctx context.Context) (keys []APIKey, err error) {
	err = s.withConn(ctx, func(conn *pgx.Conn) error {
		keys, err = queryAll(ctx, conn, `SELECT id, name, token_hash, scopes, project_ids, note_ids,
			created_at, expires_at, revoked_at, last_used_at FROM api_keys ORDER BY created_at DESC, id`, scanKey)
		return err
	})
	return
}

func (s *Store) APIKeyByHash(ctx context.Context, hash string) (key APIKey, err error) {
	err = s.transact(ctx, func(tx pgx.Tx) error {
		var id string
		if err := tx.QueryRow(ctx, `SELECT id FROM api_keys WHERE token_hash = $1 FOR UPDATE`, hash).Scan(&id); err != nil {
			return err
		}
		key, err = scanKey(tx.QueryRow(ctx, `UPDATE api_keys SET last_used_at = clock_timestamp()
			WHERE id = $1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > clock_timestamp())
			RETURNING id, name, token_hash, scopes, project_ids, note_ids, created_at, expires_at, revoked_at, last_used_at`, id))
		return err
	})
	if err != nil {
		return APIKey{}, err
	}
	return key, nil
}

func stringsOrEmpty(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func (s *Store) CreateAPIKey(ctx context.Context, input APIKey) (key APIKey, err error) {
	if input.ID == "" {
		input.ID = NewID()
	}
	err = s.withConn(ctx, func(conn *pgx.Conn) error {
		key, err = scanKey(conn.QueryRow(ctx, `INSERT INTO api_keys (id, name, token_hash, scopes, project_ids, note_ids, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, name, token_hash, scopes, project_ids, note_ids,
			created_at, expires_at, revoked_at, last_used_at`, input.ID, input.Name, input.TokenHash,
			stringsOrEmpty(input.Scopes), stringsOrEmpty(input.ProjectIDs), stringsOrEmpty(input.NoteIDs), input.ExpiresAt))
		return err
	})
	return
}

func (s *Store) RevokeAPIKey(ctx context.Context, id string) error {
	return s.withConn(ctx, func(conn *pgx.Conn) error {
		tag, err := conn.Exec(ctx, `UPDATE api_keys SET revoked_at = COALESCE(revoked_at, clock_timestamp()) WHERE id = $1`, id)
		if err == nil && tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return err
	})
}

// These types are intentionally usable internally with their stored hashes, but
// accidental JSON responses must not leak password or authentication hashes.
func (o Owner) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Username string `json:"username"`
	}{o.Username})
}

func (s Session) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		CSRFToken string    `json:"csrf_token"`
		ExpiresAt time.Time `json:"expires_at"`
	}{s.CSRFToken, s.ExpiresAt})
}

func (s ShareLink) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ID        string    `json:"id"`
		NoteID    string    `json:"note_id"`
		CreatedAt time.Time `json:"created_at"`
	}{s.ID, s.NoteID, s.CreatedAt})
}
