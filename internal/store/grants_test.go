package store

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestAPIKeyResourceGrants(t *testing.T) {
	n := Note{ID: "note", ProjectID: "project"}
	for _, tc := range []struct {
		name          string
		key           APIKey
		project, note bool
	}{
		{"empty", APIKey{}, false, false},
		{"global without scope", APIKey{AllProjects: true}, false, false},
		{"global wrong scope", APIKey{AllProjects: true, Scopes: []string{"attachments:read"}}, false, false},
		{"global", APIKey{AllProjects: true, Scopes: []string{"notes:read"}}, true, true},
		{"explicit project", APIKey{ProjectIDs: []string{"project"}, Scopes: []string{"notes:read"}}, true, true},
		{"explicit note", APIKey{NoteIDs: []string{"note"}, Scopes: []string{"notes:read"}}, false, true},
		{"other resources", APIKey{ProjectIDs: []string{"other"}, NoteIDs: []string{"other"}, Scopes: []string{"notes:read"}}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.key.AllowsProject(n.ProjectID, "notes:read"); got != tc.project {
				t.Fatalf("AllowsProject = %v, want %v", got, tc.project)
			}
			if got := tc.key.AllowsNote(n, "notes:read"); got != tc.note {
				t.Fatalf("AllowsNote = %v, want %v", got, tc.note)
			}
		})
	}
	for _, global := range []bool{false, true} {
		data, err := json.Marshal(APIKey{AllProjects: global})
		if err != nil || !strings.Contains(string(data), `"all_projects":`+map[bool]string{false: "false", true: "true"}[global]) {
			t.Fatalf("explicit all_projects JSON = %s, %v", data, err)
		}
	}
}

func TestPostgresMigrationV1PreservesKeyGrants(t *testing.T) {
	db := newPostgresTestDB(t)
	conn := db.connect(t)
	if _, err := conn.Exec(db.ctx, schemaSQL); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(db.ctx, `CREATE TABLE schema_migrations (
		version integer PRIMARY KEY CHECK (version > 0), applied_at timestamptz NOT NULL DEFAULT clock_timestamp());
		INSERT INTO schema_migrations (version) VALUES (1);
		INSERT INTO api_keys (id, name, token_hash, scopes, project_ids, note_ids, expires_at, revoked_at, last_used_at)
		VALUES ('active', 'old', 'active-hash', '{notes:read,notes:write}', '{old-project}', '{old-note}',
			clock_timestamp() + interval '1 day', NULL, clock_timestamp()),
		('expired', 'old expired', 'expired-hash', '{notes:read}', '{}', '{}', clock_timestamp() - interval '1 day', NULL, NULL),
		('revoked', 'old revoked', 'revoked-hash', '{attachments:read}', '{deleted-project}', '{}', NULL, clock_timestamp(), NULL)`); err != nil {
		t.Fatal(err)
	}
	// Compare all pre-existing columns, including lifecycle timestamps and hashes.
	var before string
	if err := conn.QueryRow(db.ctx, `SELECT jsonb_agg(to_jsonb(k) ORDER BY id)::text FROM api_keys k`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	s := db.open(t)
	_ = db.open(t) // Reopening must not reapply the ALTER or widen any grant.
	var after string
	var version, count int
	if err := conn.QueryRow(db.ctx, `SELECT jsonb_agg(to_jsonb(k) - 'all_projects' ORDER BY id)::text FROM api_keys k`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatalf("migration changed existing key fields:\nbefore %s\nafter %s", before, after)
	}
	if err := conn.QueryRow(db.ctx, `SELECT max(version), count(*) FROM schema_migrations`).Scan(&version, &count); err != nil || version != 2 || count != 2 {
		t.Fatalf("migration versions = %d (%d rows), %v", version, count, err)
	}
	keys, err := s.APIKeys(db.ctx)
	if err != nil || len(keys) != 3 {
		t.Fatalf("migrated keys = %+v, %v", keys, err)
	}
	for _, key := range keys {
		if key.AllProjects || key.AllowsProject("future-project", "notes:read") || key.AllowsNote(Note{ID: "future-note", ProjectID: "future-project"}, "notes:read") {
			t.Fatalf("old key gained global access: %+v", key)
		}
	}
	// The database default also protects inserts that omit the new column.
	var global bool
	if err := conn.QueryRow(db.ctx, `INSERT INTO api_keys (id, name, token_hash) VALUES ('default', 'default', 'default-hash') RETURNING all_projects`).Scan(&global); err != nil || global {
		t.Fatalf("all_projects default = %v, %v", global, err)
	}
}

func TestPostgresAllProjectsIncludesFutureResourcesWithScopes(t *testing.T) {
	db := newPostgresTestDB(t)
	s := db.open(t)
	p := mustProject(t, s, db.ctx, "existing")
	global := mustKey(t, s, db.ctx, APIKey{AllProjects: true, Scopes: []string{"notes:read", "notes:write", "attachments:read", "attachments:write"}})
	restricted := mustKey(t, s, db.ctx, APIKey{ProjectIDs: []string{p.ID}, Scopes: global.Scopes})
	readOnly := mustKey(t, s, db.ctx, APIKey{AllProjects: true, Scopes: []string{"notes:read", "attachments:read"}})
	future := mustProject(t, s, db.ctx, "future")
	n := mustNote(t, s, db.ctx, future.ID, "future note")
	for _, scope := range global.Scopes {
		if !global.AllowsProject(future.ID, scope) || !global.AllowsNote(n, scope) || restricted.AllowsProject(future.ID, scope) || restricted.AllowsNote(n, scope) {
			t.Fatalf("future resource grants incorrect for %s", scope)
		}
	}
	for _, key := range []APIKey{restricted, readOnly} {
		_, err := s.CreateNote(db.ctx, Note{ProjectID: future.ID}, Actor{KeyID: key.ID})
		requireErrorIs(t, err, ErrForbidden)
		_, err = s.UpdateNote(db.ctx, n.ID, "denied", "", "", n.Version, Actor{KeyID: key.ID})
		requireErrorIs(t, err, ErrForbidden)
		_, err = s.CreateAttachment(db.ctx, testAttachment(n.ID, 1), Actor{KeyID: key.ID}, 100)
		requireErrorIs(t, err, ErrForbidden)
	}
	if _, err := s.CreateNote(db.ctx, Note{ProjectID: future.ID}, Actor{KeyID: global.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpdateNote(db.ctx, n.ID, "global write", "", "", n.Version, Actor{KeyID: global.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateAttachment(db.ctx, testAttachment(n.ID, 1), Actor{KeyID: global.ID}, 100); err != nil {
		t.Fatal(err)
	}
	got, err := s.APIKeyByHash(db.ctx, global.TokenHash)
	if err != nil || !got.AllProjects || !got.AllowsNote(n, "notes:read") {
		t.Fatalf("persisted global key = %+v, %v", got, err)
	}
}

func listedKey(t *testing.T, s *Store, db *postgresTestDB, id string) APIKey {
	t.Helper()
	keys, err := s.APIKeys(db.ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range keys {
		if key.ID == id {
			return key
		}
	}
	t.Fatalf("key %s missing", id)
	return APIKey{}
}

func TestPostgresUpdateAPIKeyAccess(t *testing.T) {
	db := newPostgresTestDB(t)
	s := db.open(t)
	other := db.open(t)
	p := mustProject(t, s, db.ctx, "existing")
	p2 := mustProject(t, s, db.ctx, "new access")
	n := mustNote(t, s, db.ctx, p2.ID, "note")
	expires := time.Now().Add(time.Hour).Truncate(time.Microsecond)
	key := mustKey(t, s, db.ctx, APIKey{Name: "same credentials", Scopes: []string{"notes:read", "notes:write", "attachments:write"}, ProjectIDs: []string{p.ID}, ExpiresAt: &expires})
	key, err := s.APIKeyByHash(db.ctx, key.TokenHash)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateAPIKeyAccess(db.ctx, key.ID, true, nil, nil); err != nil {
		t.Fatal(err)
	}
	expected := key
	expected.AllProjects = true
	expected.ProjectIDs, expected.NoteIDs = []string{}, []string{}
	if got := listedKey(t, other, db, key.ID); !reflect.DeepEqual(got, expected) {
		t.Fatalf("update changed non-grant fields: got %+v, want %+v", got, expected)
	}
	authenticated, err := other.APIKeyByHash(db.ctx, key.TokenHash)
	if err != nil || !authenticated.AllProjects || !reflect.DeepEqual(authenticated.Scopes, key.Scopes) {
		t.Fatalf("updated grants not visible: %+v, %v", authenticated, err)
	}
	actor := Actor{KeyID: key.ID}
	n, err = other.UpdateNote(db.ctx, n.ID, "expanded", "", "", n.Version, actor)
	if err != nil {
		t.Fatal(err)
	}
	_, err = other.UpdateNote(db.ctx, n.ID, "stale ETag", "", "", n.Version-1, actor)
	requireErrorIs(t, err, ErrConflict)
	if err := s.UpdateAPIKeyAccess(db.ctx, key.ID, false, []string{p.ID}, nil); err != nil {
		t.Fatal(err)
	}
	// Even a previously authenticated actor must use the narrowed persisted grants.
	_, err = other.UpdateNote(db.ctx, n.ID, "denied", "", "", n.Version, actor)
	requireErrorIs(t, err, ErrForbidden)
	_, err = other.CreateNote(db.ctx, Note{ProjectID: p2.ID}, actor)
	requireErrorIs(t, err, ErrForbidden)
	_, err = other.CreateAttachment(db.ctx, testAttachment(n.ID, 1), actor, 100)
	requireErrorIs(t, err, ErrForbidden)
	if err := s.UpdateAPIKeyAccess(db.ctx, key.ID, false, nil, []string{n.ID}); err != nil {
		t.Fatal(err)
	}
	got, err := other.APIKeyByHash(db.ctx, key.TokenHash)
	if err != nil || got.AllProjects || !got.AllowsNote(n, "notes:write") || got.AllowsProject(p2.ID, "notes:write") {
		t.Fatalf("explicit note update = %+v, %v", got, err)
	}
	if _, err := other.UpdateNote(db.ctx, n.ID, "explicit note", "", "", n.Version, actor); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateAPIKeyAccess(db.ctx, key.ID, false, nil, nil); err != nil {
		t.Fatal(err)
	}
	got, err = other.APIKeyByHash(db.ctx, key.TokenHash)
	if err != nil || got.AllProjects || len(got.ProjectIDs)+len(got.NoteIDs) != 0 || got.AllowsNote(n, "notes:read") {
		t.Fatalf("empty restricted grants = %+v, %v", got, err)
	}
}

func TestPostgresUpdateAPIKeyAccessRejectsWithoutMutation(t *testing.T) {
	db := newPostgresTestDB(t)
	s := db.open(t)
	p := mustProject(t, s, db.ctx, "A")
	n := mustNote(t, s, db.ctx, p.ID, "A")
	key := mustKey(t, s, db.ctx, APIKey{Scopes: []string{"notes:read"}, ProjectIDs: []string{p.ID}})
	for _, global := range []bool{false, true} {
		for _, ids := range []struct{ projects, notes []string }{
			{[]string{p.ID, "missing"}, []string{n.ID}},
			{[]string{p.ID}, []string{n.ID, "missing"}},
		} {
			before := listedKey(t, s, db, key.ID)
			requireErrorIs(t, s.UpdateAPIKeyAccess(db.ctx, key.ID, global, ids.projects, ids.notes), ErrNotFound)
			if after := listedKey(t, s, db, key.ID); !reflect.DeepEqual(before, after) {
				t.Fatalf("invalid resources mutated key: before %+v, after %+v", before, after)
			}
		}
	}
	past := time.Now().Add(-time.Minute)
	expired := mustKey(t, s, db.ctx, APIKey{Scopes: key.Scopes, ProjectIDs: key.ProjectIDs, ExpiresAt: &past})
	if err := s.RevokeAPIKey(db.ctx, key.ID); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []APIKey{key, expired} {
		before := listedKey(t, s, db, invalid.ID)
		requireErrorIs(t, s.UpdateAPIKeyAccess(db.ctx, invalid.ID, true, nil, nil), ErrForbidden)
		if after := listedKey(t, s, db, invalid.ID); !reflect.DeepEqual(before, after) {
			t.Fatalf("inactive key mutated: before %+v, after %+v", before, after)
		}
		_, err := s.APIKeyByHash(db.ctx, invalid.TokenHash)
		requireErrorIs(t, err, ErrNotFound)
	}
	requireErrorIs(t, s.UpdateAPIKeyAccess(db.ctx, "missing", true, nil, nil), ErrNotFound)
}

func TestPostgresAccessNarrowingRechecksWaitingWrites(t *testing.T) {
	for _, operation := range []string{"create", "update", "attachment"} {
		t.Run(operation, func(t *testing.T) {
			db := newPostgresTestDB(t)
			s := db.open(t)
			p := mustProject(t, s, db.ctx, "A")
			n := mustNote(t, s, db.ctx, p.ID, "A")
			key := mustKey(t, s, db.ctx, APIKey{AllProjects: true, Scopes: []string{"notes:write", "attachments:write"}})
			tx := beginTestTx(t, db)
			if err := lockStructure(db.ctx, tx); err != nil {
				t.Fatal(err)
			}
			update := make(chan error, 1)
			go func() { update <- s.UpdateAPIKeyAccess(db.ctx, key.ID, false, nil, nil) }()
			observer := db.connect(t)
			waitForBlocked(t, db, observer, 1)
			write := make(chan error, 1)
			go func() {
				var err error
				switch operation {
				case "create":
					_, err = s.CreateNote(db.ctx, Note{ProjectID: p.ID}, Actor{KeyID: key.ID})
				case "update":
					_, err = s.UpdateNote(db.ctx, n.ID, "denied", "", "", n.Version, Actor{KeyID: key.ID})
				case "attachment":
					_, err = s.CreateAttachment(db.ctx, testAttachment(n.ID, 1), Actor{KeyID: key.ID}, 100)
				}
				write <- err
			}()
			waitForBlocked(t, db, observer, 2)
			if err := tx.Commit(db.ctx); err != nil {
				t.Fatal(err)
			}
			if err := <-update; err != nil {
				t.Fatal(err)
			}
			requireErrorIs(t, <-write, ErrForbidden)
			var count int
			if err := observer.QueryRow(db.ctx, `SELECT count(*) FROM audit_events WHERE actor_key_id = $1`, key.ID).Scan(&count); err != nil || count != 0 {
				t.Fatalf("denied writes left audit events: %d, %v", count, err)
			}
		})
	}
}

func TestPostgresAccessUpdateRevocationAndExpiryOrdering(t *testing.T) {
	t.Run("update holds key until commit before revocation", func(t *testing.T) {
		db := newPostgresTestDB(t)
		s := db.open(t)
		other := db.open(t)
		key := mustKey(t, s, db.ctx, APIKey{Scopes: []string{"notes:read"}})
		tx := beginTestTx(t, db)
		if err := lockStructure(db.ctx, tx); err != nil {
			t.Fatal(err)
		}
		update := make(chan error, 1)
		go func() { update <- s.UpdateAPIKeyAccess(db.ctx, key.ID, true, nil, nil) }()
		observer := db.connect(t)
		waitForBlocked(t, db, observer, 1)
		revoke := make(chan error, 1)
		go func() { revoke <- other.RevokeAPIKey(db.ctx, key.ID) }()
		waitForBlocked(t, db, observer, 2)
		if err := tx.Commit(db.ctx); err != nil {
			t.Fatal(err)
		}
		if err := <-update; err != nil {
			t.Fatal(err)
		}
		if err := <-revoke; err != nil {
			t.Fatal(err)
		}
		got := listedKey(t, s, db, key.ID)
		if !got.AllProjects || got.RevokedAt == nil {
			t.Fatalf("grant update/revocation ordering = %+v", got)
		}
		requireErrorIs(t, s.UpdateAPIKeyAccess(db.ctx, key.ID, false, nil, nil), ErrForbidden)
		_, err := s.APIKeyByHash(db.ctx, key.TokenHash)
		requireErrorIs(t, err, ErrNotFound)
	})
	t.Run("revocation wins before key lock", func(t *testing.T) {
		db := newPostgresTestDB(t)
		s := db.open(t)
		key := mustKey(t, s, db.ctx, APIKey{Scopes: []string{"notes:read"}})
		tx := beginTestTx(t, db)
		if _, err := tx.Exec(db.ctx, `UPDATE api_keys SET revoked_at = clock_timestamp() WHERE id = $1`, key.ID); err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() { result <- s.UpdateAPIKeyAccess(db.ctx, key.ID, true, nil, nil) }()
		waitForBlocked(t, db, db.connect(t), 1)
		if err := tx.Commit(db.ctx); err != nil {
			t.Fatal(err)
		}
		requireErrorIs(t, <-result, ErrForbidden)
		got := listedKey(t, s, db, key.ID)
		if got.AllProjects || got.RevokedAt == nil {
			t.Fatalf("revoked key expanded or resurrected: %+v", got)
		}
	})
	t.Run("expiry during structure wait rolls back", func(t *testing.T) {
		db := newPostgresTestDB(t)
		s := db.open(t)
		expires := time.Now().Add(2 * time.Second)
		key := mustKey(t, s, db.ctx, APIKey{Scopes: []string{"notes:read"}, ExpiresAt: &expires})
		tx := beginTestTx(t, db)
		if err := lockStructure(db.ctx, tx); err != nil {
			t.Fatal(err)
		}
		result := make(chan error, 1)
		go func() { result <- s.UpdateAPIKeyAccess(db.ctx, key.ID, true, nil, nil) }()
		observer := db.connect(t)
		waitForBlocked(t, db, observer, 1)
		if _, err := observer.Exec(db.ctx, `SELECT pg_sleep(GREATEST(0, EXTRACT(EPOCH FROM ($1::timestamptz - clock_timestamp()))) + 0.02)`, key.ExpiresAt); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(db.ctx); err != nil {
			t.Fatal(err)
		}
		requireErrorIs(t, <-result, ErrForbidden)
		if got := listedKey(t, s, db, key.ID); !reflect.DeepEqual(got, key) {
			t.Fatalf("expired update mutated key: %+v, want %+v", got, key)
		}
	})
}

func TestPostgresAccessUpdateCoordinatesStructure(t *testing.T) {
	for _, operation := range []string{"delete project", "delete note", "move note"} {
		t.Run(operation, func(t *testing.T) {
			db := newPostgresTestDB(t)
			s := db.open(t)
			p := mustProject(t, s, db.ctx, "A")
			p2 := mustProject(t, s, db.ctx, "B")
			n := mustNote(t, s, db.ctx, p.ID, "A")
			key := mustKey(t, s, db.ctx, APIKey{Scopes: []string{"notes:write"}})
			tx := beginTestTx(t, db)
			if err := lockStructure(db.ctx, tx); err != nil {
				t.Fatal(err)
			}
			result := make(chan error, 1)
			go func() { result <- s.UpdateAPIKeyAccess(db.ctx, key.ID, false, []string{p.ID}, []string{n.ID}) }()
			waitForBlocked(t, db, db.connect(t), 1)
			switch operation {
			case "delete project":
				if _, err := tx.Exec(db.ctx, `DELETE FROM projects WHERE id = $1`, p.ID); err != nil {
					t.Fatal(err)
				}
			case "delete note":
				if _, err := tx.Exec(db.ctx, `DELETE FROM notes WHERE id = $1`, n.ID); err != nil {
					t.Fatal(err)
				}
			case "move note":
				if _, err := tx.Exec(db.ctx, `UPDATE notes SET project_id = $2, version = version + 1 WHERE id = $1`, n.ID, p2.ID); err != nil {
					t.Fatal(err)
				}
			}
			if err := tx.Commit(db.ctx); err != nil {
				t.Fatal(err)
			}
			if operation == "move note" {
				if err := <-result; err != nil {
					t.Fatal(err)
				}
				got, err := s.Note(db.ctx, n.ID)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := s.UpdateNote(db.ctx, got.ID, "explicit note survives move", "", "", got.Version, Actor{KeyID: key.ID}); err != nil {
					t.Fatal(err)
				}
			} else {
				requireErrorIs(t, <-result, ErrNotFound)
				if got := listedKey(t, s, db, key.ID); !reflect.DeepEqual(got, key) {
					t.Fatalf("deleted resource update mutated key: %+v", got)
				}
			}
		})
	}
}
