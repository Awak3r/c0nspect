package store

import (
	"testing"
	"time"
)

func TestOAuthMigrationUpgrade(t *testing.T) {
	db := newPostgresTestDB(t)
	s := db.open(t)
	if err := s.InitOAuth(db.ctx); err != nil {
		t.Fatal(err)
	}
	conn := db.connect(t)
	// Simulate a persisted OAuth-v1 installation from before replay history.
	if _, err := conn.Exec(db.ctx, `DROP TABLE oauth_refresh_history; DELETE FROM oauth_schema_migrations WHERE version = 2`); err != nil {
		t.Fatal(err)
	}
	if err := s.InitOAuth(db.ctx); err != nil {
		t.Fatal(err)
	}
	var version, baseVersion int
	var history bool
	if err := conn.QueryRow(db.ctx, `SELECT (SELECT max(version) FROM oauth_schema_migrations),
		(SELECT max(version) FROM schema_migrations), to_regclass('oauth_refresh_history') IS NOT NULL`).Scan(&version, &baseVersion, &history); err != nil {
		t.Fatal(err)
	}
	if version != 2 || baseVersion != 2 || !history {
		t.Fatalf("migration failed: OAuth=%d base=%d history=%v", version, baseVersion, history)
	}
}

func TestValidateOAuthKeyAllProjects(t *testing.T) {
	for _, tc := range []struct {
		name            string
		global          bool
		projects, notes int
		valid           bool
	}{
		{"restricted empty", false, 0, 0, false},
		{"global empty", true, 0, 0, true},
		{"restricted project", false, 1, 0, true},
		{"restricted note", false, 0, 1, true},
		{"restricted limit", false, 128, 128, true},
		{"global limit", true, 128, 128, true},
		{"restricted over limit", false, 128, 129, false},
		{"global over limit", true, 128, 129, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			key := APIKey{TokenHash: "hash", Scopes: []string{"notes:read"}, AllProjects: tc.global,
				ProjectIDs: make([]string, tc.projects), NoteIDs: make([]string, tc.notes)}
			err := validateOAuthKey(key)
			if tc.valid && err != nil {
				t.Fatal(err)
			}
			if !tc.valid {
				requireErrorIs(t, err, ErrForbidden)
			}
		})
	}
	past := time.Now().Add(-time.Minute)
	for _, key := range []APIKey{
		{TokenHash: "hash", AllProjects: true},
		{TokenHash: "hash", AllProjects: true, Scopes: []string{"unknown"}},
		{AllProjects: true, Scopes: []string{"notes:read"}},
		{TokenHash: "hash", AllProjects: true, Scopes: []string{"notes:read"}, ExpiresAt: &past},
		{TokenHash: "hash", AllProjects: true, Scopes: []string{"notes:read"}, RevokedAt: &past},
	} {
		requireErrorIs(t, validateOAuthKey(key), ErrForbidden)
	}
}

func TestOAuthGrantPersistsAllProjects(t *testing.T) {
	db := newPostgresTestDB(t)
	s := db.open(t)
	if err := s.InitOAuth(db.ctx); err != nil {
		t.Fatal(err)
	}
	client, err := s.CreateOAuthClient(db.ctx, OAuthClient{Name: "test", AuthMethod: "none", RedirectURIs: []string{"https://client.example/callback"}})
	if err != nil {
		t.Fatal(err)
	}
	p := mustProject(t, s, db.ctx, "existing")
	for _, global := range []bool{false, true} {
		key := APIKey{ID: NewID(), Name: "OAuth", TokenHash: NewID(), Scopes: []string{"notes:read", "notes:write"}, AllProjects: global}
		if !global {
			key.ProjectIDs = []string{p.ID}
		}
		grant := OAuthGrant{ClientID: client.ID, KeyID: key.ID, Resource: "https://server.example/mcp", Scope: "mcp",
			RedirectURI: client.RedirectURIs[0], CodeHash: NewID(), CodeChallenge: "challenge", CodeExpiresAt: time.Now().Add(time.Minute)}
		if err := s.CreateOAuthGrant(db.ctx, grant, key); err != nil {
			t.Fatal(err)
		}
		got, err := s.APIKeyByHash(db.ctx, key.TokenHash)
		if err != nil || got.AllProjects != global || got.ID != key.ID || len(got.ProjectIDs) != len(key.ProjectIDs) {
			t.Fatalf("OAuth key grants = %+v, %v", got, err)
		}
		future := mustProject(t, s, db.ctx, "future")
		n := mustNote(t, s, db.ctx, future.ID, "future note")
		if got.AllowsProject(future.ID, "notes:read") != global || got.AllowsNote(n, "notes:read") != global || got.AllowsNote(n, "attachments:read") {
			t.Fatalf("OAuth key future grants or scopes incorrect: %+v", got)
		}
		if global {
			if _, err := s.CreateNote(db.ctx, Note{ProjectID: future.ID}, Actor{KeyID: key.ID}); err != nil {
				t.Fatal(err)
			}
		}
	}
}
