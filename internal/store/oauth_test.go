package store

import (
	"testing"
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
	if version != 2 || baseVersion != 1 || !history {
		t.Fatalf("migration failed: OAuth=%d base=%d history=%v", version, baseVersion, history)
	}
}
