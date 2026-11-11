package store

import (
	"context"
	_ "embed"
	"fmt"

	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
)

//go:embed oauth_schema.sql
var oauthSchemaSQL string

// OAuthRepository is separate from Repository so existing repositories and mocks
// need not implement OAuth. Call InitOAuth after Open before using these methods.
type OAuthRepository interface {
	InitOAuth(ctx context.Context) error
	CreateOAuthClient(ctx context.Context, client OAuthClient) (OAuthClient, error)
	OAuthClient(ctx context.Context, id string) (OAuthClient, error)
	CreateOAuthGrant(ctx context.Context, grant OAuthGrant, key APIKey) error
	ExchangeOAuthCode(ctx context.Context, codeHash, clientID, redirectURI, resource, challenge, accessHash, refreshHash string, accessExpires, refreshExpires time.Time) (OAuthGrant, error)
	RefreshOAuthGrant(ctx context.Context, refreshHash, clientID, resource, accessHash, newRefreshHash, requestedScope string, accessExpires, refreshExpires time.Time) (OAuthGrant, error)
	OAuthGrantByAccess(ctx context.Context, hash, resource string) (OAuthGrant, error)
	RevokeOAuthToken(ctx context.Context, hash, clientID string) error
}

var _ OAuthRepository = (*Store)(nil)

type OAuthClient struct {
	ID           string
	Name         string
	SecretHash   string `json:"-"`
	AuthMethod   string
	RedirectURIs []string
	CreatedAt    time.Time
}

type OAuthGrant struct {
	ID               string
	ClientID         string
	KeyID            string
	Resource         string
	Scope            string
	RedirectURI      string
	CodeHash         string `json:"-"`
	CodeChallenge    string
	AccessHash       string `json:"-"`
	RefreshHash      string `json:"-"`
	CodeExpiresAt    time.Time
	AccessExpiresAt  time.Time
	RefreshExpiresAt time.Time
}

// InitOAuth versions OAuth tables independently and leaves the current base
// schema_migrations version unchanged.
func (s *Store) InitOAuth(ctx context.Context) error {
	return s.transact(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended(current_schema() || ':conspect:oauth-migrations', 0))`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS oauth_schema_migrations (
			version integer PRIMARY KEY CHECK (version > 0),
			applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
		)`); err != nil {
			return err
		}
		var version int
		if err := tx.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) FROM oauth_schema_migrations`).Scan(&version); err != nil {
			return err
		}
		if version > 2 {
			return fmt.Errorf("OAuth schema version %d is newer than supported version 2", version)
		}
		if version < 2 {
			if _, err := tx.Exec(ctx, oauthSchemaSQL); err != nil {
				return err
			}
			if version == 0 {
				if _, err := tx.Exec(ctx, `INSERT INTO oauth_schema_migrations (version) VALUES (1)`); err != nil {
					return err
				}
			}
			// Version 2 adds consumed refresh-token history to installations that
			// already initialized the original OAuth tables. All DDL is additive.
			_, err := tx.Exec(ctx, `INSERT INTO oauth_schema_migrations (version) VALUES (2)`)
			return err
		}
		return nil
	})
}

func scanOAuthClient(row scanner) (client OAuthClient, err error) {
	err = row.Scan(&client.ID, &client.Name, &client.SecretHash, &client.AuthMethod, &client.RedirectURIs, &client.CreatedAt)
	return
}

const oauthGrantColumns = `g.id, g.client_id, g.key_id, g.resource, g.scope, g.redirect_uri,
	g.code_hash, g.code_challenge, g.access_hash, g.refresh_hash,
	g.code_expires_at, g.access_expires_at, g.refresh_expires_at`

func scanOAuthGrant(row scanner) (grant OAuthGrant, err error) {
	var accessExpires, refreshExpires *time.Time
	err = row.Scan(&grant.ID, &grant.ClientID, &grant.KeyID, &grant.Resource, &grant.Scope, &grant.RedirectURI,
		&grant.CodeHash, &grant.CodeChallenge, &grant.AccessHash, &grant.RefreshHash,
		&grant.CodeExpiresAt, &accessExpires, &refreshExpires)
	if accessExpires != nil {
		grant.AccessExpiresAt = *accessExpires
	}
	if refreshExpires != nil {
		grant.RefreshExpiresAt = *refreshExpires
	}
	return
}

func (s *Store) CreateOAuthClient(ctx context.Context, input OAuthClient) (OAuthClient, error) {
	if input.ID == "" {
		input.ID = NewID()
	}
	// PostgreSQL bounds the total array size; bound each URI here as well.
	for _, uri := range input.RedirectURIs {
		if uri == "" || utf8.RuneCountInString(uri) > 2048 {
			return OAuthClient{}, fmt.Errorf("%w: invalid OAuth redirect URI length", ErrForbidden)
		}
	}
	var client OAuthClient
	err := s.transact(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended(current_schema() || ':conspect:oauth-clients', 0))`); err != nil {
			return err
		}
		var count int
		if err := tx.QueryRow(ctx, `SELECT COUNT(*) FROM oauth_clients`).Scan(&count); err != nil {
			return err
		}
		if count >= 500 {
			return ErrQuota
		}
		var err error
		client, err = scanOAuthClient(tx.QueryRow(ctx, `INSERT INTO oauth_clients (id, name, secret_hash, auth_method, redirect_uris)
			VALUES ($1, $2, $3, $4, $5) RETURNING id, name, secret_hash, auth_method, redirect_uris, created_at`,
			input.ID, input.Name, input.SecretHash, input.AuthMethod, stringsOrEmpty(input.RedirectURIs)))
		return err
	})
	if err != nil {
		return OAuthClient{}, err
	}
	return client, nil
}

func (s *Store) OAuthClient(ctx context.Context, id string) (OAuthClient, error) {
	var client OAuthClient
	err := s.withConn(ctx, func(conn *pgx.Conn) error {
		var err error
		client, err = scanOAuthClient(conn.QueryRow(ctx, `SELECT id, name, secret_hash, auth_method, redirect_uris, created_at
			FROM oauth_clients WHERE id = $1`, id))
		return err
	})
	if err != nil {
		return OAuthClient{}, err
	}
	return client, nil
}

func validateOAuthKey(key APIKey) error {
	if len(key.Scopes) == 0 || len(key.Scopes) > 4 || (!key.AllProjects && len(key.ProjectIDs)+len(key.NoteIDs) == 0) || len(key.ProjectIDs)+len(key.NoteIDs) > 256 {
		return fmt.Errorf("%w: invalid OAuth key scopes or resource count", ErrForbidden)
	}
	for _, scope := range key.Scopes {
		switch scope {
		case "notes:read", "notes:write", "attachments:read", "attachments:write":
		default:
			return fmt.Errorf("%w: unknown OAuth key scope", ErrForbidden)
		}
	}
	if key.TokenHash == "" || key.RevokedAt != nil || (key.ExpiresAt != nil && !key.ExpiresAt.After(time.Now())) {
		return fmt.Errorf("%w: OAuth key must have a hash and be active", ErrForbidden)
	}
	return nil
}

func (s *Store) CreateOAuthGrant(ctx context.Context, grant OAuthGrant, key APIKey) error {
	if err := validateOAuthKey(key); err != nil {
		return err
	}
	if key.ID == "" {
		key.ID = grant.KeyID
		if key.ID == "" {
			key.ID = NewID()
		}
	}
	if grant.KeyID == "" {
		grant.KeyID = key.ID
	}
	if grant.KeyID != key.ID || grant.CodeHash == "" || grant.CodeExpiresAt.IsZero() {
		return fmt.Errorf("%w: invalid OAuth grant key or code", ErrForbidden)
	}
	if grant.ID == "" {
		grant.ID = NewID()
	}
	return s.transact(ctx, func(tx pgx.Tx) error {
		// Coordinate with project deletion and note moves while checking the
		// selected resources. api_keys uses arrays rather than foreign keys.
		if err := lockKeyResources(ctx, tx, key.ProjectIDs, key.NoteIDs); err != nil {
			return err
		}
		// Keep this INSERT identical to CreateAPIKey, on this transaction's
		// connection: calling CreateAPIKey here would commit independently.
		if _, err := tx.Exec(ctx, `INSERT INTO api_keys (id, name, token_hash, scopes, all_projects, project_ids, note_ids, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, key.ID, key.Name, key.TokenHash,
			stringsOrEmpty(key.Scopes), key.AllProjects, stringsOrEmpty(key.ProjectIDs), stringsOrEmpty(key.NoteIDs), key.ExpiresAt); err != nil {
			return err
		}
		// Caller-supplied access/refresh credentials and expiries are ignored:
		// only a successful code exchange can activate the grant.
		var id string
		return tx.QueryRow(ctx, `INSERT INTO oauth_grants (id, client_id, key_id, resource, scope, redirect_uri,
			code_hash, code_challenge, code_expires_at)
			SELECT $1, c.id, $3, $4, $5, $6, $7, $8, $9 FROM oauth_clients c
			WHERE c.id = $2 AND $6 = ANY(c.redirect_uris) RETURNING id`,
			grant.ID, grant.ClientID, grant.KeyID, grant.Resource, grant.Scope, grant.RedirectURI,
			grant.CodeHash, grant.CodeChallenge, grant.CodeExpiresAt).Scan(&id)
	})
}

// All token operations lock the API key before touching the grant. This shares
// the lock used by RevokeAPIKey and API writes, and avoids key/grant deadlocks.
// predicate is always an internal SQL literal, never caller-provided SQL.
func lockOAuthGrantKey(ctx context.Context, tx pgx.Tx, predicate string, args ...any) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `SELECT k.id FROM api_keys k JOIN oauth_grants g ON g.key_id = k.id
		WHERE `+predicate+` FOR UPDATE OF k`, args...).Scan(&id)
	return id, err
}

const oauthActiveKey = `EXISTS (SELECT 1 FROM api_keys k WHERE k.id = g.key_id
	AND k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at > clock_timestamp()))`

// challenge is the caller-verified PKCE challenge (not the raw verifier).
func (s *Store) ExchangeOAuthCode(ctx context.Context, codeHash, clientID, redirectURI, resource, challenge, accessHash, refreshHash string, accessExpires, refreshExpires time.Time) (OAuthGrant, error) {
	if codeHash == "" || accessHash == "" || refreshHash == "" || accessHash == refreshHash || accessHash == codeHash || refreshHash == codeHash {
		return OAuthGrant{}, ErrNotFound
	}
	var grant OAuthGrant
	err := s.transact(ctx, func(tx pgx.Tx) error {
		if _, err := lockOAuthGrantKey(ctx, tx, `g.code_hash = $1 AND g.client_id = $2`, codeHash, clientID); err != nil {
			return err
		}
		var err error
		grant, err = scanOAuthGrant(tx.QueryRow(ctx, `UPDATE oauth_grants g SET code_hash = '',
			access_hash = $6, refresh_hash = $7, access_expires_at = $8, refresh_expires_at = $9
			WHERE g.code_hash = $1 AND g.client_id = $2 AND g.redirect_uri = $3 AND g.resource = $4
			AND g.code_challenge = $5 AND g.code_expires_at > clock_timestamp()
			AND $8 > clock_timestamp() AND $9 > clock_timestamp() AND `+oauthActiveKey+`
			RETURNING `+oauthGrantColumns, codeHash, clientID, redirectURI, resource, challenge,
			accessHash, refreshHash, accessExpires, refreshExpires))
		return err
	})
	if err != nil {
		return OAuthGrant{}, err
	}
	return grant, nil
}

func (s *Store) RefreshOAuthGrant(ctx context.Context, refreshHash, clientID, resource, accessHash, newRefreshHash, requestedScope string, accessExpires, refreshExpires time.Time) (OAuthGrant, error) {
	if refreshHash == "" || accessHash == "" || newRefreshHash == "" || newRefreshHash == refreshHash || accessHash == refreshHash || accessHash == newRefreshHash {
		return OAuthGrant{}, ErrNotFound
	}
	var grant OAuthGrant
	reused := false
	err := s.transact(ctx, func(tx pgx.Tx) error {
		keyID, err := lockOAuthGrantKey(ctx, tx, `(g.refresh_hash = $1 OR EXISTS (
			SELECT 1 FROM oauth_refresh_history h WHERE h.grant_id = g.id AND h.token_hash = $1
		)) AND g.client_id = $2`, refreshHash, clientID)
		if err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM oauth_refresh_history h
			JOIN oauth_grants g ON g.id = h.grant_id WHERE h.token_hash = $1 AND g.key_id = $2)`, refreshHash, keyID).Scan(&reused); err != nil {
			return err
		}
		if reused {
			if _, err := tx.Exec(ctx, `UPDATE api_keys SET revoked_at = COALESCE(revoked_at, clock_timestamp()) WHERE id = $1`, keyID); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `UPDATE oauth_grants SET code_hash = '', access_hash = '', refresh_hash = '',
				access_expires_at = NULL, refresh_expires_at = NULL WHERE key_id = $1`, keyID)
			return err // Commit revocation before returning invalid_grant outside the transaction.
		}
		if _, err := tx.Exec(ctx, `INSERT INTO oauth_refresh_history (token_hash, grant_id, expires_at)
			SELECT refresh_hash, id, refresh_expires_at FROM oauth_grants g WHERE key_id = $1
			AND refresh_hash = $2 AND resource = $3 AND refresh_expires_at > clock_timestamp() AND `+oauthActiveKey,
			keyID, refreshHash, resource); err != nil {
			return err
		}
		grant, err = scanOAuthGrant(tx.QueryRow(ctx, `UPDATE oauth_grants g SET access_hash = $4,
			refresh_hash = $5, access_expires_at = $6, refresh_expires_at = $7
			WHERE g.refresh_hash = $1 AND g.client_id = $2 AND g.resource = $3
			AND g.refresh_expires_at > clock_timestamp()
			AND $6 > clock_timestamp() AND $7 > clock_timestamp()
			AND ($8 = '' OR (string_to_array(g.scope, ' ') @> string_to_array($8, ' ')
			AND string_to_array($8, ' ') @> string_to_array(g.scope, ' '))) AND `+oauthActiveKey+`
			RETURNING `+oauthGrantColumns, refreshHash, clientID, resource, accessHash, newRefreshHash, accessExpires, refreshExpires, requestedScope))
		return err
	})
	if err != nil {
		return OAuthGrant{}, err
	}
	if reused {
		return OAuthGrant{}, ErrNotFound
	}
	return grant, nil
}

func (s *Store) OAuthGrantByAccess(ctx context.Context, hash, resource string) (OAuthGrant, error) {
	if hash == "" {
		return OAuthGrant{}, ErrNotFound
	}
	var grant OAuthGrant
	err := s.transact(ctx, func(tx pgx.Tx) error {
		if _, err := lockOAuthGrantKey(ctx, tx, `g.access_hash = $1 AND g.resource = $2`, hash, resource); err != nil {
			return err
		}
		var err error
		grant, err = scanOAuthGrant(tx.QueryRow(ctx, `SELECT `+oauthGrantColumns+` FROM oauth_grants g
			WHERE g.access_hash = $1 AND g.resource = $2 AND g.access_expires_at > clock_timestamp()
			AND `+oauthActiveKey, hash, resource))
		return err
	})
	if err != nil {
		return OAuthGrant{}, err
	}
	return grant, nil
}

func (s *Store) RevokeOAuthToken(ctx context.Context, hash, clientID string) error {
	if hash == "" {
		return nil
	}
	return s.transact(ctx, func(tx pgx.Tx) error {
		// A hash may appear in different token columns; revoke every matching
		// grant rather than relying on cross-column uniqueness.
		rows, err := tx.Query(ctx, `SELECT k.id FROM api_keys k JOIN oauth_grants g ON g.key_id = k.id
			WHERE g.client_id = $2 AND (g.access_hash = $1 OR g.refresh_hash = $1)
			ORDER BY k.id FOR UPDATE OF k`, hash, clientID)
		if err != nil {
			return err
		}
		ids := make([]string, 0)
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, id := range ids {
			// Recheck hashes after acquiring the key lock: a concurrent refresh
			// may already have rotated this token while we waited.
			tag, err := tx.Exec(ctx, `UPDATE oauth_grants SET code_hash = '', access_hash = '', refresh_hash = '',
				access_expires_at = NULL, refresh_expires_at = NULL
				WHERE key_id = $1 AND client_id = $3 AND (access_hash = $2 OR refresh_hash = $2)`, id, hash, clientID)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 0 {
				if _, err := tx.Exec(ctx, `UPDATE api_keys SET revoked_at = COALESCE(revoked_at, clock_timestamp()) WHERE id = $1`, id); err != nil {
					return err
				}
			}
		}
		return nil
	})
}
