CREATE TABLE IF NOT EXISTS oauth_clients (
    id text PRIMARY KEY CHECK (char_length(id) BETWEEN 1 AND 256),
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 300),
    secret_hash text NOT NULL DEFAULT '' CHECK (char_length(secret_hash) <= 512),
    auth_method text NOT NULL CHECK (char_length(auth_method) BETWEEN 1 AND 64),
    redirect_uris text[] NOT NULL CHECK (
        array_ndims(redirect_uris) = 1 AND cardinality(redirect_uris) BETWEEN 1 AND 32
        AND array_position(redirect_uris, NULL) IS NULL
        AND NOT ('' = ANY(redirect_uris))
        AND octet_length(array_to_string(redirect_uris, ',')) <= 65536
    ),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS oauth_grants (
    id text PRIMARY KEY CHECK (char_length(id) BETWEEN 1 AND 256),
    client_id text NOT NULL REFERENCES oauth_clients (id),
    key_id text NOT NULL UNIQUE REFERENCES api_keys (id) ON DELETE CASCADE,
    resource text NOT NULL CHECK (char_length(resource) BETWEEN 1 AND 2048),
    scope text NOT NULL CHECK (char_length(scope) BETWEEN 1 AND 1024),
    redirect_uri text NOT NULL CHECK (char_length(redirect_uri) BETWEEN 1 AND 2048),
    code_hash text NOT NULL DEFAULT '' CHECK (char_length(code_hash) <= 512),
    code_challenge text NOT NULL CHECK (char_length(code_challenge) BETWEEN 1 AND 128),
    code_expires_at timestamptz NOT NULL,
    access_hash text NOT NULL DEFAULT '' CHECK (char_length(access_hash) <= 512),
    access_expires_at timestamptz,
    refresh_hash text NOT NULL DEFAULT '' CHECK (char_length(refresh_hash) <= 512),
    refresh_expires_at timestamptz,
    CHECK ((access_hash = '') = (access_expires_at IS NULL)),
    CHECK ((refresh_hash = '') = (refresh_expires_at IS NULL)),
    CHECK (access_hash = '' OR access_hash <> refresh_hash)
);
-- Keep consumed refresh hashes so replay revokes the whole connection.
CREATE TABLE IF NOT EXISTS oauth_refresh_history (
    token_hash text PRIMARY KEY,
    grant_id text NOT NULL REFERENCES oauth_grants (id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS oauth_refresh_history_grant_idx ON oauth_refresh_history (grant_id);
CREATE INDEX IF NOT EXISTS oauth_refresh_history_expires_idx ON oauth_refresh_history (expires_at);
CREATE INDEX IF NOT EXISTS oauth_grants_client_idx ON oauth_grants (client_id);
CREATE UNIQUE INDEX IF NOT EXISTS oauth_grants_code_hash_idx
    ON oauth_grants (code_hash) WHERE code_hash <> '';
CREATE UNIQUE INDEX IF NOT EXISTS oauth_grants_access_hash_idx
    ON oauth_grants (access_hash) WHERE access_hash <> '';
CREATE UNIQUE INDEX IF NOT EXISTS oauth_grants_refresh_hash_idx
    ON oauth_grants (refresh_hash) WHERE refresh_hash <> '';
