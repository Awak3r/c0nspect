CREATE TABLE owners (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    username text NOT NULL,
    password_hash text NOT NULL
);

CREATE TABLE sessions (
    token_hash text PRIMARY KEY CHECK (token_hash <> ''),
    csrf_token text NOT NULL,
    expires_at timestamptz NOT NULL
);
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);

CREATE TABLE projects (
    id text PRIMARY KEY,
    name text NOT NULL,
    description text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE notes (
    id text PRIMARY KEY,
    project_id text NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    title text NOT NULL,
    markdown text NOT NULL DEFAULT '',
    source_name text NOT NULL DEFAULT '',
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX notes_project_modified_idx ON notes (project_id, updated_at DESC, id);

CREATE TABLE attachments (
    id text PRIMARY KEY,
    note_id text NOT NULL REFERENCES notes (id) ON DELETE CASCADE,
    name text NOT NULL,
    storage_key text NOT NULL UNIQUE CHECK (storage_key <> ''),
    mime_type text NOT NULL,
    size bigint NOT NULL CHECK (size >= 0),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX attachments_note_idx ON attachments (note_id, created_at, id);

CREATE TABLE share_links (
    id text PRIMARY KEY,
    note_id text NOT NULL REFERENCES notes (id) ON DELETE CASCADE,
    token_hash text NOT NULL UNIQUE CHECK (token_hash <> ''),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    revoked_at timestamptz
);
CREATE UNIQUE INDEX share_links_active_note_idx ON share_links (note_id) WHERE revoked_at IS NULL;

CREATE TABLE api_keys (
    id text PRIMARY KEY,
    name text NOT NULL,
    token_hash text NOT NULL UNIQUE CHECK (token_hash <> ''),
    scopes text[] NOT NULL DEFAULT '{}',
    project_ids text[] NOT NULL DEFAULT '{}',
    note_ids text[] NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz,
    revoked_at timestamptz,
    last_used_at timestamptz
);

-- Identifiers are snapshots, deliberately not foreign keys: deletion must not erase history.
CREATE TABLE audit_events (
    id text PRIMARY KEY,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    actor_owner boolean NOT NULL,
    actor_key_id text,
    note_id text NOT NULL,
    action text NOT NULL,
    old_version bigint CHECK (old_version > 0),
    new_version bigint CHECK (new_version > 0),
    CHECK ((actor_owner AND actor_key_id IS NULL) OR
           (NOT actor_owner AND actor_key_id IS NOT NULL AND actor_key_id <> ''))
);
CREATE INDEX audit_events_note_idx ON audit_events (note_id, created_at, id);
