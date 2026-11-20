-- The users of rsim-api, their sessions and API tokens, the failed sign-ins
-- and the sign-in events. A password is stored only as its Argon2id hash, and
-- a session token or an API token only as its SHA-256 hash.

CREATE TABLE users (
    id bigserial PRIMARY KEY,
    name text NOT NULL UNIQUE CHECK (name ~ '^[a-z0-9][a-z0-9._@-]{0,63}$'),
    role text NOT NULL CHECK (role IN ('viewer', 'operator', 'admin')),
    password_hash text NOT NULL CHECK (password_hash LIKE '$argon2id$%'),
    disabled boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
    token_hash bytea PRIMARY KEY CHECK (length(token_hash) = 32),
    user_id bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX sessions_user ON sessions (user_id);

CREATE TABLE api_tokens (
    id bigserial PRIMARY KEY,
    token_hash bytea NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    user_id bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name text NOT NULL CHECK (name <> '' AND length(name) <= 100),
    scopes text[] NOT NULL CHECK (
        cardinality(scopes) > 0
        AND scopes <@ ARRAY['rsim.read', 'rsim.scenario.write', 'rsim.inventory.write', 'rsim.admin']
    ),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz,
    last_used_at timestamptz,
    revoked boolean NOT NULL DEFAULT false
);
CREATE INDEX api_tokens_user ON api_tokens (user_id);

CREATE TABLE login_failures (
    id bigserial PRIMARY KEY,
    name text NOT NULL,
    client text NOT NULL,
    at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX login_failures_name ON login_failures (name, at);
CREATE INDEX login_failures_client ON login_failures (client, at);

CREATE TABLE auth_events (
    id bigserial PRIMARY KEY,
    at timestamptz NOT NULL DEFAULT now(),
    event text NOT NULL CHECK (event IN (
        'setup', 'sign_in', 'sign_in_failed', 'sign_out',
        'token_created', 'token_revoked', 'user_created', 'user_changed',
        'user_deleted', 'refused'
    )),
    actor text,
    subject text,
    client text,
    detail text
);
