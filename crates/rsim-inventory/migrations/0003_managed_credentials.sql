-- Managed credentials: the database holds the kind, the user and the
-- sealed secret of a credential with the source `managed`. A credential
-- with the source `env` or `env-url` holds only the key of its source.

ALTER TABLE credentials
    DROP CONSTRAINT credentials_source_check,
    DROP CONSTRAINT credentials_key_check,
    ALTER COLUMN key DROP NOT NULL,
    ADD COLUMN kind text CHECK (kind IN ('password', 'ssh-key', 'api-key')),
    ADD COLUMN user_name text CHECK (user_name <> ''),
    ADD COLUMN sealed bytea,
    ADD COLUMN secret_key_id text CHECK (secret_key_id ~ '^[0-9a-f]{16}$'),
    ADD COLUMN secret_revision bigint CHECK (secret_revision >= 1),
    ADD CONSTRAINT credentials_source_check CHECK (source IN ('env', 'env-url', 'managed')),
    ADD CONSTRAINT credentials_key_check CHECK (key ~ '^[A-Z0-9_]+$'),
    ADD CONSTRAINT credentials_source_fields CHECK (
        (source IN ('env', 'env-url')
            AND key IS NOT NULL
            AND kind IS NULL
            AND user_name IS NULL
            AND sealed IS NULL
            AND secret_key_id IS NULL
            AND secret_revision IS NULL)
        OR (source = 'managed'
            AND key IS NULL
            AND kind IS NOT NULL
            AND sealed IS NOT NULL
            AND secret_key_id IS NOT NULL
            AND secret_revision IS NOT NULL
            AND ((kind = 'api-key') = (user_name IS NULL)))
    );
