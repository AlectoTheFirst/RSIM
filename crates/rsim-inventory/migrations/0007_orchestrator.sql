-- The settings of an API orchestrator: the release, the API base path, the
-- requests in flight and the module refresh in seconds.

ALTER TABLE device_groups
    ADD COLUMN orchestrator_release text,
    ADD COLUMN api_base text,
    ADD COLUMN concurrency integer CHECK (concurrency BETWEEN 1 AND 16),
    ADD COLUMN refresh_seconds integer CHECK (refresh_seconds BETWEEN 0 AND 86400);

ALTER TABLE devices
    ADD COLUMN orchestrator_release text,
    ADD COLUMN api_base text,
    ADD COLUMN concurrency integer CHECK (concurrency BETWEEN 1 AND 16),
    ADD COLUMN refresh_seconds integer CHECK (refresh_seconds BETWEEN 0 AND 86400);
