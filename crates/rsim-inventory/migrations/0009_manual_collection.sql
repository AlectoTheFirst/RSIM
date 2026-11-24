-- The collection mode of a device: on the schedule of its interval, or
-- only on a request. A request names a device that the collector collects
-- at its next wake.

ALTER TABLE device_groups
    ADD COLUMN collection text CHECK (collection IN ('auto', 'manual'));

ALTER TABLE devices
    ADD COLUMN collection text CHECK (collection IN ('auto', 'manual'));

CREATE TABLE collection_requests (
    device text PRIMARY KEY REFERENCES devices (name) ON DELETE CASCADE ON UPDATE CASCADE,
    actor text NOT NULL,
    requested_at timestamptz NOT NULL DEFAULT now()
);
