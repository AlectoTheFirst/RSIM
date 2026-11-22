-- The time between 2 collections of a device, in seconds.

ALTER TABLE device_groups
    ADD COLUMN interval_seconds integer CHECK (interval_seconds BETWEEN 60 AND 86400);

ALTER TABLE devices
    ADD COLUMN interval_seconds integer CHECK (interval_seconds BETWEEN 60 AND 86400);
