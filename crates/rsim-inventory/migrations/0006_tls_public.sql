-- The TLS trust `public`: the certificate chains to a public root.

ALTER TABLE device_groups
    DROP CONSTRAINT device_groups_tls_trust_check,
    ADD CONSTRAINT device_groups_tls_trust_check
        CHECK (tls_trust IN ('pin', 'ca', 'public', 'none'));

ALTER TABLE devices
    DROP CONSTRAINT devices_tls_trust_check,
    ADD CONSTRAINT devices_tls_trust_check
        CHECK (tls_trust IN ('pin', 'ca', 'public', 'none'));
