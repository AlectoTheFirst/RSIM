-- The settings of an Equinix account: the read of the Network Edge
-- sections and the items of one page.

ALTER TABLE device_groups
    ADD COLUMN network_edge text CHECK (network_edge IN ('off', 'on')),
    ADD COLUMN page_size integer CHECK (page_size BETWEEN 1 AND 1000);

ALTER TABLE devices
    ADD COLUMN network_edge text CHECK (network_edge IN ('off', 'on')),
    ADD COLUMN page_size integer CHECK (page_size BETWEEN 1 AND 1000);
