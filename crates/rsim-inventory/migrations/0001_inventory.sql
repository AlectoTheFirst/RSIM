-- The inventory: credential references, jump hosts, routes, device groups,
-- devices, the Equinix bindings, the inventory version and the audit log.
-- A credential row is a reference: the secret stays in its source.

CREATE TABLE inventory_version (
    only_row boolean PRIMARY KEY DEFAULT true CHECK (only_row),
    version bigint NOT NULL CHECK (version >= 0)
);
INSERT INTO inventory_version (only_row, version) VALUES (true, 0);

CREATE TABLE credentials (
    name text PRIMARY KEY CHECK (name ~ '^[a-z0-9][a-z0-9._-]*$'),
    source text NOT NULL CHECK (source IN ('env', 'env-url')),
    key text NOT NULL CHECK (key ~ '^[A-Z0-9_]+$'),
    description text
);

CREATE TABLE jump_hosts (
    name text PRIMARY KEY CHECK (name ~ '^[a-z0-9][a-z0-9._-]*$'),
    address text NOT NULL CHECK (address <> ''),
    credential text NOT NULL REFERENCES credentials (name),
    ssh_algorithms text NOT NULL DEFAULT 'modern' CHECK (ssh_algorithms IN ('modern', 'legacy'))
);

CREATE TABLE routes (
    name text PRIMARY KEY CHECK (name ~ '^[a-z0-9][a-z0-9._-]*$'),
    proxy text CHECK (proxy ~ '^(http|socks5|socks5h)://[^@/[:space:]]+$'),
    proxy_credential text REFERENCES credentials (name),
    CHECK (proxy_credential IS NULL OR proxy IS NOT NULL)
);

CREATE TABLE route_jumps (
    route text NOT NULL REFERENCES routes (name) ON DELETE CASCADE,
    position integer NOT NULL CHECK (position >= 0),
    jump_host text NOT NULL REFERENCES jump_hosts (name),
    PRIMARY KEY (route, position)
);

CREATE TABLE device_groups (
    name text PRIMARY KEY CHECK (name ~ '^[a-z0-9][a-z0-9._-]*$'),
    vendor text NOT NULL CHECK (vendor ~ '^[a-z0-9][a-z0-9-]*$'),
    description text,
    credential text REFERENCES credentials (name),
    route text REFERENCES routes (name),
    ssh_algorithms text CHECK (ssh_algorithms IN ('modern', 'legacy')),
    ssh_mode text CHECK (ssh_mode IN ('exec', 'shell', 'connection')),
    ssh_channels integer CHECK (ssh_channels >= 1),
    nxos_json text CHECK (nxos_json IN ('plain', 'native')),
    tls_trust text CHECK (tls_trust IN ('pin', 'ca', 'none')),
    tls_ca_file text CHECK (tls_ca_file <> ''),
    capture_bgp text CHECK (capture_bgp IN ('off', 'sessions', 'all')),
    timeout_seconds integer CHECK (timeout_seconds BETWEEN 1 AND 86400),
    section_timeout_seconds integer CHECK (section_timeout_seconds BETWEEN 1 AND 86400),
    request_timeout_seconds integer CHECK (request_timeout_seconds BETWEEN 1 AND 86400),
    paged_section_timeout_seconds integer CHECK (paged_section_timeout_seconds BETWEEN 1 AND 86400),
    retries integer CHECK (retries BETWEEN 0 AND 10),
    ha text CHECK (ha IN ('none', 'all', 'one'))
);

CREATE TABLE devices (
    name text PRIMARY KEY CHECK (name ~ '^[^/[:space:]]+$'),
    device_group text NOT NULL REFERENCES device_groups (name),
    address text NOT NULL CHECK (address <> ''),
    site text,
    location text,
    console_site text,
    credential text REFERENCES credentials (name),
    route text REFERENCES routes (name),
    ssh_algorithms text CHECK (ssh_algorithms IN ('modern', 'legacy')),
    ssh_mode text CHECK (ssh_mode IN ('exec', 'shell', 'connection')),
    ssh_channels integer CHECK (ssh_channels >= 1),
    nxos_json text CHECK (nxos_json IN ('plain', 'native')),
    tls_trust text CHECK (tls_trust IN ('pin', 'ca', 'none')),
    tls_ca_file text CHECK (tls_ca_file <> ''),
    capture_bgp text CHECK (capture_bgp IN ('off', 'sessions', 'all')),
    timeout_seconds integer CHECK (timeout_seconds BETWEEN 1 AND 86400),
    section_timeout_seconds integer CHECK (section_timeout_seconds BETWEEN 1 AND 86400),
    request_timeout_seconds integer CHECK (request_timeout_seconds BETWEEN 1 AND 86400),
    paged_section_timeout_seconds integer CHECK (paged_section_timeout_seconds BETWEEN 1 AND 86400),
    retries integer CHECK (retries BETWEEN 0 AND 10),
    ha text CHECK (ha IN ('none', 'all', 'one'))
);

CREATE INDEX devices_device_group ON devices (device_group);

CREATE TABLE fabric_port_bindings (
    account text NOT NULL REFERENCES devices (name),
    fabric_port text NOT NULL CHECK (fabric_port <> ''),
    device text NOT NULL REFERENCES devices (name),
    port text NOT NULL CHECK (port <> ''),
    PRIMARY KEY (account, fabric_port),
    UNIQUE (device, port)
);

CREATE TABLE edge_device_bindings (
    account text NOT NULL REFERENCES devices (name),
    edge_device text NOT NULL CHECK (edge_device <> ''),
    device text NOT NULL REFERENCES devices (name),
    PRIMARY KEY (account, edge_device)
);

CREATE TABLE audit_log (
    id bigserial PRIMARY KEY,
    at timestamptz NOT NULL DEFAULT now(),
    actor text NOT NULL CHECK (actor <> ''),
    version bigint NOT NULL,
    kind text NOT NULL,
    key text NOT NULL,
    action text NOT NULL CHECK (action IN ('create', 'update', 'delete')),
    old_value jsonb,
    new_value jsonb
);
