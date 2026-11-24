//! The inventory of rsim in PostgreSQL: the device groups, the devices, the
//! credential references, the routes, the Equinix bindings, the inventory
//! version, the audit log, and the users of `rsim-api` with their sessions
//! and API tokens.
//!
//! `rsim-api` writes the inventory and `rsim-collect` reads it at the start
//! of each cycle. The engine does not read it. A credential names a key of
//! the env file of the collector, or it is managed: the database holds its
//! kind, its user and its secret, sealed by the secret key of [`SecretKey`],
//! and no reader of the inventory gives the secret back.
//!
//! The schema is in `migrations/`, applied in order by [`Db::migrate`],
//! which records each version in the table `schema_migrations`.

mod db;
pub mod env;
mod resolve;
mod secret;
mod types;

pub use db::{
    Account, Attempt, AuthEvent, AuthEventPage, Change, Db, Error, MAX_PASSWORD, MIGRATIONS,
    Principal, Role, SCOPE_ADMIN, SCOPE_INVENTORY_WRITE, SCOPE_READ, SCOPE_SCENARIO_WRITE, SCOPES,
    SESSION_MAX_SECONDS, TOKEN_PREFIX, TokenInfo, User, Via, check_password, hash_password,
    import_changes, new_secret, schema_version, secret_hash, valid_user_name, verify_nothing,
    verify_password,
};
pub use resolve::{
    DEFAULT_CONCURRENCY, DEFAULT_INTERVAL_SECONDS, DEFAULT_PAGED_SECTION_TIMEOUT_SECONDS,
    DEFAULT_REFRESH_SECONDS, DEFAULT_REQUEST_TIMEOUT_SECONDS, DEFAULT_SECTION_TIMEOUT_SECONDS,
    DEFAULT_TIMEOUT_SECONDS, Origin, Resolved, ResolvedDevice, ResolvedDevices, ResolvedSettings,
    default_tls_trust, resolve_device, resolve_settings,
};
pub use secret::{KEY_VAR, MAX_SECRET, Sealed, SecretInput, SecretKey};
pub use types::{
    Action, AuditPage, AuditRecord, Bindings, COLLECTOR_VENDORS, CaptureBgp, Collection,
    CollectorTransport, Credential, CredentialKind, CredentialSource, DEFAULT_HISTORY_DAYS, Device,
    EdgeDeviceBinding, FabricPortBinding, Group, Ha, Inventory, JumpHost, NxosJson, Route,
    Settings, SshAlgorithms, SshMode, TlsTrust, valid_device_name, valid_name,
};

/// The environment variable of the URL of the inventory database.
pub const URL_VAR: &str = "RSIM_INVENTORY_URL";
/// The environment variable of the PEM file of the CA bundle of the
/// inventory database.
pub const CA_FILE_VAR: &str = "RSIM_INVENTORY_CA_FILE";
/// The environment variable of the URL of the database of the SQL tests.
pub const TEST_URL_VAR: &str = "RSIM_TEST_DATABASE_URL";

/// A database of a test in its own schema, migrated. `None`, with a line on
/// stderr, if `RSIM_TEST_DATABASE_URL` is not set. Each name gets a new
/// empty schema, so tests that run at the same time do not share records.
pub async fn test_database(name: &str) -> Option<Db> {
    let Ok(url) = std::env::var(TEST_URL_VAR) else {
        eprintln!("skipped {name}: {TEST_URL_VAR} is not set");
        return None;
    };
    let schema = format!(
        "t_{}_{}",
        name.chars()
            .map(|c| if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '_'
            })
            .collect::<String>(),
        std::process::id()
    );
    let admin = Db::new(&url, None).expect("the test database URL");
    admin
        .batch(&format!(
            "DROP SCHEMA IF EXISTS {schema} CASCADE; CREATE SCHEMA {schema}"
        ))
        .await
        .expect("the schema of the test");
    let mut config: tokio_postgres::Config = url.parse().expect("the test database URL");
    config.options(format!("-c search_path={schema}"));
    let db = Db::with_config(config, None).expect("the test database");
    db.migrate().await.expect("the migrations");
    Some(db)
}
