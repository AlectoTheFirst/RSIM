//! The PostgreSQL side: the connection, the migrations, the reader and the
//! writer. Each write is one transaction that changes the records, writes
//! one audit record for each changed record and increases the inventory
//! version by 1. The database gives the time of an audit record.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use serde::Serialize;
use tokio::sync::Mutex;
use tokio_postgres::error::SqlState;
use tokio_postgres::types::ToSql;
use tokio_postgres::{Client, Config, GenericClient, IsolationLevel, Row};
use tokio_postgres_rustls::MakeRustlsConnect;

mod auth;
pub use auth::*;

use crate::secret::Sealed;
use crate::types::{
    Action, AuditPage, AuditRecord, Bindings, CaptureBgp, Credential, CredentialKind,
    CredentialSource, Device, EdgeDeviceBinding, FabricPortBinding, Group, Ha, Inventory, JumpHost,
    NxosJson, Route, Settings, SshAlgorithms, SshMode, TlsTrust, valid_device_name, valid_name,
};

/// The migrations: the version, the name and the SQL, in order. A version
/// that a database has is never changed.
pub const MIGRATIONS: &[(u32, &str, &str)] = &[
    (
        1,
        "inventory",
        include_str!("../migrations/0001_inventory.sql"),
    ),
    (2, "auth", include_str!("../migrations/0002_auth.sql")),
    (
        3,
        "managed_credentials",
        include_str!("../migrations/0003_managed_credentials.sql"),
    ),
];

/// The schema version of this build: the last migration.
pub fn schema_version() -> u32 {
    MIGRATIONS.last().map_or(0, |m| m.0)
}

/// The key of the advisory lock of the migrations.
const MIGRATION_LOCK: i64 = 0x7273_696d_5f69_6e76;

/// An error of the inventory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The record is not in the inventory.
    NotFound(String),
    /// The change conflicts with another record, for example a group that
    /// devices use.
    Conflict(String),
    /// The record is not valid.
    Invalid(String),
    /// The schema of the database is not the schema of this build.
    Schema(String),
    /// The database cannot be reached or gave an error.
    Database(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::NotFound(e)
            | Error::Conflict(e)
            | Error::Invalid(e)
            | Error::Schema(e)
            | Error::Database(e) => f.write_str(e),
        }
    }
}

impl std::error::Error for Error {}

impl From<tokio_postgres::Error> for Error {
    fn from(e: tokio_postgres::Error) -> Self {
        let Some(db) = e.as_db_error() else {
            return Error::Database(format!("the inventory database: {e}"));
        };
        let text = match db.detail() {
            Some(d) => format!("{}: {d}", db.message()),
            None => db.message().to_string(),
        };
        let code = db.code();
        if *code == SqlState::FOREIGN_KEY_VIOLATION || *code == SqlState::UNIQUE_VIOLATION {
            Error::Conflict(text)
        } else if *code == SqlState::CHECK_VIOLATION
            || *code == SqlState::NOT_NULL_VIOLATION
            || *code == SqlState::STRING_DATA_RIGHT_TRUNCATION
        {
            Error::Invalid(text)
        } else if *code == SqlState::UNDEFINED_TABLE {
            Error::Schema(format!(
                "the database has no inventory schema ({text}); run rsim-inventory migrate"
            ))
        } else {
            Error::Database(format!("the inventory database: {text}"))
        }
    }
}

type Result<T> = std::result::Result<T, Error>;

/// The TLS connector: the CA bundle of a PEM file, or no root when no file
/// is given. A server with no TLS gets a plain connection with the
/// default `sslmode=prefer`.
fn tls(ca_pem: Option<&str>) -> Result<MakeRustlsConnect> {
    use rustls::pki_types::CertificateDer;
    use rustls::pki_types::pem::PemObject;
    let mut roots = rustls::RootCertStore::empty();
    if let Some(pem) = ca_pem {
        for c in CertificateDer::pem_slice_iter(pem.as_bytes()) {
            let c = c.map_err(|e| Error::Invalid(format!("the CA bundle: {e}")))?;
            roots
                .add(c)
                .map_err(|e| Error::Invalid(format!("the CA bundle: {e}")))?;
        }
        if roots.is_empty() {
            return Err(Error::Invalid("the CA bundle has no certificate".into()));
        }
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| Error::Invalid(e.to_string()))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(MakeRustlsConnect::new(config))
}

/// A connection to the inventory database. It connects at the first use
/// and again after the connection closes. The calls take turns on the one
/// connection.
pub struct Db {
    config: Config,
    tls: MakeRustlsConnect,
    client: Mutex<Option<Client>>,
}

impl fmt::Debug for Db {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Db")
            .field("hosts", &self.config.get_hosts())
            .field("dbname", &self.config.get_dbname())
            .finish_non_exhaustive()
    }
}

impl Db {
    /// The database of a URL `postgres://user:password@host:port/db`, with
    /// the CA bundle of the server in PEM, if any. It does not connect yet.
    pub fn new(url: &str, ca_pem: Option<&str>) -> Result<Db> {
        let config: Config = url
            .parse()
            .map_err(|e| Error::Invalid(format!("the inventory URL: {e}")))?;
        Db::with_config(config, ca_pem)
    }

    /// The database of a configuration.
    pub fn with_config(config: Config, ca_pem: Option<&str>) -> Result<Db> {
        Ok(Db {
            config,
            tls: tls(ca_pem)?,
            client: Mutex::new(None),
        })
    }

    /// The same database on a connection of its own.
    pub fn reopen(&self) -> Db {
        Db {
            config: self.config.clone(),
            tls: self.tls.clone(),
            client: Mutex::new(None),
        }
    }

    async fn client<'a>(
        &self,
        slot: &'a mut tokio::sync::MutexGuard<'_, Option<Client>>,
    ) -> Result<&'a mut Client> {
        if slot.as_ref().is_none_or(Client::is_closed) {
            let (client, connection) =
                self.config.connect(self.tls.clone()).await.map_err(|e| {
                    Error::Database(format!(
                        "the inventory database cannot be reached: {e}; with TLS, give the CA \
                     bundle of the server"
                    ))
                })?;
            tokio::spawn(async move {
                let _ = connection.await;
            });
            **slot = Some(client);
        }
        Ok(slot.as_mut().expect("the client is set"))
    }

    /// Runs SQL statements with no parameters.
    pub(crate) async fn batch(&self, sql: &str) -> Result<()> {
        let mut slot = self.client.lock().await;
        let client = self.client(&mut slot).await?;
        client.batch_execute(sql).await?;
        Ok(())
    }

    /// Applies the migrations that the database does not have, in one
    /// transaction under an advisory lock. Gives the versions applied.
    pub async fn migrate(&self) -> Result<Vec<u32>> {
        let mut slot = self.client.lock().await;
        let client = self.client(&mut slot).await?;
        let tx = client.transaction().await?;
        tx.execute("SELECT pg_advisory_xact_lock($1)", &[&MIGRATION_LOCK])
            .await?;
        tx.batch_execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations (
                 version integer PRIMARY KEY,
                 name text NOT NULL,
                 applied_at timestamptz NOT NULL DEFAULT now()
             )",
        )
        .await?;
        let have: i32 = tx
            .query_one(
                "SELECT coalesce(max(version), 0) FROM schema_migrations",
                &[],
            )
            .await?
            .get(0);
        if have > schema_version() as i32 {
            return Err(Error::Schema(format!(
                "the inventory schema is version {have}, newer than version {} of this build",
                schema_version()
            )));
        }
        let mut applied = Vec::new();
        for (version, name, sql) in MIGRATIONS {
            if *version as i32 <= have {
                continue;
            }
            tx.batch_execute(sql).await?;
            tx.execute(
                "INSERT INTO schema_migrations (version, name) VALUES ($1, $2)",
                &[&(*version as i32), name],
            )
            .await?;
            applied.push(*version);
        }
        tx.commit().await?;
        Ok(applied)
    }

    /// The whole inventory at one version, read in one transaction. It
    /// gives no secret.
    pub async fn load(&self) -> Result<Inventory> {
        Ok(self.read(false).await?.0)
    }

    /// The whole inventory at one version and the sealed secret of each
    /// managed credential by name, read in one transaction. Only the
    /// collector reads the secrets.
    pub async fn load_with_secrets(&self) -> Result<(Inventory, BTreeMap<String, Sealed>)> {
        self.read(true).await
    }

    async fn read(&self, secrets: bool) -> Result<(Inventory, BTreeMap<String, Sealed>)> {
        let mut slot = self.client.lock().await;
        let client = self.client(&mut slot).await?;
        let tx = client
            .build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()
            .await?;
        check_schema(&tx).await?;
        let version = read_version(&tx).await?;
        let inv = Inventory {
            version,
            credentials: credentials(&tx, None).await?,
            jump_hosts: jump_hosts(&tx, None).await?,
            routes: routes(&tx, None).await?,
            groups: groups(&tx, None).await?,
            devices: devices(&tx, None).await?,
            bindings: Bindings {
                fabric_ports: fabric_ports(&tx, None).await?,
                edge_devices: edge_devices(&tx, None).await?,
            },
        };
        let sealed = if secrets {
            sealed_secrets(&tx).await?
        } else {
            BTreeMap::new()
        };
        tx.commit().await?;
        Ok((inv, sealed))
    }

    /// A page of the audit log, the newest record first: at most `limit`
    /// records with an id below `before`.
    pub async fn audit(&self, limit: u32, before: Option<i64>) -> Result<AuditPage> {
        let mut slot = self.client.lock().await;
        let client = self.client(&mut slot).await?;
        let limit = i64::from(limit.clamp(1, 1000));
        let rows = client
            .query(
                "SELECT id,
                        to_char(at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') AS at,
                        actor, version, kind, key, action, old_value, new_value
                 FROM audit_log
                 WHERE ($1::bigint IS NULL OR id < $1)
                 ORDER BY id DESC
                 LIMIT $2",
                &[&before, &(limit + 1)],
            )
            .await?;
        let mut records = Vec::with_capacity(rows.len());
        for r in rows.iter().take(limit as usize) {
            let action: String = r.get("action");
            records.push(AuditRecord {
                id: r.get("id"),
                at: r.get("at"),
                actor: r.get("actor"),
                version: r.get::<_, i64>("version") as u64,
                kind: r.get("kind"),
                key: r.get("key"),
                action: match action.as_str() {
                    "create" => Action::Create,
                    "update" => Action::Update,
                    _ => Action::Delete,
                },
                old: r.get("old_value"),
                new: r.get("new_value"),
            });
        }
        let next_before = (rows.len() as i64 > limit)
            .then(|| records.last().map(|r| r.id))
            .flatten();
        Ok(AuditPage {
            records,
            next_before,
        })
    }

    /// Applies the changes in one transaction as `actor`. A change that
    /// leaves its record as it is writes nothing. If a record changes, the
    /// inventory version increases by 1 and each changed record gets an
    /// audit record. Gives the inventory version after the changes.
    pub async fn apply(&self, actor: &str, changes: &[Change]) -> Result<u64> {
        if actor.is_empty() {
            return Err(Error::Invalid("the actor of a change has no name".into()));
        }
        for c in changes {
            c.check()?;
        }
        let mut slot = self.client.lock().await;
        let client = self.client(&mut slot).await?;
        let tx = client.transaction().await?;
        check_schema(&tx).await?;
        let version: i64 = tx
            .query_one("SELECT version FROM inventory_version FOR UPDATE", &[])
            .await?
            .get(0);
        let mut audits = Vec::new();
        for c in changes {
            if let Some(a) = c.write(&tx).await? {
                audits.push(a);
            }
        }
        if audits.is_empty() {
            tx.commit().await?;
            return Ok(version as u64);
        }
        let next = version + 1;
        tx.execute("UPDATE inventory_version SET version = $1", &[&next])
            .await?;
        for a in &audits {
            tx.execute(
                "INSERT INTO audit_log (actor, version, kind, key, action, old_value, new_value)
                 VALUES ($1, $2, $3, $4, $5, $6, $7)",
                &[
                    &actor,
                    &next,
                    &a.kind,
                    &a.key,
                    &a.action.word(),
                    &a.old,
                    &a.new,
                ],
            )
            .await?;
        }
        tx.commit().await?;
        Ok(next as u64)
    }
}

async fn check_schema(c: &impl GenericClient) -> Result<()> {
    let have: i32 = c
        .query_one(
            "SELECT coalesce(max(version), 0) FROM schema_migrations",
            &[],
        )
        .await?
        .get(0);
    if have != schema_version() as i32 {
        return Err(Error::Schema(format!(
            "the inventory schema is version {have} and this build needs version {}; run \
             rsim-inventory migrate with the newer of the two builds",
            schema_version()
        )));
    }
    Ok(())
}

async fn read_version(c: &impl GenericClient) -> Result<u64> {
    let v: i64 = c
        .query_one("SELECT version FROM inventory_version", &[])
        .await?
        .get(0);
    Ok(v as u64)
}

/// One change of the inventory. A put makes the record or replaces it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    /// A credential with the new sealed secret of a managed credential. A
    /// managed credential with no new secret keeps its stored secret, which
    /// needs the same kind; a new managed credential needs its secret.
    PutCredential(Credential, Option<Sealed>),
    DeleteCredential(String),
    PutJumpHost(JumpHost),
    DeleteJumpHost(String),
    PutRoute(Route),
    DeleteRoute(String),
    PutGroup(Group),
    DeleteGroup(String),
    PutDevice(Device),
    DeleteDevice(String),
    PutFabricPort(FabricPortBinding),
    DeleteFabricPort {
        account: String,
        fabric_port: String,
    },
    PutEdgeDevice(EdgeDeviceBinding),
    DeleteEdgeDevice {
        account: String,
        edge_device: String,
    },
}

struct Audit {
    kind: &'static str,
    key: String,
    action: Action,
    old: Option<serde_json::Value>,
    new: Option<serde_json::Value>,
}

fn json<T: Serialize>(v: &T) -> serde_json::Value {
    serde_json::to_value(v).unwrap_or(serde_json::Value::Null)
}

fn name_check(kind: &str, name: &str) -> Result<()> {
    if valid_name(name) {
        Ok(())
    } else {
        Err(Error::Invalid(format!(
            "the {kind} name {name:?} is not lower-case letters, digits, '.', '_' and '-'"
        )))
    }
}

fn number(field: &str, v: Option<u32>) -> Result<Option<i32>> {
    v.map(|n| i32::try_from(n).map_err(|_| Error::Invalid(format!("{field} {n} is too large"))))
        .transpose()
}

impl Change {
    /// The checks that need no database.
    fn check(&self) -> Result<()> {
        match self {
            Change::PutCredential(c, sealed) => {
                name_check("credential", &c.name)?;
                c.check().map_err(Error::Invalid)?;
                if sealed.is_some() && c.source != CredentialSource::Managed {
                    return Err(Error::Invalid(format!(
                        "the credential {} of the source {} has no secret in the inventory",
                        c.name, c.source
                    )));
                }
                Ok(())
            }
            Change::PutJumpHost(j) => name_check("jump host", &j.name),
            Change::PutRoute(r) => {
                name_check("route", &r.name)?;
                if let Some(p) = &r.proxy {
                    let (_, login) = crate::env::split_proxy(p)
                        .map_err(|e| Error::Invalid(format!("the proxy of {}: {e}", r.name)))?;
                    if login {
                        return Err(Error::Invalid(format!(
                            "the proxy URL of {} holds a login",
                            r.name
                        )));
                    }
                }
                Ok(())
            }
            Change::PutGroup(g) => {
                name_check("group", &g.name)?;
                settings_params(&g.settings).map(|_| ())
            }
            Change::PutDevice(d) => {
                if !valid_device_name(&d.name) {
                    return Err(Error::Invalid(format!(
                        "the device name {:?} is empty or has a '/' or a space",
                        d.name
                    )));
                }
                settings_params(&d.settings).map(|_| ())
            }
            _ => Ok(()),
        }
    }

    async fn write(&self, tx: &impl GenericClient) -> Result<Option<Audit>> {
        let audit =
            |kind, key: String, old: Option<serde_json::Value>, new: Option<serde_json::Value>| {
                if old == new {
                    return None;
                }
                let action = match (&old, &new) {
                    (None, _) => Action::Create,
                    (_, None) => Action::Delete,
                    _ => Action::Update,
                };
                Some(Audit {
                    kind,
                    key,
                    action,
                    old,
                    new,
                })
            };
        let missing = |kind: &str, key: &str| Error::NotFound(format!("no {kind} is named {key}"));
        match self {
            Change::PutCredential(c, sealed) => {
                let old = credentials(tx, Some(&c.name)).await?.pop();
                let stored = old
                    .as_ref()
                    .filter(|o| o.source == CredentialSource::Managed && o.kind == c.kind);
                let mut new = c.clone();
                new.secret_revision = match (c.source, sealed, stored) {
                    (CredentialSource::Managed, Some(_), _) => {
                        Some(old.as_ref().and_then(|o| o.secret_revision).unwrap_or(0) + 1)
                    }
                    (CredentialSource::Managed, None, Some(o)) => o.secret_revision,
                    (CredentialSource::Managed, None, None) => {
                        return Err(Error::Invalid(format!(
                            "the managed credential {} needs its secret",
                            c.name
                        )));
                    }
                    _ => None,
                };
                if old.as_ref() != Some(&new) {
                    let kind = new.kind.map(CredentialKind::word);
                    if c.source == CredentialSource::Managed && sealed.is_none() {
                        tx.execute(
                            "UPDATE credentials SET user_name = $2, description = $3
                             WHERE name = $1",
                            &[&new.name, &new.user, &new.description],
                        )
                        .await?;
                    } else {
                        let revision = new.secret_revision.map(|r| r as i64);
                        let (bytes, key_id) = sealed
                            .as_ref()
                            .map(|s| (s.bytes.clone(), s.key_id.clone()))
                            .unzip();
                        tx.execute(
                            "INSERT INTO credentials (name, source, key, kind, user_name,
                                 description, sealed, secret_key_id, secret_revision)
                             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                             ON CONFLICT (name) DO UPDATE SET source = EXCLUDED.source,
                                 key = EXCLUDED.key, kind = EXCLUDED.kind,
                                 user_name = EXCLUDED.user_name,
                                 description = EXCLUDED.description,
                                 sealed = EXCLUDED.sealed,
                                 secret_key_id = EXCLUDED.secret_key_id,
                                 secret_revision = EXCLUDED.secret_revision",
                            &[
                                &new.name,
                                &new.source.word(),
                                &new.key,
                                &kind,
                                &new.user,
                                &new.description,
                                &bytes,
                                &key_id,
                                &revision,
                            ],
                        )
                        .await?;
                    }
                }
                Ok(audit(
                    "credential",
                    c.name.clone(),
                    old.map(|o| json(&o)),
                    Some(json(&new)),
                ))
            }
            Change::DeleteCredential(name) => {
                let old = credentials(tx, Some(name)).await?.pop();
                let old = old.ok_or_else(|| missing("credential", name))?;
                tx.execute("DELETE FROM credentials WHERE name = $1", &[name])
                    .await?;
                Ok(audit("credential", name.clone(), Some(json(&old)), None))
            }
            Change::PutJumpHost(j) => {
                let old = jump_hosts(tx, Some(&j.name)).await?.pop();
                if old.as_ref() != Some(j) {
                    tx.execute(
                        "INSERT INTO jump_hosts (name, address, credential, ssh_algorithms)
                         VALUES ($1, $2, $3, $4)
                         ON CONFLICT (name) DO UPDATE SET address = EXCLUDED.address,
                             credential = EXCLUDED.credential,
                             ssh_algorithms = EXCLUDED.ssh_algorithms",
                        &[&j.name, &j.address, &j.credential, &j.ssh_algorithms.word()],
                    )
                    .await?;
                }
                Ok(audit(
                    "jump_host",
                    j.name.clone(),
                    old.map(|o| json(&o)),
                    Some(json(j)),
                ))
            }
            Change::DeleteJumpHost(name) => {
                let old = jump_hosts(tx, Some(name)).await?.pop();
                let old = old.ok_or_else(|| missing("jump host", name))?;
                tx.execute("DELETE FROM jump_hosts WHERE name = $1", &[name])
                    .await?;
                Ok(audit("jump_host", name.clone(), Some(json(&old)), None))
            }
            Change::PutRoute(r) => {
                let old = routes(tx, Some(&r.name)).await?.pop();
                if old.as_ref() != Some(r) {
                    tx.execute(
                        "INSERT INTO routes (name, proxy, proxy_credential) VALUES ($1, $2, $3)
                         ON CONFLICT (name) DO UPDATE SET proxy = EXCLUDED.proxy,
                             proxy_credential = EXCLUDED.proxy_credential",
                        &[&r.name, &r.proxy, &r.proxy_credential],
                    )
                    .await?;
                    tx.execute("DELETE FROM route_jumps WHERE route = $1", &[&r.name])
                        .await?;
                    for (i, j) in r.jumps.iter().enumerate() {
                        tx.execute(
                            "INSERT INTO route_jumps (route, position, jump_host) VALUES ($1, $2, $3)",
                            &[&r.name, &(i as i32), j],
                        )
                        .await?;
                    }
                }
                Ok(audit(
                    "route",
                    r.name.clone(),
                    old.map(|o| json(&o)),
                    Some(json(r)),
                ))
            }
            Change::DeleteRoute(name) => {
                let old = routes(tx, Some(name)).await?.pop();
                let old = old.ok_or_else(|| missing("route", name))?;
                tx.execute("DELETE FROM routes WHERE name = $1", &[name])
                    .await?;
                Ok(audit("route", name.clone(), Some(json(&old)), None))
            }
            Change::PutGroup(g) => {
                let old = groups(tx, Some(&g.name)).await?.pop();
                if old.as_ref() != Some(g) {
                    let s = settings_params(&g.settings)?;
                    let mut p: Vec<&(dyn ToSql + Sync)> = vec![&g.name, &g.vendor, &g.description];
                    p.extend(s.iter().map(|b| b.as_ref() as &(dyn ToSql + Sync)));
                    tx.execute(
                        &upsert("device_groups", &["name", "vendor", "description"]),
                        &p,
                    )
                    .await?;
                }
                Ok(audit(
                    "group",
                    g.name.clone(),
                    old.map(|o| json(&o)),
                    Some(json(g)),
                ))
            }
            Change::DeleteGroup(name) => {
                let old = groups(tx, Some(name)).await?.pop();
                let old = old.ok_or_else(|| missing("group", name))?;
                tx.execute("DELETE FROM device_groups WHERE name = $1", &[name])
                    .await?;
                Ok(audit("group", name.clone(), Some(json(&old)), None))
            }
            Change::PutDevice(d) => {
                let old = devices(tx, Some(&d.name)).await?.pop();
                if old.as_ref() != Some(d) {
                    let s = settings_params(&d.settings)?;
                    let mut p: Vec<&(dyn ToSql + Sync)> = vec![
                        &d.name,
                        &d.group,
                        &d.address,
                        &d.site,
                        &d.location,
                        &d.console_site,
                    ];
                    p.extend(s.iter().map(|b| b.as_ref() as &(dyn ToSql + Sync)));
                    tx.execute(
                        &upsert(
                            "devices",
                            &[
                                "name",
                                "device_group",
                                "address",
                                "site",
                                "location",
                                "console_site",
                            ],
                        ),
                        &p,
                    )
                    .await?;
                }
                Ok(audit(
                    "device",
                    d.name.clone(),
                    old.map(|o| json(&o)),
                    Some(json(d)),
                ))
            }
            Change::DeleteDevice(name) => {
                let old = devices(tx, Some(name)).await?.pop();
                let old = old.ok_or_else(|| missing("device", name))?;
                tx.execute("DELETE FROM devices WHERE name = $1", &[name])
                    .await?;
                Ok(audit("device", name.clone(), Some(json(&old)), None))
            }
            Change::PutFabricPort(b) => {
                let old = fabric_ports(tx, Some((&b.account, &b.fabric_port)))
                    .await?
                    .pop();
                if old.as_ref() != Some(b) {
                    tx.execute(
                        "INSERT INTO fabric_port_bindings (account, fabric_port, device, port)
                         VALUES ($1, $2, $3, $4)
                         ON CONFLICT (account, fabric_port) DO UPDATE SET device = EXCLUDED.device,
                             port = EXCLUDED.port",
                        &[&b.account, &b.fabric_port, &b.device, &b.port],
                    )
                    .await?;
                }
                Ok(audit(
                    "fabric_port_binding",
                    format!("{}/{}", b.account, b.fabric_port),
                    old.map(|o| json(&o)),
                    Some(json(b)),
                ))
            }
            Change::DeleteFabricPort {
                account,
                fabric_port,
            } => {
                let key = format!("{account}/{fabric_port}");
                let old = fabric_ports(tx, Some((account, fabric_port))).await?.pop();
                let old = old.ok_or_else(|| missing("Fabric port binding", &key))?;
                tx.execute(
                    "DELETE FROM fabric_port_bindings WHERE account = $1 AND fabric_port = $2",
                    &[account, fabric_port],
                )
                .await?;
                Ok(audit("fabric_port_binding", key, Some(json(&old)), None))
            }
            Change::PutEdgeDevice(b) => {
                let old = edge_devices(tx, Some((&b.account, &b.edge_device)))
                    .await?
                    .pop();
                if old.as_ref() != Some(b) {
                    tx.execute(
                        "INSERT INTO edge_device_bindings (account, edge_device, device)
                         VALUES ($1, $2, $3)
                         ON CONFLICT (account, edge_device) DO UPDATE SET device = EXCLUDED.device",
                        &[&b.account, &b.edge_device, &b.device],
                    )
                    .await?;
                }
                Ok(audit(
                    "edge_device_binding",
                    format!("{}/{}", b.account, b.edge_device),
                    old.map(|o| json(&o)),
                    Some(json(b)),
                ))
            }
            Change::DeleteEdgeDevice {
                account,
                edge_device,
            } => {
                let key = format!("{account}/{edge_device}");
                let old = edge_devices(tx, Some((account, edge_device))).await?.pop();
                let old = old.ok_or_else(|| missing("Network Edge binding", &key))?;
                tx.execute(
                    "DELETE FROM edge_device_bindings WHERE account = $1 AND edge_device = $2",
                    &[account, edge_device],
                )
                .await?;
                Ok(audit("edge_device_binding", key, Some(json(&old)), None))
            }
        }
    }
}

/// The settings columns, in the order of [`settings_params`].
const SETTINGS: [&str; 15] = [
    "credential",
    "route",
    "ssh_algorithms",
    "ssh_mode",
    "ssh_channels",
    "nxos_json",
    "tls_trust",
    "tls_ca_file",
    "capture_bgp",
    "timeout_seconds",
    "section_timeout_seconds",
    "request_timeout_seconds",
    "paged_section_timeout_seconds",
    "retries",
    "ha",
];

/// The insert of a record with its settings, or the update of all its
/// columns if the first column exists.
fn upsert(table: &str, columns: &[&str]) -> String {
    let all: Vec<&str> = columns.iter().copied().chain(SETTINGS).collect();
    let values: Vec<String> = (1..=all.len()).map(|i| format!("${i}")).collect();
    let set: Vec<String> = all[1..]
        .iter()
        .map(|c| format!("{c} = EXCLUDED.{c}"))
        .collect();
    format!(
        "INSERT INTO {table} ({}) VALUES ({}) ON CONFLICT ({}) DO UPDATE SET {}",
        all.join(", "),
        values.join(", "),
        all[0],
        set.join(", ")
    )
}

fn settings_params(s: &Settings) -> Result<Vec<Box<dyn ToSql + Sync + Send>>> {
    let w = |v: Option<&'static str>| -> Box<dyn ToSql + Sync + Send> { Box::new(v) };
    Ok(vec![
        Box::new(s.credential.clone()),
        Box::new(s.route.clone()),
        w(s.ssh_algorithms.map(SshAlgorithms::word)),
        w(s.ssh_mode.map(SshMode::word)),
        Box::new(number("ssh_channels", s.ssh_channels)?),
        w(s.nxos_json.map(NxosJson::word)),
        w(s.tls_trust.map(TlsTrust::word)),
        Box::new(s.tls_ca_file.clone()),
        w(s.capture_bgp.map(CaptureBgp::word)),
        Box::new(number("timeout_seconds", s.timeout_seconds)?),
        Box::new(number(
            "section_timeout_seconds",
            s.section_timeout_seconds,
        )?),
        Box::new(number(
            "request_timeout_seconds",
            s.request_timeout_seconds,
        )?),
        Box::new(number(
            "paged_section_timeout_seconds",
            s.paged_section_timeout_seconds,
        )?),
        Box::new(number("retries", s.retries)?),
        w(s.ha.map(Ha::word)),
    ])
}

fn word<T>(row: &Row, column: &str, parse: fn(&str) -> Option<T>) -> Result<Option<T>> {
    let v: Option<String> = row.get(column);
    v.map(|w| {
        parse(&w).ok_or_else(|| Error::Database(format!("{column} has the unknown word {w}")))
    })
    .transpose()
}

fn count(row: &Row, column: &str) -> Option<u32> {
    row.get::<_, Option<i32>>(column).map(|n| n.max(0) as u32)
}

fn settings(row: &Row) -> Result<Settings> {
    Ok(Settings {
        credential: row.get("credential"),
        route: row.get("route"),
        ssh_algorithms: word(row, "ssh_algorithms", SshAlgorithms::parse)?,
        ssh_mode: word(row, "ssh_mode", SshMode::parse)?,
        ssh_channels: count(row, "ssh_channels"),
        nxos_json: word(row, "nxos_json", NxosJson::parse)?,
        tls_trust: word(row, "tls_trust", TlsTrust::parse)?,
        tls_ca_file: row.get("tls_ca_file"),
        capture_bgp: word(row, "capture_bgp", CaptureBgp::parse)?,
        timeout_seconds: count(row, "timeout_seconds"),
        section_timeout_seconds: count(row, "section_timeout_seconds"),
        request_timeout_seconds: count(row, "request_timeout_seconds"),
        paged_section_timeout_seconds: count(row, "paged_section_timeout_seconds"),
        retries: count(row, "retries"),
        ha: word(row, "ha", Ha::parse)?,
    })
}

async fn credentials(c: &impl GenericClient, name: Option<&String>) -> Result<Vec<Credential>> {
    let rows = c
        .query(
            "SELECT name, source, key, kind, user_name, description, secret_revision
             FROM credentials
             WHERE ($1::text IS NULL OR name = $1) ORDER BY name COLLATE \"C\"",
            &[&name],
        )
        .await?;
    rows.iter()
        .map(|r| {
            Ok(Credential {
                name: r.get("name"),
                source: word(r, "source", CredentialSource::parse)?
                    .ok_or_else(|| Error::Database("a credential has no source".into()))?,
                key: r.get("key"),
                kind: word(r, "kind", CredentialKind::parse)?,
                user: r.get("user_name"),
                description: r.get("description"),
                secret_revision: r
                    .get::<_, Option<i64>>("secret_revision")
                    .map(|n| n.max(0) as u64),
            })
        })
        .collect()
}

/// The sealed secret of each managed credential, by name.
async fn sealed_secrets(c: &impl GenericClient) -> Result<BTreeMap<String, Sealed>> {
    let rows = c
        .query(
            "SELECT name, sealed, secret_key_id FROM credentials WHERE source = 'managed'",
            &[],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| {
            (
                r.get("name"),
                Sealed {
                    key_id: r.get("secret_key_id"),
                    bytes: r.get("sealed"),
                },
            )
        })
        .collect())
}

async fn jump_hosts(c: &impl GenericClient, name: Option<&String>) -> Result<Vec<JumpHost>> {
    let rows = c
        .query(
            "SELECT name, address, credential, ssh_algorithms FROM jump_hosts
             WHERE ($1::text IS NULL OR name = $1) ORDER BY name COLLATE \"C\"",
            &[&name],
        )
        .await?;
    rows.iter()
        .map(|r| {
            Ok(JumpHost {
                name: r.get("name"),
                address: r.get("address"),
                credential: r.get("credential"),
                ssh_algorithms: word(r, "ssh_algorithms", SshAlgorithms::parse)?
                    .unwrap_or(SshAlgorithms::Modern),
            })
        })
        .collect()
}

async fn routes(c: &impl GenericClient, name: Option<&String>) -> Result<Vec<Route>> {
    let rows = c
        .query(
            "SELECT name, proxy, proxy_credential FROM routes
             WHERE ($1::text IS NULL OR name = $1) ORDER BY name COLLATE \"C\"",
            &[&name],
        )
        .await?;
    let jumps = c
        .query(
            "SELECT route, jump_host FROM route_jumps
             WHERE ($1::text IS NULL OR route = $1) ORDER BY route COLLATE \"C\", position",
            &[&name],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| {
            let n: String = r.get("name");
            Route {
                jumps: jumps
                    .iter()
                    .filter(|j| j.get::<_, &str>("route") == n)
                    .map(|j| j.get("jump_host"))
                    .collect(),
                name: n,
                proxy: r.get("proxy"),
                proxy_credential: r.get("proxy_credential"),
            }
        })
        .collect())
}

async fn groups(c: &impl GenericClient, name: Option<&String>) -> Result<Vec<Group>> {
    let rows = c
        .query(
            &format!(
                "SELECT name, vendor, description, {} FROM device_groups
                 WHERE ($1::text IS NULL OR name = $1) ORDER BY name COLLATE \"C\"",
                SETTINGS.join(", ")
            ),
            &[&name],
        )
        .await?;
    rows.iter()
        .map(|r| {
            Ok(Group {
                name: r.get("name"),
                vendor: r.get("vendor"),
                description: r.get("description"),
                settings: settings(r)?,
            })
        })
        .collect()
}

async fn devices(c: &impl GenericClient, name: Option<&String>) -> Result<Vec<Device>> {
    let rows = c
        .query(
            &format!(
                "SELECT name, device_group, address, site, location, console_site, {} FROM devices
                 WHERE ($1::text IS NULL OR name = $1) ORDER BY name COLLATE \"C\"",
                SETTINGS.join(", ")
            ),
            &[&name],
        )
        .await?;
    rows.iter()
        .map(|r| {
            Ok(Device {
                name: r.get("name"),
                group: r.get("device_group"),
                address: r.get("address"),
                site: r.get("site"),
                location: r.get("location"),
                console_site: r.get("console_site"),
                settings: settings(r)?,
            })
        })
        .collect()
}

async fn fabric_ports(
    c: &impl GenericClient,
    key: Option<(&String, &String)>,
) -> Result<Vec<FabricPortBinding>> {
    let (a, p) = key.unzip();
    let rows = c
        .query(
            "SELECT account, fabric_port, device, port FROM fabric_port_bindings
             WHERE ($1::text IS NULL OR (account = $1 AND fabric_port = $2))
             ORDER BY account COLLATE \"C\", fabric_port COLLATE \"C\"",
            &[&a, &p],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| FabricPortBinding {
            account: r.get("account"),
            fabric_port: r.get("fabric_port"),
            device: r.get("device"),
            port: r.get("port"),
        })
        .collect())
}

async fn edge_devices(
    c: &impl GenericClient,
    key: Option<(&String, &String)>,
) -> Result<Vec<EdgeDeviceBinding>> {
    let (a, e) = key.unzip();
    let rows = c
        .query(
            "SELECT account, edge_device, device FROM edge_device_bindings
             WHERE ($1::text IS NULL OR (account = $1 AND edge_device = $2))
             ORDER BY account COLLATE \"C\", edge_device COLLATE \"C\"",
            &[&a, &e],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| EdgeDeviceBinding {
            account: r.get("account"),
            edge_device: r.get("edge_device"),
            device: r.get("device"),
        })
        .collect())
}

/// The changes that write the records of an env import, in the order of
/// their dependencies.
pub fn import_changes(r: crate::env::Records) -> Vec<Change> {
    let mut out = Vec::new();
    out.extend(
        r.credentials
            .into_iter()
            .map(|c| Change::PutCredential(c, None)),
    );
    out.extend(r.jump_hosts.into_iter().map(Change::PutJumpHost));
    out.extend(r.routes.into_iter().map(Change::PutRoute));
    out.extend(r.groups.into_iter().map(Change::PutGroup));
    out.extend(r.devices.into_iter().map(Change::PutDevice));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_upsert_names_each_settings_column_once() {
        let sql = upsert("devices", &["name", "device_group"]);
        assert!(sql.starts_with("INSERT INTO devices (name, device_group, credential, route,"));
        assert!(sql.contains("VALUES ($1, $2, $3,"));
        assert!(sql.contains("$17)"));
        assert!(
            sql.contains("ON CONFLICT (name) DO UPDATE SET device_group = EXCLUDED.device_group")
        );
        assert!(!sql.contains("name = EXCLUDED.name,"));
        assert_eq!(
            settings_params(&Settings::default()).unwrap().len(),
            SETTINGS.len()
        );
    }

    #[test]
    fn a_route_with_a_proxy_login_and_a_bad_name_are_refused() {
        let r = Route {
            name: "r".into(),
            proxy: Some("http://u:p@192.0.2.9:3128".into()),
            proxy_credential: None,
            jumps: vec![],
        };
        assert!(
            matches!(Change::PutRoute(r).check(), Err(Error::Invalid(e)) if e.contains("login"))
        );
        let c = Credential::env("Bad Name", CredentialSource::Env, "X");
        assert!(matches!(
            Change::PutCredential(c, None).check(),
            Err(Error::Invalid(_))
        ));
        let d = Device {
            name: "a/b".into(),
            group: "g".into(),
            address: "192.0.2.1".into(),
            site: None,
            location: None,
            console_site: None,
            settings: Settings::default(),
        };
        assert!(matches!(
            Change::PutDevice(d).check(),
            Err(Error::Invalid(_))
        ));
    }

    #[test]
    fn the_migrations_are_in_order() {
        assert!(MIGRATIONS.windows(2).all(|w| w[0].0 < w[1].0));
        assert_eq!(MIGRATIONS[0].0, 1);
    }

    #[test]
    fn a_route_takes_only_a_proxy_that_the_collector_reads() {
        let route = |proxy: &str| {
            Change::PutRoute(Route {
                name: "r".into(),
                proxy: Some(proxy.into()),
                proxy_credential: None,
                jumps: vec![],
            })
            .check()
        };
        assert!(route("socks5://[2001:db8::1]:1080").is_ok());
        assert!(route("http://proxy.example:3128/").is_ok());
        for bad in [
            "socks5://[2001:db8::1]",
            "http://proxy.example:abc",
            "http://proxy.example:70000",
            "http://:3128",
        ] {
            assert!(matches!(route(bad), Err(Error::Invalid(_))), "{bad}");
        }
    }
}
