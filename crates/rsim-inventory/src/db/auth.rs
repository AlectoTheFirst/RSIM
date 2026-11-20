//! The users of `rsim-api`: the local accounts with their roles, the
//! sessions, the API tokens, the failed sign-ins and the sign-in events.
//! The database gives each time, so the expiry needs no clock of the
//! caller. A password is stored as its Argon2id hash, and a session token or
//! an API token as its SHA-256 hash.

use std::sync::OnceLock;

use argon2::Argon2;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};
use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tokio_postgres::GenericClient;

use super::{Db, Error, Result, check_schema};

/// The scope to read the twins, the tables, the queries and the claims.
pub const SCOPE_READ: &str = "rsim.read";
/// The scope to make and change what-if scenarios.
pub const SCOPE_SCENARIO_WRITE: &str = "rsim.scenario.write";
/// The scope to change the inventory.
pub const SCOPE_INVENTORY_WRITE: &str = "rsim.inventory.write";
/// The scope to manage the users and the tokens of other users.
pub const SCOPE_ADMIN: &str = "rsim.admin";
/// All scopes, in the order of the roles.
pub const SCOPES: [&str; 4] = [
    SCOPE_READ,
    SCOPE_SCENARIO_WRITE,
    SCOPE_INVENTORY_WRITE,
    SCOPE_ADMIN,
];

/// A session stops this long after its last use.
pub const SESSION_IDLE: &str = "12 hours";
/// A session stops this long after the sign-in.
pub const SESSION_MAX: &str = "7 days";
/// The lifetime of the session cookie in seconds: the longest life of a
/// session.
pub const SESSION_MAX_SECONDS: u64 = 7 * 24 * 3600;
/// The failed sign-ins of one user name or one client address that the
/// window accepts.
pub const SIGN_IN_FAILURES: i64 = 5;
/// The window of the failed sign-ins.
pub const SIGN_IN_WINDOW: &str = "15 minutes";
/// The shortest password.
pub const MIN_PASSWORD: usize = 12;
/// The longest password.
pub const MAX_PASSWORD: usize = 1024;
/// The prefix of an API token.
pub const TOKEN_PREFIX: &str = "rsim_";

/// The role of a user.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Reads the twins.
    Viewer,
    /// Reads the twins and writes what-if scenarios.
    Operator,
    /// Each scope, the inventory and the users included.
    Admin,
}

impl Role {
    pub fn word(self) -> &'static str {
        match self {
            Role::Viewer => "viewer",
            Role::Operator => "operator",
            Role::Admin => "admin",
        }
    }

    pub fn parse(s: &str) -> Option<Role> {
        match s {
            "viewer" => Some(Role::Viewer),
            "operator" => Some(Role::Operator),
            "admin" => Some(Role::Admin),
            _ => None,
        }
    }

    /// The scopes of the role.
    pub fn scopes(self) -> &'static [&'static str] {
        match self {
            Role::Viewer => &SCOPES[..1],
            Role::Operator => &SCOPES[..2],
            Role::Admin => &SCOPES[..],
        }
    }
}

/// How a request proved its user.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Via {
    /// The session cookie of a browser.
    Session,
    /// An API token with its id.
    Token(i64),
}

/// The user of a request with the scopes that the request has: the scopes
/// of the role, and for a token only those that the token also names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal {
    pub user_id: i64,
    pub name: String,
    pub role: Role,
    pub scopes: Vec<String>,
    pub via: Via,
}

impl Principal {
    pub fn has(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }
}

/// A user as an admin sees it. The password hash is not part of it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct User {
    pub name: String,
    pub role: Role,
    pub disabled: bool,
    pub created_at: String,
}

/// An API token as its user sees it. The token text is given only once,
/// when the token is made.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TokenInfo {
    pub id: i64,
    pub name: String,
    pub scopes: Vec<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub last_used_at: Option<String>,
    pub revoked: bool,
}

/// One sign-in event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AuthEvent {
    pub id: i64,
    pub at: String,
    pub event: String,
    pub actor: Option<String>,
    pub subject: Option<String>,
    pub client: Option<String>,
    pub detail: Option<String>,
}

/// A page of the sign-in events, the newest first.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AuthEventPage {
    pub events: Vec<AuthEvent>,
    pub next_before: Option<i64>,
}

/// The account of a user name for a sign-in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    pub user_id: i64,
    pub role: Role,
    pub password_hash: String,
    pub disabled: bool,
}

/// A secret of 32 random bytes as 64 hex digits after a prefix, and its
/// SHA-256 hash.
pub fn new_secret(prefix: &str) -> Result<(String, Vec<u8>)> {
    let mut b = [0u8; 32];
    SystemRandom::new()
        .fill(&mut b)
        .map_err(|_| Error::Database("no random bytes".into()))?;
    let mut text = String::with_capacity(prefix.len() + 64);
    text.push_str(prefix);
    for x in b {
        text.push_str(&format!("{x:02x}"));
    }
    let hash = secret_hash(&text);
    Ok((text, hash))
}

/// The SHA-256 hash of a session token or an API token.
pub fn secret_hash(text: &str) -> Vec<u8> {
    digest(&SHA256, text.as_bytes()).as_ref().to_vec()
}

/// The rules of a password: 12 to 1024 characters.
pub fn check_password(password: &str) -> Result<()> {
    let n = password.chars().count();
    if n < MIN_PASSWORD {
        return Err(Error::Invalid(format!(
            "the password has {n} characters; it needs at least {MIN_PASSWORD}"
        )));
    }
    if n > MAX_PASSWORD {
        return Err(Error::Invalid(format!(
            "the password has more than {MAX_PASSWORD} characters"
        )));
    }
    Ok(())
}

/// The Argon2id hash of a password with a random salt, after the rules of
/// [`check_password`].
pub fn hash_password(password: &str) -> Result<String> {
    check_password(password)?;
    Argon2::default()
        .hash_password(password.as_bytes())
        .map(|h| h.to_string())
        .map_err(|e| Error::Invalid(format!("the password hash: {e}")))
}

/// True if the password matches the hash.
pub fn verify_password(password: &str, hash: &str) -> bool {
    Argon2::default()
        .verify_password(password.as_bytes(), hash)
        .is_ok()
}

/// Spends the time of one password check, for a user name with no account,
/// so that the time of an answer does not tell if the user exists.
pub fn verify_nothing(password: &str) {
    static DUMMY: OnceLock<Option<String>> = OnceLock::new();
    if let Some(h) = DUMMY.get_or_init(|| hash_password("rsim-no-such-user-password").ok()) {
        let _ = verify_password(password, h);
    }
}

/// True for a valid user name: a lower-case letter or digit, then up to 63
/// lower-case letters, digits, `.`, `_`, `@` and `-`.
pub fn valid_user_name(name: &str) -> bool {
    let b = name.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'@' | b'-')
        })
}

fn check_user_name(name: &str) -> Result<()> {
    if valid_user_name(name) {
        Ok(())
    } else {
        Err(Error::Invalid(format!(
            "{name:?} is not a user name: lower-case letters, digits, '.', '_', '@' and '-', at most 64"
        )))
    }
}

const TIME: &str = "'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'";

fn time(col: &str) -> String {
    format!("to_char({col} AT TIME ZONE 'UTC', {TIME})")
}

fn role_of(s: &str) -> Result<Role> {
    Role::parse(s).ok_or_else(|| Error::Database(format!("the role {s} is not known")))
}

/// The scopes of a token that its role still gives, in the order of
/// [`SCOPES`].
fn effective(role: Role, token: Option<&[String]>) -> Vec<String> {
    role.scopes()
        .iter()
        .filter(|s| token.is_none_or(|t| t.iter().any(|x| x == *s)))
        .map(|s| s.to_string())
        .collect()
}

async fn event(
    c: &impl GenericClient,
    event: &str,
    actor: Option<&str>,
    subject: Option<&str>,
    client: Option<&str>,
    detail: Option<&str>,
) -> Result<()> {
    c.execute(
        "INSERT INTO auth_events (event, actor, subject, client, detail)
         VALUES ($1, $2, $3, $4, $5)",
        &[&event, &actor, &subject, &client, &detail],
    )
    .await?;
    Ok(())
}

/// The count of enabled admins other than the user `name`.
async fn other_admins(c: &impl GenericClient, name: &str) -> Result<i64> {
    Ok(c.query_one(
        "SELECT count(*) FROM users WHERE role = 'admin' AND NOT disabled AND name <> $1",
        &[&name],
    )
    .await?
    .get(0))
}

/// The key of the advisory lock of the sign-in attempts.
const SIGN_IN_LOCK: i64 = 0x7273_696d_5f6c_6f67;

/// The start of a sign-in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Attempt {
    /// The limit of the window is reached: the seconds to wait.
    Wait(u64),
    /// The attempt is recorded with this id; check the password.
    Go(i64),
}

async fn sign_in_wait(
    c: &impl GenericClient,
    name: &str,
    client_addr: &str,
) -> Result<Option<u64>> {
    let sql = format!(
        "SELECT ceil(extract(epoch FROM (at + interval '{SIGN_IN_WINDOW}' - now())))::bigint
         FROM login_failures
         WHERE {{col}} = $1 AND at > now() - interval '{SIGN_IN_WINDOW}'
         ORDER BY at DESC OFFSET $2 LIMIT 1"
    );
    let mut wait: Option<i64> = None;
    for (col, value) in [("name", name), ("client", client_addr)] {
        if col == "name" && !valid_user_name(value) {
            continue;
        }
        let row = c
            .query_opt(
                &sql.replace("{col}", col),
                &[&value, &(SIGN_IN_FAILURES - 1)],
            )
            .await?;
        if let Some(r) = row {
            let s: i64 = r.get(0);
            wait = Some(wait.map_or(s, |w| w.max(s)));
        }
    }
    Ok(wait.map(|w| w.max(1) as u64))
}

impl Db {
    /// True while the database has no user: the one-time setup is open.
    pub async fn setup_open(&self) -> Result<bool> {
        let mut slot = self.client.lock().await;
        let client = self.client(&mut slot).await?;
        check_schema(&*client).await?;
        let n: i64 = client
            .query_one("SELECT count(*) FROM users", &[])
            .await?
            .get(0);
        Ok(n == 0)
    }

    /// Makes the first user, an admin, with a session, while the database
    /// has no user. A lock on the table makes sure that only one request
    /// makes it. `Conflict` when a user exists.
    pub async fn setup(
        &self,
        name: &str,
        password_hash: &str,
        session_hash: &[u8],
        client_addr: &str,
    ) -> Result<Principal> {
        check_user_name(name)?;
        let mut slot = self.client.lock().await;
        let client = self.client(&mut slot).await?;
        let tx = client.transaction().await?;
        check_schema(&tx).await?;
        tx.batch_execute("LOCK TABLE users IN EXCLUSIVE MODE")
            .await?;
        let n: i64 = tx
            .query_one("SELECT count(*) FROM users", &[])
            .await?
            .get(0);
        if n > 0 {
            return Err(Error::Conflict("the setup is done: a user exists".into()));
        }
        let id: i64 = tx
            .query_one(
                "INSERT INTO users (name, role, password_hash) VALUES ($1, 'admin', $2) RETURNING id",
                &[&name, &password_hash],
            )
            .await?
            .get(0);
        tx.execute(
            "INSERT INTO sessions (token_hash, user_id) VALUES ($1, $2)",
            &[&session_hash, &id],
        )
        .await?;
        event(
            &tx,
            "setup",
            Some(name),
            Some(name),
            Some(client_addr),
            None,
        )
        .await?;
        tx.commit().await?;
        Ok(Principal {
            user_id: id,
            name: name.to_string(),
            role: Role::Admin,
            scopes: effective(Role::Admin, None),
            via: Via::Session,
        })
    }

    /// The account of a user name, if any.
    pub async fn account(&self, name: &str) -> Result<Option<Account>> {
        let mut slot = self.client.lock().await;
        let client = self.client(&mut slot).await?;
        check_schema(&*client).await?;
        let row = client
            .query_opt(
                "SELECT id, role, password_hash, disabled FROM users WHERE name = $1",
                &[&name],
            )
            .await?;
        row.map(|r| {
            Ok(Account {
                user_id: r.get(0),
                role: role_of(r.get(1))?,
                password_hash: r.get(2),
                disabled: r.get(3),
            })
        })
        .transpose()
    }

    /// The seconds to wait before the next sign-in of a user name or a
    /// client address, or `None` when the attempts of both are below the
    /// limit of the window.
    pub async fn sign_in_wait(&self, name: &str, client_addr: &str) -> Result<Option<u64>> {
        let mut slot = self.client.lock().await;
        let client = self.client(&mut slot).await?;
        sign_in_wait(&*client, name, client_addr).await
    }

    /// Starts a sign-in of a user name from a client address: in one
    /// transaction under a lock, the wait of [`Db::sign_in_wait`], or a
    /// record of the attempt in the failures of the window before the
    /// password check, so that parallel attempts cannot pass the limit. A
    /// success removes the record with [`Db::forget_attempt`]. A name that
    /// is not a valid user name is recorded as the empty name, so that a
    /// password typed into the name field is not stored.
    pub async fn begin_sign_in(&self, name: &str, client_addr: &str) -> Result<Attempt> {
        let mut slot = self.client.lock().await;
        let client = self.client(&mut slot).await?;
        let tx = client.transaction().await?;
        check_schema(&tx).await?;
        tx.execute("SELECT pg_advisory_xact_lock($1)", &[&SIGN_IN_LOCK])
            .await?;
        if let Some(w) = sign_in_wait(&tx, name, client_addr).await? {
            tx.commit().await?;
            return Ok(Attempt::Wait(w));
        }
        let stored = if valid_user_name(name) { name } else { "" };
        let id: i64 = tx
            .query_one(
                "INSERT INTO login_failures (name, client) VALUES ($1, $2) RETURNING id",
                &[&stored, &client_addr],
            )
            .await?
            .get(0);
        tx.execute(
            "DELETE FROM login_failures WHERE at < now() - interval '1 day'",
            &[],
        )
        .await?;
        tx.commit().await?;
        Ok(Attempt::Go(id))
    }

    /// Removes the record of a sign-in attempt that succeeded.
    pub async fn forget_attempt(&self, id: i64) -> Result<()> {
        let mut slot = self.client.lock().await;
        let client = self.client(&mut slot).await?;
        client
            .execute("DELETE FROM login_failures WHERE id = $1", &[&id])
            .await?;
        Ok(())
    }

    /// Records the event of a failed sign-in. Its attempt stays in the
    /// failures of the window.
    pub async fn sign_in_failed(&self, name: &str, client_addr: &str) -> Result<()> {
        let subject = valid_user_name(name).then_some(name);
        let mut slot = self.client.lock().await;
        let client = self.client(&mut slot).await?;
        event(
            &*client,
            "sign_in_failed",
            None,
            subject,
            Some(client_addr),
            None,
        )
        .await
    }

    /// Starts a session of a user after a sign-in, and removes the expired
    /// sessions.
    pub async fn start_session(
        &self,
        user_id: i64,
        name: &str,
        session_hash: &[u8],
        client_addr: &str,
    ) -> Result<()> {
        let mut slot = self.client.lock().await;
        let client = self.client(&mut slot).await?;
        let tx = client.transaction().await?;
        check_schema(&tx).await?;
        tx.execute(
            &format!(
                "DELETE FROM sessions WHERE last_used_at < now() - interval '{SESSION_IDLE}'
                 OR created_at < now() - interval '{SESSION_MAX}'"
            ),
            &[],
        )
        .await?;
        tx.execute(
            "INSERT INTO sessions (token_hash, user_id) VALUES ($1, $2)",
            &[&session_hash, &user_id],
        )
        .await?;
        event(
            &tx,
            "sign_in",
            Some(name),
            Some(name),
            Some(client_addr),
            None,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// The user of a valid session, which the call marks as used. `None`
    /// for an unknown or expired session or a disabled user.
    pub async fn session(&self, session_hash: &[u8]) -> Result<Option<Principal>> {
        let mut slot = self.client.lock().await;
        let client = self.client(&mut slot).await?;
        let row = client
            .query_opt(
                &format!(
                    "WITH s AS (
                         UPDATE sessions SET last_used_at = now()
                         WHERE token_hash = $1
                           AND last_used_at > now() - interval '{SESSION_IDLE}'
                           AND created_at > now() - interval '{SESSION_MAX}'
                         RETURNING user_id)
                     SELECT u.id, u.name, u.role FROM s JOIN users u ON u.id = s.user_id
                     WHERE NOT u.disabled"
                ),
                &[&session_hash],
            )
            .await?;
        row.map(|r| {
            let role = role_of(r.get(2))?;
            Ok(Principal {
                user_id: r.get(0),
                name: r.get(1),
                role,
                scopes: effective(role, None),
                via: Via::Session,
            })
        })
        .transpose()
    }

    /// Ends a session.
    pub async fn end_session(&self, session_hash: &[u8], client_addr: &str) -> Result<()> {
        let mut slot = self.client.lock().await;
        let client = self.client(&mut slot).await?;
        let tx = client.transaction().await?;
        let row = tx
            .query_opt(
                "DELETE FROM sessions s USING users u
                 WHERE s.token_hash = $1 AND u.id = s.user_id RETURNING u.name",
                &[&session_hash],
            )
            .await?;
        if let Some(r) = row {
            let name: String = r.get(0);
            event(
                &tx,
                "sign_out",
                Some(&name),
                Some(&name),
                Some(client_addr),
                None,
            )
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// The user of a valid API token, which the call marks as used, with
    /// the scopes that both the token and the role give. `None` for an
    /// unknown, revoked or expired token or a disabled user.
    pub async fn api_token(&self, token_hash: &[u8]) -> Result<Option<Principal>> {
        let mut slot = self.client.lock().await;
        let client = self.client(&mut slot).await?;
        let row = client
            .query_opt(
                "WITH t AS (
                     UPDATE api_tokens SET last_used_at = now()
                     WHERE token_hash = $1 AND NOT revoked
                       AND (expires_at IS NULL OR expires_at > now())
                     RETURNING id, user_id, scopes)
                 SELECT t.id, u.id, u.name, u.role, t.scopes FROM t JOIN users u ON u.id = t.user_id
                 WHERE NOT u.disabled",
                &[&token_hash],
            )
            .await?;
        row.map(|r| {
            let role = role_of(r.get(3))?;
            let scopes: Vec<String> = r.get(4);
            Ok(Principal {
                user_id: r.get(1),
                name: r.get(2),
                role,
                scopes: effective(role, Some(&scopes)),
                via: Via::Token(r.get(0)),
            })
        })
        .transpose()
    }

    /// Makes an API token of a user with a hash of its text. The scopes
    /// must be scopes of the role of the user. `expires_days` of `None`
    /// makes a token with no expiry.
    pub async fn create_token(
        &self,
        user: &Principal,
        name: &str,
        scopes: &[String],
        expires_days: Option<u32>,
        token_hash: &[u8],
    ) -> Result<TokenInfo> {
        let name = name.trim();
        if name.is_empty() || name.chars().count() > 100 {
            return Err(Error::Invalid(
                "the token name has 1 to 100 characters".into(),
            ));
        }
        if scopes.is_empty() {
            return Err(Error::Invalid("the token has no scope".into()));
        }
        for s in scopes {
            if !user.role.scopes().contains(&s.as_str()) {
                return Err(Error::Invalid(format!(
                    "the role {} does not give the scope {s}",
                    user.role.word()
                )));
            }
        }
        let mut scopes: Vec<String> = scopes.to_vec();
        scopes.sort_by_key(|s| SCOPES.iter().position(|x| x == s));
        scopes.dedup();
        let days = expires_days.map(|d| i32::try_from(d.clamp(1, 3650)).unwrap_or(3650));
        let mut slot = self.client.lock().await;
        let client = self.client(&mut slot).await?;
        let tx = client.transaction().await?;
        check_schema(&tx).await?;
        let row = tx
            .query_one(
                &format!(
                    "INSERT INTO api_tokens (token_hash, user_id, name, scopes, expires_at)
                     VALUES ($1, $2, $3, $4,
                             CASE WHEN $5::int IS NULL THEN NULL
                                  ELSE now() + make_interval(days => $5::int) END)
                     RETURNING id, {}, {}",
                    time("created_at"),
                    time("expires_at")
                ),
                &[&token_hash, &user.user_id, &name, &scopes, &days],
            )
            .await?;
        let id: i64 = row.get(0);
        event(
            &tx,
            "token_created",
            Some(&user.name),
            Some(&id.to_string()),
            None,
            Some(name),
        )
        .await?;
        tx.commit().await?;
        Ok(TokenInfo {
            id,
            name: name.to_string(),
            scopes,
            created_at: row.get(1),
            expires_at: row.get(2),
            last_used_at: None,
            revoked: false,
        })
    }

    /// The API tokens of a user, the newest first.
    pub async fn tokens(&self, user_id: i64) -> Result<Vec<TokenInfo>> {
        let mut slot = self.client.lock().await;
        let client = self.client(&mut slot).await?;
        let rows = client
            .query(
                &format!(
                    "SELECT id, name, scopes, {}, {}, {}, revoked FROM api_tokens
                     WHERE user_id = $1 ORDER BY id DESC",
                    time("created_at"),
                    time("expires_at"),
                    time("last_used_at")
                ),
                &[&user_id],
            )
            .await?;
        Ok(rows
            .iter()
            .map(|r| TokenInfo {
                id: r.get(0),
                name: r.get(1),
                scopes: r.get(2),
                created_at: r.get(3),
                expires_at: r.get(4),
                last_used_at: r.get(5),
                revoked: r.get(6),
            })
            .collect())
    }

    /// Revokes an API token of a user. `NotFound` for a token of another
    /// user.
    pub async fn revoke_token(&self, user: &Principal, id: i64) -> Result<()> {
        let mut slot = self.client.lock().await;
        let client = self.client(&mut slot).await?;
        let tx = client.transaction().await?;
        let n = tx
            .execute(
                "UPDATE api_tokens SET revoked = true WHERE id = $1 AND user_id = $2",
                &[&id, &user.user_id],
            )
            .await?;
        if n == 0 {
            return Err(Error::NotFound(format!(
                "the token {id} is not a token of the user"
            )));
        }
        event(
            &tx,
            "token_revoked",
            Some(&user.name),
            Some(&id.to_string()),
            None,
            None,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// The users in name order.
    pub async fn users(&self) -> Result<Vec<User>> {
        let mut slot = self.client.lock().await;
        let client = self.client(&mut slot).await?;
        check_schema(&*client).await?;
        let rows = client
            .query(
                &format!(
                    "SELECT name, role, disabled, {} FROM users ORDER BY name",
                    time("created_at")
                ),
                &[],
            )
            .await?;
        rows.iter()
            .map(|r| {
                Ok(User {
                    name: r.get(0),
                    role: role_of(r.get(1))?,
                    disabled: r.get(2),
                    created_at: r.get(3),
                })
            })
            .collect()
    }

    /// Makes a user or changes it. A new user needs a password hash. A new
    /// password or a disabled user ends the sessions of the user. The last
    /// enabled admin cannot lose the role or be disabled.
    pub async fn put_user(
        &self,
        actor: &str,
        name: &str,
        role: Role,
        disabled: bool,
        password_hash: Option<&str>,
    ) -> Result<User> {
        check_user_name(name)?;
        let mut slot = self.client.lock().await;
        let client = self.client(&mut slot).await?;
        let tx = client.transaction().await?;
        check_schema(&tx).await?;
        tx.batch_execute("LOCK TABLE users IN EXCLUSIVE MODE")
            .await?;
        let old = tx
            .query_opt(
                "SELECT id, role, disabled FROM users WHERE name = $1",
                &[&name],
            )
            .await?;
        let still_admin = role == Role::Admin && !disabled;
        let id: i64 = match &old {
            None => {
                let hash = password_hash
                    .ok_or_else(|| Error::Invalid("a new user needs a password".into()))?;
                let id = tx
                    .query_one(
                        "INSERT INTO users (name, role, password_hash, disabled)
                         VALUES ($1, $2, $3, $4) RETURNING id",
                        &[&name, &role.word(), &hash, &disabled],
                    )
                    .await?
                    .get(0);
                event(
                    &tx,
                    "user_created",
                    Some(actor),
                    Some(name),
                    None,
                    Some(role.word()),
                )
                .await?;
                id
            }
            Some(r) => {
                let id: i64 = r.get(0);
                let was: String = r.get(1);
                let was_disabled: bool = r.get(2);
                if was == "admin"
                    && !was_disabled
                    && !still_admin
                    && other_admins(&tx, name).await? == 0
                {
                    return Err(Error::Conflict(format!("{name} is the last enabled admin")));
                }
                tx.execute(
                    "UPDATE users SET role = $2, disabled = $3,
                         password_hash = coalesce($4, password_hash)
                     WHERE id = $1",
                    &[&id, &role.word(), &disabled, &password_hash],
                )
                .await?;
                if disabled || password_hash.is_some() {
                    tx.execute("DELETE FROM sessions WHERE user_id = $1", &[&id])
                        .await?;
                }
                let detail = format!(
                    "role {}{}{}",
                    role.word(),
                    if disabled { ", disabled" } else { "" },
                    if password_hash.is_some() {
                        ", new password"
                    } else {
                        ""
                    }
                );
                event(
                    &tx,
                    "user_changed",
                    Some(actor),
                    Some(name),
                    None,
                    Some(&detail),
                )
                .await?;
                id
            }
        };
        let row = tx
            .query_one(
                &format!(
                    "SELECT name, role, disabled, {} FROM users WHERE id = $1",
                    time("created_at")
                ),
                &[&id],
            )
            .await?;
        tx.commit().await?;
        Ok(User {
            name: row.get(0),
            role: role_of(row.get(1))?,
            disabled: row.get(2),
            created_at: row.get(3),
        })
    }

    /// Removes a user with the sessions and the tokens of the user. The
    /// last enabled admin cannot be removed.
    pub async fn delete_user(&self, actor: &str, name: &str) -> Result<()> {
        let mut slot = self.client.lock().await;
        let client = self.client(&mut slot).await?;
        let tx = client.transaction().await?;
        check_schema(&tx).await?;
        tx.batch_execute("LOCK TABLE users IN EXCLUSIVE MODE")
            .await?;
        let row = tx
            .query_opt("SELECT role, disabled FROM users WHERE name = $1", &[&name])
            .await?
            .ok_or_else(|| Error::NotFound(format!("{name} is not a user")))?;
        let role: String = row.get(0);
        let disabled: bool = row.get(1);
        if role == "admin" && !disabled && other_admins(&tx, name).await? == 0 {
            return Err(Error::Conflict(format!("{name} is the last enabled admin")));
        }
        tx.execute("DELETE FROM users WHERE name = $1", &[&name])
            .await?;
        event(&tx, "user_deleted", Some(actor), Some(name), None, None).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Records a refused request of a user, or of no user.
    pub async fn refused(
        &self,
        actor: Option<&str>,
        path: &str,
        client_addr: &str,
        detail: &str,
    ) -> Result<()> {
        let mut slot = self.client.lock().await;
        let client = self.client(&mut slot).await?;
        let path: String = path.chars().take(200).collect();
        let path = path.as_str();
        event(
            &*client,
            "refused",
            actor,
            Some(path),
            Some(client_addr),
            Some(detail),
        )
        .await
    }

    /// A page of the sign-in events, the newest first: at most `limit`
    /// events with an id below `before`.
    pub async fn auth_events(&self, limit: u32, before: Option<i64>) -> Result<AuthEventPage> {
        let mut slot = self.client.lock().await;
        let client = self.client(&mut slot).await?;
        let limit = i64::from(limit.clamp(1, 1000));
        let rows = client
            .query(
                &format!(
                    "SELECT id, {}, event, actor, subject, client, detail FROM auth_events
                     WHERE ($1::bigint IS NULL OR id < $1) ORDER BY id DESC LIMIT $2",
                    time("at")
                ),
                &[&before, &(limit + 1)],
            )
            .await?;
        let events: Vec<AuthEvent> = rows
            .iter()
            .take(limit as usize)
            .map(|r| AuthEvent {
                id: r.get(0),
                at: r.get(1),
                event: r.get(2),
                actor: r.get(3),
                subject: r.get(4),
                client: r.get(5),
                detail: r.get(6),
            })
            .collect();
        let next_before = (rows.len() as i64 > limit)
            .then(|| events.last().map(|e| e.id))
            .flatten();
        Ok(AuthEventPage {
            events,
            next_before,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roles_give_nested_scopes() {
        assert_eq!(Role::Viewer.scopes(), ["rsim.read"]);
        assert_eq!(
            Role::Operator.scopes(),
            ["rsim.read", "rsim.scenario.write"]
        );
        assert_eq!(Role::Admin.scopes(), SCOPES);
    }

    #[test]
    fn a_token_keeps_only_the_scopes_of_its_role() {
        let t = vec!["rsim.admin".to_string(), "rsim.read".to_string()];
        assert_eq!(effective(Role::Viewer, Some(&t)), ["rsim.read"]);
        assert_eq!(
            effective(Role::Admin, Some(&t)),
            ["rsim.read", "rsim.admin"]
        );
    }

    #[test]
    fn a_password_hash_verifies_only_its_password() {
        let h = hash_password("correct horse battery").unwrap();
        assert!(h.starts_with("$argon2id$"));
        assert!(verify_password("correct horse battery", &h));
        assert!(!verify_password("correct horse batterz", &h));
        assert!(hash_password("short").is_err());
    }

    #[test]
    fn a_secret_has_its_prefix_and_its_hash() {
        let (t, h) = new_secret(TOKEN_PREFIX).unwrap();
        assert!(t.starts_with("rsim_") && t.len() == 5 + 64);
        assert_eq!(h, secret_hash(&t));
        let (u, _) = new_secret(TOKEN_PREFIX).unwrap();
        assert_ne!(t, u);
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[tokio::test]
    async fn sessions_and_tokens_expire() {
        let Some(db) = crate::test_database("auth_expiry").await else {
            return;
        };
        let hash = hash_password("a long test password").unwrap();
        let (_, idle) = new_secret("").unwrap();
        let admin = db.setup("admin", &hash, &idle, "192.0.2.1").await.unwrap();
        let (_, old) = new_secret("").unwrap();
        db.start_session(admin.user_id, "admin", &old, "192.0.2.1")
            .await
            .unwrap();
        let (_, fresh) = new_secret("").unwrap();
        db.start_session(admin.user_id, "admin", &fresh, "192.0.2.1")
            .await
            .unwrap();
        db.batch(&format!(
            "UPDATE sessions SET last_used_at = now() - interval '13 hours'
             WHERE token_hash = '\\x{}';
             UPDATE sessions SET created_at = now() - interval '8 days'
             WHERE token_hash = '\\x{}'",
            hex(&idle),
            hex(&old)
        ))
        .await
        .unwrap();
        assert_eq!(db.session(&idle).await.unwrap(), None);
        assert_eq!(db.session(&old).await.unwrap(), None);
        assert!(db.session(&fresh).await.unwrap().is_some());

        let (_, t) = new_secret(TOKEN_PREFIX).unwrap();
        db.create_token(&admin, "short", &admin.scopes, Some(1), &t)
            .await
            .unwrap();
        assert!(db.api_token(&t).await.unwrap().is_some());
        db.batch(&format!(
            "UPDATE api_tokens SET expires_at = now() - interval '1 second'
             WHERE token_hash = '\\x{}'",
            hex(&t)
        ))
        .await
        .unwrap();
        assert_eq!(db.api_token(&t).await.unwrap(), None);
    }

    #[tokio::test]
    async fn the_database_holds_the_hash_of_a_token_and_not_its_text() {
        let Some(db) = crate::test_database("auth_hash_only").await else {
            return;
        };
        let hash = hash_password("a long test password").unwrap();
        let (session, session_hash) = new_secret("").unwrap();
        let admin = db
            .setup("admin", &hash, &session_hash, "192.0.2.1")
            .await
            .unwrap();
        let (token, token_hash) = new_secret(TOKEN_PREFIX).unwrap();
        db.create_token(&admin, "t", &admin.scopes, None, &token_hash)
            .await
            .unwrap();
        let mut slot = db.client.lock().await;
        let c: &tokio_postgres::Client = db.client(&mut slot).await.unwrap();
        for (table, text, hash) in [
            ("api_tokens", &token, &token_hash),
            ("sessions", &session, &session_hash),
        ] {
            let count = |v: Vec<u8>| {
                let sql = format!("SELECT count(*) FROM {table} WHERE token_hash = $1");
                async move { c.query_one(&sql, &[&v]).await.unwrap().get::<_, i64>(0) }
            };
            assert_eq!(count(hash.clone()).await, 1, "{table}");
            assert_eq!(count(text.as_bytes().to_vec()).await, 0, "{table}");
            let row = c
                .query_one(&format!("SELECT count(*) FROM {table} WHERE position($1::bytea in token_hash) > 0 OR position(convert_to($2, 'UTF8') in token_hash) > 0"), &[&text.as_bytes(), &text])
                .await
                .unwrap();
            assert_eq!(row.get::<_, i64>(0), 0, "{table}");
        }
        let users = c
            .query_one("SELECT password_hash FROM users", &[])
            .await
            .unwrap();
        let stored: String = users.get(0);
        assert!(stored.starts_with("$argon2id$") && !stored.contains("a long test password"));
    }

    #[tokio::test]
    async fn a_failed_sign_in_keeps_no_text_that_is_not_a_user_name() {
        let Some(db) = crate::test_database("auth_failure_name").await else {
            return;
        };
        db.begin_sign_in("My Secret Password 1", "192.0.2.9")
            .await
            .unwrap();
        db.sign_in_failed("My Secret Password 1", "192.0.2.9")
            .await
            .unwrap();
        {
            let mut slot = db.client.lock().await;
            let c = db.client(&mut slot).await.unwrap();
            let names: Vec<String> = c
                .query("SELECT name FROM login_failures", &[])
                .await
                .unwrap()
                .iter()
                .map(|r| r.get(0))
                .collect();
            assert_eq!(names, [""]);
        }
        db.sign_in_failed("admin", "192.0.2.9").await.unwrap();
        let page = db.auth_events(10, None).await.unwrap();
        let subjects: Vec<Option<String>> = page.events.iter().map(|e| e.subject.clone()).collect();
        assert_eq!(subjects, [Some("admin".to_string()), None]);
    }

    #[test]
    fn user_names() {
        assert!(valid_user_name("chris"));
        assert!(valid_user_name("ops.bot@home"));
        assert!(!valid_user_name("Chris"));
        assert!(!valid_user_name(".x"));
        assert!(!valid_user_name(""));
    }
}
