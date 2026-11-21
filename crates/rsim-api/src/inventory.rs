//! The inventory routes: the device groups, the devices with their
//! inherited settings resolved, the credentials, the routes, the jump
//! hosts, the Equinix bindings and the audit log. A write is one
//! transaction of the inventory database with its audit records. The
//! secret of a managed credential comes only in a PUT body; the server
//! seals it with its secret key, and no answer gives it back.

use std::future::Future;
use std::sync::Arc;

use rsim_contract::schema;
use rsim_inventory::{
    AuditPage, Bindings, COLLECTOR_VENDORS, Change, CollectorTransport, Credential, CredentialKind,
    CredentialSource, Db, Device, EdgeDeviceBinding, Error, FabricPortBinding, Group, Inventory,
    JumpHost, ResolvedDevice, ResolvedDevices, Route, SecretInput, SecretKey,
};
use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::handler::{Request, Response, State};
use crate::openapi::Route as ApiRoute;
use crate::problem::{Problem, problem};

/// The actor of the audit records of a server with no sign-in.
pub const ACTOR: &str = "rsim-api";

/// The inventory database of a server and the runtime of its connection.
/// The handler runs on a worker thread and waits for each call.
#[derive(Clone, Debug)]
pub struct InventoryHandle {
    db: Arc<Db>,
    rt: tokio::runtime::Handle,
    key: Option<Arc<SecretKey>>,
}

impl InventoryHandle {
    pub fn new(db: Arc<Db>, rt: tokio::runtime::Handle) -> Self {
        InventoryHandle { db, rt, key: None }
    }

    /// The handle with the key that seals the secrets of the managed
    /// credentials.
    pub fn with_secret_key(mut self, key: SecretKey) -> Self {
        self.key = Some(Arc::new(key));
        self
    }

    pub(crate) fn run<F: Future>(&self, f: F) -> F::Output {
        self.rt.block_on(f)
    }

    /// The inventory database.
    pub(crate) fn db(&self) -> &Db {
        &self.db
    }
}

/// The answer of a write: the inventory version after it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WrittenOut {
    pub version: u64,
}

/// The PUT body of a credential: the record with the secret of a managed
/// credential. A managed credential with no secret keeps its stored secret
/// when the kind stays; a new managed credential and a new kind need the
/// secret.
#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CredentialPut {
    /// The name of the credential. It can be left out; the path gives it.
    #[serde(default)]
    pub name: String,
    pub source: CredentialSource,
    /// The key in the env file: the prefix of `env`, the variable of
    /// `env-url`. None for `managed`.
    #[serde(default)]
    pub key: Option<String>,
    /// The kind of the secret of `managed`.
    #[serde(default)]
    pub kind: Option<CredentialKind>,
    /// The user of `managed` with the kind `password` or `ssh-key`.
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// The revision of the stored record. The write ignores it.
    #[serde(default)]
    pub secret_revision: Option<u64>,
    /// The new secret of `managed`. No answer gives it back.
    #[serde(default)]
    pub secret: Option<SecretInput>,
}

impl CredentialPut {
    fn split(self) -> (Credential, Option<SecretInput>) {
        (
            Credential {
                name: self.name,
                source: self.source,
                key: self.key,
                kind: self.kind,
                user: self.user,
                description: self.description,
                secret_revision: None,
            },
            self.secret,
        )
    }
}

/// The secret key of the server.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SecretKeyOut {
    /// True if the server has a secret key, so that it can write the secret
    /// of a managed credential.
    pub present: bool,
}

/// The device groups at one version.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct GroupsOut {
    pub version: u64,
    pub groups: Vec<Group>,
}

/// The credential references at one version.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct CredentialsOut {
    pub version: u64,
    pub credentials: Vec<Credential>,
}

/// The routes at one version.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RoutesOut {
    pub version: u64,
    pub routes: Vec<Route>,
}

/// The jump hosts at one version.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct JumpHostsOut {
    pub version: u64,
    pub jump_hosts: Vec<JumpHost>,
}

/// The bindings at one version.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct BindingsOut {
    pub version: u64,
    pub bindings: Bindings,
}

/// A vendor that has a collector, with its transport.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct VendorOut {
    pub vendor: String,
    pub transport: CollectorTransport,
}

/// The vendors that have a collector, in name order.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct VendorsOut {
    pub vendors: Vec<VendorOut>,
}

fn vendors() -> VendorsOut {
    VendorsOut {
        vendors: COLLECTOR_VENDORS
            .iter()
            .map(|(v, t)| VendorOut {
                vendor: (*v).to_string(),
                transport: *t,
            })
            .collect(),
    }
}

const ONE: &[(&str, &str)] = &[];

/// The inventory routes, in a fixed order.
pub const ROUTES: &[ApiRoute] = &[
    ApiRoute {
        method: "get",
        path: "/v1/inventory",
        id: "getInventory",
        summary: "The whole inventory at its version: the credential references, the jump hosts, the routes, the groups, the devices as stored and the bindings.",
        query: ONE,
        body: &[],
        ok: (200, &[schema::<Inventory>]),
    },
    ApiRoute {
        method: "get",
        path: "/v1/inventory/vendors",
        id: "listVendors",
        summary: "The vendors that have a collector, each with its transport. A group of another vendor is allowed; the collector skips its devices.",
        query: ONE,
        body: &[],
        ok: (200, &[schema::<VendorsOut>]),
    },
    ApiRoute {
        method: "get",
        path: "/v1/inventory/groups",
        id: "listGroups",
        summary: "The device groups.",
        query: ONE,
        body: &[],
        ok: (200, &[schema::<GroupsOut>]),
    },
    ApiRoute {
        method: "get",
        path: "/v1/inventory/groups/{group}",
        id: "getGroup",
        summary: "A device group.",
        query: ONE,
        body: &[],
        ok: (200, &[schema::<Group>]),
    },
    ApiRoute {
        method: "put",
        path: "/v1/inventory/groups/{group}",
        id: "putGroup",
        summary: "Makes or replaces a device group. The path gives the name.",
        query: ONE,
        body: &[schema::<Group>],
        ok: (200, &[schema::<WrittenOut>]),
    },
    ApiRoute {
        method: "delete",
        path: "/v1/inventory/groups/{group}",
        id: "deleteGroup",
        summary: "Removes a device group with no device.",
        query: ONE,
        body: &[],
        ok: (200, &[schema::<WrittenOut>]),
    },
    ApiRoute {
        method: "get",
        path: "/v1/inventory/devices",
        id: "listDevices",
        summary: "The devices with the settings of their groups resolved: each setting has its value and its origin device, group or default.",
        query: ONE,
        body: &[],
        ok: (200, &[schema::<ResolvedDevices>]),
    },
    ApiRoute {
        method: "get",
        path: "/v1/inventory/devices/{device}",
        id: "getDevice",
        summary: "A device with the settings of its group resolved.",
        query: ONE,
        body: &[],
        ok: (200, &[schema::<ResolvedDevice>]),
    },
    ApiRoute {
        method: "put",
        path: "/v1/inventory/devices/{device}",
        id: "putDevice",
        summary: "Makes or replaces a device. A setting that is not given inherits from the group. The path gives the name.",
        query: ONE,
        body: &[schema::<Device>],
        ok: (200, &[schema::<WrittenOut>]),
    },
    ApiRoute {
        method: "delete",
        path: "/v1/inventory/devices/{device}",
        id: "deleteDevice",
        summary: "Removes a device with no binding.",
        query: ONE,
        body: &[],
        ok: (200, &[schema::<WrittenOut>]),
    },
    ApiRoute {
        method: "get",
        path: "/v1/inventory/credentials",
        id: "listCredentials",
        summary: "The credentials. No answer gives a secret.",
        query: ONE,
        body: &[],
        ok: (200, &[schema::<CredentialsOut>]),
    },
    ApiRoute {
        method: "put",
        path: "/v1/inventory/credentials/{credential}",
        id: "putCredential",
        summary: "Makes or replaces a credential: a key of the env file, or a managed credential with its kind, its user and its secret, which the server seals with its secret key.",
        query: ONE,
        body: &[schema::<CredentialPut>],
        ok: (200, &[schema::<WrittenOut>]),
    },
    ApiRoute {
        method: "delete",
        path: "/v1/inventory/credentials/{credential}",
        id: "deleteCredential",
        summary: "Removes a credential that nothing uses.",
        query: ONE,
        body: &[],
        ok: (200, &[schema::<WrittenOut>]),
    },
    ApiRoute {
        method: "get",
        path: "/v1/inventory/secret-key",
        id: "getSecretKey",
        summary: "Whether the server has a secret key.",
        query: ONE,
        body: &[],
        ok: (200, &[schema::<SecretKeyOut>]),
    },
    ApiRoute {
        method: "get",
        path: "/v1/inventory/routes",
        id: "listRoutes",
        summary: "The routes: the proxy and the jump hosts in order.",
        query: ONE,
        body: &[],
        ok: (200, &[schema::<RoutesOut>]),
    },
    ApiRoute {
        method: "put",
        path: "/v1/inventory/routes/{route}",
        id: "putRoute",
        summary: "Makes or replaces a route. A proxy URL holds no login; the login is a credential reference.",
        query: ONE,
        body: &[schema::<Route>],
        ok: (200, &[schema::<WrittenOut>]),
    },
    ApiRoute {
        method: "delete",
        path: "/v1/inventory/routes/{route}",
        id: "deleteRoute",
        summary: "Removes a route that no group and no device uses.",
        query: ONE,
        body: &[],
        ok: (200, &[schema::<WrittenOut>]),
    },
    ApiRoute {
        method: "get",
        path: "/v1/inventory/jump-hosts",
        id: "listJumpHosts",
        summary: "The SSH jump hosts.",
        query: ONE,
        body: &[],
        ok: (200, &[schema::<JumpHostsOut>]),
    },
    ApiRoute {
        method: "put",
        path: "/v1/inventory/jump-hosts/{jump_host}",
        id: "putJumpHost",
        summary: "Makes or replaces a jump host.",
        query: ONE,
        body: &[schema::<JumpHost>],
        ok: (200, &[schema::<WrittenOut>]),
    },
    ApiRoute {
        method: "delete",
        path: "/v1/inventory/jump-hosts/{jump_host}",
        id: "deleteJumpHost",
        summary: "Removes a jump host that no route uses.",
        query: ONE,
        body: &[],
        ok: (200, &[schema::<WrittenOut>]),
    },
    ApiRoute {
        method: "get",
        path: "/v1/inventory/bindings",
        id: "listBindings",
        summary: "The Equinix bindings: each Fabric port with its device port, and each Network Edge device with its device of the estate.",
        query: ONE,
        body: &[],
        ok: (200, &[schema::<BindingsOut>]),
    },
    ApiRoute {
        method: "put",
        path: "/v1/inventory/bindings/fabric-ports/{account}/{fabric_port}",
        id: "putFabricPortBinding",
        summary: "Binds a Fabric port of an account to a device port.",
        query: ONE,
        body: &[schema::<FabricPortBinding>],
        ok: (200, &[schema::<WrittenOut>]),
    },
    ApiRoute {
        method: "delete",
        path: "/v1/inventory/bindings/fabric-ports/{account}/{fabric_port}",
        id: "deleteFabricPortBinding",
        summary: "Removes the binding of a Fabric port.",
        query: ONE,
        body: &[],
        ok: (200, &[schema::<WrittenOut>]),
    },
    ApiRoute {
        method: "put",
        path: "/v1/inventory/bindings/edge-devices/{account}/{edge_device}",
        id: "putEdgeDeviceBinding",
        summary: "Binds a Network Edge device of an account to a device of the estate.",
        query: ONE,
        body: &[schema::<EdgeDeviceBinding>],
        ok: (200, &[schema::<WrittenOut>]),
    },
    ApiRoute {
        method: "delete",
        path: "/v1/inventory/bindings/edge-devices/{account}/{edge_device}",
        id: "deleteEdgeDeviceBinding",
        summary: "Removes the binding of a Network Edge device.",
        query: ONE,
        body: &[],
        ok: (200, &[schema::<WrittenOut>]),
    },
    ApiRoute {
        method: "get",
        path: "/v1/inventory/audit",
        id: "listAudit",
        summary: "The audit log, the newest record first: who changed which record when, with its old and its new value.",
        query: &[
            (
                "limit",
                "The records of a page, from 1 to 1000; 100 if not given.",
            ),
            (
                "before",
                "Only the records with an id below this id: the next_before of the page before.",
            ),
        ],
        body: &[],
        ok: (200, &[schema::<AuditPage>]),
    },
];

pub(crate) fn from_error(e: Error) -> Problem {
    match e {
        Error::NotFound(d) => problem(404, "not_found", d),
        Error::Conflict(d) => problem(409, "conflict", d),
        Error::Invalid(d) => problem(422, "invalid_record", d),
        Error::Schema(d) | Error::Database(d) => {
            eprintln!("inventory database: {d}");
            problem(
                503,
                "inventory_unavailable",
                "the inventory database cannot be used; the log of the server has the reason"
                    .into(),
            )
        }
    }
}

pub(crate) fn json_out<T: Serialize>(v: &T) -> Response {
    Response {
        status: 200,
        headers: vec![
            ("content-type".into(), "application/json".into()),
            ("cache-control".into(), "no-store".into()),
        ],
        body: rsim_contract::json::to_text(v, false).into_bytes(),
    }
}

/// A path segment with its percent encoding decoded.
pub(crate) fn decode(seg: &str) -> Result<String, Problem> {
    let b = seg.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = |c: u8| char::from(c).to_digit(16);
            match (
                b.get(i + 1).copied().and_then(hex),
                b.get(i + 2).copied().and_then(hex),
            ) {
                (Some(h), Some(l)) => {
                    out.push((h * 16 + l) as u8);
                    i += 3;
                    continue;
                }
                _ => {
                    return Err(problem(
                        404,
                        "not_found",
                        format!("{seg} is not a valid segment"),
                    ));
                }
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8(out).map_err(|_| problem(404, "not_found", format!("{seg} is not UTF-8")))
}

/// The body of a PUT, with the name of the path. A name in the body must be
/// the name of the path.
pub(crate) fn body<T: DeserializeOwned>(req: &Request) -> Result<T, Problem> {
    serde_json::from_slice(&req.body).map_err(|e| {
        problem(
            422,
            "invalid_body",
            format!("the body is not a valid record: {e}"),
        )
    })
}

fn named(field: &mut String, path: &str, what: &str) -> Result<(), Problem> {
    if field.is_empty() {
        *field = path.to_string();
        Ok(())
    } else if field == path {
        Ok(())
    } else {
        Err(problem(
            422,
            "invalid_body",
            format!("the {what} of the body is {field} and the path names {path}"),
        ))
    }
}

pub(crate) fn allow(req: &Request, methods: &[&str]) -> Result<(), Problem> {
    if methods.contains(&req.method.as_str()) {
        Ok(())
    } else {
        Err(problem(
            405,
            "method_not_allowed",
            format!(
                "{} is not allowed; use {}",
                req.method,
                methods.join(" or ")
            ),
        ))
    }
}

/// Handles a request below `/v1/inventory`; `rest` is the path after it.
/// A write records the name of the user of the request as its actor, or
/// `rsim-api` for a server with no sign-in.
pub fn route(
    state: &State,
    req: &Request,
    rest: &[&str],
    user: Option<&rsim_inventory::Principal>,
) -> Result<Response, Problem> {
    let actor = user.map_or(ACTOR, |u| u.name.as_str());
    if rest == ["vendors"] {
        allow(req, &["GET"])?;
        return Ok(json_out(&vendors()));
    }
    let Some(h) = state.inventory.as_ref() else {
        return Err(problem(
            404,
            "no_inventory",
            "the server has no inventory database; start it with --inventory".into(),
        ));
    };
    let segs: Vec<String> = rest.iter().map(|s| decode(s)).collect::<Result<_, _>>()?;
    let segs: Vec<&str> = segs.iter().map(String::as_str).collect();
    let load = || h.run(h.db.load()).map_err(from_error);
    let write = |changes: Vec<Change>| -> Result<Response, Problem> {
        let version = h.run(h.db.apply(actor, &changes)).map_err(from_error)?;
        Ok(json_out(&WrittenOut { version }))
    };
    let not_found =
        |what: &str, name: &str| problem(404, "not_found", format!("no {what} is named {name}"));
    match segs.as_slice() {
        [] => {
            allow(req, &["GET"])?;
            Ok(json_out(&load()?))
        }
        ["groups"] => {
            allow(req, &["GET"])?;
            let inv = load()?;
            Ok(json_out(&GroupsOut {
                version: inv.version,
                groups: inv.groups,
            }))
        }
        ["groups", name] => {
            allow(req, &["GET", "PUT", "DELETE"])?;
            match req.method.as_str() {
                "GET" => {
                    let inv = load()?;
                    let g = inv.group(name).ok_or_else(|| not_found("group", name))?;
                    Ok(json_out(g))
                }
                "PUT" => {
                    let mut g: Group = body(req)?;
                    named(&mut g.name, name, "name")?;
                    write(vec![Change::PutGroup(g)])
                }
                _ => write(vec![Change::DeleteGroup(name.to_string())]),
            }
        }
        ["devices"] => {
            allow(req, &["GET"])?;
            let inv = load()?;
            let devices = inv.resolve().map_err(|e| problem(500, "internal", e))?;
            Ok(json_out(&ResolvedDevices {
                version: inv.version,
                devices,
            }))
        }
        ["devices", name] => {
            allow(req, &["GET", "PUT", "DELETE"])?;
            match req.method.as_str() {
                "GET" => {
                    let inv = load()?;
                    let d = inv
                        .resolve()
                        .map_err(|e| problem(500, "internal", e))?
                        .into_iter()
                        .find(|d| d.name == *name)
                        .ok_or_else(|| not_found("device", name))?;
                    Ok(json_out(&d))
                }
                "PUT" => {
                    let mut d: Device = body(req)?;
                    named(&mut d.name, name, "name")?;
                    write(vec![Change::PutDevice(d)])
                }
                _ => write(vec![Change::DeleteDevice(name.to_string())]),
            }
        }
        ["credentials"] => {
            allow(req, &["GET"])?;
            let inv = load()?;
            Ok(json_out(&CredentialsOut {
                version: inv.version,
                credentials: inv.credentials,
            }))
        }
        ["credentials", name] => {
            allow(req, &["PUT", "DELETE"])?;
            if req.method == "PUT" {
                let put: CredentialPut = body(req)?;
                let (mut c, secret) = put.split();
                named(&mut c.name, name, "name")?;
                let sealed =
                    match secret {
                        None => None,
                        Some(secret) => {
                            let kind = c.kind.filter(|_| c.source == CredentialSource::Managed);
                            let kind = kind.ok_or_else(|| {
                            problem(
                                422,
                                "invalid_record",
                                format!(
                                    "the credential {} has a secret and is not managed with a kind",
                                    c.name
                                ),
                            )
                        })?;
                            secret.check(kind).map_err(|e| {
                                problem(
                                    422,
                                    "invalid_record",
                                    format!("the credential {}: {e}", c.name),
                                )
                            })?;
                            let key = h.key.as_ref().ok_or_else(|| {
                                problem(
                                    409,
                                    "no_secret_key",
                                    "rsim-api has no RSIM_SECRET_KEY".into(),
                                )
                            })?;
                            Some(key.seal(&c.name, kind, &secret).map_err(|e| {
                                problem(500, "internal", format!("the secret: {e}"))
                            })?)
                        }
                    };
                write(vec![Change::PutCredential(c, sealed)])
            } else {
                write(vec![Change::DeleteCredential(name.to_string())])
            }
        }
        ["secret-key"] => {
            allow(req, &["GET"])?;
            Ok(json_out(&SecretKeyOut {
                present: h.key.is_some(),
            }))
        }
        ["routes"] => {
            allow(req, &["GET"])?;
            let inv = load()?;
            Ok(json_out(&RoutesOut {
                version: inv.version,
                routes: inv.routes,
            }))
        }
        ["routes", name] => {
            allow(req, &["PUT", "DELETE"])?;
            if req.method == "PUT" {
                let mut r: Route = body(req)?;
                named(&mut r.name, name, "name")?;
                write(vec![Change::PutRoute(r)])
            } else {
                write(vec![Change::DeleteRoute(name.to_string())])
            }
        }
        ["jump-hosts"] => {
            allow(req, &["GET"])?;
            let inv = load()?;
            Ok(json_out(&JumpHostsOut {
                version: inv.version,
                jump_hosts: inv.jump_hosts,
            }))
        }
        ["jump-hosts", name] => {
            allow(req, &["PUT", "DELETE"])?;
            if req.method == "PUT" {
                let mut j: JumpHost = body(req)?;
                named(&mut j.name, name, "name")?;
                write(vec![Change::PutJumpHost(j)])
            } else {
                write(vec![Change::DeleteJumpHost(name.to_string())])
            }
        }
        ["bindings"] => {
            allow(req, &["GET"])?;
            let inv = load()?;
            Ok(json_out(&BindingsOut {
                version: inv.version,
                bindings: inv.bindings,
            }))
        }
        ["bindings", "fabric-ports", account, port] => {
            allow(req, &["PUT", "DELETE"])?;
            if req.method == "PUT" {
                let mut b: FabricPortBinding = body(req)?;
                named(&mut b.account, account, "account")?;
                named(&mut b.fabric_port, port, "fabric_port")?;
                write(vec![Change::PutFabricPort(b)])
            } else {
                write(vec![Change::DeleteFabricPort {
                    account: account.to_string(),
                    fabric_port: port.to_string(),
                }])
            }
        }
        ["bindings", "edge-devices", account, edge] => {
            allow(req, &["PUT", "DELETE"])?;
            if req.method == "PUT" {
                let mut b: EdgeDeviceBinding = body(req)?;
                named(&mut b.account, account, "account")?;
                named(&mut b.edge_device, edge, "edge_device")?;
                write(vec![Change::PutEdgeDevice(b)])
            } else {
                write(vec![Change::DeleteEdgeDevice {
                    account: account.to_string(),
                    edge_device: edge.to_string(),
                }])
            }
        }
        ["audit"] => {
            allow(req, &["GET"])?;
            let mut limit = 100;
            let mut before = None;
            for (k, v) in &req.query {
                let bad = || problem(422, "invalid_query", format!("{k}={v} is not a number"));
                match k.as_str() {
                    "limit" => limit = v.parse().map_err(|_| bad())?,
                    "before" => before = Some(v.parse().map_err(|_| bad())?),
                    _ => {}
                }
            }
            let page = h.run(h.db.audit(limit, before)).map_err(from_error)?;
            Ok(json_out(&page))
        }
        _ => Err(problem(
            404,
            "not_found",
            format!("{} is not a resource", req.path),
        )),
    }
}
