//! The inventory routes: the device groups, the devices with their
//! inherited settings resolved, the credentials, the routes, the jump
//! hosts, the Equinix bindings, the settings of the collector and the audit
//! log. A write is one transaction of the inventory database with its audit
//! records. The secret of a managed credential comes only in a PUT body; the
//! server seals it with its secret key, and no answer gives it back.

use std::future::Future;
use std::sync::Arc;

use rsim_contract::schema;
use rsim_inventory::{
    AuditPage, Bindings, COLLECTOR_VENDORS, Change, Collection, CollectorTransport, Credential,
    CredentialKind, CredentialSource, Db, Device, EdgeDeviceBinding, Error, FabricPortBinding,
    Group, Inventory, JumpHost, ResolvedDevice, ResolvedDevices, Route, SecretInput, SecretKey,
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

/// Write result
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct WrittenOut {
    pub version: u64,
}

/// Credential body
#[derive(Clone, Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CredentialPut {
    /// Name
    #[serde(default)]
    pub name: String,
    pub source: CredentialSource,
    /// Env key
    #[serde(default)]
    pub key: Option<String>,
    /// Secret kind
    #[serde(default)]
    pub kind: Option<CredentialKind>,
    /// User
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    /// Revision
    #[serde(default)]
    pub secret_revision: Option<u64>,
    /// Secret
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

/// Secret key
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct SecretKeyOut {
    /// Secret key present
    pub present: bool,
}

/// Device groups
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct GroupsOut {
    pub version: u64,
    pub groups: Vec<Group>,
}

/// Collector settings
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct CollectionOut {
    pub version: u64,
    pub collection: Collection,
}

/// Credentials
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct CredentialsOut {
    pub version: u64,
    pub credentials: Vec<Credential>,
}

/// Routes
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct RoutesOut {
    pub version: u64,
    pub routes: Vec<Route>,
}

/// Jump hosts
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct JumpHostsOut {
    pub version: u64,
    pub jump_hosts: Vec<JumpHost>,
}

/// Bindings
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct BindingsOut {
    pub version: u64,
    pub bindings: Bindings,
}

/// Collector vendor
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct VendorOut {
    pub vendor: String,
    pub transport: CollectorTransport,
}

/// Collector vendors
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
        summary: "Inventory",
        query: ONE,
        body: &[],
        ok: (200, &[schema::<Inventory>]),
    },
    ApiRoute {
        method: "get",
        path: "/v1/inventory/vendors",
        id: "listVendors",
        summary: "Collector vendors",
        query: ONE,
        body: &[],
        ok: (200, &[schema::<VendorsOut>]),
    },
    ApiRoute {
        method: "get",
        path: "/v1/inventory/collection",
        id: "getCollection",
        summary: "Collector settings",
        query: ONE,
        body: &[],
        ok: (200, &[schema::<CollectionOut>]),
    },
    ApiRoute {
        method: "put",
        path: "/v1/inventory/collection",
        id: "putCollection",
        summary: "Put collector settings",
        query: ONE,
        body: &[schema::<Collection>],
        ok: (200, &[schema::<WrittenOut>]),
    },
    ApiRoute {
        method: "get",
        path: "/v1/inventory/groups",
        id: "listGroups",
        summary: "Device groups",
        query: ONE,
        body: &[],
        ok: (200, &[schema::<GroupsOut>]),
    },
    ApiRoute {
        method: "get",
        path: "/v1/inventory/groups/{group}",
        id: "getGroup",
        summary: "Device group",
        query: ONE,
        body: &[],
        ok: (200, &[schema::<Group>]),
    },
    ApiRoute {
        method: "put",
        path: "/v1/inventory/groups/{group}",
        id: "putGroup",
        summary: "Put device group",
        query: ONE,
        body: &[schema::<Group>],
        ok: (200, &[schema::<WrittenOut>]),
    },
    ApiRoute {
        method: "delete",
        path: "/v1/inventory/groups/{group}",
        id: "deleteGroup",
        summary: "Delete device group",
        query: ONE,
        body: &[],
        ok: (200, &[schema::<WrittenOut>]),
    },
    ApiRoute {
        method: "get",
        path: "/v1/inventory/devices",
        id: "listDevices",
        summary: "Devices",
        query: ONE,
        body: &[],
        ok: (200, &[schema::<ResolvedDevices>]),
    },
    ApiRoute {
        method: "get",
        path: "/v1/inventory/devices/{device}",
        id: "getDevice",
        summary: "Device",
        query: ONE,
        body: &[],
        ok: (200, &[schema::<ResolvedDevice>]),
    },
    ApiRoute {
        method: "put",
        path: "/v1/inventory/devices/{device}",
        id: "putDevice",
        summary: "Put device",
        query: ONE,
        body: &[schema::<Device>],
        ok: (200, &[schema::<WrittenOut>]),
    },
    ApiRoute {
        method: "delete",
        path: "/v1/inventory/devices/{device}",
        id: "deleteDevice",
        summary: "Delete device",
        query: ONE,
        body: &[],
        ok: (200, &[schema::<WrittenOut>]),
    },
    ApiRoute {
        method: "get",
        path: "/v1/inventory/credentials",
        id: "listCredentials",
        summary: "Credentials",
        query: ONE,
        body: &[],
        ok: (200, &[schema::<CredentialsOut>]),
    },
    ApiRoute {
        method: "put",
        path: "/v1/inventory/credentials/{credential}",
        id: "putCredential",
        summary: "Put credential",
        query: ONE,
        body: &[schema::<CredentialPut>],
        ok: (200, &[schema::<WrittenOut>]),
    },
    ApiRoute {
        method: "delete",
        path: "/v1/inventory/credentials/{credential}",
        id: "deleteCredential",
        summary: "Delete credential",
        query: ONE,
        body: &[],
        ok: (200, &[schema::<WrittenOut>]),
    },
    ApiRoute {
        method: "get",
        path: "/v1/inventory/secret-key",
        id: "getSecretKey",
        summary: "Secret key",
        query: ONE,
        body: &[],
        ok: (200, &[schema::<SecretKeyOut>]),
    },
    ApiRoute {
        method: "get",
        path: "/v1/inventory/routes",
        id: "listRoutes",
        summary: "Routes",
        query: ONE,
        body: &[],
        ok: (200, &[schema::<RoutesOut>]),
    },
    ApiRoute {
        method: "put",
        path: "/v1/inventory/routes/{route}",
        id: "putRoute",
        summary: "Put route",
        query: ONE,
        body: &[schema::<Route>],
        ok: (200, &[schema::<WrittenOut>]),
    },
    ApiRoute {
        method: "delete",
        path: "/v1/inventory/routes/{route}",
        id: "deleteRoute",
        summary: "Delete route",
        query: ONE,
        body: &[],
        ok: (200, &[schema::<WrittenOut>]),
    },
    ApiRoute {
        method: "get",
        path: "/v1/inventory/jump-hosts",
        id: "listJumpHosts",
        summary: "Jump hosts",
        query: ONE,
        body: &[],
        ok: (200, &[schema::<JumpHostsOut>]),
    },
    ApiRoute {
        method: "put",
        path: "/v1/inventory/jump-hosts/{jump_host}",
        id: "putJumpHost",
        summary: "Put jump host",
        query: ONE,
        body: &[schema::<JumpHost>],
        ok: (200, &[schema::<WrittenOut>]),
    },
    ApiRoute {
        method: "delete",
        path: "/v1/inventory/jump-hosts/{jump_host}",
        id: "deleteJumpHost",
        summary: "Delete jump host",
        query: ONE,
        body: &[],
        ok: (200, &[schema::<WrittenOut>]),
    },
    ApiRoute {
        method: "get",
        path: "/v1/inventory/bindings",
        id: "listBindings",
        summary: "Bindings",
        query: ONE,
        body: &[],
        ok: (200, &[schema::<BindingsOut>]),
    },
    ApiRoute {
        method: "put",
        path: "/v1/inventory/bindings/fabric-ports/{account}/{fabric_port}",
        id: "putFabricPortBinding",
        summary: "Bind Fabric port",
        query: ONE,
        body: &[schema::<FabricPortBinding>],
        ok: (200, &[schema::<WrittenOut>]),
    },
    ApiRoute {
        method: "delete",
        path: "/v1/inventory/bindings/fabric-ports/{account}/{fabric_port}",
        id: "deleteFabricPortBinding",
        summary: "Delete Fabric port binding",
        query: ONE,
        body: &[],
        ok: (200, &[schema::<WrittenOut>]),
    },
    ApiRoute {
        method: "put",
        path: "/v1/inventory/bindings/edge-devices/{account}/{edge_device}",
        id: "putEdgeDeviceBinding",
        summary: "Bind Network Edge device",
        query: ONE,
        body: &[schema::<EdgeDeviceBinding>],
        ok: (200, &[schema::<WrittenOut>]),
    },
    ApiRoute {
        method: "delete",
        path: "/v1/inventory/bindings/edge-devices/{account}/{edge_device}",
        id: "deleteEdgeDeviceBinding",
        summary: "Delete Network Edge device binding",
        query: ONE,
        body: &[],
        ok: (200, &[schema::<WrittenOut>]),
    },
    ApiRoute {
        method: "get",
        path: "/v1/inventory/audit",
        id: "listAudit",
        summary: "Audit log",
        query: &[("limit", "Page size"), ("before", "Before id")],
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
                "inventory database not usable".into(),
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
            format!("{what} {field} in the body, {path} in the path"),
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
        return Err(problem(404, "no_inventory", "no inventory database".into()));
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
        ["collection"] => {
            allow(req, &["GET", "PUT"])?;
            if req.method == "PUT" {
                let c: Collection = body(req)?;
                return write(vec![Change::PutCollection(c)]);
            }
            let inv = load()?;
            Ok(json_out(&CollectionOut {
                version: inv.version,
                collection: inv.collection,
            }))
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
