//! The tools of the server: their definitions and their calls.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

use rsim_cli::commands::Loaded;
use rsim_cli::json::{self, ErrorOut};
use rsim_cli::{QueryError, args, commands, tables};
use rsim_contract::args::Form;
use rsim_contract::args::{TableQueryArgs, TableVerb};
use rsim_contract::claim::ClaimArgs;
use rsim_contract::registry;
use rsim_contract::twin::{TwinJson, snapshot_name};
use serde::Serialize;
use serde_json::{Map, Value, json};

/// The result of a tool: the output object as compact JSON, and true if it
/// is the error object.
pub struct Output {
    pub json: String,
    pub is_error: bool,
}

/// The topology name of the store of the server.
pub const STORE: &str = "store";

/// A cache of values by key. The build of a value holds only the slot of
/// its key: a call for another key does not wait, and the calls for one key
/// build its value once. A failed build is not kept.
pub struct Cache<T> {
    slots: Mutex<BTreeMap<String, Slot<T>>>,
}

type Slot<T> = Arc<Mutex<Option<Arc<T>>>>;

impl<T> Default for Cache<T> {
    fn default() -> Self {
        Cache {
            slots: Mutex::new(BTreeMap::new()),
        }
    }
}

impl<T> Cache<T> {
    /// The value of `key`, built with `load` if the cache has none.
    pub fn get_or_load<E>(
        &self,
        key: &str,
        load: impl FnOnce() -> Result<T, E>,
    ) -> Result<Arc<T>, E> {
        let slot = {
            let mut slots = self.slots.lock().unwrap_or_else(|p| p.into_inner());
            Arc::clone(slots.entry(key.to_string()).or_default())
        };
        let mut value = slot.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(v) = &*value {
            return Ok(Arc::clone(v));
        }
        let v = Arc::new(load()?);
        *value = Some(Arc::clone(&v));
        Ok(v)
    }
}

/// The number of scenario twins that the tools hold.
pub const SCENARIOS: usize = 4;

/// A cache of the values of the last `cap` keys that a call named. The
/// build of a value holds only the slot of its key, and the calls for one
/// key build its value once. A failed build is not kept.
pub struct Recent<T> {
    cap: usize,
    /// The keys with their slots, the key of the newest call last.
    slots: Mutex<VecDeque<(String, Slot<T>)>>,
}

impl<T> Recent<T> {
    pub fn new(cap: usize) -> Self {
        Recent {
            cap,
            slots: Mutex::new(VecDeque::new()),
        }
    }

    fn lock(&self) -> MutexGuard<'_, VecDeque<(String, Slot<T>)>> {
        self.slots.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The value of `key`, built with `load` if the cache has none. The key
    /// becomes the newest key. After a build, the cache releases the oldest
    /// keys above `cap`.
    pub fn get_or_load<E>(
        &self,
        key: &str,
        load: impl FnOnce() -> Result<T, E>,
    ) -> Result<Arc<T>, E> {
        let slot = {
            let mut slots = self.lock();
            let slot = match slots.iter().position(|(k, _)| k == key) {
                Some(i) => slots.remove(i).map(|(_, s)| s).unwrap_or_default(),
                None => Slot::default(),
            };
            slots.push_back((key.to_string(), Arc::clone(&slot)));
            slot
        };
        let mut value = slot.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(v) = &*value {
            return Ok(Arc::clone(v));
        }
        match load() {
            Ok(v) => {
                let v = Arc::new(v);
                *value = Some(Arc::clone(&v));
                drop(value);
                let mut slots = self.lock();
                let excess = slots.len().saturating_sub(self.cap);
                slots.drain(..excess);
                Ok(v)
            }
            Err(e) => {
                drop(value);
                self.lock().retain(|(_, s)| !Arc::ptr_eq(s, &slot));
                Err(e)
            }
        }
    }

    /// The keys in the order of their last call, the newest last.
    pub fn keys(&self) -> Vec<String> {
        self.lock().iter().map(|(k, _)| k.clone()).collect()
    }
}

/// Runs tools. It keeps the twin of each topology that a call named, the
/// last [`SCENARIOS`] scenario twins by twin ID, and no answer. With a store, the topology `store` is the newest snapshot of the
/// store when the first call names it; with `reload_store`, it is the newest
/// built snapshot, and a newer snapshot builds in the background. The
/// clones of one `Tools` share its cache of twins.
#[derive(Clone)]
pub struct Tools {
    twins: Arc<Cache<Loaded>>,
    scenarios: Arc<Recent<Loaded>>,
    store: Option<String>,
    reload: Option<Arc<Reload<Loaded>>>,
    /// The cycle of `HEAD` of the last read and the time of its snapshot.
    head: Arc<Mutex<Option<(u64, u64)>>>,
}

impl Default for Tools {
    fn default() -> Self {
        Tools {
            twins: Arc::default(),
            scenarios: Arc::new(Recent::new(SCENARIOS)),
            store: None,
            reload: None,
            head: Arc::default(),
        }
    }
}

/// The build of the value of a version, with the text of its error.
type Load<T> = Arc<dyn Fn(u64) -> Result<T, String> + Send + Sync>;

/// A value that follows the newest version of its source. The current value
/// is the value of the newest version that is built, and it answers each
/// call with no wait. A newer version builds on its own thread; when it is
/// built, it becomes the current value and the older current value becomes
/// the previous value. Before a build starts, the previous value is
/// released, so at most 2 values are held. A version that does not build
/// is not built again, and the current value stays.
struct Reload<T> {
    held: Mutex<Held<T>>,
    /// Signals the end of a build.
    idle: Condvar,
    load: Load<T>,
    version: fn(&T) -> Option<u64>,
}

struct Held<T> {
    current: Option<Arc<T>>,
    previous: Option<Arc<T>>,
    /// The version that builds now.
    building: Option<u64>,
    /// The newest version that did not build, with the text of its error.
    failed: Option<(u64, String)>,
    /// The error of the last read of the newest version.
    head_error: Option<String>,
}

impl<T: Send + Sync + 'static> Reload<T> {
    fn new(load: Load<T>, version: fn(&T) -> Option<u64>) -> Self {
        Reload {
            held: Mutex::new(Held {
                current: None,
                previous: None,
                building: None,
                failed: None,
                head_error: None,
            }),
            idle: Condvar::new(),
            load,
            version,
        }
    }

    fn lock(&self) -> MutexGuard<'_, Held<T>> {
        self.held.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// The lock of the state after the first build, if one runs.
    fn lock_built(&self) -> MutexGuard<'_, Held<T>> {
        let mut h = self.lock();
        while h.current.is_none() && h.building.is_some() {
            h = self.idle.wait(h).unwrap_or_else(|p| p.into_inner());
        }
        h
    }

    /// A copy of the state.
    fn status(&self) -> Held<T> {
        let h = self.lock();
        Held {
            current: h.current.clone(),
            previous: h.previous.clone(),
            building: h.building,
            failed: h.failed.clone(),
            head_error: h.head_error.clone(),
        }
    }

    /// The current value or the previous value whose version `matches`,
    /// with no read of the newest version.
    fn find(&self, matches: impl Fn(u64) -> bool) -> Option<Arc<T>> {
        let h = self.lock();
        [&h.current, &h.previous]
            .into_iter()
            .flatten()
            .find(|v| (self.version)(v).is_some_and(&matches))
            .cloned()
    }

    /// Waits until no build runs.
    fn wait(&self) {
        let mut h = self.lock();
        while h.building.is_some() {
            h = self.idle.wait(h).unwrap_or_else(|p| p.into_inner());
        }
    }

    /// The build of a version, with a panic as an error.
    fn build(&self, version: u64) -> Result<T, String> {
        let load = Arc::clone(&self.load);
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| load(version)))
            .unwrap_or_else(|_| Err("the build stopped with a panic".to_string()))
    }

    /// The current value. `head` reads the newest version, through the
    /// current value when there is one.
    ///
    /// With no current value, the call builds the value of the newest
    /// version and waits for it, and the other calls wait for that build; a
    /// version that did not build gives its error until a newer version
    /// comes, and no newest version gives an error. With a current value,
    /// the call gets it at once, and if the newest version is newer and is
    /// not the version that did not build, the call starts its build on its
    /// own thread when no build runs. A head that cannot be read keeps the
    /// current value and is recorded.
    fn newest(
        self: &Arc<Self>,
        head: impl FnOnce(Option<&T>) -> Result<Option<u64>, String>,
    ) -> Result<Arc<T>, String> {
        let current = self.lock_built().current.clone();
        let head = head(current.as_deref());
        let mut h = self.lock_built();
        let current = h.current.clone();
        let head = match head {
            Ok(head) => {
                h.head_error = None;
                head
            }
            Err(text) => {
                h.head_error = Some(text.clone());
                return current.ok_or(text);
            }
        };
        let failed = |h: &Held<T>, head: u64| h.failed.as_ref().is_some_and(|f| f.0 >= head);
        if let Some(v) = current {
            let newer = head.filter(|&head| {
                h.building.is_none()
                    && !(self.version)(&v).is_some_and(|c| c >= head)
                    && !failed(&h, head)
            });
            if let Some(head) = newer {
                h.previous = None;
                h.building = Some(head);
                drop(h);
                let r = Arc::clone(self);
                let spawned = std::thread::Builder::new()
                    .name("rsim-reload".into())
                    .spawn(move || r.background(head));
                if let Err(e) = spawned {
                    let mut h = self.lock();
                    h.building = None;
                    h.failed = Some((head, format!("the build thread does not start: {e}")));
                }
            }
            return Ok(v);
        }
        let Some(head) = head else {
            return Err("the store has no snapshot".to_string());
        };
        if let Some((_, text)) = h.failed.as_ref().filter(|_| failed(&h, head)) {
            return Err(text.clone());
        }
        h.building = Some(head);
        drop(h);
        let out = self.build(head);
        let mut h = self.lock();
        h.building = None;
        let out = match out {
            Ok(v) => {
                let v = Arc::new(v);
                h.current = Some(Arc::clone(&v));
                h.failed = None;
                Ok(v)
            }
            Err(text) => {
                h.failed = Some((head, text.clone()));
                Err(text)
            }
        };
        drop(h);
        self.idle.notify_all();
        out
    }

    /// The build of the version `head` on the build thread.
    fn background(&self, head: u64) {
        let out = self.build(head);
        let mut h = self.lock();
        match out {
            Ok(v) => {
                h.previous = h.current.take();
                h.current = Some(Arc::new(v));
                h.failed = None;
            }
            Err(text) => h.failed = Some((head, text)),
        }
        h.building = None;
        drop(h);
        self.idle.notify_all();
    }
}

/// The state of the store of the tools, each snapshot by its name: the
/// current twin, the previous twin, the newest snapshot of the store, the
/// snapshot whose twin builds now, the newest snapshot that did not build
/// with its error, and the error of the last read of the newest snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreStatus {
    pub held: Option<String>,
    pub previous: Option<String>,
    pub newest: Option<String>,
    pub loading: Option<String>,
    pub failed: Option<(String, String)>,
    pub head_error: Option<String>,
}

/// The time of the snapshot of a store twin, in milliseconds since the Unix
/// epoch: the version of the reload.
fn time_of(t: &Loaded) -> Option<u64> {
    t.source.as_ref().map(|s| s.snapshot.manifest.time)
}

/// The twin of the snapshot of the time `time` of the store in a data
/// folder, found on the parents of the newest snapshot by its second.
fn load_at_time(folder: &str, time: u64) -> Result<Loaded, String> {
    let store = commands::open_store(folder).map_err(|e| e.detail)?;
    let cycle = store
        .cycle_at(time / 1000)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("{} not in the store", snapshot_name(time)))?;
    commands::load_store_at(folder, Some(cycle), &[]).map_err(|e| e.detail)
}

impl Tools {
    /// Tools with the topology `store` for the store in a data folder.
    pub fn with_store(folder: String) -> Tools {
        Tools {
            store: Some(folder),
            ..Tools::default()
        }
    }

    /// The same tools with the topology `store` as the newest built
    /// snapshot of the store. A call for the store reads the newest
    /// snapshot; if it is newer than the current twin, the twin of the
    /// newest snapshot builds on its own thread while the current twin
    /// answers, and then becomes the current twin. The tools keep the
    /// previous twin until the next build starts. The first call builds the
    /// twin and waits for it. If a snapshot does not build, its error goes
    /// to stderr and to the state of the store, and it is not built again.
    pub fn reload_store(mut self) -> Tools {
        if let Some(folder) = self.store.clone() {
            let load: Load<Loaded> = Arc::new(move |time| {
                load_at_time(&folder, time).inspect_err(|e| {
                    eprintln!(
                        "rsim: {} of the store does not build: {e}",
                        snapshot_name(time)
                    );
                })
            });
            self.reload = Some(Arc::new(Reload::new(load, time_of)));
        }
        self
    }

    /// Waits until no build of the twin `store` runs.
    pub fn wait_store(&self) {
        if let Some(r) = &self.reload {
            r.wait();
        }
    }

    /// The time of the newest snapshot of the store, read through the store
    /// of `held` when there is one; none for a new data folder. The time of
    /// the manifest of a cycle is read once.
    fn store_head(&self, held: Option<&Loaded>) -> Result<Option<u64>, String> {
        let opened;
        let store = match held.and_then(|t| t.source.as_ref()) {
            Some(s) => &s.store,
            None => {
                let Some(folder) = &self.store else {
                    return Ok(None);
                };
                if commands::new_data_folder(folder) {
                    return Ok(None);
                }
                opened = commands::open_store(folder).map_err(|e| e.detail)?;
                &opened
            }
        };
        let Some(cycle) = store.head().map_err(|e| e.to_string())? else {
            return Ok(None);
        };
        let mut head = self.head.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((c, time)) = *head
            && c == cycle
        {
            return Ok(Some(time));
        }
        let time = store
            .snapshot_manifest(cycle)
            .map_err(|e| e.to_string())?
            .time;
        *head = Some((cycle, time));
        Ok(Some(time))
    }

    /// The topology names: the hand-built topologies of the tests, then `store` if the
    /// server has a store.
    pub fn names(&self) -> Vec<&'static str> {
        let mut v = commands::topology_names();
        if self.store.is_some() {
            v.push(STORE);
        }
        v
    }

    /// The twin of a topology name: `store` for the store of the server, or
    /// a hand-built topology of the tests. Only the names of `names` go into
    /// the cache.
    pub fn twin(&self, topology: &str) -> Result<Arc<Loaded>, QueryError> {
        let source = match (&self.store, topology) {
            (Some(folder), STORE) => format!("{}{folder}", commands::STORE_PREFIX),
            (_, t) if t.starts_with(commands::STORE_PREFIX) => {
                return Err(QueryError::new(
                    rsim_cli::ErrorCode::UnknownTopology,
                    format!("{t}: a store is set only when the server starts"),
                ));
            }
            _ => topology.to_string(),
        };
        if !self.names().contains(&topology) {
            return commands::load(&source).map(Arc::new);
        }
        if let (STORE, Some(r)) = (topology, &self.reload) {
            return r
                .newest(|held| self.store_head(held))
                .map_err(|text| QueryError::new(rsim_cli::ErrorCode::Store, text));
        }
        self.twins.get_or_load(topology, || commands::load(&source))
    }

    /// The scenario twin of the snapshot of the store twin `base` with a
    /// link-down layer for each `<device>:<interface>` of `down`, in order.
    /// With no layer, it is `base`. The tools hold the last [`SCENARIOS`]
    /// scenario twins by twin ID.
    pub fn scenario(&self, base: Arc<Loaded>, down: &[String]) -> Result<Arc<Loaded>, QueryError> {
        if down.is_empty() {
            return Ok(base);
        }
        let layers = commands::layers(down)?;
        let (Some(folder), Some(source)) = (&self.store, &base.source) else {
            return Err(QueryError::new(
                rsim_cli::ErrorCode::InvalidQuery,
                format!(
                    "{} is not a store twin, and a link-down layer needs a store twin",
                    base.identity.id
                ),
            ));
        };
        let texts: Vec<String> = layers.iter().map(|l| l.text()).collect();
        let manifest = &source.snapshot.manifest;
        let id = TwinJson::scenario(manifest.time, texts.clone()).id;
        let load = || commands::load_store_at(folder, Some(manifest.cycle), &layers);
        let twin = self.scenarios.get_or_load(&id, load)?;
        if twin.identity.layers == texts {
            return Ok(twin);
        }
        // Another list of layers with the same twin ID is held.
        load().map(Arc::new)
    }

    /// The twin of a topology name with the layers of `down`.
    fn twin_with(&self, topology: &str, down: &[String]) -> Result<Arc<Loaded>, QueryError> {
        self.scenario(self.twin(topology)?, down)
    }

    /// The state of the store of the tools that follow its newest snapshot,
    /// after a call for the store when a twin is held, so a newer snapshot
    /// starts its build. `None` with no such store.
    pub fn store_status(&self) -> Option<StoreStatus> {
        let r = self.reload.as_ref()?;
        if r.lock().current.is_some() {
            let _ = self.twin(STORE);
        }
        let st = r.status();
        let id = |t: Option<Arc<Loaded>>| t.map(|t| t.identity.id.clone());
        let head = self.store_head(st.current.as_deref());
        Some(StoreStatus {
            head_error: st.head_error.or_else(|| head.as_ref().err().cloned()),
            newest: head.ok().flatten().map(snapshot_name),
            held: id(st.current),
            previous: id(st.previous),
            loading: st.building.map(snapshot_name),
            failed: st.failed.map(|(t, e)| (snapshot_name(t), e)),
        })
    }

    /// The twin of the snapshot of the second `second` of the store, if the
    /// tools hold it as the current or the previous twin, and the current
    /// twin. The call is a call for the store, so a newer snapshot starts
    /// its build.
    pub fn store_snapshot(
        &self,
        second: u64,
    ) -> Result<(Option<Arc<Loaded>>, Arc<Loaded>), QueryError> {
        let current = self.twin(STORE)?;
        let at = |t: u64| t / 1000 == second;
        let found = match &self.reload {
            Some(r) => r.find(at),
            None => time_of(&current)
                .is_some_and(at)
                .then(|| Arc::clone(&current)),
        };
        Ok((found, current))
    }

    /// Calls the tool `name`. `None` is a name that is not a tool.
    pub fn call(&self, name: &str, arguments: &Map<String, Value>) -> Option<Output> {
        let mut arguments = arguments.clone();
        let down = match registry::by_tool(name) {
            Some(op) if op.layers => match take_down(&mut arguments) {
                Ok(d) => d,
                Err(e) => return Some(error(e)),
            },
            _ => Vec::new(),
        };
        let (arguments, down) = (&arguments, down.as_slice());
        let r = match name {
            "list_devices" => args::topology(arguments)
                .and_then(|t| self.twin(&t).map(|twin| commands::devices(&t, &twin)))
                .map(|o| text(&o)),
            "path_query" => args::form(arguments).and_then(|form| {
                args::query(arguments, &["form"]).and_then(|q| {
                    let t = self.twin_with(&q.topology, down)?;
                    match form {
                        Form::Full => commands::path(&q, &t).map(|o| text(&o)),
                        f => commands::path_brief(&q, &t, f).map(|o| text(&o)),
                    }
                })
            }),
            "set_query" => args::form(arguments).and_then(|form| {
                args::set_query(arguments, &["form"]).and_then(|q| {
                    let t = self.twin_with(&q.topology, down)?;
                    match form {
                        Form::Full => commands::set(&q, &t).map(|o| text(&o)),
                        f => commands::set_brief(&q, &t, f).map(|o| text(&o)),
                    }
                })
            }),
            "explain_step" => args::source_lines(arguments).and_then(|lines| {
                let with_lines = |mut o: rsim_contract::json::StepOut, t: &Loaded| {
                    if lines {
                        rsim_cli::sources::attach(&mut o, t);
                    }
                    text(&o)
                };
                match args::mode(arguments) {
                    Ok(false) => args::step(arguments).and_then(|(q, at)| {
                        let t = self.twin_with(&q.topology, down)?;
                        commands::explain(&q, at, &t).map(|o| with_lines(o, &t))
                    }),
                    Ok(true) => args::set_step(arguments).and_then(|(q, at)| {
                        let t = self.twin_with(&q.topology, down)?;
                        commands::explain_set(&q, at, &t).map(|o| with_lines(o, &t))
                    }),
                    Err(e) => Err(e),
                }
            }),
            "list_tables" => Ok(text(&tables::catalog())),
            "list_claims" => Ok(text(&rsim_cli::claims::catalog())),
            "get_topology" => serde_json::from_value::<rsim_contract::args::TopologyViewArgs>(
                Value::Object(arguments.clone()),
            )
            .map_err(|e| QueryError::new(rsim_cli::ErrorCode::InvalidQuery, e.to_string()))
            .and_then(|a| {
                let t = a.topology.clone();
                let twin = self.twin(&t)?;
                rsim_cli::topology::topology(&t, &twin, &a).map(|o| text(&o))
            }),
            "run_claim" => serde_json::from_value::<ClaimArgs>(Value::Object(arguments.clone()))
                .map_err(|e| QueryError::new(rsim_cli::ErrorCode::InvalidQuery, e.to_string()))
                .and_then(|a| {
                    let t = a.topology.clone();
                    let twin = self.twin_with(&t, down)?;
                    rsim_cli::claims::run(&t, &twin, &a).map(|o| text(&o))
                }),
            "table_query" => {
                serde_json::from_value::<TableQueryArgs>(Value::Object(arguments.clone()))
                    .map_err(|e| QueryError::new(rsim_cli::ErrorCode::InvalidQuery, e.to_string()))
                    .and_then(|a| {
                        let t = a.topology.clone();
                        let twin = self.twin_with(&t, down)?;
                        let s = &a.selection;
                        let name = a.table.as_str();
                        match a.verb.unwrap_or_default() {
                            TableVerb::Show => tables::show(&t, &twin, name, s).map(|o| text(&o)),
                            TableVerb::Top => tables::top(
                                &t,
                                &twin,
                                name,
                                a.column.as_deref().unwrap_or_default(),
                                a.count.unwrap_or(5),
                                a.ascending.unwrap_or(false),
                                s,
                            )
                            .map(|o| text(&o)),
                            TableVerb::Lpm => tables::lpm(
                                &t,
                                &twin,
                                name,
                                a.column.as_deref().unwrap_or("prefix"),
                                a.address.as_deref().unwrap_or_default(),
                                s,
                            )
                            .map(|o| text(&o)),
                            TableVerb::Unique => {
                                let mut sel = s.clone();
                                let columns = sel.columns.take().unwrap_or_default();
                                tables::unique(&t, &twin, name, &columns, &sel).map(|o| text(&o))
                            }
                            TableVerb::Summarize => {
                                tables::summarize(&t, &twin, name, s).map(|o| text(&o))
                            }
                        }
                    })
            }
            _ => return None,
        };
        Some(match r {
            Ok(json) => Output {
                json,
                is_error: false,
            },
            Err(e) => error(e),
        })
    }
}

/// The output of an error.
fn error(e: QueryError) -> Output {
    Output {
        json: text(&ErrorOut::new(e)),
        is_error: true,
    }
}

/// Takes the argument `down` out of the arguments: a list of
/// `<device>:<interface>`, or none.
fn take_down(arguments: &mut Map<String, Value>) -> Result<Vec<String>, QueryError> {
    let invalid = || {
        QueryError::new(
            rsim_cli::ErrorCode::InvalidQuery,
            "down is not a list of <device>:<interface>".to_string(),
        )
    };
    match arguments.remove("down") {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .into_iter()
            .map(|v| match v {
                Value::String(s) => Ok(s),
                _ => Err(invalid()),
            })
            .collect(),
        Some(_) => Err(invalid()),
    }
}

fn text<T: Serialize>(v: &T) -> String {
    json::to_text(v, false)
}

/// The tool definitions, from the registry of operations. `names` are the
/// topology names.
pub fn definitions(names: &[&str]) -> Value {
    Value::Array(
        registry::OPERATIONS
            .iter()
            .filter_map(|op| {
                Some(json!({
                    "name": op.tool?,
                    "description": op.description,
                    "inputSchema": registry::tool_input(op, names),
                    "outputSchema": registry::tool_output(op),
                    "annotations": {"readOnlyHint": op.effect == registry::Effect::Read}
                }))
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::{Cache, Load, Recent, Reload};
    use std::sync::atomic::Ordering::SeqCst;
    use std::sync::atomic::{AtomicU64, AtomicUsize};
    use std::sync::mpsc::channel;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    #[test]
    fn a_cached_key_does_not_wait_for_the_build_of_another_key() {
        let cache: Arc<Cache<u32>> = Arc::default();
        assert_eq!(*cache.get_or_load("a", || Ok::<_, ()>(1)).unwrap(), 1);
        let (started_tx, started_rx) = channel();
        let (go_tx, go_rx) = channel::<()>();
        let slow = {
            let cache = Arc::clone(&cache);
            std::thread::spawn(move || {
                cache
                    .get_or_load("b", || {
                        started_tx.send(()).unwrap();
                        go_rx.recv().unwrap();
                        Ok::<_, ()>(2)
                    })
                    .map(|v| *v)
            })
        };
        started_rx.recv().unwrap();
        let (done_tx, done_rx) = channel();
        let fast = {
            let cache = Arc::clone(&cache);
            std::thread::spawn(move || {
                let v = cache.get_or_load("a", || Ok::<_, ()>(9)).map(|v| *v);
                done_tx.send(v).unwrap();
            })
        };
        let got = done_rx.recv_timeout(Duration::from_secs(10));
        go_tx.send(()).unwrap();
        assert_eq!(got, Ok(Ok(1)), "the cached key waited for the build");
        fast.join().unwrap();
        assert_eq!(slow.join().unwrap(), Ok(2));
    }

    /// A source for the tests: a head that a test sets, the versions that
    /// do not build, a gate that holds each build, and a count of the
    /// builds. The version 99 panics.
    #[derive(Default)]
    struct Source {
        head: AtomicU64,
        builds: AtomicUsize,
        bad: Mutex<Vec<u64>>,
        gate: Mutex<()>,
    }

    impl Source {
        fn set(&self, head: u64) {
            self.head.store(head, SeqCst);
        }
        fn builds(&self) -> usize {
            self.builds.load(SeqCst)
        }
        fn bad(&self, v: &[u64]) {
            *self.bad.lock().unwrap() = v.to_vec();
        }
    }

    fn reload(s: &Arc<Source>) -> Arc<Reload<u64>> {
        let src = Arc::clone(s);
        let load: Load<u64> = Arc::new(move |v| {
            src.builds.fetch_add(1, SeqCst);
            let _gate = src.gate.lock().unwrap_or_else(|p| p.into_inner());
            assert_ne!(v, 99, "the version 99 panics");
            if src.bad.lock().unwrap().contains(&v) {
                Err(format!("{v} does not build"))
            } else {
                Ok(v)
            }
        });
        Arc::new(Reload::new(load, |v| Some(*v)))
    }

    fn newest(r: &Arc<Reload<u64>>, s: &Source) -> Result<u64, String> {
        r.newest(|_| Ok(Some(s.head.load(SeqCst)))).map(|v| *v)
    }

    fn held(r: &Reload<u64>) -> (Option<u64>, Option<u64>) {
        let st = r.status();
        (st.current.map(|v| *v), st.previous.map(|v| *v))
    }

    #[test]
    fn a_newer_version_builds_on_a_thread_while_the_current_value_answers() {
        let s = Arc::new(Source::default());
        let r = reload(&s);
        s.set(1);
        assert_eq!(newest(&r, &s), Ok(1));
        assert_eq!(newest(&r, &s), Ok(1));
        assert_eq!(s.builds(), 1);
        s.set(2);
        let gate = s.gate.lock().unwrap();
        assert_eq!(
            newest(&r, &s),
            Ok(1),
            "the call does not wait for the build"
        );
        assert_eq!(r.status().building, Some(2));
        assert_eq!(newest(&r, &s), Ok(1));
        drop(gate);
        r.wait();
        assert_eq!(s.builds(), 2, "one build of 2");
        assert_eq!(newest(&r, &s), Ok(2));
        assert_eq!(held(&r), (Some(2), Some(1)));
        assert_eq!(r.find(|v| v == 1).map(|v| *v), Some(1));
        assert_eq!(r.find(|v| v == 2).map(|v| *v), Some(2));
        assert_eq!(r.find(|v| v == 3), None);
    }

    #[test]
    fn a_build_releases_the_previous_value_so_at_most_2_values_are_held() {
        let s = Arc::new(Source::default());
        let r = reload(&s);
        s.set(1);
        assert_eq!(newest(&r, &s), Ok(1));
        s.set(2);
        assert_eq!(newest(&r, &s), Ok(1));
        r.wait();
        let one = Arc::downgrade(&r.find(|v| v == 1).unwrap());
        s.set(3);
        let gate = s.gate.lock().unwrap();
        assert_eq!(newest(&r, &s), Ok(2));
        assert_eq!(held(&r), (Some(2), None));
        assert!(one.upgrade().is_none(), "the previous value is freed");
        drop(gate);
        r.wait();
        assert_eq!(held(&r), (Some(3), Some(2)));
        assert_eq!(r.find(|v| v == 1), None);
    }

    #[test]
    fn a_version_that_does_not_build_keeps_the_current_value_and_is_not_built_again() {
        let s = Arc::new(Source::default());
        let r = reload(&s);
        s.set(1);
        assert_eq!(newest(&r, &s), Ok(1));
        s.set(2);
        s.bad(&[2]);
        assert_eq!(newest(&r, &s), Ok(1));
        r.wait();
        for _ in 0..3 {
            assert_eq!(newest(&r, &s), Ok(1));
        }
        assert_eq!(s.builds(), 2);
        assert_eq!(r.status().failed, Some((2, "2 does not build".to_string())));
        s.set(3);
        assert_eq!(newest(&r, &s), Ok(1));
        r.wait();
        assert_eq!(newest(&r, &s), Ok(3));
        assert_eq!(r.status().failed, None);
    }

    #[test]
    fn a_failed_first_build_is_not_built_again_until_the_head_changes() {
        let s = Arc::new(Source::default());
        let r = reload(&s);
        s.set(1);
        s.bad(&[1]);
        assert_eq!(newest(&r, &s), Err("1 does not build".to_string()));
        assert_eq!(newest(&r, &s), Err("1 does not build".to_string()));
        assert_eq!(s.builds(), 1);
        s.set(2);
        assert_eq!(newest(&r, &s), Ok(2));
    }

    #[test]
    fn the_calls_during_the_first_build_wait_for_it() {
        let s = Arc::new(Source::default());
        let r = reload(&s);
        s.set(1);
        let gate = s.gate.lock().unwrap();
        let calls: Vec<_> = (0..3)
            .map(|_| {
                let (r, s) = (Arc::clone(&r), Arc::clone(&s));
                std::thread::spawn(move || newest(&r, &s))
            })
            .collect();
        while s.builds() == 0 {
            std::thread::yield_now();
        }
        drop(gate);
        for c in calls {
            assert_eq!(c.join().unwrap(), Ok(1));
        }
        assert_eq!(s.builds(), 1);
    }

    #[test]
    fn a_build_that_panics_is_a_failed_build() {
        let s = Arc::new(Source::default());
        let r = reload(&s);
        s.set(1);
        assert_eq!(newest(&r, &s), Ok(1));
        s.set(99);
        assert_eq!(newest(&r, &s), Ok(1));
        r.wait();
        assert_eq!(newest(&r, &s), Ok(1));
        assert_eq!(r.status().failed.map(|f| f.0), Some(99));
    }

    #[test]
    fn a_head_that_cannot_be_read_keeps_the_value_and_is_recorded() {
        let s = Arc::new(Source::default());
        let r = reload(&s);
        s.set(1);
        assert_eq!(newest(&r, &s), Ok(1));
        assert_eq!(r.newest(|_| Err("no HEAD".to_string())).map(|v| *v), Ok(1));
        assert_eq!(r.status().head_error, Some("no HEAD".to_string()));
        assert_eq!(newest(&r, &s), Ok(1));
        assert_eq!(r.status().head_error, None);
    }

    #[test]
    fn a_store_with_no_snapshot_gives_an_error_and_no_build() {
        let s = Arc::new(Source::default());
        let r = reload(&s);
        assert_eq!(
            r.newest(|_| Ok(None)).map(|v| *v),
            Err("the store has no snapshot".to_string())
        );
        assert_eq!(s.builds(), 0);
    }

    #[test]
    fn the_recent_cache_holds_the_last_keys_and_no_failed_build() {
        let c: Recent<u32> = Recent::new(2);
        let ok = |v: u32| move || Ok::<_, &str>(v);
        assert_eq!(c.get_or_load("a", ok(1)).map(|v| *v), Ok(1));
        assert_eq!(c.get_or_load("b", ok(2)).map(|v| *v), Ok(2));
        assert_eq!(c.get_or_load("a", ok(9)).map(|v| *v), Ok(1));
        assert_eq!(c.get_or_load("c", ok(3)).map(|v| *v), Ok(3));
        assert_eq!(c.keys(), ["a", "c"]);
        assert_eq!(c.get_or_load("b", ok(4)).map(|v| *v), Ok(4));
        assert_eq!(c.keys(), ["c", "b"]);
        assert_eq!(c.get_or_load("d", || Err::<u32, _>("no")), Err("no"));
        assert_eq!(c.keys(), ["c", "b"]);
        assert_eq!(c.get_or_load("c", ok(8)).map(|v| *v), Ok(3));
    }

    #[test]
    fn a_name_that_is_not_a_topology_takes_no_slot() {
        let tools = super::Tools::default();
        assert!(tools.twin("nothing").is_err());
        let slots = tools.twins.slots.lock().unwrap();
        assert!(slots.is_empty(), "{:?}", slots.keys().collect::<Vec<_>>());
    }

    #[test]
    fn the_calls_for_one_key_build_it_once_and_a_failed_build_is_not_kept() {
        let cache: Arc<Cache<u32>> = Arc::default();
        assert_eq!(cache.get_or_load("a", || Err::<u32, _>("no")), Err("no"));
        let builds = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let threads: Vec<_> = (0..4)
            .map(|i| {
                let cache = Arc::clone(&cache);
                let builds = Arc::clone(&builds);
                std::thread::spawn(move || {
                    *cache
                        .get_or_load("a", || {
                            builds.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            std::thread::yield_now();
                            Ok::<_, ()>(i)
                        })
                        .unwrap()
                })
            })
            .collect();
        let values: Vec<u32> = threads.into_iter().map(|t| t.join().unwrap()).collect();
        assert_eq!(builds.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert!(values.windows(2).all(|w| w[0] == w[1]), "{values:?}");
    }
}
