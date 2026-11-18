//! The tools of the server: their definitions and their calls.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use rsim_cli::commands::Loaded;
use rsim_cli::json::{self, ErrorOut};
use rsim_cli::{QueryError, args, commands, tables};
use rsim_contract::args::Form;
use rsim_contract::args::{TableQueryArgs, TableVerb};
use rsim_contract::claim::ClaimArgs;
use rsim_contract::registry;
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

/// Runs tools. It keeps the twin of each topology that a call named, and no
/// answer. With a store, the topology `store` is the newest snapshot of the
/// store when the first call names it. The clones of one `Tools` share its
/// cache of twins.
#[derive(Clone, Default)]
pub struct Tools {
    twins: Arc<Cache<Loaded>>,
    store: Option<String>,
}

impl Tools {
    /// Tools with the topology `store` for the store in a data folder.
    pub fn with_store(folder: String) -> Tools {
        Tools {
            twins: Arc::default(),
            store: Some(folder),
        }
    }

    /// The topology names: the built-in topologies, then `store` if the
    /// server has a store.
    pub fn names(&self) -> Vec<&'static str> {
        let mut v = commands::topology_names();
        if self.store.is_some() {
            v.push(STORE);
        }
        v
    }

    /// The twin of a topology name: a built-in topology, or `store` for the
    /// store of the server. Only the names of `names` go into the cache.
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
        self.twins.get_or_load(topology, || commands::load(&source))
    }

    /// Calls the tool `name`. `None` is a name that is not a tool.
    pub fn call(&self, name: &str, arguments: &Map<String, Value>) -> Option<Output> {
        let r = match name {
            "list_devices" => args::topology(arguments)
                .and_then(|t| self.twin(&t).map(|twin| commands::devices(&t, &twin)))
                .map(|o| text(&o)),
            "path_query" => args::form(arguments).and_then(|form| {
                args::query(arguments, &["form"]).and_then(|q| {
                    let t = self.twin(&q.topology)?;
                    match form {
                        Form::Full => commands::path(&q, &t).map(|o| text(&o)),
                        f => commands::path_brief(&q, &t, f).map(|o| text(&o)),
                    }
                })
            }),
            "set_query" => args::form(arguments).and_then(|form| {
                args::set_query(arguments, &["form"]).and_then(|q| {
                    let t = self.twin(&q.topology)?;
                    match form {
                        Form::Full => commands::set(&q, &t).map(|o| text(&o)),
                        f => commands::set_brief(&q, &t, f).map(|o| text(&o)),
                    }
                })
            }),
            "explain_step" => match args::mode(arguments) {
                Ok(false) => args::step(arguments)
                    .and_then(|(q, at)| {
                        self.twin(&q.topology)
                            .and_then(|t| commands::explain(&q, at, &t))
                    })
                    .map(|o| text(&o)),
                Ok(true) => args::set_step(arguments)
                    .and_then(|(q, at)| {
                        self.twin(&q.topology)
                            .and_then(|t| commands::explain_set(&q, at, &t))
                    })
                    .map(|o| text(&o)),
                Err(e) => Err(e),
            },
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
                    let twin = self.twin(&t)?;
                    rsim_cli::claims::run(&t, &twin, &a).map(|o| text(&o))
                }),
            "table_query" => {
                serde_json::from_value::<TableQueryArgs>(Value::Object(arguments.clone()))
                    .map_err(|e| QueryError::new(rsim_cli::ErrorCode::InvalidQuery, e.to_string()))
                    .and_then(|a| {
                        let t = a.topology.clone();
                        let twin = self.twin(&t)?;
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
            Err(e) => Output {
                json: text(&ErrorOut::new(e)),
                is_error: true,
            },
        })
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
    use super::Cache;
    use std::sync::Arc;
    use std::sync::mpsc::channel;
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
