//! The tools of the server: their definitions and their calls.

use std::collections::BTreeMap;

use rsim_cli::commands::Loaded;
use rsim_cli::json::{self, ErrorOut};
use rsim_cli::{QueryError, args, commands, tables};
use rsim_contract::args::Form;
use rsim_contract::args::{TableQueryArgs, TableVerb};
use rsim_contract::claim::ClaimArgs;
use rsim_contract::json::{PathBriefOut, SetBriefOut};
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

/// Runs tools. It keeps the twin of each topology that a call named, and no
/// answer. With a store, the topology `store` is the newest snapshot of the
/// store when the first call names it.
#[derive(Default)]
pub struct Tools {
    twins: BTreeMap<String, Loaded>,
    store: Option<String>,
}

impl Tools {
    /// Tools with the topology `store` for the store in a data folder.
    pub fn with_store(folder: String) -> Tools {
        Tools {
            twins: BTreeMap::new(),
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

    fn twin(&mut self, topology: &str) -> Result<&Loaded, QueryError> {
        if !self.twins.contains_key(topology) {
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
            let twin = commands::load(&source)?;
            self.twins.insert(topology.to_string(), twin);
        }
        match self.twins.get(topology) {
            Some(t) => Ok(t),
            None => unreachable!("the twin was inserted"),
        }
    }

    /// Calls the tool `name`. `None` is a name that is not a tool.
    pub fn call(&mut self, name: &str, arguments: &Map<String, Value>) -> Option<Output> {
        let r = match name {
            "list_devices" => args::topology(arguments)
                .and_then(|t| self.twin(&t).map(|twin| commands::devices(&t, twin)))
                .map(|o| text(&o)),
            "path_query" => args::form(arguments).and_then(|form| {
                args::query(arguments, &["form"])
                    .and_then(|q| self.twin(&q.topology).and_then(|t| commands::path(&q, t)))
                    .map(|o| match form {
                        Form::Full => text(&o),
                        f => text(&PathBriefOut::from_full(&o, f)),
                    })
            }),
            "set_query" => args::form(arguments).and_then(|form| {
                args::set_query(arguments, &["form"])
                    .and_then(|q| self.twin(&q.topology).and_then(|t| commands::set(&q, t)))
                    .map(|o| match form {
                        Form::Full => text(&o),
                        f => text(&SetBriefOut::from_full(&o, f)),
                    })
            }),
            "explain_step" => match args::mode(arguments) {
                Ok(false) => args::step(arguments)
                    .and_then(|(q, at)| {
                        self.twin(&q.topology)
                            .and_then(|t| commands::explain(&q, at, t))
                    })
                    .map(|o| text(&o)),
                Ok(true) => args::set_step(arguments)
                    .and_then(|(q, at)| {
                        self.twin(&q.topology)
                            .and_then(|t| commands::explain_set(&q, at, t))
                    })
                    .map(|o| text(&o)),
                Err(e) => Err(e),
            },
            "list_tables" => Ok(text(&tables::catalog())),
            "list_claims" => Ok(text(&rsim_cli::claims::catalog())),
            "run_claim" => serde_json::from_value::<ClaimArgs>(Value::Object(arguments.clone()))
                .map_err(|e| QueryError::new(rsim_cli::ErrorCode::InvalidQuery, e.to_string()))
                .and_then(|a| {
                    let t = a.topology.clone();
                    let twin = self.twin(&t)?;
                    rsim_cli::claims::run(&t, twin, &a).map(|o| text(&o))
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
                            TableVerb::Show => tables::show(&t, twin, name, s).map(|o| text(&o)),
                            TableVerb::Top => tables::top(
                                &t,
                                twin,
                                name,
                                a.column.as_deref().unwrap_or_default(),
                                a.count.unwrap_or(5),
                                a.ascending.unwrap_or(false),
                                s,
                            )
                            .map(|o| text(&o)),
                            TableVerb::Lpm => tables::lpm(
                                &t,
                                twin,
                                name,
                                a.column.as_deref().unwrap_or("prefix"),
                                a.address.as_deref().unwrap_or_default(),
                                s,
                            )
                            .map(|o| text(&o)),
                            TableVerb::Unique => {
                                let mut sel = s.clone();
                                let columns = sel.columns.take().unwrap_or_default();
                                tables::unique(&t, twin, name, &columns, &sel).map(|o| text(&o))
                            }
                            TableVerb::Summarize => {
                                tables::summarize(&t, twin, name, s).map(|o| text(&o))
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
