//! The effective configuration of an edge: the module body of its profile
//! with the edge-specific data of the edge on top.
//!
//! A key of the edge data takes the place of the same key of the profile
//! body. The blocks of `segments` merge by segment, key by key. In a rule
//! list of `RULE_LISTS`, the rules of the edge come first, then each rule of
//! the profile whose `ruleLogicalId` no edge rule repeats.

use std::collections::{BTreeMap, BTreeSet};

use super::json::{J, body, int, module, numeric_id, segment_id};

/// The keys whose value is a list of rules.
pub const RULE_LISTS: &[&str] = &["rules", "defaults", "outbound", "inbound", "inboundV6"];

/// A rule of a merged list, and true when it comes from the edge data.
#[derive(Clone, Copy, Debug)]
pub struct Ruled<'a> {
    pub rule: J<'a>,
    pub edge: bool,
}

/// A member of a merged object.
#[derive(Clone, Debug)]
pub enum Field<'a> {
    Value(J<'a>),
    Rules(Vec<Ruled<'a>>),
    Segments(Vec<Merged<'a>>),
}

/// A merged object, by key.
#[derive(Clone, Debug, Default)]
pub struct Merged<'a> {
    pub fields: BTreeMap<String, Field<'a>>,
}

impl<'a> Merged<'a> {
    /// The value of a key that is not a rule list and not `segments`.
    pub fn get(&self, key: &str) -> Option<J<'a>> {
        match self.fields.get(key)? {
            Field::Value(j) => Some(*j),
            _ => None,
        }
    }

    /// The merged rule list of a key of `RULE_LISTS`.
    pub fn rules(&self, key: &str) -> &[Ruled<'a>] {
        match self.fields.get(key) {
            Some(Field::Rules(r)) => r,
            _ => &[],
        }
    }

    /// The merged segment blocks.
    pub fn segments(&self) -> &[Merged<'a>] {
        match self.fields.get("segments") {
            Some(Field::Segments(s)) => s,
            _ => &[],
        }
    }

    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// The segment id of a segment block.
    pub fn segment_id(&self) -> Option<u32> {
        let own = self.get("segmentId").and_then(|j| int(j.v));
        let nested = self
            .get("segment")
            .and_then(|j| j.v.get("segmentId"))
            .and_then(int);
        own.or(nested).and_then(|n| u32::try_from(n).ok())
    }

    /// The segment name of a segment block.
    pub fn segment_name(&self) -> Option<String> {
        self.get("segment")
            .and_then(|j| j.str("name"))
            .map(str::to_string)
    }

    fn key(&self) -> Option<String> {
        self.segment_id()
            .map(|n| n.to_string())
            .or_else(|| self.segment_name())
    }
}

/// The key of a segment block before the merge.
fn block_key(j: J<'_>) -> Option<String> {
    segment_id(j).map(|n| n.to_string()).or_else(|| {
        j.obj("segment")
            .and_then(|s| s.str("name"))
            .map(str::to_string)
    })
}

/// The merge of a profile body and the edge data.
pub fn merge<'a>(profile: Option<J<'a>>, edge: Option<J<'a>>) -> Merged<'a> {
    let mut out = Merged::default();
    if let Some(p) = profile {
        merge_into(&mut out, p, false);
    }
    if let Some(e) = edge {
        merge_into(&mut out, e, true);
    }
    out
}

fn merge_into<'a>(out: &mut Merged<'a>, j: J<'a>, edge: bool) {
    for (key, v) in j.members() {
        if key == "segments" {
            let mut segs = match out.fields.remove(key) {
                Some(Field::Segments(s)) => s,
                _ => Vec::new(),
            };
            for block in v.elems().into_iter().filter(|b| b.v.is_object()) {
                add_segment(&mut segs, block, edge);
            }
            out.fields.insert(key.to_string(), Field::Segments(segs));
        } else if RULE_LISTS.contains(&key) {
            let base = match out.fields.remove(key) {
                Some(Field::Rules(r)) => r,
                _ => Vec::new(),
            };
            out.fields
                .insert(key.to_string(), Field::Rules(merge_rules(base, v, edge)));
        } else {
            out.fields.insert(key.to_string(), Field::Value(v));
        }
    }
}

fn add_segment<'a>(segs: &mut Vec<Merged<'a>>, block: J<'a>, edge: bool) {
    let key = block_key(block);
    let found = key
        .as_ref()
        .and_then(|k| segs.iter().position(|s| s.key().as_ref() == Some(k)));
    match found {
        Some(i) => merge_into(&mut segs[i], block, edge),
        None => {
            let mut m = Merged::default();
            merge_into(&mut m, block, edge);
            segs.push(m);
        }
    }
}

fn merge_rules<'a>(base: Vec<Ruled<'a>>, list: J<'a>, edge: bool) -> Vec<Ruled<'a>> {
    let new: Vec<Ruled<'a>> = list
        .elems()
        .into_iter()
        .filter(|r| r.v.is_object())
        .map(|rule| Ruled { rule, edge })
        .collect();
    if !edge {
        return base.into_iter().chain(new).collect();
    }
    let repeated: BTreeSet<&'a str> = new
        .iter()
        .filter_map(|r| r.rule.str("ruleLogicalId"))
        .collect();
    let mut out = new;
    out.extend(base.into_iter().filter(|r| {
        r.rule
            .str("ruleLogicalId")
            .is_none_or(|id| !repeated.contains(id))
    }));
    out
}

/// The effective body of one module of an edge.
#[derive(Clone, Debug, Default)]
pub struct Effective<'a> {
    pub body: Merged<'a>,
    /// Why the profile part of the body is not known.
    pub profile_unknown: Option<String>,
    /// True if a configuration scope of the edge names the module.
    pub named: bool,
}

/// The effective body of the module `name` of a listing row. The
/// enterprise scope of the `configuration` of the row is read first, then
/// the operator scope; the first that names the module binds the profile
/// of its `id`. `profiles` holds the profile rows by numeric id, or is
/// `None` when the profiles are not collected.
pub fn effective<'a>(
    row: J<'a>,
    profiles: Option<&BTreeMap<u64, J<'a>>>,
    name: &str,
) -> Effective<'a> {
    let Some(config) = row.obj("configuration") else {
        return Effective {
            profile_unknown: Some("no configuration".to_string()),
            ..Effective::default()
        };
    };
    for scope in ["enterprise", "operator"] {
        let Some(scope) = config.obj(scope) else {
            continue;
        };
        let Some(summary) = module(scope, name) else {
            continue;
        };
        let edge = summary.obj("edgeSpecificData").map(body);
        let id = scope.v.get("id").and_then(numeric_id);
        let (profile, unknown) = match (profiles, id) {
            (None, _) => (None, Some("profiles not collected".to_string())),
            (Some(_), None) => (None, Some("no profile id".to_string())),
            (Some(p), Some(id)) => match p.get(&id) {
                None => (None, Some(format!("profile {id} not in profiles"))),
                Some(row) => match module(*row, name) {
                    Some(m) => (Some(body(m)), None),
                    None => (None, Some(format!("no {name} module in profile {id}"))),
                },
            },
        };
        return Effective {
            body: merge(profile, edge),
            profile_unknown: unknown,
            named: true,
        };
    }
    Effective::default()
}
