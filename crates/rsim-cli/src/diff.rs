//! The difference of a query answer and of a claim from the twin `against`
//! to a twin. The field `provenance` is not compared at any depth.

use std::collections::BTreeMap;

use rsim_contract::claim::{ClaimOut, Evidence};
use rsim_contract::diff::{
    AnswerDiff, BranchChange, BranchSide, ClaimDiffOut, EvidenceChange, QueryDiffOut, ReplyChange,
};
use rsim_contract::json::{AnswerJson, BranchJson, ReplyJson, VERSION};
use rsim_contract::table::{DiffCounts, RowChange};
use rsim_contract::twin::TwinJson;
use serde::Serialize;
use serde_json::{Value, json};

/// The JSON value of `v` with each field `provenance` removed.
fn plain<T: Serialize>(v: &T) -> Value {
    fn strip(v: &mut Value) {
        match v {
            Value::Object(m) => {
                m.remove("provenance");
                m.values_mut().for_each(strip);
            }
            Value::Array(a) => a.iter_mut().for_each(strip),
            _ => {}
        }
    }
    let mut x = serde_json::to_value(v).unwrap_or(Value::Null);
    strip(&mut x);
    x
}

fn counts(changes: impl Iterator<Item = RowChange>) -> DiffCounts {
    let mut c = DiffCounts::default();
    for ch in changes {
        match ch {
            RowChange::Added => c.added += 1,
            RowChange::Removed => c.removed += 1,
            RowChange::Changed => c.changed += 1,
        }
    }
    c
}

/// Removes from `before` and `after` each pair of items with equal values
/// of `value`, in the order of `before`.
fn drop_equal<T>(before: &mut Vec<T>, after: &mut Vec<T>, value: impl Fn(&T) -> Value) {
    let mut i = 0;
    while i < before.len() {
        let v = value(&before[i]);
        match after.iter().position(|x| value(x) == v) {
            Some(j) => {
                after.remove(j);
                before.remove(i);
            }
            None => i += 1,
        }
    }
}

/// The changes of the evidence rows, in the order of the subjects. Rows
/// with 1 subject pair by equal values. 1 row left on each side is a
/// changed row, and other rows left are removed or added.
pub fn evidence(before: &[Evidence], after: &[Evidence]) -> Vec<EvidenceChange> {
    type Sides<'a> = (Vec<&'a Evidence>, Vec<&'a Evidence>);
    let mut groups: BTreeMap<&str, Sides> = BTreeMap::new();
    for e in before {
        groups.entry(&e.subject).or_default().0.push(e);
    }
    for e in after {
        groups.entry(&e.subject).or_default().1.push(e);
    }
    let mut out = Vec::new();
    for (_, (mut b, mut a)) in groups {
        drop_equal(&mut b, &mut a, |e| plain(*e));
        match (b.as_slice(), a.as_slice()) {
            ([x], [y]) => out.push(EvidenceChange {
                change: RowChange::Changed,
                row: (*y).clone(),
                before: Some((*x).clone()),
            }),
            _ => {
                out.extend(b.into_iter().map(|e| EvidenceChange {
                    change: RowChange::Removed,
                    row: e.clone(),
                    before: None,
                }));
                out.extend(a.into_iter().map(|e| EvidenceChange {
                    change: RowChange::Added,
                    row: e.clone(),
                    before: None,
                }));
            }
        }
    }
    out
}

/// The difference of a claim from `before`, the answer on the twin
/// `against`, to `after`.
pub fn claim(before: &ClaimOut, after: ClaimOut) -> ClaimDiffOut {
    let rows = evidence(&before.evidence, &after.evidence);
    ClaimDiffOut {
        rsim_json: VERSION,
        kind: "claim_diff".into(),
        topology: after.topology,
        twin: after.twin,
        against: before.twin.clone(),
        claim: after.claim,
        scope: after.scope,
        result: after.result,
        before: before.result,
        counts: counts(rows.iter().map(|r| r.change)),
        rows,
    }
}

/// The alternatives and the flood copies on the steps of a branch: the
/// choice, the key and the label of an alternative, and the flood and the
/// port of a copy.
fn signature(b: &BranchJson) -> Vec<Vec<String>> {
    b.steps
        .iter()
        .filter_map(|s| match (&s.alternative, &s.flood_copy) {
            (Some(a), _) => Some(vec![a.choice.clone(), a.key.clone(), a.label.clone()]),
            (None, Some(f)) => Some(vec![f.flood.clone(), f.port.clone()]),
            (None, None) => None,
        })
        .collect()
}

fn reply_value(r: Option<&ReplyJson>) -> Value {
    match r {
        None => Value::Null,
        Some(r) => json!([r.ran, r.not_run_reason, plain(&r.answer)]),
    }
}

/// A branch with its reply.
type Leg<'a> = (&'a BranchJson, Option<&'a ReplyJson>);

/// The value of a leg with no branch index.
fn leg_value((b, r): &Leg) -> Value {
    let mut v = plain(*b);
    if let Value::Object(m) = &mut v {
        m.remove("index");
    }
    json!([v, reply_value(*r)])
}

fn side(b: &BranchJson, at: Option<usize>) -> BranchSide {
    BranchSide {
        index: b.index,
        verdict: b.verdict.clone(),
        packets: b.packets.clone(),
        delay: b.delay.clone(),
        step: at.and_then(|i| b.steps.get(i).cloned()),
    }
}

fn reply(before: Option<&ReplyJson>, after: Option<&ReplyJson>) -> Option<ReplyChange> {
    if reply_value(before) == reply_value(after) {
        return None;
    }
    let ran = |r: Option<&ReplyJson>| r.is_some_and(|r| r.ran);
    let diff = match (
        before.and_then(|r| r.answer.as_ref()),
        after.and_then(|r| r.answer.as_ref()),
    ) {
        (Some(x), Some(y)) => Some(Box::new(answer(x, y))),
        _ => None,
    };
    Some(ReplyChange {
        ran: ran(after),
        before_ran: ran(before),
        diff,
    })
}

fn changed((b, rb): Leg, (a, ra): Leg) -> BranchChange {
    let first =
        (0..b.steps.len().max(a.steps.len())).find(|&i| match (b.steps.get(i), a.steps.get(i)) {
            (Some(x), Some(y)) => plain(x) != plain(y),
            _ => true,
        });
    BranchChange {
        change: RowChange::Changed,
        branch: side(a, first),
        before: Some(side(b, first)),
        first_step: first,
        reply: reply(rb, ra),
    }
}

fn one_side(change: RowChange, b: &BranchJson) -> BranchChange {
    BranchChange {
        change,
        branch: side(b, None),
        before: None,
        first_step: None,
        reply: None,
    }
}

fn legs(a: &AnswerJson) -> Vec<Leg<'_>> {
    a.branches
        .iter()
        .map(|b| {
            let r = a.replies.iter().find(|r| r.forward_branch == b.index);
            (b, r)
        })
        .collect()
}

/// The difference of an answer from `before` to `after`.
///
/// Branches pair by the alternatives and the flood copies on their steps,
/// with no alternative index.
/// In 1 group of branches, branches with equal values and equal replies
/// pair and are not changes, the other branches pair in the order of
/// their index as changed branches, and the branches left are removed or
/// added. The changed and the added branches come in the order of their
/// index in `after`, and then the removed branches in the order of their
/// index in `before`.
pub fn answer(before: &AnswerJson, after: &AnswerJson) -> AnswerDiff {
    let mut added_parts: Vec<_> = after.summary.iter().collect();
    let mut removed_parts: Vec<_> = before.summary.iter().collect();
    drop_equal(&mut removed_parts, &mut added_parts, |p| plain(*p));

    type Sides<'a> = (Vec<Leg<'a>>, Vec<Leg<'a>>);
    let mut groups: BTreeMap<Vec<Vec<String>>, Sides> = BTreeMap::new();
    for l in legs(before) {
        groups.entry(signature(l.0)).or_default().0.push(l);
    }
    for l in legs(after) {
        groups.entry(signature(l.0)).or_default().1.push(l);
    }
    let mut changes = Vec::new();
    let mut removed = Vec::new();
    for (_, (mut b, mut a)) in groups {
        drop_equal(&mut b, &mut a, leg_value);
        let n = b.len().min(a.len());
        for (x, y) in b.iter().zip(&a) {
            changes.push(changed(*x, *y));
        }
        changes.extend(a[n..].iter().map(|l| one_side(RowChange::Added, l.0)));
        removed.extend(b[n..].iter().map(|l| one_side(RowChange::Removed, l.0)));
    }
    changes.sort_by_key(|c| c.branch.index);
    removed.sort_by_key(|c| c.branch.index);
    changes.extend(removed);
    AnswerDiff {
        added_parts: added_parts.into_iter().cloned().collect(),
        removed_parts: removed_parts.into_iter().cloned().collect(),
        counts: counts(changes.iter().map(|c| c.change)),
        branches: changes,
    }
}

/// The difference of the answers of 1 query from the twin `against` to a
/// twin.
pub fn query(
    topology: &str,
    qid: &str,
    twin: &TwinJson,
    against: &TwinJson,
    before: &AnswerJson,
    after: &AnswerJson,
) -> QueryDiffOut {
    QueryDiffOut {
        rsim_json: VERSION,
        kind: "query_diff".into(),
        topology: topology.to_string(),
        twin: twin.clone(),
        against: against.clone(),
        qid: qid.to_string(),
        diff: answer(before, after),
    }
}
