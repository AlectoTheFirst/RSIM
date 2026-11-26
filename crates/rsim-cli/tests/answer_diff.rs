//! The difference of a query answer and of claim evidence between 2 twins,
//! on the stored answer of `leaf-spine` and on hand-built evidence rows.

use rsim_cli::diff;
use rsim_contract::claim::{ClaimResult, Evidence};
use rsim_contract::json::{AnswerJson, PathAnswerOut};
use rsim_contract::table::{DiffCounts, RowChange};

/// The answer of `leaf-spine.json`: 2 branches, 1 for each next hop of
/// leaf1, each with a reply.
fn stored() -> AnswerJson {
    let text = include_str!("golden/leaf-spine.json");
    serde_json::from_str::<PathAnswerOut>(text).unwrap().answer
}

#[test]
fn an_answer_has_no_difference_from_itself_or_from_other_spans() {
    let a = stored();
    let d = diff::answer(&a, &a);
    assert!(d.branches.is_empty() && d.added_parts.is_empty() && d.removed_parts.is_empty());
    let mut b = a.clone();
    for s in &mut b.branches[0].steps {
        s.provenance.clear();
    }
    assert!(diff::answer(&a, &b).branches.is_empty());
}

#[test]
fn a_changed_step_gives_the_first_different_step_of_its_branch() {
    let before = stored();
    let mut after = before.clone();
    after.branches[1].steps[4].reason.detail = "other".into();
    after.branches[1].steps[7].reason.detail = "other".into();
    let d = diff::answer(&before, &after);
    assert_eq!(
        d.counts,
        DiffCounts {
            added: 0,
            removed: 0,
            changed: 1
        }
    );
    let c = &d.branches[0];
    assert_eq!((c.change, c.first_step), (RowChange::Changed, Some(4)));
    assert_eq!(c.branch.index, 1);
    assert_eq!(c.branch.step.as_ref().unwrap().reason.detail, "other");
    assert_ne!(
        c.before
            .as_ref()
            .unwrap()
            .step
            .as_ref()
            .unwrap()
            .reason
            .detail,
        "other"
    );
    assert!(c.reply.is_none());
}

#[test]
fn a_branch_of_a_next_hop_that_is_gone_is_removed() {
    let before = stored();
    let mut after = before.clone();
    after.branches.remove(0);
    after.branches[0].index = 0;
    after.replies.retain(|r| r.forward_branch == 1);
    after.replies[0].forward_branch = 0;
    let d = diff::answer(&before, &after);
    assert_eq!(
        d.counts,
        DiffCounts {
            added: 0,
            removed: 1,
            changed: 0
        }
    );
    assert_eq!(d.branches[0].change, RowChange::Removed);
    assert_eq!(d.branches[0].branch.index, 0);
    let d = diff::answer(&after, &before);
    assert_eq!(d.branches[0].change, RowChange::Added);
}

#[test]
fn a_changed_reply_changes_its_forward_branch() {
    let before = stored();
    let mut after = before.clone();
    let reply = after.replies[1].answer.as_mut().unwrap();
    reply.branches[0].steps[2].reason.detail = "other".into();
    let d = diff::answer(&before, &after);
    assert_eq!(d.counts.changed, 1);
    let c = &d.branches[0];
    assert_eq!((c.branch.index, c.first_step), (1, None));
    let r = c.reply.as_ref().unwrap();
    assert!(r.ran && r.before_ran);
    let inner = r.diff.as_ref().unwrap();
    assert_eq!(inner.counts.changed, 1);
    assert_eq!(inner.branches[0].first_step, Some(2));
}

fn row(subject: &str, result: ClaimResult, span: &str) -> Evidence {
    Evidence {
        subject: subject.into(),
        result,
        expected: None,
        observed: None,
        reason: "x".into(),
        detail: String::new(),
        provenance: vec![span.into()],
    }
}

#[test]
fn evidence_rows_pair_by_subject_and_ignore_spans() {
    use ClaimResult::*;
    let before = [
        row("a", Confirmed, "s1"),
        row("b", Confirmed, "s1"),
        row("c", Confirmed, "s1"),
    ];
    let after = [
        row("d", Unknown, "s2"),
        row("b", Refuted, "s2"),
        row("a", Confirmed, "s2"),
    ];
    let d = diff::evidence(&before, &after);
    let got: Vec<(&str, RowChange)> = d
        .iter()
        .map(|c| (c.row.subject.as_str(), c.change))
        .collect();
    assert_eq!(
        got,
        [
            ("b", RowChange::Changed),
            ("c", RowChange::Removed),
            ("d", RowChange::Added)
        ]
    );
    assert_eq!(d[0].before.as_ref().unwrap().result, Confirmed);
    assert_eq!(d[0].row.result, Refuted);
}
