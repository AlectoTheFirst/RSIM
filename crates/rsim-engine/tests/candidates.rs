//! The summary over the candidates of a selection that is not collected.

use rsim_core::{Destination, DeviceId, FunctionId, Reason, ReasonCode, Verdict, VerdictKind};
use rsim_engine::Summary;
use rsim_engine::answer::{combine_candidates, combine_paths};

fn select() -> FunctionId {
    FunctionId::new("edge1/sdwan/select/0/hub1")
}

fn deliver(device: &str) -> Summary {
    Summary::Same(Verdict::Deliver(Destination::Device(DeviceId::new(device))))
}

fn denied(detail: &str) -> Summary {
    Summary::Same(Verdict::Drop(Reason::new(ReasonCode::Denied, detail)))
}

#[test]
fn candidates_with_one_result_give_that_result() {
    let s = [deliver("hub1"), deliver("hub1"), deliver("hub1")];
    assert_eq!(combine_candidates(&select(), &s), deliver("hub1"));
}

#[test]
fn candidates_with_one_kind_of_result_give_that_kind() {
    let s = [denied("rule 10"), denied("rule 20")];
    assert_eq!(
        combine_candidates(&select(), &s),
        Summary::SameKind(VerdictKind::Drop)
    );
}

#[test]
fn candidates_with_different_kinds_of_result_give_unknown() {
    let s = [deliver("hub1"), denied("rule 10")];
    let Summary::Same(Verdict::Unknown(r)) = combine_candidates(&select(), &s) else {
        panic!("the summary is not unknown");
    };
    assert_eq!(r.code, ReasonCode::SelectionNotCollected);
    assert_eq!(
        r.detail,
        "the candidates of edge1/sdwan/select/0/hub1 end differently"
    );
}

#[test]
fn a_candidate_that_depends_on_its_path_gives_unknown() {
    let s = [deliver("hub1"), Summary::DependsOnPath];
    assert_eq!(
        combine_candidates(&select(), &s).kind(),
        Some(VerdictKind::Unknown)
    );
}

#[test]
fn the_paths_of_a_forwarding_choice_keep_their_rule() {
    let s = [deliver("hub1"), denied("rule 10")];
    assert_eq!(combine_paths(&s), Summary::DependsOnPath);
}
