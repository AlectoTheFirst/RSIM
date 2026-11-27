//! The table `fabric-connections` of a twin of an Equinix account.

use std::collections::BTreeMap;

use rsim_cli::commands::Loaded;
use rsim_contract::table::Selection;
use rsim_contract::twin::TwinJson;
use rsim_ingest::estate::{Input, assemble};
use serde_json::{Value, json};

const ACCT: &str = "equinix-lab";

fn section(name: &str, v: Value) -> (String, (Vec<u8>, String)) {
    (
        name.to_string(),
        (
            serde_json::to_vec_pretty(&v).unwrap(),
            format!("{ACCT}/{name}@b1"),
        ),
    )
}

fn colo(port: &str, tag: i64) -> Value {
    json!({"accessPoint": {
        "type": "COLO",
        "port": {"uuid": port},
        "linkProtocol": {"type": "DOT1Q", "vlanTag": tag},
    }})
}

fn loaded() -> Loaded {
    let port = |uuid: &str| {
        json!({"uuid": uuid, "name": format!("lab-{uuid}"), "state": "ACTIVE",
               "encapsulation": {"type": "DOT1Q"}})
    };
    let sections: BTreeMap<String, (Vec<u8>, String)> = [
        section("ports", json!([port("p1"), port("p2")])),
        section(
            "connections",
            json!([
                {"uuid": "c-1", "name": "dc-a-to-dc-b", "type": "EVPL_VC", "state": "ACTIVE",
                 "aSide": colo("p1", 100), "zSide": colo("p2", 200)},
                {"uuid": "c-2", "type": "EVPL_VC", "state": "DEPROVISIONED",
                 "aSide": colo("p1", 300), "zSide": colo("p2", 300)},
                {"uuid": "c-3", "type": "EVPL_VC", "state": "PENDING",
                 "aSide": colo("p1", 400), "zSide": colo("p2", 400)},
            ]),
        ),
    ]
    .into_iter()
    .collect();
    let estate = assemble(vec![Input::Equinix {
        name: ACCT.into(),
        sections,
    }]);
    Loaded {
        twin: estate.builder.build().expect("the twin builds"),
        identity: TwinJson::builtin("equinix").unwrap(),
        coverage: estate.coverage,
        bgp: estate.bgp,
        facts: BTreeMap::new(),
        seen: estate.seen,
        fabric: estate.fabric,
        mtu: estate.mtu,
        guard: estate.guard,
        tables: Default::default(),
        source: None,
    }
}

#[test]
fn each_circuit_of_the_account_is_a_row_with_its_result() {
    let t = loaded();
    let out =
        rsim_cli::tables::show("equinix", &t, "fabric-connections", &Selection::default()).unwrap();
    let rows: Vec<Value> = out.rows.iter().map(|r| json!(r)).collect();
    assert_eq!(
        rows,
        [
            json!([
                ACCT,
                "c-1",
                "dc-a-to-dc-b",
                "EVPL_VC",
                "ACTIVE",
                "port lab-p1 DOT1Q tag 100",
                "port lab-p2 DOT1Q tag 200",
                "lowered",
                null,
                [format!("{ACCT}/connections@b1:2-31")]
            ]),
            json!([
                ACCT,
                "c-2",
                null,
                "EVPL_VC",
                "DEPROVISIONED",
                "port lab-p1 DOT1Q tag 300",
                "port lab-p2 DOT1Q tag 300",
                "ended",
                null,
                [format!("{ACCT}/connections@b1:32-60")]
            ]),
            json!([
                ACCT,
                "c-3",
                null,
                "EVPL_VC",
                "PENDING",
                "port lab-p1 DOT1Q tag 400",
                "port lab-p2 DOT1Q tag 400",
                "unknown",
                "the circuit state PENDING is not handled",
                [format!("{ACCT}/connections@b1:61-89")]
            ]),
        ]
    );
}
