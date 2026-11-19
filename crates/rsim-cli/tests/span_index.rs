//! Each source span of each trace step lies inside the span index of its
//! twin, so the source lines of a step are given: for the built-in
//! topologies, and for the fixture store with each line served.

use std::collections::BTreeSet;

use rsim_cli::SetInput;
use rsim_cli::commands::{self, Loaded};
use rsim_cli::set_query::{Ranges, parse_transports};
use rsim_cli::sources::{self, SpanIndex};
use rsim_contract::query::IngressRef;
use rsim_engine::{Answer, ReplyResult};

#[path = "support/fixture_store.rs"]
mod fixture_store;

/// The largest number of ingress interfaces of a twin that the tests query.
const MAX_INGRESS: usize = 12;

/// The spans of the trace steps of a set query of TCP and UDP to a few
/// ports of each destination, with the replies, from the ingress interfaces of a twin: each one, or an
/// evenly spaced choice of at most `MAX_INGRESS` of them.
fn step_spans(topology: &str, twin: &Loaded) -> BTreeSet<(String, u32, u32)> {
    let ingress: BTreeSet<(String, String)> = twin
        .functions()
        .filter_map(|f| Some((f.device()?.to_string(), f.ingress_interface()?.to_string())))
        .collect();
    assert!(!ingress.is_empty(), "{topology}");
    let step = ingress.len().div_ceil(MAX_INGRESS);
    let mut out = BTreeSet::new();
    for (device, interface) in ingress.into_iter().step_by(step) {
        let input = SetInput {
            topology: topology.to_string(),
            ingress: Some(IngressRef { device, interface }),
            transport: Some(parse_transports("tcp,udp").unwrap()),
            source_port: Some(Ranges(vec![(40000, 40000)])),
            destination_port: Some(Ranges(vec![
                (22, 22),
                (53, 53),
                (80, 80),
                (443, 443),
                (8123, 8123),
            ])),
            reply: Some(true),
            ..SetInput::default()
        };
        if let Ok(a) = commands::run_set(&input, twin) {
            collect(&a, &mut out);
        }
    }
    out
}

/// The spans of each trace step of an answer and of its replies.
fn collect(a: &Answer, out: &mut BTreeSet<(String, u32, u32)>) {
    for b in a.branches() {
        for st in b.steps {
            for s in &st.provenance {
                out.insert((s.file.to_string(), s.first_line, s.last_line));
            }
        }
    }
    for r in &a.replies {
        if let ReplyResult::Ran(x) = &r.result {
            collect(x, out);
        }
    }
}

#[test]
fn each_step_span_of_a_built_in_topology_is_in_the_index() {
    for name in commands::topology_names() {
        let twin = commands::load(name).unwrap();
        let index = SpanIndex::of(&twin.twin);
        let spans = step_spans(name, &twin);
        assert!(!spans.is_empty(), "{name}");
        for (file, a, b) in spans {
            assert_eq!(
                index.covered(&file, a, b),
                vec![(a, b)],
                "{name}: {file}:{a}-{b}"
            );
        }
    }
}

#[test]
#[allow(clippy::disallowed_methods)]
fn each_step_span_of_the_fixture_store_is_served_whole() {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join("rsim-cli-span-index");
    let _ = std::fs::remove_dir_all(&dir);
    fixture_store::write(&dir);
    let topology = format!("store:{}", dir.display());
    let twin = commands::load(&topology).unwrap();
    let spans = step_spans(&topology, &twin);
    let files: BTreeSet<&str> = spans.iter().map(|s| s.0.as_str()).collect();
    assert!(
        files.iter().any(|f| f.starts_with("r1/config@")),
        "{files:?}"
    );
    assert!(files.iter().any(|f| f.starts_with("site1/")), "{files:?}");
    let index = SpanIndex::of(&twin.twin);
    let mut served = 0;
    for (file, a, b) in &spans {
        assert_eq!(
            index.covered(file, *a, *b),
            vec![(*a, *b)],
            "{file}:{a}-{b}"
        );
        // The table sections of the fixture store hold no readable text.
        if !file.contains("/config@") && !file.starts_with("site1/") {
            continue;
        }
        let t = sources::text(&twin, file, *a, *b)
            .unwrap_or_else(|e| panic!("{file}:{a}-{b}: {}", e.detail));
        assert!(t.left_out.is_empty(), "{file}:{a}-{b}: {:?}", t.left_out);
        assert_eq!(t.lines.len() as u32, (b - a + 1).min(200), "{file}:{a}-{b}");
        served += 1;
    }
    assert!(served > 0);
}
