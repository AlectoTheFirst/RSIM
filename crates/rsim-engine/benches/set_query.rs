//! Set query benchmark. Each iteration builds its query. Before the
//! measurement, the benchmark prints the parts, the branches and the nodes
//! of each query.

use criterion::{Criterion, criterion_group, criterion_main};
use rsim_core::{PacketSet, SetSpec};
use rsim_engine::{ExecOptions, Executor, Query, Twin};
use rsim_topologies::*;
use std::hint::black_box;

fn query(twin: &Twin, spec: &SetSpec, reply: bool) -> Query {
    let arena = twin.arena(None);
    let mut q = Query::set(PacketSet::from_spec(&arena, spec));
    q.reply = reply;
    q
}

fn spec(src: &str, dst: &str, protocols: &[(u8, u8)]) -> SetSpec {
    SetSpec {
        src_ip: Some(vec![src.parse().unwrap()]),
        dst_ip: Some(vec![dst.parse().unwrap()]),
        protocol: Some(protocols.to_vec()),
        ..SetSpec::default()
    }
}

fn bench(c: &mut Criterion) {
    let opts = ExecOptions {
        check_contract: false,
        ..ExecOptions::default()
    };
    let mini = mini_enterprise(MiniOpts::default()).build().unwrap();
    let ecmp_twin = ecmp().build().unwrap();
    let chain10 = chain(10, 20, 100).build().unwrap();
    let cases: Vec<(&str, &Twin, SetSpec, bool)> = vec![
        (
            "mini-enterprise guest /24 to corp /24, tcp and udp, forward",
            &mini,
            spec("172.31.10.0/24", "10.20.0.0/24", &[(6, 6), (17, 17)]),
            false,
        ),
        (
            "mini-enterprise guest /24 to corp /24, tcp and udp, forward+reply",
            &mini,
            spec("172.31.10.0/24", "10.20.0.0/24", &[(6, 6), (17, 17)]),
            true,
        ),
        (
            "ecmp client /24 to server /24, all protocols, forward",
            &ecmp_twin,
            spec("10.1.0.0/24", "10.4.0.0/24", &[(0, 255)]),
            false,
        ),
        (
            "chain of 10 routers, client /24 to server /24, all protocols, forward",
            &chain10,
            spec("10.254.0.0/24", "10.255.0.0/24", &[(0, 255)]),
            false,
        ),
    ];
    for (name, twin, s, reply) in &cases {
        let ex = Executor::with_options(twin, opts);
        let a = ex.run(&query(twin, s, *reply)).unwrap();
        let nodes: usize = a.runs.iter().map(|r| r.input.arena().local_nodes()).sum();
        let members: usize = a.summary.iter().map(|p| p.packets.describe().len()).sum();
        eprintln!(
            "{name}: {} parts, {} members in the parts, {} branches, {} runs, {nodes} nodes",
            a.summary.len(),
            members,
            a.branches().len(),
            a.runs.len()
        );
        c.bench_function(name, |b| {
            b.iter(|| black_box(ex.run(&query(twin, black_box(s), *reply)).unwrap()))
        });
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
