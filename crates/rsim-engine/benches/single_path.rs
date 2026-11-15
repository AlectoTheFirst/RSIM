//! Single path query benchmark (section 14).

#[path = "../tests/common/mod.rs"]
mod common;

use common::*;
use criterion::{Criterion, criterion_group, criterion_main};
use rsim_core::EndpointId;
use rsim_engine::{ExecOptions, Executor, Query};
use std::hint::black_box;

fn bench(c: &mut Criterion) {
    let opts = ExecOptions {
        check_contract: false,
        ..ExecOptions::default()
    };

    let mini = mini_enterprise(MiniOpts::default()).build().unwrap();
    let mut q = Query::from_endpoint(
        &mini,
        &EndpointId::new("guest-client"),
        udp("172.31.10.20", 40000, "10.20.0.53", 53),
    )
    .unwrap();
    q.reply = false;
    let ex = Executor::with_options(&mini, opts);
    c.bench_function("mini-enterprise guest->dns forward (21 steps)", |b| {
        b.iter(|| black_box(ex.run(black_box(&q)).unwrap()))
    });
    q.reply = true;
    c.bench_function("mini-enterprise guest->dns forward+reply (42 steps)", |b| {
        b.iter(|| black_box(ex.run(black_box(&q)).unwrap()))
    });
    let ex_checked = Executor::new(&mini);
    c.bench_function(
        "mini-enterprise guest->dns forward+reply, contract checks on",
        |b| b.iter(|| black_box(ex_checked.run(black_box(&q)).unwrap())),
    );

    let chain10 = chain(10, 20, 100).build().unwrap();
    let mut q = Query::from_endpoint(
        &chain10,
        &EndpointId::new("client"),
        tcp("10.254.0.10", 40000, "10.255.0.10", 443),
    )
    .unwrap();
    q.reply = false;
    let ex = Executor::with_options(&chain10, opts);
    c.bench_function("chain of 10 routers forward (60 steps)", |b| {
        b.iter(|| black_box(ex.run(black_box(&q)).unwrap()))
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
