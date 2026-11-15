//! Single path query benchmark. Each iteration builds its query, as a real
//! query does.

use criterion::{Criterion, criterion_group, criterion_main};
use rsim_core::Header;
use rsim_engine::{ExecOptions, Executor, Query, Twin};
use rsim_topologies::*;
use std::hint::black_box;

fn query(twin: &Twin, h: &Header, reply: bool) -> Query {
    let mut q = Query::path(twin, h);
    q.reply = reply;
    q
}

fn bench(c: &mut Criterion) {
    let opts = ExecOptions {
        check_contract: false,
        ..ExecOptions::default()
    };

    let mini = mini_enterprise(MiniOpts::default()).build().unwrap();
    let h = udp("172.31.10.20", 40000, "10.20.0.53", 53);
    let ex = Executor::with_options(&mini, opts);
    c.bench_function("mini-enterprise guest->dns forward (21 steps)", |b| {
        b.iter(|| black_box(ex.run(&query(&mini, black_box(&h), false)).unwrap()))
    });
    c.bench_function("mini-enterprise guest->dns forward+reply (42 steps)", |b| {
        b.iter(|| black_box(ex.run(&query(&mini, black_box(&h), true)).unwrap()))
    });
    let ex_checked = Executor::new(&mini);
    c.bench_function(
        "mini-enterprise guest->dns forward+reply, contract checks on",
        |b| b.iter(|| black_box(ex_checked.run(&query(&mini, black_box(&h), true)).unwrap())),
    );

    let chain10 = chain(10, 20, 100).build().unwrap();
    let h = tcp("10.254.0.10", 40000, "10.255.0.10", 443);
    let ex = Executor::with_options(&chain10, opts);
    c.bench_function("chain of 10 routers forward (60 steps)", |b| {
        b.iter(|| black_box(ex.run(&query(&chain10, black_box(&h), false)).unwrap()))
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
