//! Principle 2: the same input gives the same output.

mod common;

use common::*;
use rsim_core::EndpointId;
use rsim_engine::{Executor, Mode, Query};

#[test]
fn the_same_query_gives_the_same_answer() {
    let twin = mini_enterprise(MiniOpts::default()).build().unwrap();
    let q = Query::from_endpoint(
        &twin,
        &EndpointId::new("guest-client"),
        udp("172.31.10.20", 40000, "10.20.0.53", 53),
        Mode::Possible,
    )
    .unwrap();
    let a = Executor::new(&twin).run(&q).unwrap();
    let b = Executor::new(&twin).run(&q).unwrap();
    assert_eq!(a, b);
    assert_eq!(format!("{a:?}"), format!("{b:?}"));
}

#[test]
fn the_insertion_order_of_the_build_does_not_change_the_answer() {
    let fwd = mini_enterprise(MiniOpts::default()).build().unwrap();
    let rev = mini_enterprise(MiniOpts {
        reverse_insertion: true,
        ..MiniOpts::default()
    })
    .build()
    .unwrap();
    for (from, h) in [
        ("guest-client", udp("172.31.10.20", 40000, "10.20.0.53", 53)),
        ("guest-client", tcp("172.31.10.20", 40000, "10.20.0.53", 80)),
        ("fra01-dns", tcp("10.20.0.53", 50000, "172.31.10.20", 22)),
    ] {
        let run = |t| {
            let q = Query::from_endpoint(t, &EndpointId::new(from), h.clone(), Mode::Guaranteed)
                .unwrap();
            Executor::new(t).run(&q).unwrap()
        };
        assert_eq!(run(&fwd), run(&rev));
    }
}

#[test]
fn queries_in_parallel_threads_give_the_same_answers() {
    let twin = ecmp().build().unwrap();
    let q = Query::from_endpoint(
        &twin,
        &EndpointId::new("client"),
        tcp("10.1.0.10", 40000, "10.4.0.10", 22),
        Mode::Possible,
    )
    .unwrap();
    let expected = Executor::new(&twin).run(&q).unwrap();
    std::thread::scope(|s| {
        let handles: Vec<_> = (0..8)
            .map(|_| s.spawn(|| Executor::new(&twin).run(&q).unwrap()))
            .collect();
        for h in handles {
            assert_eq!(h.join().unwrap(), expected);
        }
    });
}
