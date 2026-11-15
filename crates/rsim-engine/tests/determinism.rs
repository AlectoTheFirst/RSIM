//! Principle 2: the same input gives the same output.

use rsim_engine::{Answer, Executor, Query};
use rsim_topologies::*;

/// The branches of an answer with their steps, verdicts and witnesses, and
/// the replies in the same form. It does not depend on the arena.
fn view(a: &Answer) -> String {
    let mut s = String::new();
    for b in a.branches() {
        s.push_str(&format!("{:?} {:?}\n", b.verdict, b.packets.witness()));
        for st in &b.steps {
            s.push_str(&format!(
                "  {} {:?} {:?} {:?}\n",
                st.function,
                st.outcome,
                st.reason,
                st.output.witness()
            ));
        }
    }
    for p in &a.summary {
        s.push_str(&format!("{:?} {:?}\n", p.summary, p.packets.witness()));
    }
    for r in &a.replies {
        match &r.result {
            rsim_engine::ReplyResult::Ran(x) => s.push_str(&view(x)),
            rsim_engine::ReplyResult::NotRun(t) => s.push_str(t),
        }
    }
    s
}

#[test]
fn the_same_query_gives_the_same_answer() {
    let twin = mini_enterprise(MiniOpts::default()).build().unwrap();
    let h = udp("172.31.10.20", 40000, "10.20.0.53", 53);
    // Two queries in two arenas give the same answer. The output form of
    // an answer does not depend on its arena.
    let a = Executor::new(&twin).run(&Query::path(&twin, &h)).unwrap();
    let b = Executor::new(&twin).run(&Query::path(&twin, &h)).unwrap();
    assert_eq!(view(&a), view(&b));
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
    for h in [
        udp("172.31.10.20", 40000, "10.20.0.53", 53),
        tcp("172.31.10.20", 40000, "10.20.0.53", 80),
        tcp("10.20.0.53", 50000, "172.31.10.20", 22),
    ] {
        let run = |t| Executor::new(t).run(&Query::path(t, &h)).unwrap();
        assert_eq!(view(&run(&fwd)), view(&run(&rev)));
    }
}

#[test]
fn queries_in_parallel_threads_give_the_same_answers() {
    let twin = ecmp().build().unwrap();
    let q = Query::path(&twin, &tcp("10.1.0.10", 40000, "10.4.0.10", 22));
    let expected = view(&Executor::new(&twin).run(&q).unwrap());
    std::thread::scope(|s| {
        let handles: Vec<_> = (0..8)
            .map(|_| s.spawn(|| view(&Executor::new(&twin).run(&q).unwrap())))
            .collect();
        for h in handles {
            assert_eq!(h.join().unwrap(), expected);
        }
    });
}

#[test]
fn a_query_that_runs_again_gives_the_same_answer() {
    let twin = mini_enterprise(MiniOpts::default()).build().unwrap();
    let q = Query::path(&twin, &udp("172.31.10.20", 40000, "10.20.0.53", 53));
    let first = view(&Executor::new(&twin).run(&q).unwrap());
    for _ in 0..10 {
        assert_eq!(view(&Executor::new(&twin).run(&q).unwrap()), first);
    }
}
