//! The parse of an IOS-XR `show route vrf all ipv4` of 100,000 routes with the
//! template that the crate carries.

use std::fmt::Write;
use std::hint::black_box;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use rsim_textfsm::Library;

const ROUTES: usize = 100_000;

/// The host routes of the three documentation networks.
fn hosts() -> impl Iterator<Item = String> {
    ["192.0.2", "198.51.100", "203.0.113"]
        .into_iter()
        .flat_map(|net| (0..256).map(move |host| format!("{net}.{host}")))
}

/// A route table of `ROUTES` routes in VRFs of 768 host routes each. Each
/// fourth route has a second path on a continuation line.
fn route_table() -> String {
    let mut text = String::new();
    let mut routes = 0;
    let mut vrf = 0;
    while routes < ROUTES {
        vrf += 1;
        writeln!(text, "\nVRF: TENANT{vrf:04}\n").unwrap();
        text.push_str(
            "Codes: C - connected, S - static, R - RIP, B - BGP, (>) - Diversion path\n       \
             O - OSPF, IA - OSPF inter area, L - local, (!) - FRR Backup path\n\n\
             Gateway of last resort is not set\n\n",
        );
        for host in hosts().take(ROUTES - routes) {
            writeln!(
                text,
                "O    {host}/32 [110/20] via 198.51.100.1, 2d03h, GigabitEthernet0/0/0/1"
            )
            .unwrap();
            if routes % 4 == 0 {
                text.push_str(
                    "                 [110/20] via 198.51.100.5, 2d03h, GigabitEthernet0/0/0/2\n",
                );
            }
            routes += 1;
        }
    }
    text
}

fn bench(c: &mut Criterion) {
    let library = Library::builtin().expect("the built-in templates read");
    let (_, template) = library
        .find("cisco_xr", "show route vrf all ipv4")
        .expect("the route template is indexed");
    let text = route_table();
    let table = template.parse_text(&text).expect("the route table parses");
    assert_eq!(table.records.len(), ROUTES + ROUTES / 4);

    let mut group = c.benchmark_group("textfsm");
    group
        .sample_size(10)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(5));
    group.bench_function("xr_show_route_100k", |b| {
        b.iter(|| template.parse_text(black_box(&text)).unwrap())
    });
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
