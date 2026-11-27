//! The lookups of the collected tables on generated frames: a table `mac`
//! and a table `arp` of `RSIM_FRAME_DEVICES` devices (default 1,000) with
//! `RSIM_FRAME_ROWS` rows for each device (default 1,000).
//!
//! The benchmark prints the build time of each frame, the time of the first
//! selection that builds an index, and the median time of a selection after
//! it: a page of the rows of one device, the rows of one MAC address, the
//! addresses inside a /24, the rows of one port with no index, and the
//! export of all rows as CSV and as Parquet.

use std::io::Write;
use std::time::{Duration, Instant};

use rsim_cli::frame::{self, Cell, Frame, FrameBuilder};
use rsim_contract::table::{self, Selection};

fn env(k: &str, default: usize) -> usize {
    std::env::var(k)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn out(line: String) {
    let mut o = std::io::stdout().lock();
    let _ = writeln!(o, "{line}");
    let _ = o.flush();
}

/// The median time of `n` runs.
fn median(n: usize, mut f: impl FnMut()) -> Duration {
    let mut v: Vec<Duration> = (0..n)
        .map(|_| {
            let t = Instant::now();
            f();
            t.elapsed()
        })
        .collect();
    v.sort();
    v[n / 2]
}

fn ms(d: Duration) -> String {
    format!("{:.3} ms", d.as_secs_f64() * 1000.0)
}

/// The time of the first selection, which builds the index, and the median
/// time of 21 selections after it.
fn lookup(what: &str, def: &'static table::TableDef, f: &Frame, sel: &Selection) {
    let t = Instant::now();
    let p = frame::show(def, f, sel).unwrap();
    let first = t.elapsed();
    let later = median(21, || {
        frame::show(def, f, sel).unwrap();
    });
    out(format!(
        "{} {what}: {} rows, first {}, then {}",
        def.name,
        p.total,
        ms(first),
        ms(later)
    ));
}

fn filter(column: &str, value: &str) -> Selection {
    Selection {
        filters: [(column.to_string(), vec![value.to_string()])].into(),
        limit: Some(100),
        ..Selection::default()
    }
}

fn main() {
    let devices = env("RSIM_FRAME_DEVICES", 1000);
    let per = env("RSIM_FRAME_ROWS", 1000);
    out(format!(
        "{devices} devices, {per} rows for each device, {} rows",
        devices * per
    ));

    let mac = table::table("mac").unwrap();
    let t = Instant::now();
    let mut b = FrameBuilder::new(mac);
    let span: [String; 1] = ["sw/mac_table@b#row".to_string()];
    for d in 0..devices {
        let device = format!("sw{d:05}");
        for r in 0..per {
            let m = format!(
                "02:00:{:02x}:{:02x}:{:02x}:{:02x}",
                (r >> 8) & 0xff,
                r & 0xff,
                (d >> 8) & 0xff,
                d & 0xff
            );
            let port = format!("eth{}", r % 48);
            b.push(&[
                Cell::Text(&device),
                Cell::Integer(10 + (r % 20) as u64),
                Cell::Text(&m),
                Cell::Text(&port),
                Cell::Text("dynamic"),
                Cell::List(&span),
            ]);
        }
    }
    let f = b.finish(&rsim_cli::tables::key_text);
    out(format!("mac build: {}", ms(t.elapsed())));
    let one = format!("sw{:05}", devices / 2);
    lookup("one device", mac, &f, &filter("device", &one));
    lookup(
        "one MAC address",
        mac,
        &f,
        &filter("mac", "02:00:00:07:00:03"),
    );
    lookup("one port, no index", mac, &f, &filter("port", "eth7"));
    let all = Selection::default();
    let t = Instant::now();
    let e = frame::export(mac, &f, &all).unwrap();
    let csv = frame::csv(&f, &e);
    out(format!(
        "mac export CSV: {} bytes, {}",
        csv.len(),
        ms(t.elapsed())
    ));
    let t = Instant::now();
    let e = frame::export(mac, &f, &all).unwrap();
    let pq = frame::parquet(&f, &e).unwrap();
    out(format!(
        "mac export Parquet: {} bytes, {}",
        pq.len(),
        ms(t.elapsed())
    ));
    drop(f);

    let arp = table::table("arp").unwrap();
    let t = Instant::now();
    let mut b = FrameBuilder::new(arp);
    for d in 0..devices {
        let device = format!("r{d:05}");
        for r in 0..per {
            let ip = format!("10.{}.{}.{}", d % 256, r / 250 + (d / 256) * 8, r % 250);
            let m = format!(
                "02:01:{:02x}:{:02x}:{:02x}:{:02x}",
                (r >> 8) & 0xff,
                r & 0xff,
                (d >> 8) & 0xff,
                d & 0xff
            );
            b.push(&[
                Cell::Text(&device),
                Cell::Text("eth0"),
                Cell::Text(&ip),
                Cell::Text(&m),
                Cell::Text("reachable"),
                Cell::List(&span),
            ]);
        }
    }
    let f = b.finish(&rsim_cli::tables::key_text);
    out(format!("arp build: {}", ms(t.elapsed())));
    let inside = Selection {
        typed: [("ip.in_prefix".to_string(), "10.7.1.0/24".to_string())].into(),
        limit: Some(100),
        ..Selection::default()
    };
    lookup("addresses inside a /24", arp, &f, &inside);
    lookup("one device", arp, &f, &filter("device", "r00007"));
}
