//! A load test of the API on a loopback port: the time and the bytes of
//! each request for each answer form, with 1 client and with more
//! clients at the same time.
//!
//! `cargo run --release -p rsim-api --example load -- <clients,...> <requests per client>`,
//! for example `-- 1,8,64 50`.

#![allow(clippy::disallowed_types)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Instant;

use rsim_api::handler::{Settings, State};

fn ask(addr: SocketAddr, text: &str) -> Vec<u8> {
    let mut c = TcpStream::connect(addr).expect("connect");
    c.write_all(text.as_bytes()).expect("write");
    let mut out = Vec::new();
    c.read_to_end(&mut out).expect("read");
    out
}

fn body(response: &[u8]) -> &[u8] {
    let i = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(0, |i| i + 4);
    &response[i..]
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let clients: Vec<usize> = args
        .first()
        .map_or("1,4".into(), String::clone)
        .split(',')
        .filter_map(|c| c.parse().ok())
        .collect();
    let per: usize = args.get(1).and_then(|n| n.parse().ok()).unwrap_or(20);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_io()
        .build()
        .expect("runtime");
    let listener = rt
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .expect("bind");
    let addr = listener.local_addr().expect("address");
    let state = Arc::new(State::new(Settings {
        listen: addr,
        store: None,
        allow_origins: Vec::new(),
        max_body: 1 << 20,
    }));
    rt.spawn(rsim_api::server::serve(listener, state));
    let query = r#"{"source.ip":"10.1.0.10","destination.ip":"10.2.0.10","network.transport":"tcp","source.port":40000,"destination.port":22}"#;
    let r = ask(
        addr,
        &format!(
            "POST /v1/twins/builtin.leaf-spine/queries HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{query}",
            query.len()
        ),
    );
    let text = String::from_utf8_lossy(&r);
    let location = text
        .lines()
        .find_map(|l| l.strip_prefix("location: "))
        .expect("a location")
        .trim()
        .to_string();
    println!("| Form | Clients | Requests | Mean time per request | Requests per second | Bytes |");
    println!("|---|---|---|---|---|---|");
    for form in ["summary", "steps", "full"] {
        let request = format!(
            "GET {location}?form={form} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
        );
        let bytes = body(&ask(addr, &request)).len();
        for &n in &clients {
            let start = Instant::now();
            let threads: Vec<_> = (0..n)
                .map(|_| {
                    let request = request.clone();
                    std::thread::spawn(move || {
                        for _ in 0..per {
                            let r = ask(addr, &request);
                            assert!(
                                r.starts_with(b"HTTP/1.1 200"),
                                "{}",
                                String::from_utf8_lossy(&r)
                            );
                        }
                    })
                })
                .collect();
            for t in threads {
                t.join().expect("client");
            }
            let total = start.elapsed();
            let count = n * per;
            println!(
                "| {form} | {n} | {count} | {:.2} ms | {:.0} | {bytes} |",
                total.as_secs_f64() * 1000.0 * n as f64 / count as f64,
                count as f64 / total.as_secs_f64()
            );
        }
    }
    rt.shutdown_background();
}
