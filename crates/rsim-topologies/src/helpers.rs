//! Helpers that build addresses, headers, rules and endpoints.

use std::net::IpAddr;

use rsim_core::{FunctionId, Header, PROTO_TCP, PROTO_UDP, Prefix};

pub fn ip(s: &str) -> IpAddr {
    s.parse().expect("valid address")
}

pub fn pfx(s: &str) -> Prefix {
    s.parse().expect("valid prefix")
}

pub fn fid(s: &str) -> FunctionId {
    FunctionId::new(s)
}

pub fn udp(src: &str, sport: u16, dst: &str, dport: u16) -> Header {
    Header::request(ip(src), ip(dst), PROTO_UDP)
        .with_src_port(sport)
        .with_dst_port(dport)
}

pub fn tcp(src: &str, sport: u16, dst: &str, dport: u16) -> Header {
    Header::request(ip(src), ip(dst), PROTO_TCP)
        .with_src_port(sport)
        .with_dst_port(dport)
}

pub fn ids(v: &[&str]) -> Vec<FunctionId> {
    v.iter().map(|s| fid(s)).collect()
}
