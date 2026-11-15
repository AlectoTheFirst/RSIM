//! Memory per device (section 14). A counting allocator measures the heap
//! bytes that stay allocated after the twin build.

// The global allocator needs `unsafe`. It is only in this benchmark binary.
#![allow(unsafe_code)]

#[path = "../tests/common/mod.rs"]
mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};

use common::*;
use rsim_engine::{Twin, TwinBuilder};

struct Counting;

static LIVE: AtomicIsize = AtomicIsize::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        LIVE.fetch_add(l.size() as isize, Ordering::Relaxed);
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        LIVE.fetch_sub(l.size() as isize, Ordering::Relaxed);
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        LIVE.fetch_add(n as isize - l.size() as isize, Ordering::Relaxed);
        unsafe { System.realloc(p, l, n) }
    }
}

#[global_allocator]
static A: Counting = Counting;

fn measure(name: &str, make: impl FnOnce() -> TwinBuilder) {
    let before = LIVE.load(Ordering::Relaxed);
    let twin: Twin = make().build().unwrap();
    let after = LIVE.load(Ordering::Relaxed);
    let bytes = (after - before) as f64;
    let devices = twin.device_count();
    println!(
        "{name:<48} devices {devices:>6}  functions {:>7}  total {:>10.1} KiB  per device {:>8.1} KiB",
        twin.function_count(),
        bytes / 1024.0,
        bytes / 1024.0 / devices as f64
    );
    drop(twin);
}

fn main() {
    // `cargo bench` passes `--bench`; there are no options to parse.
    println!("live heap bytes after the twin build, counted by the global allocator");
    measure("mini-enterprise (3 devices)", || {
        mini_enterprise(MiniOpts::default())
    });
    for n in [100, 1000, 10_000] {
        measure(
            &format!("chain, 20 ACL rules, 102 routes ({n} routers)"),
            || chain(n, 20, 100),
        );
    }
}
