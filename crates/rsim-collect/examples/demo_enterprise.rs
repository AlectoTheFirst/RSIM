//! Writes the command replies of the demo estate into a folder, the
//! top-level folder `demo/` of the repository:
//! `cargo run -p rsim-collect --example demo_enterprise -- demo`.
//! `rsim-collect seed --demo <folder>` writes them into a new store.

#[path = "demo_enterprise/mod.rs"]
mod demo_enterprise;

fn main() {
    let Some(out) = std::env::args().nth(1) else {
        eprintln!("usage: demo_enterprise <output folder>");
        std::process::exit(2);
    };
    if let Err(e) = demo_enterprise::generate(std::path::Path::new(&out)) {
        eprintln!("error: {out}: {e}");
        std::process::exit(1);
    }
}
