//! Tells the crate which files of the browser UI exist in `ui/dist`, the
//! output of `npm --prefix ui run build`. With `RSIM_UI_REQUIRED=1`, a
//! missing file of the app is a build error.

use std::path::Path;

/// The files of the app, by the fixed names of `ui/vite.config.ts`.
const APP: &[&str] = &["index.html", "assets/app.js", "assets/app.css"];

/// The font files and their licenses, from `ui/public/fonts`.
const FONTS: &[&str] = &[
    "fonts/Inter-Variable.woff2",
    "fonts/JetBrainsMono-Variable.ttf",
    "fonts/OFL-Inter.txt",
    "fonts/OFL-JetBrainsMono.txt",
];

fn main() {
    println!("cargo::rustc-check-cfg=cfg(rsim_ui)");
    println!("cargo::rustc-check-cfg=cfg(rsim_ui_fonts)");
    println!("cargo::rerun-if-env-changed=RSIM_UI_REQUIRED");
    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());
    let ui = Path::new(&manifest).join("../../ui");
    let dist = ui.join("dist");
    // A directory that exists, so that the build script runs again when
    // the UI is built or removed.
    if dist.is_dir() {
        println!("cargo::rerun-if-changed={}", dist.display());
    } else if ui.is_dir() {
        println!("cargo::rerun-if-changed={}", ui.display());
    }
    let missing = |files: &[&str]| -> Vec<String> {
        files
            .iter()
            .filter(|f| !dist.join(f).is_file())
            .map(|f| f.to_string())
            .collect()
    };
    let app = missing(APP);
    if app.is_empty() {
        println!("cargo::rustc-cfg=rsim_ui");
    } else if std::env::var("RSIM_UI_REQUIRED").as_deref() == Ok("1") {
        panic!(
            "the browser UI is not built: {} missing in {}; run `npm --prefix ui ci` and `npm --prefix ui run build`",
            app.join(", "),
            dist.display()
        );
    }
    if app.is_empty() && missing(FONTS).is_empty() {
        println!("cargo::rustc-cfg=rsim_ui_fonts");
    }
}
