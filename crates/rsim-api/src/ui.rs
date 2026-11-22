//! The files of the browser UI, embedded in the binary from `ui/dist`.
//! Without a built UI, the page at `/` says how to build it.

/// One file of the UI.
pub struct File {
    /// The path of the file in a request.
    pub path: &'static str,
    pub content_type: &'static str,
    pub body: &'static [u8],
}

/// The policy of the UI pages: each script, style, font and request comes
/// from the server itself.
pub const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

#[cfg(rsim_ui)]
macro_rules! dist {
    ($path:literal, $ty:literal) => {
        File {
            path: concat!("/", $path),
            content_type: $ty,
            body: include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../ui/dist/",
                $path
            )),
        }
    };
}

/// True if the binary holds the built UI.
pub fn built() -> bool {
    cfg!(rsim_ui)
}

#[cfg(rsim_ui)]
const APP: &[File] = &[
    dist!("index.html", "text/html; charset=utf-8"),
    dist!("assets/app.js", "text/javascript; charset=utf-8"),
    dist!("assets/app.css", "text/css; charset=utf-8"),
];

#[cfg(not(rsim_ui))]
const APP: &[File] = &[File {
    path: "/index.html",
    content_type: "text/html; charset=utf-8",
    body: b"<!doctype html>\n<html lang=\"en\">\n<head><meta charset=\"utf-8\"><title>rsim</title></head>\n<body><p>This build of rsim-api has no browser UI. Run <code>npm --prefix ui ci</code> and <code>npm --prefix ui run build</code>, then build rsim-api again.</p></body>\n</html>\n",
}];

#[cfg(rsim_ui_fonts)]
const FONTS: &[File] = &[
    dist!("fonts/Inter-Variable.woff2", "font/woff2"),
    dist!("fonts/JetBrainsMono-Variable.ttf", "font/ttf"),
    dist!("fonts/OFL-Inter.txt", "text/plain; charset=utf-8"),
    dist!("fonts/OFL-JetBrainsMono.txt", "text/plain; charset=utf-8"),
];

#[cfg(not(rsim_ui_fonts))]
const FONTS: &[File] = &[];

/// Each file that the server serves.
pub fn files() -> impl Iterator<Item = &'static File> {
    APP.iter().chain(FONTS.iter())
}

/// The file of a request path; `/` is the page.
pub fn get(path: &str) -> Option<&'static File> {
    let p = if path == "/" { "/index.html" } else { path };
    files().find(|f| f.path == p)
}
