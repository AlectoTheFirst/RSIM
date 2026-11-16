# Proposal: a Rust native UI for rsim

Date: 2026-11-16. Status: proposal for the owner. It changes items 11 and 12 of section 15, section 17 and step 9 of `BUILD_BRIEF.md` if accepted.

## 1. Recommendation

Build the UI as one crate, `rsim-ui`, on **egui** with **eframe** on the **wgpu** renderer. Pin one exact version (0.37.0 is the current release on crates.io).

The same crate builds as a native program and as WebAssembly for the browser. The TypeScript viewer with `three` is then not necessary, and the exception to "Rust for all components" goes.

The first view is a 2D function graph with a trace timeline. A 3D camera is a later option on the same canvas and the same anchors. It is not a different framework.

## 2. Why egui fits rsim

| rsim property | Effect on the UI | egui |
|---|---|---|
| The twin is immutable for each version. An answer is a value. | The UI has no state to keep in step with the engine. | Immediate mode: each frame draws from the twin and the answer. No view model, no sync layer. |
| A path query takes microseconds. | A query can run on each edit of the query bar, and on each move of the timeline. | The native UI holds the `Twin` in process and calls `Executor::run` directly. No serialisation. |
| Product is Rust. No dependency that builds C or C++. | No webview, no Skia, no Qt, no GTK. | egui, epaint, winit, wgpu and naga are Rust. Section 5 gives the result of the dependency check. |
| Deterministic output, golden files. | UI tests must be stable. | `egui_kittest` runs the UI headless and compares image snapshots. |
| Agents use rsim through MCP. | An agent can check what the view shows. | The inspection protocol of egui reads the accessibility tree of a running program and sends events to it. |
| Step 9 requires a browser viewer and a live run through server-sent events. | The view must run in a browser. | eframe builds the same code for `wasm32`. WebGPU with a WebGL fallback. |
| 10,000+ routers. | The canvas must draw many nodes. | A wgpu paint callback draws instanced nodes and vectors below the widgets. The Rerun viewer proves this design: egui for the panels, its own wgpu renderer for 2D and 3D, a timeline, a graph view, native and web from one code base. |

Parts from the egui ecosystem:

| Need | Crate |
|---|---|
| Window, event loop, native and web | `eframe` |
| Dock layout with tabs and splits | `egui_tiles` |
| Large tables with virtual rows (trace steps, set parts, routes, coverage) | `egui_table` |
| Delay and counter plots | `egui_plot` |
| Headless tests with snapshots | `egui_kittest` |
| Function graph canvas | In-house, on `egui::Scene` (pan and zoom) and `Painter`, then on a wgpu paint callback at scale |

The function graph canvas is in-house code. The node graph crates for egui (`egui-snarl`, `egui_graphs`) are editors for small graphs that a person draws. rsim has fixed anchors from the engine, aggregation levels and vectors with a magnitude. That is a different widget.

## 3. Structure

```
rsim-engine ──► rsim-viz ──────────────► graph export, anchors, event stream
     │          (no render code, no I/O)        │
     ▼                                          ▼
engine command interface (section 10) ◄──── rsim-ui  (egui)
     ▲            ▲                           │
  rsim-cli     rsim-mcp            native: in process
                                   browser: wasm, JSON version 2 + JSON lines + SSE + HTTP
```

- `rsim-viz` stays as section 3 of the brief defines it. It gives the graph export and the event stream. It has no render code.
- `rsim-ui` is the only crate that depends on egui. The engine crates, `rsim-cli` and `rsim-mcp` do not change, and their `clippy.toml` rules stay.
- The native program calls the engine command interface in the same process.
- The browser build uses the transport of section 17 with no change: the JSON lines of the event stream, server-sent events for a live run, HTTP for what-if commands. Only the language of the viewer changes.
- Wall-clock time exists only in the playback of `rsim-ui`. It never goes into the engine.
- `rsim-ui` is a workspace member outside `default-members`, so `cargo build` and `cargo test` of the engine do not compile the UI tree.

## 4. The four uses

Layout (one dock, each pane can move):

```
┌ query bar: source.ip 172.31.10.20  destination.ip 10.20.0.53  network.transport udp  destination.port 53 ┐
├──────────────┬───────────────────────────────────────────────────────┬──────────────────────────────────┤
│ twin         │ function graph                                        │ inspector                        │
│  version     │  x: position of the device in the topology            │  trace step, outcome, reason     │
│  layers      │  y: processing stage, ingress to egress               │  packet before and after         │
│  devices     │  levels: site > device > function group > function    │  provenance: source lines        │
│  coverage    │  vectors: one for each hand-off, branch, alternative  │  parameters (what-if edit)       │
├──────────────┴───────────────────────────────────────────────────────┴──────────────────────────────────┤
│ timeline (virtual time or round number) │ trace steps │ set parts │ reply │ compare                     │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

**Visualisation**

- The function graph uses the anchors of section 17. The two topology axes become one horizontal axis for each aggregation level, and the processing stage is the vertical axis.
- Zoom changes the aggregation level: site, device, function group, function. A vector at a higher level is the sum of the vectors below it.
- A flow is a static vector: width for the magnitude, colour for the outcome, the traffic class or the delay. No moving objects. Playback moves a highlight from step to step in virtual time.
- A branch that ends in `Drop` or `Unknown` stops at its function and shows the reason code.
- A forwarding choice and a flood show as parallel vectors with one row for each alternative or copy.

**Interaction**

- A click on a node or a vector selects the trace step. The inspector shows the outcome, the reason, the QoS view, the header before and after, and the source spans.
- The timeline has step, pause, speed and position. The trace table and the graph have the same selection.
- The reply of a branch opens as a second lane below the forward path.

**Configuration**

- The inspector shows the editable parameters of a function type. A change makes a what-if layer through the engine command interface. The layer list shows each layer with its source span, and each answer names its layers.
- A link selection edits the latency and the utilisation.
- The twin pane shows the store, the newest snapshot, the collection state of each device and the coverage report with each unhandled stanza.

**Querying**

- The query bar takes the flags of `rsim path` and `rsim set` with the same names (`source.ip`, `destination.ip`, `network.transport`, ...). The parser of `rsim-cli` is used again, so the CLI, MCP and the UI accept the same query.
- A set query shows the parts as a table: one row for each result with the exact packet set as members.
- An unstated field shows as not known, not as all values.
- Each query can be copied as the `rsim` command and as the MCP tool call. A person can give an agent the exact query on the screen.
- Compare: two answers, or the same query on two twin versions (snapshot, what-if layer).

## 5. Dependency check

I resolved the dependency tree of `eframe 0.37.0` (features `wgpu`, `x11`, `default_fonts`, `accesskit`) with `egui_extras`, `egui_tiles 0.18.0` and `egui_plot 0.38.0`. I did not compile it.

| Target | Crates | `-sys` crates | Users of `cc`, `cmake`, `bindgen` |
|---|---|---|---|
| `aarch64-apple-darwin` | 164 | `core-foundation-sys`, `objc-sys` (bindings to system frameworks) | None |
| `wasm32-unknown-unknown` | 135 | `js-sys`, `web-sys` (bindings to the browser) | None |
| `x86_64-unknown-linux-gnu` | 246 | `wayland-sys`, `renderdoc-sys`, `linux-raw-sys`; `x11-dl` uses `pkg-config` | `cc` is a build dependency of `wayland-backend`. No `cmake`, no `bindgen`. |

- No C++ code and no CMake on any target.
- On Linux, the rule "the dependency tree has no `-sys` crate" does not hold for `rsim-ui`. The crates are bindings to the display server. The rule still holds for all other crates, because only `rsim-ui` depends on egui.
- Not checked: if `wayland-backend` compiles C code in this configuration. Check it in the trial scene. A build with X11 only is the fallback.
- egui forbids `unsafe` in its own code. `rsim-ui` needs no `unsafe`, so `unsafe_code = "deny"` stays.

## 6. Limits of egui

| Limit | Effect | Measure |
|---|---|---|
| Version 0.x. Each release breaks some API. 2026 had 0.34 to 0.37. | Upgrade work. | Pin one exact version, the same as `russh`. Upgrade on purpose. |
| The default look is that of a developer tool. | The mockups in `ux-ideas/` need a theme. | One theme module: fonts, spacing, colours, rounded frames. Rerun has such a module (`re_ui`). |
| Immediate mode layout has one pass. | Layouts that depend on the size of later content are hard. | Dock, tables and forms are not affected. Do not build responsive page layouts. |
| A frame draws all visible widgets again. | CPU use if the UI draws without a reason. | eframe draws only on input or on a repaint request. Request a repaint only during playback and on a new event. |
| The graph canvas is in-house. | The largest part of the work. | It is also the part that makes the product. Start on `Painter`, move to the wgpu callback when the node count requires it. |

## 7. Alternatives

| Framework | For | Against | Result |
|---|---|---|---|
| **iced** 0.14 | Elm architecture: messages match the engine command interface. wgpu canvas and shader widget. COSMIC uses it. | States that it is experimental software. No ready dock and no virtual table of the quality of the egui crates. Less proof for wasm and for a large custom canvas. | Second choice. Take it if a retained widget tree is more important than the ecosystem. |
| **GPUI** (Zed) | Best text and frame rate. `gpui-component` has 60+ widgets. | crates.io has 0.2.2, about 11 months behind Zed. Zed develops GPUI for the editor only. Current code means a git dependency or a fork. The web target is new. | No. The supply risk is too high for a product. |
| **Slint** 1.16 | Stable 1.x API, live preview, best look with least work. | Licence is GPLv3, royalty-free or paid; rsim is MIT. UI in a second language (`.slint`). The best renderer is Skia, which is C++. A custom canvas with 100,000 nodes is not its use. | No. |
| **Xilem / Masonry** | Rust native, Vello renderer, good architecture. | Before 1.0. A new layout system and a new render abstraction came in 2026 Q1. | Not now. Look again after step 5. |
| **Bevy** | A full 3D engine. | A game engine for a tool with tables and forms. Large dependency tree. | Only if the owner decides for a full 3D scene as the main view. egui runs inside Bevy, so the panels would stay. |
| **Dioxus, Tauri, Leptos** | Fast UI work, web look. | Webview or DOM. Not a Rust native renderer. | No. |

## 8. Decisions for the owner

1. Does the Rust UI replace the TypeScript viewer of item 11? If yes, section 17 "Viewer and transport" changes only in its first sentence.
2. Is the main view the 2D function graph, with 3D as a later camera on the same anchors? Or does the 3D view stay the main view?
3. Is the browser build part of the first delivery, or does the native program come first?
4. The two open points of step 9 stay open: the location of the declaration of the editable parameters, and the trial scene.

## 9. Trial scene

One trial scene answers decisions 1 and 2 and closes the open point "a trial scene confirms the look before step 9".

- Twin: `mini-enterprise`. Query: the guest to DNS path query of the README, with its reply.
- Panes: query bar, function graph at the levels device and function, trace table, inspector with source spans.
- Done when: the same query gives the same picture in the `egui_kittest` snapshot; the native program and the wasm build show the same scene; the dependency check of section 5 is confirmed by a real build on macOS and Linux.

The trial scene needs only what exists after step 2: `Twin`, `Executor::run`, `Answer` and the trace. It needs no event stream.

## Sources

- [egui 0.35.0 release notes: inspection protocol](https://newreleases.io/project/github/emilk/egui/release/0.35.0)
- [egui 0.33.0 release notes: egui_kittest snapshots](https://sourceforge.net/projects/egui.mirror/files/0.33.0)
- [Rerun architecture: egui, eframe, wgpu, re_renderer, native and web](https://github.com/rerun-io/rerun/blob/main/ARCHITECTURE.md)
- [Thanks for All the Frames: Rust GUI Observations (Tritium, 2026)](https://tritium.legal/blog/desktop)
- [iced 0.14.0 on docs.rs](https://docs.rs/crate/iced/latest), [iced 0.14.0 release](https://github.com/iced-rs/iced/releases/tag/0.14.0)
- [GPUI on crates.io and the wgpu backend](https://baeseokjae.github.io/posts/native-app-for-coding-agents-rust-gpui/), [GPUI book, chapter 9: forks and scope](https://vanuan.github.io/gpui-book/chapter_9.html), [gpui-component](https://github.com/longbridge/gpui-component)
- [Slint licences](https://github.com/slint-ui/slint), [Slint 1.16 release](https://slint.dev/blog/slint-1.16-released)
- [Linebender in 2026 Q1: Xilem and Masonry](https://linebender.org/blog/tmil-25/)
