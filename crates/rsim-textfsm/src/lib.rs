//! A TextFSM engine: it reads TextFSM templates and parses command output into
//! records, with the semantics of Python `textfsm` 2.1.0.
//!
//! A template has `Value` lines with the options Required, Filldown, Fillup,
//! Key and List, then states of rules `^regex -> LineOp.RecordOp NewState`.
//! The regular expressions run on the `regex` crate; a construct that it reads
//! in another way than Python's `re` module is a template error.
//!
//! [`Index`] reads the index of ntc-templates, and [`Library`] holds the
//! templates that the crate carries for IOS-XR (`cisco_xr`) and IOS-XE
//! (`cisco_ios`), with their index.

mod index;
mod library;
mod run;
mod template;

pub use index::{Index, IndexError, IndexRow};
pub use library::{BUILTIN_INDEX, BUILTIN_TEMPLATES, Library, LibraryError};
pub use run::{Field, Item, ParseError, Table, split_lines};
pub use template::{LineOp, RecordOp, Rule, State, Template, TemplateError, Value, ValueOption};
