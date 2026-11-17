//! The parse of an input text with a template.

use std::fmt;

use regex::CaptureLocations;

use crate::template::{LineOp, RecordOp, Target, Template, Value, ValueOption};

/// One cell of a record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Field {
    /// The text of a value. A value with no match is the empty text.
    Text(String),
    /// The items of a List value.
    List(Vec<Item>),
}

impl Field {
    /// The text of the cell, or `None` for a list.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(text) => Some(text),
            Self::List(_) => None,
        }
    }

    /// Whether the cell is the empty text or an empty list.
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Text(text) => text.is_empty(),
            Self::List(items) => items.is_empty(),
        }
    }
}

/// One item of a List value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Item {
    /// The text that the value matched.
    Text(String),
    /// The value was assigned by a rule in which its group did not take part.
    Missing,
    /// The named groups of the value regex, in the order of the regex, for a
    /// value regex with named groups inside it.
    Map(Vec<(String, Option<String>)>),
}

/// The records of one parse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Table {
    /// The names of the values: the columns of each record.
    pub header: Vec<String>,
    /// The records, each with one cell for each column.
    pub records: Vec<Vec<Field>>,
}

/// A parse that the template stopped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// An `Error` rule matched a line.
    Rule {
        /// The line of the rule in the template, from 1.
        rule_line: usize,
        /// The message of the rule as the template writes it, quotes included.
        message: Option<String>,
        /// The line of the input, from 1.
        input_line: usize,
        /// The text of the input line.
        input: String,
    },
    /// A List value whose regex has groups inside it was assigned by a rule in
    /// which its group did not take part, so there is no text to match the
    /// inner groups against.
    ListItem {
        /// The name of the value.
        value: String,
        /// The line of the rule in the template, from 1.
        rule_line: usize,
        /// The line of the input, from 1.
        input_line: usize,
    },
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rule {
                rule_line,
                message: Some(message),
                input,
                ..
            } => write!(
                f,
                "Error: {message}. Rule Line: {rule_line}. Input Line: {input}."
            ),
            Self::Rule {
                rule_line,
                message: None,
                input,
                ..
            } => write!(
                f,
                "State Error raised. Rule Line: {rule_line}. Input Line: {input}"
            ),
            Self::ListItem {
                value,
                rule_line,
                input_line,
            } => write!(
                f,
                "List value '{value}' assigned with no match by rule line {rule_line} at input line {input_line}"
            ),
        }
    }
}

impl std::error::Error for ParseError {}

/// The content of a value while a record is built.
#[derive(Clone, Debug)]
enum Cell {
    None,
    Text(String),
    List(Vec<Item>),
}

impl Cell {
    fn is_truthy(&self) -> bool {
        match self {
            Self::None => false,
            Self::Text(text) => !text.is_empty(),
            Self::List(items) => !items.is_empty(),
        }
    }
}

/// The state of one value during a parse.
#[derive(Clone, Debug)]
struct Slot {
    cell: Cell,
    /// The content that a Filldown value takes back at a clear.
    kept: Option<String>,
    /// The items of a List value.
    items: Vec<Item>,
}

struct Run<'t> {
    template: &'t Template,
    slots: Vec<Slot>,
    records: Vec<Vec<Field>>,
}

impl<'t> Run<'t> {
    fn new(template: &'t Template) -> Self {
        let slots = template
            .values
            .iter()
            .map(|_| Slot {
                cell: Cell::None,
                kept: None,
                items: Vec::new(),
            })
            .collect();
        Self {
            template,
            slots,
            records: Vec::new(),
        }
    }

    /// Assigns the text of a group to a value; `None` when the group did not
    /// take part in the match.
    fn assign(&mut self, index: usize, text: Option<&str>) -> Result<(), String> {
        let value: &Value = &self.template.values[index];
        let slot = &mut self.slots[index];
        slot.cell = match text {
            Some(text) => Cell::Text(text.to_string()),
            None => Cell::None,
        };
        for option in &value.options {
            match option {
                ValueOption::Filldown => slot.kept = text.map(str::to_string),
                ValueOption::Fillup => {
                    if let Some(text) = text.filter(|t| !t.is_empty()) {
                        for record in self.records.iter_mut().rev() {
                            if !record[index].is_empty() {
                                break;
                            }
                            record[index] = Field::Text(text.to_string());
                        }
                    }
                }
                ValueOption::List => {
                    let item = if value.nested {
                        let Some(text) = text else {
                            return Err(value.name.clone());
                        };
                        list_item(value, text)
                    } else {
                        match text {
                            Some(text) => Item::Text(text.to_string()),
                            None => Item::Missing,
                        }
                    };
                    slot.items.push(item);
                }
                ValueOption::Required | ValueOption::Key => {}
            }
        }
        Ok(())
    }

    fn clear(&mut self) {
        for (value, slot) in self.template.values.iter().zip(&mut self.slots) {
            slot.cell = Cell::None;
            for option in &value.options {
                match option {
                    ValueOption::Filldown => {
                        slot.cell = match &slot.kept {
                            Some(text) => Cell::Text(text.clone()),
                            None => Cell::None,
                        }
                    }
                    ValueOption::List if !value.has(ValueOption::Filldown) => slot.items.clear(),
                    _ => {}
                }
            }
        }
    }

    fn clear_all(&mut self) {
        for slot in &mut self.slots {
            slot.cell = Cell::None;
            slot.kept = None;
            slot.items.clear();
        }
    }

    /// Keeps the current record when no Required value is empty and the
    /// record is not empty.
    fn append_record(&mut self) {
        if self.template.values.is_empty() {
            return;
        }
        for (value, slot) in self.template.values.iter().zip(&mut self.slots) {
            for option in &value.options {
                match option {
                    ValueOption::Required if !slot.cell.is_truthy() => {
                        self.clear();
                        return;
                    }
                    ValueOption::List => slot.cell = Cell::List(slot.items.clone()),
                    _ => {}
                }
            }
        }
        let empty = self.slots.iter().all(|slot| match &slot.cell {
            Cell::None => true,
            Cell::List(items) => items.is_empty(),
            Cell::Text(_) => false,
        });
        if empty {
            return;
        }
        let record = self
            .slots
            .iter()
            .map(|slot| match &slot.cell {
                Cell::None => Field::Text(String::new()),
                Cell::Text(text) => Field::Text(text.clone()),
                Cell::List(items) => Field::List(items.clone()),
            })
            .collect();
        self.records.push(record);
        self.clear();
    }
}

/// The item of a List value whose regex has groups inside it.
fn list_item(value: &Value, text: &str) -> Item {
    let named = value.anchored.capture_names().flatten().next().is_some();
    match value.anchored.captures(text) {
        Some(caps) if named => Item::Map(
            value
                .anchored
                .capture_names()
                .flatten()
                .map(|name| {
                    (
                        name.to_string(),
                        caps.name(name).map(|m| m.as_str().to_string()),
                    )
                })
                .collect(),
        ),
        _ => Item::Text(text.to_string()),
    }
}

/// Splits a text into lines as Python's `str.splitlines` does.
pub fn split_lines(text: &str) -> impl Iterator<Item = &str> {
    let bytes = text.as_bytes();
    let mut start = 0;
    let mut i = 0;
    std::iter::from_fn(move || {
        while i < bytes.len() {
            let (end, next) = match bytes[i] {
                b'\n' | 0x0b | 0x0c | 0x1c..=0x1e => (i, i + 1),
                b'\r' if bytes.get(i + 1) == Some(&b'\n') => (i, i + 2),
                b'\r' => (i, i + 1),
                0xc2 if bytes.get(i + 1) == Some(&0x85) => (i, i + 2),
                0xe2 if bytes.get(i + 1) == Some(&0x80)
                    && matches!(bytes.get(i + 2), Some(0xa8 | 0xa9)) =>
                {
                    (i, i + 3)
                }
                _ => {
                    i += 1;
                    continue;
                }
            };
            let line = &text[start..end];
            start = next;
            i = next;
            return Some(line);
        }
        if start < bytes.len() {
            let line = &text[start..];
            start = bytes.len();
            return Some(line);
        }
        None
    })
}

impl Template {
    /// Parses an input text into records, as TextFSM's `ParseText` does with
    /// the end of the input as the end of the text.
    pub fn parse_text(&self, text: &str) -> Result<Table, ParseError> {
        let mut run = Run::new(self);
        let mut locations: Vec<Vec<CaptureLocations>> = self
            .states
            .iter()
            .map(|state| {
                state
                    .rules
                    .iter()
                    .map(|rule| rule.regex.capture_locations())
                    .collect()
            })
            .collect();
        let mut state = self.start;
        let mut finished = None;
        'lines: for (number, line) in split_lines(text).enumerate() {
            let rules = &self.states[state].rules;
            for (rule, locs) in rules.iter().zip(locations[state].iter_mut()) {
                if rule.regex.captures_read(locs, line).is_none() {
                    continue;
                }
                for &(group, index) in &rule.slots {
                    let text = locs.get(group).map(|(s, e)| &line[s..e]);
                    run.assign(index, text)
                        .map_err(|value| ParseError::ListItem {
                            value,
                            rule_line: rule.line,
                            input_line: number + 1,
                        })?;
                }
                match rule.record_op {
                    RecordOp::Record => run.append_record(),
                    RecordOp::Clear => run.clear(),
                    RecordOp::Clearall => run.clear_all(),
                    RecordOp::NoRecord => {}
                }
                match rule.line_op {
                    LineOp::Error => {
                        return Err(ParseError::Rule {
                            rule_line: rule.line,
                            message: rule.new_state.clone(),
                            input_line: number + 1,
                            input: line.to_string(),
                        });
                    }
                    LineOp::Continue => continue,
                    LineOp::Next => {}
                }
                match rule.target {
                    Target::Stay => {}
                    Target::State(next) => state = next,
                    Target::End | Target::Eof => {
                        finished = Some(rule.target);
                        break 'lines;
                    }
                }
                break;
            }
        }
        if finished != Some(Target::End) && !self.has_eof {
            run.append_record();
        }
        Ok(Table {
            header: self.values.iter().map(|v| v.name.clone()).collect(),
            records: run.records,
        })
    }
}
