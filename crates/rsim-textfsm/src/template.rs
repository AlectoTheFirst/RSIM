//! The template language: values, states and rules, read from the text of a
//! template.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::LazyLock;

use regex::{Regex, RegexBuilder};

/// The longest name of a value or a state.
const MAX_NAME_LEN: usize = 48;

/// The size limit of one compiled regular expression. A rule of a large
/// template, with its Unicode classes, can exceed the default limit.
const REGEX_SIZE_LIMIT: usize = 1 << 26;

/// An option of a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ValueOption {
    /// A record is kept only when the value is not empty.
    Required,
    /// The value keeps its content into the next record.
    Filldown,
    /// An assignment fills the empty cells of the value in the records above,
    /// up to the first record that has the value.
    Fillup,
    /// The value is part of the key of the record. The parse does not use it.
    Key,
    /// Each assignment adds an item to a list.
    List,
}

impl ValueOption {
    fn from_name(name: &str) -> Option<Self> {
        match name {
            "Required" => Some(Self::Required),
            "Filldown" => Some(Self::Filldown),
            "Fillup" => Some(Self::Fillup),
            "Key" => Some(Self::Key),
            "List" => Some(Self::List),
            _ => None,
        }
    }

    /// The name of the option as a template writes it.
    pub fn name(self) -> &'static str {
        match self {
            Self::Required => "Required",
            Self::Filldown => "Filldown",
            Self::Fillup => "Fillup",
            Self::Key => "Key",
            Self::List => "List",
        }
    }
}

/// A `Value` line of a template.
#[derive(Clone, Debug)]
pub struct Value {
    pub(crate) name: String,
    pub(crate) options: Vec<ValueOption>,
    pub(crate) regex: String,
    /// The value regex anchored at the start, for the items of a List value.
    pub(crate) anchored: Regex,
    /// Whether the value regex has more than one group, so that a List item is
    /// matched again for its named groups.
    pub(crate) nested: bool,
}

impl Value {
    /// The name of the value.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The options of the value, in the order of the template.
    pub fn options(&self) -> &[ValueOption] {
        &self.options
    }

    /// Whether the value has the option.
    pub fn has(&self, option: ValueOption) -> bool {
        self.options.contains(&option)
    }

    /// The regular expression of the value, as the template writes it.
    pub fn regex(&self) -> &str {
        &self.regex
    }
}

/// The line operation of a rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineOp {
    /// Read the next line, from the first rule of the new state.
    Next,
    /// Keep the line and try the next rule of the state.
    Continue,
    /// Stop the parse with an error.
    Error,
}

/// The record operation of a rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordOp {
    /// Leave the record as it is.
    NoRecord,
    /// Keep the record and clear it.
    Record,
    /// Clear the values that are not Filldown.
    Clear,
    /// Clear all values.
    Clearall,
}

/// Where a rule goes after a match.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Target {
    Stay,
    State(usize),
    End,
    Eof,
}

/// A rule of a state.
#[derive(Clone, Debug)]
pub struct Rule {
    pub(crate) line: usize,
    pub(crate) pattern: String,
    pub(crate) regex: Regex,
    /// For each capture group that names a value: the group and the value.
    pub(crate) slots: Vec<(usize, usize)>,
    pub(crate) line_op: LineOp,
    pub(crate) record_op: RecordOp,
    pub(crate) new_state: Option<String>,
    pub(crate) target: Target,
}

impl Rule {
    /// The line of the rule in the template, from 1.
    pub fn line(&self) -> usize {
        self.line
    }

    /// The regular expression of the rule after the substitution of the values.
    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    /// The line operation.
    pub fn line_op(&self) -> LineOp {
        self.line_op
    }

    /// The record operation.
    pub fn record_op(&self) -> RecordOp {
        self.record_op
    }

    /// The new state, or for an `Error` rule its message as the template
    /// writes it.
    pub fn new_state(&self) -> Option<&str> {
        self.new_state.as_deref()
    }
}

/// A state of a template.
#[derive(Clone, Debug)]
pub struct State {
    pub(crate) name: String,
    pub(crate) rules: Vec<Rule>,
}

impl State {
    /// The name of the state.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The rules of the state, in order.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }
}

/// A template that cannot be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemplateError {
    /// The line of the template, from 1.
    pub line: usize,
    /// What is wrong.
    pub message: String,
}

impl fmt::Display for TemplateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "template line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for TemplateError {}

/// A parsed template.
#[derive(Clone, Debug)]
pub struct Template {
    pub(crate) values: Vec<Value>,
    pub(crate) states: Vec<State>,
    /// The index of the `Start` state.
    pub(crate) start: usize,
    /// Whether the template defines an `EOF` state.
    pub(crate) has_eof: bool,
}

impl Template {
    /// Reads a template from its text.
    pub fn parse(text: &str) -> Result<Self, TemplateError> {
        Reader::new(text).read()
    }

    /// The values, in the order of the template.
    pub fn values(&self) -> &[Value] {
        &self.values
    }

    /// The names of the values, in the order of the template: the columns of a
    /// record.
    pub fn header(&self) -> Vec<&str> {
        self.values.iter().map(|v| v.name.as_str()).collect()
    }

    /// The states, in the order of the template. A defined `End` state is not
    /// one of them.
    pub fn states(&self) -> &[State] {
        &self.states
    }
}

/// Whether a character is whitespace as Python's `str.isspace` defines it.
pub(crate) fn is_py_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

fn rstrip(s: &str) -> &str {
    s.trim_end_matches(is_py_space)
}

fn strip(s: &str) -> &str {
    s.trim_matches(is_py_space)
}

/// Whether a line is a comment: optional whitespace, then `#`.
fn is_comment(line: &str) -> bool {
    line.trim_start_matches(is_py_space).starts_with('#')
}

/// Whether a name is one or more word characters.
fn is_word(name: &str) -> bool {
    !name.is_empty() && name.chars().all(is_word_char)
}

fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Compiles a regular expression that matches only at the start of the text.
pub(crate) fn compile_anchored(pattern: &str) -> Result<Regex, String> {
    check_portable(pattern)?;
    RegexBuilder::new(&format!(r"\A(?:{pattern})"))
        .size_limit(REGEX_SIZE_LIMIT)
        .dfa_size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map_err(|e| e.to_string())
}

/// Rejects the constructs that the regex crate reads in another way than
/// Python's `re` module: the escapes `\<` and `\>`, and a `[`, `&&`, `--` or
/// `~~` inside a character class.
fn check_portable(pattern: &str) -> Result<(), String> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    let mut in_class = false;
    let mut class_start = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' {
            if let Some(&next) = chars.get(i + 1)
                && (next == '<' || next == '>')
            {
                return Err(format!("the escape \\{next} has no portable meaning"));
            }
            i += 2;
            continue;
        }
        if in_class {
            let first = i == class_start || (i == class_start + 1 && chars[class_start] == '^');
            if c == ']' && !first {
                in_class = false;
            } else if c == '[' {
                return Err("a '[' inside a character class has no portable meaning".into());
            } else if matches!(c, '&' | '-' | '~') && chars.get(i + 1) == Some(&c) {
                return Err(format!(
                    "'{c}{c}' inside a character class has no portable meaning"
                ));
            }
        } else if c == '[' {
            in_class = true;
            class_start = i + 1;
        }
        i += 1;
    }
    Ok(())
}

/// Substitutes `$name` and `${name}` with the value regexes, and `$$` with `$`,
/// as Python's `string.Template.substitute` does.
fn substitute(text: &str, values: &BTreeMap<&str, &str>) -> Result<String, String> {
    let mut out = String::with_capacity(text.len() * 2);
    let mut rest = text;
    while let Some(pos) = rest.find('$') {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + 1..];
        if let Some(tail) = after.strip_prefix('$') {
            out.push('$');
            rest = tail;
            continue;
        }
        let ident_len = identifier_len(after);
        let (name, tail) = if ident_len > 0 {
            (&after[..ident_len], &after[ident_len..])
        } else if let Some(inner) = after.strip_prefix('{') {
            let len = identifier_len(inner);
            match inner[len..].strip_prefix('}') {
                Some(tail) if len > 0 => (&inner[..len], tail),
                _ => return Err("invalid placeholder".into()),
            }
        } else {
            return Err("invalid placeholder".into());
        };
        match values.get(name) {
            Some(regex) => out.push_str(regex),
            None => return Err(format!("unknown value '{name}'")),
        }
        rest = tail;
    }
    out.push_str(rest);
    Ok(out)
}

/// The length of the ASCII identifier at the start of the text.
fn identifier_len(text: &str) -> usize {
    let bytes = text.as_bytes();
    match bytes.first() {
        Some(b) if b.is_ascii_alphabetic() || *b == b'_' => {}
        _ => return 0,
    }
    bytes
        .iter()
        .take_while(|b| b.is_ascii_alphanumeric() || **b == b'_')
        .count()
}

/// Splits a template into lines as a file read in text mode does: at `\n`,
/// `\r\n` and `\r`.
fn template_lines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let bytes = text.as_bytes();
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\n' => {
                lines.push(&text[start..i]);
                start = i + 1;
            }
            b'\r' => {
                lines.push(&text[start..i]);
                if bytes.get(i + 1) == Some(&b'\n') {
                    i += 1;
                }
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    if start < bytes.len() {
        lines.push(&text[start..]);
    }
    lines
}

struct Reader<'a> {
    lines: Vec<&'a str>,
    next: usize,
}

/// A rule before its new state is resolved.
struct RawRule {
    rule: Rule,
}

impl<'a> Reader<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            lines: template_lines(text),
            next: 0,
        }
    }

    /// The next line, right-stripped, with its number.
    fn next_line(&mut self) -> Option<(usize, &'a str)> {
        let line = self.lines.get(self.next)?;
        self.next += 1;
        Some((self.next, rstrip(line)))
    }

    fn read(mut self) -> Result<Template, TemplateError> {
        let values = self.read_values()?;
        let value_map: BTreeMap<&str, String> = values
            .iter()
            .map(|v| (v.name.as_str(), named_group(&v.name, &v.regex)))
            .collect();
        let value_map: BTreeMap<&str, &str> =
            value_map.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let value_index: BTreeMap<&str, usize> = values
            .iter()
            .enumerate()
            .map(|(i, v)| (v.name.as_str(), i))
            .collect();

        let mut states: Vec<(String, usize, Vec<RawRule>)> = Vec::new();
        loop {
            let mut header = None;
            while let Some((num, line)) = self.next_line() {
                if line.is_empty() || is_comment(line) {
                    continue;
                }
                let reserved = matches!(
                    line,
                    "Continue" | "Next" | "Error" | "Clear" | "Clearall" | "Record" | "NoRecord"
                );
                if !is_word(line) || line.chars().count() > MAX_NAME_LEN || reserved {
                    return Err(TemplateError {
                        line: num,
                        message: format!("invalid state name '{line}'"),
                    });
                }
                if states.iter().any(|(name, _, _)| name == line) {
                    return Err(TemplateError {
                        line: num,
                        message: format!("duplicate state name '{line}'"),
                    });
                }
                header = Some((line.to_string(), num));
                break;
            }
            let Some((name, num)) = header else { break };
            let mut rules = Vec::new();
            while let Some((num, line)) = self.next_line() {
                if line.is_empty() {
                    break;
                }
                if is_comment(line) {
                    continue;
                }
                if !(line.starts_with(" ^") || line.starts_with("  ^") || line.starts_with("\t^")) {
                    return Err(TemplateError {
                        line: num,
                        message: "missing white space or caret ('^') before rule".into(),
                    });
                }
                rules.push(RawRule {
                    rule: read_rule(line, num, &value_map, &value_index)?,
                });
            }
            states.push((name, num, rules));
        }

        let Some(start) = states.iter().position(|(name, _, _)| name == "Start") else {
            return Err(TemplateError {
                line: self.lines.len(),
                message: "missing state 'Start'".into(),
            });
        };
        for special in ["End", "EOF"] {
            if let Some((_, num, rules)) = states.iter().find(|(name, _, _)| name == special)
                && !rules.is_empty()
            {
                return Err(TemplateError {
                    line: *num,
                    message: format!("non-empty '{special}' state"),
                });
            }
        }
        states.retain(|(name, _, _)| name != "End");
        let start = states
            .iter()
            .position(|(name, _, _)| name == "Start")
            .unwrap_or(start);
        let has_eof = states.iter().any(|(name, _, _)| name == "EOF");
        let names: Vec<String> = states.iter().map(|(name, _, _)| name.clone()).collect();

        let mut resolved = Vec::with_capacity(states.len());
        for (name, _, rules) in states {
            let mut out = Vec::with_capacity(rules.len());
            for RawRule { mut rule } in rules {
                rule.target = match (rule.line_op, rule.new_state.as_deref()) {
                    (LineOp::Error, _) | (_, None) => Target::Stay,
                    (_, Some("End")) => Target::End,
                    (_, Some("EOF")) => Target::Eof,
                    (_, Some(next)) => match names.iter().position(|n| n == next) {
                        Some(i) => Target::State(i),
                        None => {
                            return Err(TemplateError {
                                line: rule.line,
                                message: format!(
                                    "state '{next}' not found, referenced in state '{name}'"
                                ),
                            });
                        }
                    },
                };
                out.push(rule);
            }
            resolved.push(State { name, rules: out });
        }
        Ok(Template {
            values,
            states: resolved,
            start,
            has_eof,
        })
    }

    fn read_values(&mut self) -> Result<Vec<Value>, TemplateError> {
        let mut values: Vec<Value> = Vec::new();
        while let Some((num, line)) = self.next_line() {
            if line.is_empty() {
                break;
            }
            if is_comment(line) {
                continue;
            }
            if line.starts_with("Value ") {
                let value =
                    read_value(line).map_err(|message| TemplateError { line: num, message })?;
                if values.iter().any(|v| v.name == value.name) {
                    return Err(TemplateError {
                        line: num,
                        message: format!("duplicate declarations for value '{}'", value.name),
                    });
                }
                values.push(value);
            } else if values.is_empty() {
                return Err(TemplateError {
                    line: num,
                    message: "no Value definitions found".into(),
                });
            } else {
                return Err(TemplateError {
                    line: num,
                    message: "expected blank line after last Value entry".into(),
                });
            }
        }
        Ok(values)
    }
}

/// The value regex with its first group named after the value.
fn named_group(name: &str, regex: &str) -> String {
    format!("(?P<{name}>{}", &regex[1..])
}

/// Reads a `Value` line: the words are separated by single spaces.
fn read_value(line: &str) -> Result<Value, String> {
    let words: Vec<&str> = line.split(' ').collect();
    if words.len() < 3 {
        return Err("expect at least 3 tokens on line".into());
    }
    let mut options = Vec::new();
    let (name, regex) = if !words[2].starts_with('(') {
        for option in words[1].split(',') {
            let Some(parsed) = ValueOption::from_name(option) else {
                return Err(format!("unknown option \"{option}\""));
            };
            if options.contains(&parsed) {
                return Err(format!("duplicate option \"{option}\""));
            }
            options.push(parsed);
        }
        (words[2], words[3..].join(" "))
    } else {
        (words[1], words[2..].join(" "))
    };
    if name.chars().count() > MAX_NAME_LEN {
        return Err(format!("invalid value name '{name}' or name too long"));
    }
    let malformed = !regex.starts_with('(')
        || !regex.ends_with(')')
        || regex.len() < 2
        || regex[..regex.len() - 1].ends_with('\\');
    if malformed {
        return Err(format!(
            "value '{regex}' must be contained within a '()' pair"
        ));
    }
    let anchored = compile_anchored(&regex)?;
    let nested = anchored.captures_len() - 1 > 1;
    Ok(Value {
        name: name.to_string(),
        options,
        regex,
        anchored,
        nested,
    })
}

/// The parts of the action of a rule.
struct Action<'a> {
    line_op: Option<&'a str>,
    record_op: Option<&'a str>,
    new_state: Option<&'a str>,
}

/// The three forms of the action after `->` that TextFSM accepts, in the order
/// it tries them.
static ACTION_FORMS: LazyLock<[Regex; 3]> = LazyLock::new(|| {
    const LINE_OP: &str = r"(?P<ln_op>Continue|Next|Error)";
    const RECORD_OP: &str = r"(?P<rec_op>Clear|Clearall|Record|NoRecord)";
    const NEW_STATE: &str = r#"(?P<new_state>\w+|".*")"#;
    [
        format!(r"\A\s+({LINE_OP}(\.{RECORD_OP})?)(\s+{NEW_STATE})?\z"),
        format!(r"\A\s+{RECORD_OP}(\s+{NEW_STATE})?\z"),
        format!(r"\A(\s+{NEW_STATE})?\z"),
    ]
    .map(|form| Regex::new(&form).expect("the action forms compile"))
});

/// Reads the action after `->`.
fn read_action(action: &str) -> Option<Action<'_>> {
    let caps = ACTION_FORMS.iter().find_map(|form| form.captures(action))?;
    Some(Action {
        line_op: caps.name("ln_op").map(|m| m.as_str()),
        record_op: caps.name("rec_op").map(|m| m.as_str()),
        new_state: caps.name("new_state").map(|m| m.as_str()),
    })
}

/// Splits a rule at its last ` ->`: the part before is the match, the part
/// after is the action.
fn split_action(line: &str) -> Option<(&str, &str)> {
    let mut found = None;
    for (i, c) in line.char_indices() {
        if is_py_space(c) && c != '\n' && line[i + c.len_utf8()..].starts_with("->") {
            found = Some((i, i + c.len_utf8() + 2));
        }
    }
    found.map(|(end, action)| (&line[..end], &line[action..]))
}

fn read_rule(
    line: &str,
    num: usize,
    values: &BTreeMap<&str, &str>,
    value_index: &BTreeMap<&str, usize>,
) -> Result<Rule, TemplateError> {
    let error = |message: String| TemplateError { line: num, message };
    let line = strip(line);
    let (matched, action) = match split_action(line) {
        Some((matched, action)) => (matched, Some(action)),
        None => (line, None),
    };
    let pattern = substitute(matched, values)
        .map_err(|e| error(format!("duplicate or invalid variable substitution: {e}")))?;
    let regex = compile_anchored(&pattern)
        .map_err(|e| error(format!("invalid regular expression '{pattern}': {e}")))?;
    let slots = regex
        .capture_names()
        .enumerate()
        .filter_map(|(group, name)| Some((group, *value_index.get(name?)?)))
        .collect();

    let mut rule = Rule {
        line: num,
        pattern,
        regex,
        slots,
        line_op: LineOp::Next,
        record_op: RecordOp::NoRecord,
        new_state: None,
        target: Target::Stay,
    };
    let Some(action) = action else {
        return Ok(rule);
    };
    let parsed =
        read_action(action).ok_or_else(|| error(format!("badly formatted rule '{line}'")))?;
    rule.line_op = match parsed.line_op {
        Some("Continue") => LineOp::Continue,
        Some("Error") => LineOp::Error,
        _ => LineOp::Next,
    };
    rule.record_op = match parsed.record_op {
        Some("Record") => RecordOp::Record,
        Some("Clear") => RecordOp::Clear,
        Some("Clearall") => RecordOp::Clearall,
        _ => RecordOp::NoRecord,
    };
    rule.new_state = parsed.new_state.map(str::to_string);
    if let Some(state) = &rule.new_state {
        if rule.line_op == LineOp::Continue {
            return Err(error(format!(
                "action 'Continue' with new state {state} specified"
            )));
        }
        if rule.line_op != LineOp::Error && !state.starts_with(is_word_char) {
            return Err(error("alphanumeric characters only in state names".into()));
        }
    }
    Ok(rule)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitution_follows_string_template() {
        let mut values = BTreeMap::new();
        values.insert("A", "(?P<A>x)");
        values.insert("A_1", "(?P<A_1>y)");
        assert_eq!(
            substitute("^${A}-$A_1$$", &values).unwrap(),
            "^(?P<A>x)-(?P<A_1>y)$"
        );
        assert!(substitute("^a$", &values).is_err());
        assert!(substitute("^${A", &values).is_err());
        assert!(substitute("^$B", &values).is_err());
        assert!(substitute("^$A_", &values).is_err());
    }

    #[test]
    fn the_action_is_after_the_last_arrow() {
        assert_eq!(
            split_action("^a -> b -> Record"),
            Some(("^a -> b", " Record"))
        );
        assert_eq!(split_action("^a->Record"), None);
    }

    #[test]
    fn non_portable_regexes_are_rejected() {
        assert!(check_portable(r"\<word").is_err());
        assert!(check_portable(r"[[:alpha:]]").is_err());
        assert!(check_portable(r"[a--b]").is_err());
        assert!(check_portable(r"[]a]").is_ok());
        assert!(check_portable(r"[^]a]").is_ok());
        assert!(check_portable(r"[\w\-\.:/]+").is_ok());
        assert!(check_portable(r"(\S+\s+-\s+.+[,]*)+").is_ok());
    }
}
