//! The template index of ntc-templates: comma-separated rows that map the
//! attributes of a command (the platform, the command text) to templates.

use std::fmt;

use regex::Regex;

use crate::template::{compile_anchored, is_py_space};

/// An index that cannot be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexError {
    /// The line of the index, from 1.
    pub line: usize,
    /// What is wrong.
    pub message: String,
}

impl fmt::Display for IndexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "index line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for IndexError {}

/// A row of an index.
#[derive(Clone, Debug)]
pub struct IndexRow {
    line: usize,
    /// The fields, with the completion syntax of the command expanded.
    fields: Vec<String>,
    /// The compiled field of each column; `None` for the template column and
    /// for an empty field.
    patterns: Vec<Option<Regex>>,
    template_column: usize,
}

impl IndexRow {
    /// The line of the row in the index, from 1.
    pub fn line(&self) -> usize {
        self.line
    }

    /// The templates of the row: the template field split at `:`.
    pub fn templates(&self) -> impl Iterator<Item = &str> {
        self.fields[self.template_column].split(':')
    }
}

/// A template index.
#[derive(Clone, Debug)]
pub struct Index {
    columns: Vec<String>,
    rows: Vec<IndexRow>,
}

impl Index {
    /// Reads an index. The first line that is not empty or a comment is the
    /// header. A row that starts with `#`, or that does not have one field for
    /// each column, is left out. A `[[word]]` in the command column matches
    /// each prefix of the word, the empty prefix included.
    pub fn parse(text: &str) -> Result<Self, IndexError> {
        let mut lines = text.split('\n').enumerate();
        let mut header = None;
        for (number, line) in lines.by_ref() {
            let content = line
                .split('#')
                .next()
                .unwrap_or("")
                .trim_matches(is_py_space);
            if !content.is_empty() {
                header = Some((number + 1, content));
                break;
            }
        }
        let Some((header_line, header)) = header else {
            return Err(IndexError {
                line: 1,
                message: "no header".into(),
            });
        };
        let mut columns: Vec<String> = Vec::new();
        for column in header.split(',') {
            let column = column.trim_matches(is_py_space).to_string();
            if columns.contains(&column) {
                return Err(IndexError {
                    line: header_line,
                    message: format!("duplicate header entry '{column}'"),
                });
            }
            columns.push(column);
        }
        let Some(template_column) = columns.iter().position(|c| c == "Template") else {
            return Err(IndexError {
                line: header_line,
                message: "no 'Template' column".into(),
            });
        };

        let mut rows = Vec::new();
        for (number, line) in lines {
            if line.starts_with('#') {
                continue;
            }
            let mut fields: Vec<String> = line
                .split(',')
                .map(|f| f.trim_matches(is_py_space).to_string())
                .collect();
            if fields.len() != columns.len() {
                continue;
            }
            let mut patterns = Vec::with_capacity(fields.len());
            for (column, field) in columns.iter().zip(fields.iter_mut()) {
                if column == "Command" {
                    *field = expand_completion(field);
                }
                if column == "Template" || field.is_empty() {
                    patterns.push(None);
                    continue;
                }
                let pattern = compile_anchored(field).map_err(|e| IndexError {
                    line: number + 1,
                    message: format!("invalid regular expression '{field}': {e}"),
                })?;
                patterns.push(Some(pattern));
            }
            rows.push(IndexRow {
                line: number + 1,
                fields,
                patterns,
                template_column,
            });
        }
        Ok(Self { columns, rows })
    }

    /// The rows, in the order of the index.
    pub fn rows(&self) -> &[IndexRow] {
        &self.rows
    }

    /// The column names, in the order of the index.
    pub fn columns(&self) -> Vec<&str> {
        self.columns.iter().map(String::as_str).collect()
    }

    /// The first row that matches each attribute: the pattern of the column
    /// matches at the start of the attribute. An attribute of a column that
    /// the index does not have, and an empty field, match each text.
    pub fn find(&self, attributes: &[(&str, &str)]) -> Option<&IndexRow> {
        self.rows.iter().find(|row| {
            attributes.iter().all(|(column, text)| {
                let Some(position) = self.columns.iter().position(|c| c == column) else {
                    return true;
                };
                match &row.patterns[position] {
                    Some(pattern) => pattern.is_match(text),
                    None => true,
                }
            })
        })
    }

    /// The template of a platform and a command: the first template of the
    /// first row that matches both.
    pub fn template_for(&self, platform: &str, command: &str) -> Option<&str> {
        self.find(&[("Platform", platform), ("Command", command)])?
            .templates()
            .next()
    }
}

/// Expands each `[[word]]` to `(w(o(r(d)?)?)?)?`.
fn expand_completion(field: &str) -> String {
    let mut out = String::with_capacity(field.len() * 2);
    let mut rest = field;
    while let Some(start) = rest.find("[[") {
        let after = &rest[start + 2..];
        let Some(first) = after.chars().next() else {
            break;
        };
        let Some(end) = after[first.len_utf8()..].find("]]") else {
            break;
        };
        let word = &after[..first.len_utf8() + end];
        out.push_str(&rest[..start]);
        out.push('(');
        let mut chars = word.chars();
        if let Some(c) = chars.next() {
            out.push(c);
        }
        for c in chars {
            out.push('(');
            out.push(c);
        }
        for _ in word.chars() {
            out.push_str(")?");
        }
        rest = &after[first.len_utf8() + end + 2..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completion_expands_each_prefix() {
        assert_eq!(
            expand_completion("sh[[ow]] ip ro[[ute]]"),
            "sh(o(w)?)? ip ro(u(t(e)?)?)?"
        );
        assert_eq!(expand_completion("show"), "show");
    }

    #[test]
    fn the_first_matching_row_wins() {
        let index = Index::parse(
            "# comment\nTemplate, Hostname, Platform, Command\n\n\
             a.textfsm, .*, os, sh[[ow]] ip ro[[ute]] vrf \\*$\n\
             b.textfsm:c.textfsm, .*, os, sh[[ow]] ip ro[[ute]]\n\
             # x.textfsm, .*, os, sh[[ow]]\n",
        )
        .unwrap();
        assert_eq!(
            index.template_for("os", "show ip route vrf *"),
            Some("a.textfsm")
        );
        assert_eq!(index.template_for("os", "sh ip ro"), Some("b.textfsm"));
        assert_eq!(
            index.template_for("os", "show ip route summary"),
            Some("b.textfsm")
        );
        assert_eq!(
            index
                .find(&[("Command", "sh ip ro")])
                .unwrap()
                .templates()
                .count(),
            2
        );
        assert_eq!(index.template_for("other", "show ip route"), None);
        assert_eq!(
            index.columns(),
            ["Template", "Hostname", "Platform", "Command"]
        );
    }
}
