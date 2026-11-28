//! The patterns of the expanded community lists and the AS-path lists: a
//! subset of the Cisco regular expressions.
//!
//! The syntax is digits, the space and `:` as literals, `.`, `^`, `$`, `_`,
//! `*`, `+`, `?`, a class `[...]` of digits and digit ranges with an
//! optional `^`, a group `(...)` and `|`. `_` matches the start, the end, or
//! one of the characters space, `,`, `{`, `}`, `(` and `)`. Each
//! other construct is a parse error. A match is a search: the pattern
//! matches when it matches a part of the text.
//!
//! The matcher compiles the pattern to a program of a nondeterministic
//! automaton and runs it over the text with a set of states for each
//! position, so its time is linear in the length of the text.

use std::fmt;

/// The characters that `_` matches between the start and the end.
const DELIMITERS: &[u8] = b" ,{}()";

#[derive(Clone, Debug, PartialEq, Eq)]
enum Node {
    Byte(Pred),
    Start,
    End,
    Concat(Vec<Node>),
    Alt(Vec<Node>),
    Star(Box<Node>),
    Plus(Box<Node>),
    Opt(Box<Node>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Pred {
    Lit(u8),
    Any,
    Class {
        negated: bool,
        ranges: Vec<(u8, u8)>,
    },
}

impl Pred {
    fn matches(&self, b: u8) -> bool {
        match self {
            Pred::Lit(c) => *c == b,
            Pred::Any => true,
            Pred::Class { negated, ranges } => {
                ranges.iter().any(|&(lo, hi)| lo <= b && b <= hi) != *negated
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Inst {
    Byte(Pred),
    Split(usize, usize),
    Jmp(usize),
    Start,
    End,
    Match,
}

/// A compiled pattern with its text.
#[derive(Clone, PartialEq, Eq)]
pub struct Pattern {
    text: String,
    program: Vec<Inst>,
}

impl fmt::Debug for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pattern({:?})", self.text)
    }
}

/// The pattern uses a construct outside the subset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PatternError {
    pub text: String,
    pub at: usize,
}

impl fmt::Display for PatternError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "pattern {:?} has an unhandled construct at {}",
            self.text, self.at
        )
    }
}

impl std::error::Error for PatternError {}

impl Pattern {
    /// Parses a pattern. The pattern loses the white space at its ends, and
    /// then the single or double quotes around it.
    pub fn parse(text: &str) -> Result<Pattern, PatternError> {
        let trimmed = text.trim();
        let bytes = trimmed.as_bytes();
        let inner = if bytes.len() >= 2
            && bytes[0] == bytes[bytes.len() - 1]
            && (bytes[0] == b'"' || bytes[0] == b'\'')
        {
            &trimmed[1..trimmed.len() - 1]
        } else {
            trimmed
        };
        let mut p = Parser {
            text: inner.as_bytes(),
            pos: 0,
        };
        let node = p.alternation().map_err(|at| PatternError {
            text: text.to_string(),
            at,
        })?;
        if p.pos != p.text.len() {
            return Err(PatternError {
                text: text.to_string(),
                at: p.pos,
            });
        }
        let mut program = Vec::new();
        compile(&node, &mut program);
        program.push(Inst::Match);
        Ok(Pattern {
            text: inner.to_string(),
            program,
        })
    }

    /// The text of the pattern without quotes.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// True if the pattern matches a part of `text`.
    pub fn is_match(&self, text: &str) -> bool {
        let text = text.as_bytes();
        let n = self.program.len();
        let mut current = States::new(n);
        let mut next = States::new(n);
        self.add(&mut current, 0, 0, text.len());
        for pos in 0..=text.len() {
            if current
                .list
                .iter()
                .any(|&pc| self.program[pc] == Inst::Match)
            {
                return true;
            }
            if pos == text.len() {
                break;
            }
            next.clear();
            for i in 0..current.list.len() {
                let pc = current.list[i];
                if let Inst::Byte(pred) = &self.program[pc]
                    && pred.matches(text[pos])
                {
                    self.add(&mut next, pc + 1, pos + 1, text.len());
                }
            }
            self.add(&mut next, 0, pos + 1, text.len());
            std::mem::swap(&mut current, &mut next);
        }
        false
    }

    /// Adds `pc` and the states that it reaches with no character at
    /// `pos`.
    fn add(&self, set: &mut States, pc: usize, pos: usize, len: usize) {
        let mut stack = vec![pc];
        while let Some(pc) = stack.pop() {
            if set.seen[pc] {
                continue;
            }
            set.seen[pc] = true;
            match &self.program[pc] {
                Inst::Split(a, b) => {
                    stack.push(*b);
                    stack.push(*a);
                }
                Inst::Jmp(a) => stack.push(*a),
                Inst::Start => {
                    if pos == 0 {
                        stack.push(pc + 1);
                    }
                }
                Inst::End => {
                    if pos == len {
                        stack.push(pc + 1);
                    }
                }
                Inst::Byte(_) | Inst::Match => set.list.push(pc),
            }
        }
    }
}

struct States {
    seen: Vec<bool>,
    list: Vec<usize>,
}

impl States {
    fn new(n: usize) -> States {
        States {
            seen: vec![false; n],
            list: Vec::new(),
        }
    }

    fn clear(&mut self) {
        self.seen.iter_mut().for_each(|s| *s = false);
        self.list.clear();
    }
}

struct Parser<'a> {
    text: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.text.get(self.pos).copied()
    }

    fn alternation(&mut self) -> Result<Node, usize> {
        let mut alts = vec![self.concat()?];
        while self.peek() == Some(b'|') {
            self.pos += 1;
            alts.push(self.concat()?);
        }
        Ok(if alts.len() == 1 {
            alts.remove(0)
        } else {
            Node::Alt(alts)
        })
    }

    fn concat(&mut self) -> Result<Node, usize> {
        let mut items = Vec::new();
        while let Some(c) = self.peek() {
            if c == b'|' || c == b')' {
                break;
            }
            items.push(self.repeat()?);
        }
        Ok(Node::Concat(items))
    }

    fn repeat(&mut self) -> Result<Node, usize> {
        let start = self.pos;
        let atom = self.atom()?;
        let Some(q @ (b'*' | b'+' | b'?')) = self.peek() else {
            return Ok(atom);
        };
        if matches!(atom, Node::Start | Node::End) {
            return Err(start);
        }
        self.pos += 1;
        if matches!(self.peek(), Some(b'*' | b'+' | b'?')) {
            return Err(self.pos);
        }
        let inner = Box::new(atom);
        Ok(match q {
            b'*' => Node::Star(inner),
            b'+' => Node::Plus(inner),
            _ => Node::Opt(inner),
        })
    }

    fn atom(&mut self) -> Result<Node, usize> {
        let at = self.pos;
        let c = self.peek().ok_or(at)?;
        self.pos += 1;
        match c {
            b'0'..=b'9' | b' ' | b':' => Ok(Node::Byte(Pred::Lit(c))),
            b'.' => Ok(Node::Byte(Pred::Any)),
            b'^' => Ok(Node::Start),
            b'$' => Ok(Node::End),
            b'_' => Ok(Node::Alt(vec![
                Node::Start,
                Node::End,
                Node::Byte(Pred::Class {
                    negated: false,
                    ranges: DELIMITERS.iter().map(|&d| (d, d)).collect(),
                }),
            ])),
            b'(' => {
                let inner = self.alternation()?;
                if self.peek() != Some(b')') {
                    return Err(self.pos);
                }
                self.pos += 1;
                Ok(inner)
            }
            b'[' => self.class(),
            _ => Err(at),
        }
    }

    fn class(&mut self) -> Result<Node, usize> {
        let negated = self.peek() == Some(b'^');
        if negated {
            self.pos += 1;
        }
        let mut ranges = Vec::new();
        loop {
            let at = self.pos;
            match self.peek() {
                Some(b']') if !ranges.is_empty() => {
                    self.pos += 1;
                    return Ok(Node::Byte(Pred::Class { negated, ranges }));
                }
                Some(lo @ b'0'..=b'9') => {
                    self.pos += 1;
                    if self.peek() == Some(b'-') {
                        self.pos += 1;
                        match self.peek() {
                            Some(hi @ b'0'..=b'9') if hi >= lo => {
                                self.pos += 1;
                                ranges.push((lo, hi));
                            }
                            _ => return Err(self.pos),
                        }
                    } else {
                        ranges.push((lo, lo));
                    }
                }
                _ => return Err(at),
            }
        }
    }
}

fn compile(node: &Node, prog: &mut Vec<Inst>) {
    match node {
        Node::Byte(p) => prog.push(Inst::Byte(p.clone())),
        Node::Start => prog.push(Inst::Start),
        Node::End => prog.push(Inst::End),
        Node::Concat(items) => items.iter().for_each(|n| compile(n, prog)),
        Node::Alt(alts) => {
            let mut jumps = Vec::new();
            for (i, alt) in alts.iter().enumerate() {
                if i + 1 < alts.len() {
                    let split = prog.len();
                    prog.push(Inst::Split(split + 1, 0));
                    compile(alt, prog);
                    jumps.push(prog.len());
                    prog.push(Inst::Jmp(0));
                    let after = prog.len();
                    prog[split] = Inst::Split(split + 1, after);
                } else {
                    compile(alt, prog);
                }
            }
            let end = prog.len();
            for j in jumps {
                prog[j] = Inst::Jmp(end);
            }
        }
        Node::Star(inner) => {
            let split = prog.len();
            prog.push(Inst::Split(split + 1, 0));
            compile(inner, prog);
            prog.push(Inst::Jmp(split));
            let out = prog.len();
            prog[split] = Inst::Split(split + 1, out);
        }
        Node::Plus(inner) => {
            let start = prog.len();
            compile(inner, prog);
            let out = prog.len() + 1;
            prog.push(Inst::Split(start, out));
        }
        Node::Opt(inner) => {
            let split = prog.len();
            prog.push(Inst::Split(split + 1, 0));
            compile(inner, prog);
            let out = prog.len();
            prog[split] = Inst::Split(split + 1, out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(p: &str, t: &str) -> bool {
        Pattern::parse(p).unwrap().is_match(t)
    }

    #[test]
    fn the_underscore_matches_a_delimiter_or_an_end_and_not_a_digit() {
        assert!(m("_64512_", "64512"));
        assert!(m("_64512_", "3356 64512 1"));
        assert!(!m("_64512_", "645120"));
        assert!(m("_1_", "{1,2}"));
        assert!(!m("_1_", "[1,2]"));
        assert!(!m("_2_", "[1,2]"));
    }

    #[test]
    fn anchors_classes_groups_and_alternation_match() {
        assert!(m("^65000 65001$", "65000 65001"));
        assert!(!m("^65000$", "65000 65001"));
        assert!(m("^(1|2)+$", "1212"));
        assert!(m("^[0-4]5?$", "35"));
        assert!(!m("^[^0-4]$", "3"));
        assert!(m("", "1 2"));
        assert!(m("^$", ""));
        assert!(m("^(1*)*$", "111"));
    }

    #[test]
    fn a_construct_outside_the_subset_is_a_parse_error() {
        for p in ["1{2}", "a", "\\d", "[1", "(1", "1**", "^*", "[]", "[5-1]"] {
            assert!(Pattern::parse(p).is_err(), "{p}");
        }
        assert!(Pattern::parse("'_1_'").is_ok());
    }
}
