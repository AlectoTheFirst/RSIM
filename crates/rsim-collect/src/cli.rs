//! The text rules of a command line interface: the removal of terminal
//! control bytes, the prompt of a shell, the removal of the echo and the
//! prompt from an answer, the login banner in front of each exec answer,
//! and the lines with which a device rejects a command.

use crate::{RawSection, TransportError};

/// The width of the terminal of a shell. A cursor move to the right is at
/// most this many spaces.
pub const SHELL_WIDTH: u32 = 511;
/// The height of the terminal of a shell.
pub const SHELL_HEIGHT: u32 = 1000;
/// The number of lines at the start of a shell answer in which the echo of
/// the command can be.
const ECHO_LINES: usize = 20;
/// The longest prompt.
const PROMPT_MAX: usize = 63;

/// Removes the bytes of a terminal from command output. A cursor move to
/// the right (`ESC [ n C`) becomes n spaces, at most [`SHELL_WIDTH`]. The
/// other escape sequences and control bytes go, except the tab and the
/// line feed. A carriage return becomes a line feed. Each line loses its
/// trailing white space.
pub fn sanitize(text: &str) -> String {
    if !text
        .chars()
        .any(|c| c == '\x1b' || c == '\r' || is_control(c))
    {
        let mut out = String::with_capacity(text.len());
        for (i, line) in text.split('\n').enumerate() {
            if i > 0 {
                out.push('\n');
            }
            out.push_str(line.trim_end());
        }
        return out;
    }
    let text = csi(text);
    let text = osc(&text);
    let text = esc_other(&text);
    let text = text.replace("\r\n", "\n").replace('\r', "\n");
    let text: String = text.chars().filter(|&c| !is_control(c)).collect();
    let mut out = String::with_capacity(text.len());
    for (i, line) in text.split('\n').enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(line.trim_end());
    }
    out
}

fn is_control(c: char) -> bool {
    matches!(c, '\x00'..='\x08' | '\x0b' | '\x0c' | '\x0e'..='\x1f' | '\x7f')
}

/// The CSI sequences: `ESC [`, parameters, intermediates and a final byte.
fn csi(text: &str) -> String {
    let b: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == '\x1b' && b.get(i + 1) == Some(&'[') {
            let mut j = i + 2;
            while j < b.len() && (b[j].is_ascii_digit() || b[j] == ';' || b[j] == '?') {
                j += 1;
            }
            let params_end = j;
            while j < b.len() && (' '..='/').contains(&b[j]) {
                j += 1;
            }
            if j < b.len() && ('@'..='~').contains(&b[j]) {
                if b[j] == 'C' {
                    let params: String = b[i + 2..params_end].iter().collect();
                    let n = if !params.is_empty() && params.bytes().all(|c| c.is_ascii_digit()) {
                        params
                            .parse::<u64>()
                            .unwrap_or(u64::MAX)
                            .min(u64::from(SHELL_WIDTH))
                    } else {
                        1
                    };
                    out.extend(std::iter::repeat_n(' ', n as usize));
                }
                i = j + 1;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// The OSC sequences: `ESC ]` up to a BEL, an `ESC \`, the next escape or
/// the end.
fn osc(text: &str) -> String {
    let b: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == '\x1b' && b.get(i + 1) == Some(&']') {
            let mut j = i + 2;
            while j < b.len() && b[j] != '\x07' && b[j] != '\x1b' {
                j += 1;
            }
            if j < b.len() && b[j] == '\x07' {
                j += 1;
            } else if j + 1 < b.len() && b[j] == '\x1b' && b[j + 1] == '\\' {
                j += 2;
            }
            i = j;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// The other 2-byte escape sequences.
fn esc_other(text: &str) -> String {
    let b: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == '\x1b'
            && let Some(&n) = b.get(i + 1)
            && (('@'..='Z').contains(&n) || ('\\'..='_').contains(&n))
        {
            i += 2;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// The prompt at the end of clean text: the last line that is not empty,
/// if it has the form of a prompt. A prompt is 1 to 63 characters with no
/// white space, then `>` or `#`.
pub fn prompt_of(text: &str) -> Option<String> {
    let line = text.lines().map(str::trim).rfind(|l| !l.is_empty())?;
    let body = line.strip_suffix(['>', '#'])?;
    let n = body.chars().count();
    ((1..=PROMPT_MAX).contains(&n) && !body.chars().any(char::is_whitespace))
        .then(|| line.to_string())
}

/// True if the prompt is alone on the last line of clean text that is not
/// empty.
pub fn at_prompt(text: &str, prompt: &str) -> bool {
    text.lines()
        .map(str::trim)
        .rfind(|l| !l.is_empty())
        .is_some_and(|l| l == prompt)
}

/// The end of the echo of a command in clean shell text: the byte after
/// the first line in the first 20 lines that is the command, alone or after
/// the prompt. A prompt that the device sent before the command can be in
/// front of the echo on the same line.
pub fn echo_line(text: &str, command: &str, prompt: &str) -> Option<usize> {
    let wanted = command.trim();
    if wanted.is_empty() {
        return None;
    }
    let mut pos = 0;
    for _ in 0..ECHO_LINES {
        let end = text[pos..].find('\n').map(|e| pos + e);
        let line = text[pos..end.unwrap_or(text.len())].trim();
        let after_prompt = line.strip_prefix(prompt).map(str::trim);
        if line == wanted || after_prompt == Some(wanted) {
            return Some(end.map_or(text.len(), |e| e + 1));
        }
        pos = end? + 1;
    }
    None
}

/// The answer to a command in clean shell text, with no echo and no
/// prompt. The text up to and including the echo goes (refer to
/// [`echo_line`]). The prompt lines at the end go. A non-empty answer ends
/// with one line feed.
pub fn output_of(text: &str, command: &str, prompt: &str) -> String {
    let start = echo_line(text, command, prompt).unwrap_or(0);
    let mut end = text.len();
    loop {
        end = start + text[start..end].trim_end().len();
        if end == start {
            return String::new();
        }
        let line = text[start..end]
            .rfind('\n')
            .map_or(start, |i| start + i + 1);
        if text[line..end].trim() != prompt {
            break;
        }
        end = line;
    }
    let mut out = text[start..end].to_string();
    out.push('\n');
    out
}

/// The whole lines at the head of each answer, or "" if fewer than 2
/// answers are given. A device that prints its login banner in front of
/// each exec answer gives the banner here.
pub fn common_head<'a>(answers: impl IntoIterator<Item = &'a [u8]>) -> Vec<u8> {
    let answers: Vec<&[u8]> = answers.into_iter().collect();
    if answers.len() < 2 {
        return Vec::new();
    }
    let first = answers[0];
    let mut shared = usize::MAX;
    for other in &answers[1..] {
        let mut lines = 0;
        let mut a = first.split_inclusive(|&c| c == b'\n');
        let mut b = other.split_inclusive(|&c| c == b'\n');
        while lines < shared {
            match (a.next(), b.next()) {
                (Some(x), Some(y)) if x == y && x.ends_with(b"\n") => {
                    lines += 1;
                }
                _ => break,
            }
        }
        if lines == 0 {
            return Vec::new();
        }
        shared = lines;
    }
    first
        .split_inclusive(|&c| c == b'\n')
        .take(shared)
        .flatten()
        .copied()
        .collect()
}

/// The rules of the command line of a vendor. A source applies them to its
/// sections after the fetch with [`CliRules::apply`].
#[derive(Clone, Copy, Debug)]
pub struct CliRules {
    /// Removes the terminal bytes with [`sanitize`].
    pub sanitize: bool,
    /// Removes the login banner that the device prints in front of each
    /// exec answer. The rule applies only if the transport sends each
    /// command in its own exec session.
    pub strip_banner: bool,
    /// The starts of the lines with which the device rejects a command.
    pub rejections: &'static [&'static str],
    /// The words of a rejection for a command that the device does not have,
    /// in lower case. Such a rejection gives [`TransportError::NotFound`].
    pub unsupported: &'static [&'static str],
    /// The words of a rejection for a command that the account cannot run,
    /// in lower case.
    pub unauthorized: &'static [&'static str],
}

impl CliRules {
    /// The rules of IOS XE, IOS XR and NX-OS.
    pub const CISCO: CliRules = CliRules {
        sanitize: true,
        strip_banner: true,
        rejections: &[
            "% Invalid input",
            "% Incomplete command",
            "% Ambiguous command",
            "% Invalid command",
            "% Unknown command",
            "% Unrecognized command",
            "% Bad IP address",
            "Line has invalid autocommand",
            "Command authorization failed",
            "% Authorization failed",
            "% Permission denied",
            "% This command is not authorized",
            "JSONScripterror",
        ],
        unsupported: &[
            "% invalid input",
            "% invalid command",
            "% incomplete command",
            "% ambiguous command",
            "% unknown command",
            "% unrecognized command",
            "line has invalid autocommand",
            "syntax error while parsing",
        ],
        unauthorized: &[
            "permission denied",
            "not authorized",
            "authorization failed",
            "access denied",
            "insufficient privilege",
        ],
    };

    /// The first line of the text that starts with a rejection, after its
    /// leading white space.
    pub fn rejection(&self, text: &str) -> Option<String> {
        text.lines()
            .map(str::trim)
            .find(|l| self.rejections.iter().any(|m| l.starts_with(m)))
            .map(str::to_string)
    }

    /// The error of a rejection text.
    fn error(&self, text: String) -> TransportError {
        let lower = text.to_lowercase();
        if self.unauthorized.iter().any(|m| lower.contains(m)) {
            TransportError::Command(format!("not authorized: {text}"))
        } else if self.unsupported.iter().any(|m| lower.contains(m)) {
            TransportError::NotFound(text)
        } else {
            TransportError::Command(format!("rejected: {text}"))
        }
    }

    /// Applies the rules to the sections of one device. `banner_each` is
    /// true if the transport sends each command in its own exec session.
    pub fn apply(&self, sections: &mut [RawSection], banner_each: bool) {
        if self.sanitize {
            for s in sections.iter_mut() {
                if let Ok(bytes) = &mut s.result {
                    *bytes = sanitize(&String::from_utf8_lossy(bytes)).into_bytes();
                }
            }
        }
        for s in sections.iter_mut() {
            let error = match &s.result {
                Ok(bytes) => self
                    .rejection(&String::from_utf8_lossy(bytes))
                    .map(|line| self.error(line)),
                Err(TransportError::Command(text)) => {
                    let lower = text.to_lowercase();
                    let known = self.unsupported.iter().any(|m| lower.contains(m))
                        || self.unauthorized.iter().any(|m| lower.contains(m));
                    known.then(|| self.error(text.clone()))
                }
                Err(_) => None,
            };
            if let Some(e) = error {
                s.result = Err(e);
            }
        }
        if self.strip_banner && banner_each {
            let head = common_head(
                sections
                    .iter()
                    .filter_map(|s| s.result.as_ref().ok().map(Vec::as_slice)),
            );
            if !head.is_empty() {
                for s in sections.iter_mut() {
                    if let Ok(bytes) = &mut s.result
                        && bytes.starts_with(&head)
                    {
                        bytes.drain(..head.len());
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SectionSpec;
    use rsim_store::{Class, Format};

    #[test]
    fn sanitize_removes_terminal_bytes() {
        assert_eq!(sanitize("a\x1b[3Cb"), "a   b");
        assert_eq!(sanitize("a\x1b[Cb"), "a b");
        assert_eq!(sanitize("a\x1b[99999999Cb").len(), 2 + SHELL_WIDTH as usize);
        assert_eq!(sanitize("\x1b[1;32mgreen\x1b[0m"), "green");
        assert_eq!(sanitize("\x1b]0;title\x07text"), "text");
        assert_eq!(sanitize("\x1b]0;title\x1b\\text"), "text");
        assert_eq!(sanitize("a\x1bMb"), "ab");
        assert_eq!(sanitize("line1\r\nline2\rline3"), "line1\nline2\nline3");
        assert_eq!(sanitize("a\x08\x00b\tc  \n  \n"), "ab\tc\n\n");
        assert_eq!(sanitize("x\x1b[2"), "x[2");
    }

    #[test]
    fn a_prompt_is_a_short_name_with_a_mark() {
        assert_eq!(prompt_of("banner\nr1#").as_deref(), Some("r1#"));
        assert_eq!(prompt_of("r1>\n\n").as_deref(), Some("r1>"));
        assert_eq!(
            prompt_of("RP/0/RSP0/CPU0:asr1#").as_deref(),
            Some("RP/0/RSP0/CPU0:asr1#")
        );
        assert_eq!(prompt_of("a b#"), None);
        assert_eq!(prompt_of("#"), None);
        assert_eq!(prompt_of(&format!("{}#", "x".repeat(64))), None);
        assert!(at_prompt("out\nr1#\n", "r1#"));
        assert!(!at_prompt("description r1# here\n", "r1#"));
    }

    #[test]
    fn the_answer_has_no_echo_and_no_prompt() {
        let text = "show ip route\nCodes: C\nC 192.0.2.0/24\n\nr1#";
        assert_eq!(
            output_of(text, "show ip route", "r1#"),
            "Codes: C\nC 192.0.2.0/24\n"
        );
        assert_eq!(output_of("show x\nr1#\nr1#", "show x", "r1#"), "");
        assert_eq!(
            output_of("banner\nshow x\nshow x\nr1#", "show x", "r1#"),
            "show x\n"
        );
        assert_eq!(
            output_of("r1#show x\nanswer\nr1#", "show x", "r1#"),
            "answer\n"
        );
        assert_eq!(echo_line("r1#\nr1#", "show x", "r1#"), None);
    }

    #[test]
    fn the_common_head_is_whole_lines() {
        let a: &[u8] = b"Authorized use only\nline 2\n{\"a\":1}";
        let b: &[u8] = b"Authorized use only\nline 2\n{\"b\":2}";
        assert_eq!(
            common_head([a, b]),
            b"Authorized use only\nline 2\n".to_vec()
        );
        assert!(common_head([a]).is_empty());
        let c: &[u8] = b"other\n";
        assert!(common_head([a, b, c]).is_empty());
    }

    fn section(result: Result<Vec<u8>, TransportError>) -> RawSection {
        RawSection {
            spec: SectionSpec {
                name: "s",
                command: "show x".into(),
                class: Class::Observation,
                format: Format::Text,
                volatile: &[],
                extracts: &[],
                keep: &[],
                optional: true,
            },
            result,
        }
    }

    #[test]
    fn cisco_rules_classify_rejections() {
        let rules = CliRules::CISCO;
        let mut s = vec![
            section(Ok(
                b"MOTD\n% Invalid input detected at '^' marker.\n".to_vec()
            )),
            section(Ok(b"MOTD\n% Permission denied\n".to_vec())),
            section(Ok(b"MOTD\nJSONScripterror\n".to_vec())),
            section(Ok(b"MOTD\nC 192.0.2.0/24 % Invalid input\n".to_vec())),
            section(Err(TransportError::Command(
                "exit status 16: Syntax error while parsing 'show ip ospf'".into(),
            ))),
            section(Err(TransportError::Command("exit status 1: other".into()))),
        ];
        rules.apply(&mut s, true);
        assert!(
            matches!(&s[0].result, Err(TransportError::NotFound(t)) if t.starts_with("% Invalid input"))
        );
        assert!(
            matches!(&s[1].result, Err(TransportError::Command(t)) if t.starts_with("not authorized"))
        );
        assert!(
            matches!(&s[2].result, Err(TransportError::Command(t)) if t.starts_with("rejected"))
        );
        assert_eq!(
            s[3].result.as_deref().unwrap(),
            b"MOTD\nC 192.0.2.0/24 % Invalid input\n",
            "one accepted answer gives no banner"
        );
        assert!(matches!(&s[4].result, Err(TransportError::NotFound(_))));
        assert!(
            matches!(&s[5].result, Err(TransportError::Command(t)) if t == "exit status 1: other")
        );
    }

    #[test]
    fn the_same_rejection_in_each_answer_is_not_a_banner() {
        let line = b"% This command is not authorized\n".to_vec();
        let mut s = vec![section(Ok(line.clone())), section(Ok(line))];
        CliRules::CISCO.apply(&mut s, true);
        for x in &s {
            assert!(
                matches!(&x.result, Err(TransportError::Command(t)) if t.starts_with("not authorized"))
            );
        }
        let mut s = vec![
            section(Ok(b"MOTD\na\n".to_vec())),
            section(Ok(b"MOTD\nb\n".to_vec())),
            section(Ok(b"MOTD\n% Invalid input\n".to_vec())),
        ];
        CliRules::CISCO.apply(&mut s, true);
        assert_eq!(s[0].result.as_deref().unwrap(), b"a\n");
        assert!(s[2].absent());
    }

    #[test]
    fn the_banner_stays_in_a_shell() {
        let mut s = vec![
            section(Ok(b"MOTD\na\n".to_vec())),
            section(Ok(b"MOTD\nb\n".to_vec())),
        ];
        CliRules::CISCO.apply(&mut s, false);
        assert_eq!(s[0].result.as_deref().unwrap(), b"MOTD\na\n");
    }
}
