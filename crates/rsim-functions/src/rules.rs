//! Ordered rules with match bounds.
//!
//! The evaluation follows the two continuations of an uncertain predicate:
//! match and no match. Packets with the same action in all continuations get
//! that action. All other packets get `Unknown`. This gives the
//! first-match regions `F_i^-` and `F_i^+`:
//!
//! ```text
//! F_i^- = M_i^- minus the union of M_k^+ for all k < i
//! F_i^+ = M_i^+ minus the union of M_k^- for all k < i
//! ```
//!
//! A rule from an unhandled stanza can change the action or the rule order,
//! so every packet that can reach it gets `Unknown`.

use rsim_core::{PacketSet, RulePredicate, SourceSpan, Tri};

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(
    clippy::large_enum_variant,
    reason = "almost all rules are handled; a box would add one allocation per rule"
)]
pub enum RuleBody<A> {
    Handled {
        predicate: RulePredicate,
        action: A,
    },
    /// The stanza of the rule was not handled by the parser.
    Unhandled,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule<A> {
    pub name: String,
    pub body: RuleBody<A>,
    pub spans: Vec<SourceSpan>,
}

impl<A> Rule<A> {
    pub fn new(name: impl Into<String>, predicate: RulePredicate, action: A) -> Self {
        Rule {
            name: name.into(),
            body: RuleBody::Handled { predicate, action },
            spans: Vec::new(),
        }
    }

    pub fn unhandled(name: impl Into<String>, span: SourceSpan) -> Self {
        Rule {
            name: name.into(),
            body: RuleBody::Unhandled,
            spans: vec![span],
        }
    }

    pub fn with_span(mut self, s: SourceSpan) -> Self {
        self.spans.push(s);
        self
    }
}

/// The rule that gave an action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RuleRef {
    Rule(usize),
    Default,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision<A> {
    /// All continuations give this action. `decided_by` lists the rules that
    /// can give it, in rule order. It has more than one entry if an uncertain
    /// rule and a later rule agree.
    Action {
        action: A,
        decided_by: Vec<RuleRef>,
    },
    Unknown {
        cause: UnknownCause,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnknownCause {
    /// Rule `rule` came from an unhandled stanza.
    Unhandled { rule: usize },
    /// Rule `rule` may match, and the continuations give different actions.
    Uncertain { rule: usize },
}

/// Evaluates ordered rules on a packet set. `scope` gives the result of the
/// context condition of a rule, for example its zones: `False` means the rule
/// does not apply, and `Unknown` makes every match of the rule uncertain.
///
/// The result partitions `input`.
pub fn evaluate<A: Clone + Eq>(
    rules: &[Rule<A>],
    default: &A,
    input: &PacketSet,
    scope: &dyn Fn(usize) -> Tri,
) -> Vec<(PacketSet, Decision<A>)> {
    let mut out = Vec::new();
    eval_from(rules, default, input, scope, 0, &mut out);
    out
}

fn eval_from<A: Clone + Eq>(
    rules: &[Rule<A>],
    default: &A,
    set: &PacketSet,
    scope: &dyn Fn(usize) -> Tri,
    start: usize,
    out: &mut Vec<(PacketSet, Decision<A>)>,
) {
    let mut rest = set.clone();
    for (i, rule) in rules.iter().enumerate().skip(start) {
        if rest.is_empty() {
            return;
        }
        let (predicate, action) = match &rule.body {
            RuleBody::Unhandled => {
                out.push((
                    rest,
                    Decision::Unknown {
                        cause: UnknownCause::Unhandled { rule: i },
                    },
                ));
                return;
            }
            RuleBody::Handled { predicate, action } => (predicate, action),
        };
        let applies = scope(i);
        if applies == Tri::False {
            continue;
        }
        let split = rest.split(predicate);
        let (matched, uncertain) = if applies == Tri::Unknown {
            (PacketSet::empty(), split.matched.union(&split.uncertain))
        } else {
            (split.matched, split.uncertain)
        };
        if !matched.is_empty() {
            out.push((
                matched,
                Decision::Action {
                    action: action.clone(),
                    decided_by: vec![RuleRef::Rule(i)],
                },
            ));
        }
        if !uncertain.is_empty() {
            // The no-match continuation of the uncertain packets.
            let mut cont = Vec::new();
            eval_from(rules, default, &uncertain, scope, i + 1, &mut cont);
            for (s, d) in cont {
                let d = match d {
                    Decision::Action {
                        action: a,
                        decided_by,
                    } if a == *action => {
                        let mut by = vec![RuleRef::Rule(i)];
                        by.extend(decided_by);
                        Decision::Action {
                            action: a,
                            decided_by: by,
                        }
                    }
                    _ => Decision::Unknown {
                        cause: UnknownCause::Uncertain { rule: i },
                    },
                };
                out.push((s, d));
            }
        }
        rest = split.unmatched;
    }
    if !rest.is_empty() {
        out.push((
            rest,
            Decision::Action {
                action: default.clone(),
                decided_by: vec![RuleRef::Default],
            },
        ));
    }
}

/// The location of a rule for a reason text: `<what> rule <name>, line <n>`.
pub fn describe<A>(rules: &[Rule<A>], what: &str, r: RuleRef) -> String {
    match r {
        RuleRef::Rule(i) => match rules[i].spans.first() {
            Some(span) => format!("{what} rule {}, line {}", rules[i].name, span.first_line),
            None => format!("{what} rule {}", rules[i].name),
        },
        RuleRef::Default => format!("{what} default action"),
    }
}

/// The locations of the rules that decided, joined with " or ".
pub fn describe_all<A>(rules: &[Rule<A>], what: &str, by: &[RuleRef]) -> String {
    by.iter()
        .map(|r| describe(rules, what, *r))
        .collect::<Vec<_>>()
        .join(" or ")
}

/// The spans of the rules that decided.
pub fn spans_of<A>(rules: &[Rule<A>], by: &[RuleRef]) -> Vec<SourceSpan> {
    let mut v = Vec::new();
    for r in by {
        if let RuleRef::Rule(i) = r {
            v.extend(rules[*i].spans.iter().cloned());
        }
    }
    v
}

/// The text and spans of an unknown cause: `<fact> · <location>`.
pub fn explain<A>(
    rules: &[Rule<A>],
    what: &str,
    cause: &UnknownCause,
    input: &PacketSet,
) -> (String, Vec<SourceSpan>) {
    let (rule, fact) = match cause {
        UnknownCause::Unhandled { rule } => (*rule, "config not supported".to_string()),
        UnknownCause::Uncertain { rule } => {
            let mut fields = Vec::new();
            if let (RuleBody::Handled { predicate, .. }, Some(p)) =
                (&rules[*rule].body, input.witness())
            {
                for m in [&predicate.definite, &predicate.upper] {
                    for (f, o) in m.open_fields(&p.current) {
                        let t = format!("{} {}", f.name(), o.text());
                        if !fields.contains(&t) {
                            fields.push(t);
                        }
                    }
                }
            }
            let fact = if fields.is_empty() {
                "rule members not known".to_string()
            } else {
                fields.join(", ")
            };
            (*rule, fact)
        }
    };
    (
        format!("{fact} · {}", describe(rules, what, RuleRef::Rule(rule))),
        rules[rule].spans.clone(),
    )
}
