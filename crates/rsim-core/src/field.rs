//! Field values with the knowledge mask and header validity.

/// The value of one header field in one packet.
///
/// The four states are different facts. They must not be merged:
///
/// - `Known`: the field is present and its value is known.
/// - `Unstated`: the request does not state the field (knowledge mask).
///   This is not the same as "all values".
/// - `Unknown`: the field was known or stated, and a function made it unknown,
///   for example a marking from a QoS stanza that was not evaluated.
/// - `Absent`: the header that holds the field is not present (header
///   validity). A later IP fragment has no port fields, and an untagged frame
///   has no VLAN field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FieldValue<T> {
    Known(T),
    Unstated,
    Unknown,
    Absent,
}

impl<T: Copy> FieldValue<T> {
    pub fn known(self) -> Option<T> {
        match self {
            FieldValue::Known(v) => Some(v),
            _ => None,
        }
    }

    /// The field with its known value changed by `f`.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> FieldValue<U> {
        match self {
            FieldValue::Known(v) => FieldValue::Known(f(v)),
            FieldValue::Unstated => FieldValue::Unstated,
            FieldValue::Unknown => FieldValue::Unknown,
            FieldValue::Absent => FieldValue::Absent,
        }
    }

    pub fn is_known(&self) -> bool {
        matches!(self, FieldValue::Known(_))
    }

    pub fn is_present(&self) -> bool {
        !matches!(self, FieldValue::Absent)
    }

    /// Evaluates a membership test against this field.
    ///
    /// An absent field never matches a predicate that reads it: a transport
    /// port predicate needs the transport header. A field that is present but
    /// not known gives `Tri::Unknown`.
    pub fn test(self, f: impl FnOnce(T) -> bool) -> Tri {
        match self {
            FieldValue::Known(v) => Tri::from(f(v)),
            FieldValue::Unstated | FieldValue::Unknown => Tri::Unknown,
            FieldValue::Absent => Tri::False,
        }
    }
}

/// A three-valued truth value (Kleene logic).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tri {
    False,
    Unknown,
    True,
}

impl Tri {
    pub fn and(self, other: Tri) -> Tri {
        self.min(other)
    }

    pub fn or(self, other: Tri) -> Tri {
        self.max(other)
    }

    pub fn negate(self) -> Tri {
        match self {
            Tri::False => Tri::True,
            Tri::Unknown => Tri::Unknown,
            Tri::True => Tri::False,
        }
    }
}

impl From<bool> for Tri {
    fn from(b: bool) -> Self {
        if b { Tri::True } else { Tri::False }
    }
}
