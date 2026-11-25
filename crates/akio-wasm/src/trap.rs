//! Why a call stopped.

use std::fmt;

/// Why a call into a [`Store`](crate::Store) stopped before returning, or why it could not start.
///
/// The variants up to [`Trap::Host`] are traps: the guest's code (or a host function it called)
/// stopped, or a [`Budget`](crate::Budget) ran out. A trap ends the store (ADR-125, section 3):
/// its memory may be half-updated, so later calls return [`Trap::Ended`]; whoever owns it drops
/// it and makes a new one. [`Trap::Ended`] and [`Trap::BadCall`] are refusals: nothing ran.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Trap {
    /// `unreachable` ran.
    Unreachable,
    /// A load, a store or a bulk memory instruction outside the memory.
    MemoryOutOfBounds,
    /// A table access or a bulk table instruction outside the table.
    TableOutOfBounds,
    /// `call_indirect` with an index past the table's end.
    UndefinedElement,
    /// `call_indirect` through a null entry.
    UninitializedElement,
    /// `call_indirect` to a function of another type than the instruction's.
    IndirectCallType,
    /// Integer division or remainder by zero.
    IntegerDivideByZero,
    /// Signed division overflow, or a float converted to an integer out of its range.
    IntegerOverflow,
    /// A NaN converted to an integer.
    InvalidConversion,
    /// The call depth passed [`InstanceLimits::max_call_depth`](crate::InstanceLimits::max_call_depth).
    CallStackExhausted,
    /// The frames passed [`InstanceLimits::max_value_stack`](crate::InstanceLimits::max_value_stack).
    ValueStackExhausted,
    /// The call's deadline passed ([`Budget::deadline`](crate::Budget::deadline)).
    Deadline,
    /// The call's fuel ran out ([`Budget::fuel`](crate::Budget::fuel)).
    OutOfFuel,
    /// The call's [`InterruptHandle`](crate::InterruptHandle) was raised.
    Interrupted,
    /// A host function failed, with its message.
    Host(Box<str>),
    /// The store ended with an earlier trap; nothing ran.
    Ended,
    /// The call was wrong: arguments or results of the wrong number or type, or a value from
    /// another store. Nothing ran, and the store goes on.
    BadCall(&'static str),
}

impl Trap {
    /// A short description: the specification's wording for the traps it defines
    /// (`"unreachable"`, `"out of bounds memory access"` ...).
    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            Self::Unreachable => "unreachable",
            Self::MemoryOutOfBounds => "out of bounds memory access",
            Self::TableOutOfBounds => "out of bounds table access",
            Self::UndefinedElement => "undefined element",
            Self::UninitializedElement => "uninitialized element",
            Self::IndirectCallType => "indirect call type mismatch",
            Self::IntegerDivideByZero => "integer divide by zero",
            Self::IntegerOverflow => "integer overflow",
            Self::InvalidConversion => "invalid conversion to integer",
            Self::CallStackExhausted => "call stack exhausted",
            Self::ValueStackExhausted => "value stack exhausted",
            Self::Deadline => "deadline passed",
            Self::OutOfFuel => "out of fuel",
            Self::Interrupted => "interrupted",
            Self::Host(m) => m,
            Self::Ended => "the store ended with an earlier trap",
            Self::BadCall(m) => m,
        }
    }

    /// Whether this ends the store: every trap does; [`Trap::Ended`] and [`Trap::BadCall`],
    /// which ran nothing, do not.
    #[must_use]
    pub const fn ends_store(&self) -> bool {
        !matches!(self, Self::Ended | Self::BadCall(_))
    }
}

impl fmt::Display for Trap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Host(m) => write!(f, "host function failed: {m}"),
            Self::BadCall(m) => write!(f, "bad call: {m}"),
            _ => write!(f, "wasm trap: {}", self.message()),
        }
    }
}

impl std::error::Error for Trap {}
