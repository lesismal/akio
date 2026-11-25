//! How long a call may run: budgets, metering, interrupts, and the limits on running.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

use crate::trap::Trap;

/// Limits on what a [`Store`](crate::Store) may hold and use while it runs (ADR-125, section 3).
///
/// ```
/// let mut limits = akio_wasm::InstanceLimits::default();
/// limits.max_memory = 16 << 20;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct InstanceLimits {
    /// The most bytes a memory may have (128 MiB, as fit's default), rounded down to whole
    /// 64 KiB pages. A memory whose initial size is larger cannot be made; `memory.grow` past it
    /// returns `-1`, as the specification lets it.
    pub max_memory: usize,
    /// The most elements a table may have (10 M); `table.grow` past it returns `-1`.
    pub max_table_elements: u32,
    /// The value stack, in 8-byte slots (1 Mi, 8 MiB): every frame's locals and operands. A call
    /// whose frame would pass it traps with [`Trap::ValueStackExhausted`].
    pub max_value_stack: u32,
    /// The call depth (10 000 frames); a call past it traps with [`Trap::CallStackExhausted`].
    pub max_call_depth: u32,
}

impl Default for InstanceLimits {
    fn default() -> Self {
        Self {
            max_memory: 128 << 20,
            max_table_elements: 10_000_000,
            max_value_stack: 1 << 20,
            max_call_depth: 10_000,
        }
    }
}

/// Raises an interrupt from another thread: the call running in the store stops at its next
/// check (within about [`Budget::SLICE`] instructions) with [`Trap::Interrupted`].
///
/// The flag stays raised, stopping every later call given it, until [`clear`](Self::clear).
#[derive(Debug, Clone, Default)]
pub struct InterruptHandle(Arc<AtomicBool>);

impl InterruptHandle {
    /// A handle, not raised.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Raises the interrupt.
    pub fn interrupt(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    /// Lowers it.
    pub fn clear(&self) {
        self.0.store(false, Ordering::Relaxed);
    }

    /// Whether it is raised.
    #[must_use]
    pub fn is_interrupted(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

/// What one call may spend: a deadline, fuel (WebAssembly instructions) and an interrupt, each
/// optional (ADR-125, section 3).
///
/// The interpreter takes each basic block's instruction count from a counter as it enters the
/// block; when the counter runs out it checks the budget and, if all allow, gives itself another
/// slice of [`Budget::SLICE`] instructions. So a call stops within one slice (tens of
/// microseconds) of its deadline, with no watchdog thread. Bulk memory and table instructions,
/// `memory.grow`, `table.grow` and a call's zeroing of its locals take fuel by the bytes they
/// touch (one unit per 64 bytes), so that the slice stays short in time too.
///
/// ```
/// use std::time::{Duration, Instant};
/// use akio_wasm::{Budget, InterruptHandle};
///
/// let stop = InterruptHandle::new();
/// let budget = Budget::deadline(Instant::now() + Duration::from_millis(100))
///     .with_fuel(10_000_000)
///     .with_interrupt(&stop);
/// ```
#[derive(Debug, Clone, Default)]
pub struct Budget {
    deadline: Option<Instant>,
    fuel: Option<u64>,
    interrupt: Option<InterruptHandle>,
}

impl Budget {
    /// The instructions run between two checks of the budget.
    pub const SLICE: u64 = 10_000;

    /// No limit but the store's [`InstanceLimits`].
    #[must_use]
    pub fn unlimited() -> Self {
        Self::default()
    }

    /// Stop with [`Trap::Deadline`] once `at` has passed.
    #[must_use]
    pub fn deadline(at: Instant) -> Self {
        Self::default().with_deadline(at)
    }

    /// Stop with [`Trap::OutOfFuel`] before running more than `fuel` instructions.
    #[must_use]
    pub fn fuel(fuel: u64) -> Self {
        Self::default().with_fuel(fuel)
    }

    /// This budget, with a deadline.
    #[must_use]
    pub const fn with_deadline(mut self, at: Instant) -> Self {
        self.deadline = Some(at);
        self
    }

    /// This budget, with fuel.
    #[must_use]
    pub const fn with_fuel(mut self, fuel: u64) -> Self {
        self.fuel = Some(fuel);
        self
    }

    /// This budget, stopped with [`Trap::Interrupted`] when `handle` is raised.
    #[must_use]
    pub fn with_interrupt(mut self, handle: &InterruptHandle) -> Self {
        self.interrupt = Some(handle.clone());
        self
    }
}

/// The interpreter's side of a [`Budget`].
#[derive(Debug)]
pub(crate) struct Meter {
    /// What is left of the current slice.
    counter: u64,
    /// Fuel not yet given to a slice; `None` when unlimited.
    reserve: Option<u64>,
    /// All the fuel given to slices.
    given: u64,
    deadline: Option<Instant>,
    interrupt: Option<Arc<AtomicBool>>,
}

impl Meter {
    pub(crate) fn new(b: &Budget) -> Self {
        Self {
            // Empty: the first block checks the budget, so a call past its deadline does not start.
            counter: 0,
            reserve: b.fuel,
            given: 0,
            deadline: b.deadline,
            interrupt: b.interrupt.as_ref().map(|h| Arc::clone(&h.0)),
        }
    }

    /// Takes `n` units.
    #[inline(always)]
    pub(crate) fn take(&mut self, n: u64) -> Result<(), Trap> {
        if n <= self.counter {
            self.counter -= n;
            Ok(())
        } else {
            self.refill(n)
        }
    }

    #[cold]
    #[inline(never)]
    fn refill(&mut self, n: u64) -> Result<(), Trap> {
        if self
            .interrupt
            .as_ref()
            .is_some_and(|f| f.load(Ordering::Relaxed))
        {
            return Err(Trap::Interrupted);
        }
        if self.deadline.is_some_and(|d| Instant::now() >= d) {
            return Err(Trap::Deadline);
        }
        let want = Budget::SLICE.max(n);
        match &mut self.reserve {
            None => {
                let add = want - self.counter;
                self.given += add;
                self.counter = want;
            }
            Some(r) => {
                let total = self.counter + *r;
                if total < n {
                    return Err(Trap::OutOfFuel);
                }
                let c = total.min(want);
                self.given += c - self.counter;
                *r = total - c;
                self.counter = c;
            }
        }
        self.counter -= n;
        Ok(())
    }

    /// The units taken so far.
    pub(crate) const fn used(&self) -> u64 {
        self.given - self.counter
    }

    /// The call's deadline.
    pub(crate) const fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// Whether the call's interrupt is raised.
    pub(crate) fn interrupted(&self) -> bool {
        self.interrupt
            .as_ref()
            .is_some_and(|f| f.load(Ordering::Relaxed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuel_is_exact() {
        let mut m = Meter::new(&Budget::fuel(25_000));
        for _ in 0..25 {
            m.take(1000).unwrap();
        }
        assert_eq!(m.used(), 25_000);
        assert_eq!(m.take(1), Err(Trap::OutOfFuel));
        assert_eq!(m.used(), 25_000);
    }

    #[test]
    fn a_large_charge_needs_that_much_fuel() {
        let mut m = Meter::new(&Budget::fuel(50_000));
        m.take(40_000).unwrap();
        assert_eq!(m.take(10_001), Err(Trap::OutOfFuel));
        m.take(10_000).unwrap();
        assert_eq!(m.used(), 50_000);
    }

    #[test]
    fn unlimited_counts_too() {
        let mut m = Meter::new(&Budget::unlimited());
        for _ in 0..100 {
            m.take(333).unwrap();
        }
        m.take(1_000_000).unwrap();
        assert_eq!(m.used(), 1_033_300);
    }

    #[test]
    fn deadline_and_interrupt() {
        let mut m = Meter::new(&Budget::deadline(Instant::now()));
        assert_eq!(m.take(1), Err(Trap::Deadline));
        let h = InterruptHandle::new();
        let mut m = Meter::new(&Budget::unlimited().with_interrupt(&h));
        m.take(1).unwrap();
        h.interrupt();
        // Seen at the next check, within a slice.
        let mut n = 0;
        while m.take(1).is_ok() {
            n += 1;
        }
        assert!(n < Budget::SLICE);
        assert!(h.is_interrupted());
        h.clear();
        assert!(!h.is_interrupted());
    }
}
