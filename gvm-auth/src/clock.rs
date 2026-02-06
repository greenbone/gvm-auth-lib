// SPDX-FileCopyrightText: 2026 Greenbone AG
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::fmt::Debug;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

pub trait Clock: Send + Sync + 'static + Debug {
    fn now(&self) -> u64;
}

#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

#[derive(Debug)]
pub struct ManualClock {
    now: AtomicU64,
}

impl ManualClock {
    pub fn new(init_unix: u64) -> Self {
        Self {
            now: AtomicU64::new(init_unix),
        }
    }

    pub fn set(&self, unix: u64) {
        self.now.store(unix, Ordering::SeqCst);
    }

    pub fn advance(&self, secs: u64) {
        self.now.fetch_add(secs, Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_clock_new_returns_initial_time() {
        let clock = ManualClock::new(0);
        assert_eq!(clock.now(), 0);
    }
    #[test]
    fn manual_clock_set_overwrites_time() {
        let c = ManualClock::new(10);
        c.set(999);
        assert_eq!(c.now(), 999);

        c.set(0);
        assert_eq!(c.now(), 0);
    }

    #[test]
    fn manual_clock_advance_increases_time() {
        let c = ManualClock::new(100);
        c.advance(5);
        assert_eq!(c.now(), 105);

        c.advance(10);
        assert_eq!(c.now(), 115);
    }

    #[test]
    fn manual_clock_advance_zero_is_noop() {
        let c = ManualClock::new(42);
        c.advance(0);
        assert_eq!(c.now(), 42);
    }

    #[test]
    fn system_clock_now_is_non_decreasing() {
        let c = SystemClock::default();

        let t1 = c.now();
        let t2 = c.now();

        assert!(t2 >= t1, "expected t2 >= t1, got t1={t1}, t2={t2}");
    }

    #[test]
    fn clock_trait_objects_work_for_manual_clock() {
        let c: Box<dyn Clock> = Box::new(ManualClock::new(7));
        assert_eq!(c.now(), 7);
    }
}
