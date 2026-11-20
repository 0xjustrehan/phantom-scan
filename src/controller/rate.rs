/// High-Performance Leased Batch Token Bucket Rate Controller with Adaptive AIMD
///
/// Features:
/// - Single atomic lease per chunk (zero CPU cache-line bouncing).
/// - Microsecond-accurate sub-packet spin pacing.
/// - Adaptive Congestion Control (AIMD): Backs off when socket buffers report congestion
///   and ramps up when latency is low and throughput is smooth.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

pub struct GlobalRateController {
    max_pps: u64,
    current_pps: AtomicU64,
    epoch: Instant,
    next_batch_time_nanos: AtomicU64,
}

impl GlobalRateController {
    pub fn new(target_pps: u64) -> Self {
        let pps = target_pps.max(1);
        Self {
            max_pps: pps,
            current_pps: AtomicU64::new(pps),
            epoch: Instant::now(),
            next_batch_time_nanos: AtomicU64::new(0),
        }
    }

    /// Lease exactly `count` tokens for a worker thread in one atomic CAS.
    /// Returns the leased count and the scheduled start timestamp in nanoseconds.
    #[inline]
    pub fn lease_batch(&self, count: u64) -> (u64, u64) {
        let pps = self.current_pps.load(Ordering::Relaxed).max(1);
        let batch_dur = (1_000_000_000u64 * count) / pps;
        let mut current = self.next_batch_time_nanos.load(Ordering::Relaxed);

        loop {
            let now = self.epoch.elapsed().as_nanos() as u64;
            let start_time = current.max(now);
            let next = start_time + batch_dur;

            match self.next_batch_time_nanos.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return (count, start_time),
                Err(actual) => current = actual,
            }
        }
    }

    /// High-resolution sub-microsecond spin-wait for packet spacing
    #[inline(always)]
    pub fn pace_packet(&self, scheduled_nano: u64) {
        while (self.epoch.elapsed().as_nanos() as u64) < scheduled_nano {
            std::hint::spin_loop();
        }
    }

    #[inline(always)]
    pub fn packet_interval_nanos(&self) -> u64 {
        let pps = self.current_pps.load(Ordering::Relaxed).max(1);
        1_000_000_000u64 / pps
    }

    /// Back off rate (Multiplicative Decrease) when socket buffers report congestion
    pub fn backoff(&self) {
        let cur = self.current_pps.load(Ordering::Relaxed);
        let new_pps = (cur * 4 / 5).max(100); // Reduce by 20%
        self.current_pps.store(new_pps, Ordering::Relaxed);
    }

    /// Ramp up rate (Additive Increase) when transmission is smooth
    pub fn ramp_up(&self) {
        let cur = self.current_pps.load(Ordering::Relaxed);
        if cur < self.max_pps {
            let increment = (self.max_pps / 50).max(10);
            let new_pps = (cur + increment).min(self.max_pps);
            self.current_pps.store(new_pps, Ordering::Relaxed);
        }
    }

    pub fn current_pps(&self) -> u64 {
        self.current_pps.load(Ordering::Relaxed)
    }
}
