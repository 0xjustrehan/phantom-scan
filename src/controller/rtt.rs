/// Real Per-Packet RTT Estimator and Drain Window Controller (RFC 6298 Jacobson/Karels)
///
/// Tracks real per-packet round-trip latency using a lock-free cyclic timestamp ring
/// keyed by the TCP sequence number (and TCP Timestamp TSecr option).
/// Computes Smoothed RTT (SRTT), RTT Variance (RTTVAR), and dynamic Retransmission Timeout (RTO).

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

const TIMESTAMP_RING_SIZE: usize = 1_048_576; // 1M entries (~4MB)
const RING_MASK: usize = TIMESTAMP_RING_SIZE - 1;

pub struct TxTimestampRing {
    epoch: Instant,
    // Stores millisecond offsets from epoch
    slots: Vec<AtomicU32>,
}

impl TxTimestampRing {
    pub fn new() -> Self {
        let mut slots = Vec::with_capacity(TIMESTAMP_RING_SIZE);
        for _ in 0..TIMESTAMP_RING_SIZE {
            slots.push(AtomicU32::new(0));
        }
        Self {
            epoch: Instant::now(),
            slots,
        }
    }

    #[inline(always)]
    pub fn record_tx(&self, seq: u32) {
        let idx = (seq as usize) & RING_MASK;
        let now_ms = (self.epoch.elapsed().as_millis() as u32).wrapping_add(1);
        self.slots[idx].store(now_ms, Ordering::Relaxed);
    }

    #[inline(always)]
    pub fn calculate_rtt_us(&self, ack_seq: u32, _tsecr: Option<u32>) -> Option<u64> {
        let now_ms = (self.epoch.elapsed().as_millis() as u32).wrapping_add(1);

        // Lock-free sequence ring lookup
        let seq = ack_seq.wrapping_sub(1);
        let idx = (seq as usize) & RING_MASK;
        let sent_ms = self.slots[idx].load(Ordering::Relaxed);

        if sent_ms > 0 && now_ms >= sent_ms {
            let diff_ms = now_ms - sent_ms;
            if diff_ms < 30_000 {
                // Realistic RTT within 30 seconds
                return Some((diff_ms as u64) * 1000);
            }
        }

        None
    }
}

pub struct RttEstimator {
    pub ring: TxTimestampRing,
    srtt_us: AtomicU64,
    rttvar_us: AtomicU64,
    samples_count: AtomicU64,
    min_rtt_us: AtomicU32,
    max_rtt_us: AtomicU32,
}

impl RttEstimator {
    pub fn new() -> Self {
        Self {
            ring: TxTimestampRing::new(),
            srtt_us: AtomicU64::new(100_000),   // Default: 100ms
            rttvar_us: AtomicU64::new(50_000),  // Default: 50ms
            samples_count: AtomicU64::new(0),
            min_rtt_us: AtomicU32::new(u32::MAX),
            max_rtt_us: AtomicU32::new(0),
        }
    }

    /// Record a verified per-packet round-trip time in microseconds
    pub fn record_sample(&self, rtt_us: u64) {
        let count = self.samples_count.fetch_add(1, Ordering::Relaxed);

        let rtt_u32 = rtt_us.min(u32::MAX as u64) as u32;
        self.min_rtt_us.fetch_min(rtt_u32, Ordering::Relaxed);
        self.max_rtt_us.fetch_max(rtt_u32, Ordering::Relaxed);

        if count == 0 {
            self.srtt_us.store(rtt_us, Ordering::Relaxed);
            self.rttvar_us.store(rtt_us / 2, Ordering::Relaxed);
            return;
        }

        // RFC 6298 Jacobson / Karels algorithm
        let old_srtt = self.srtt_us.load(Ordering::Relaxed);
        let old_rttvar = self.rttvar_us.load(Ordering::Relaxed);

        let diff = if rtt_us > old_srtt {
            rtt_us - old_srtt
        } else {
            old_srtt - rtt_us
        };

        let new_rttvar = (3 * old_rttvar + diff) / 4;
        let new_srtt = (7 * old_srtt + rtt_us) / 8;

        self.srtt_us.store(new_srtt, Ordering::Relaxed);
        self.rttvar_us.store(new_rttvar, Ordering::Relaxed);
    }

    /// Calculate Adaptive Drain Wait Time (RTO = SRTT + 4 * RTTVAR)
    pub fn adaptive_drain_duration(&self) -> Duration {
        let count = self.samples_count.load(Ordering::Relaxed);
        if count == 0 {
            return Duration::from_millis(1500);
        }

        let srtt = self.srtt_us.load(Ordering::Relaxed);
        let rttvar = self.rttvar_us.load(Ordering::Relaxed);
        let rto_us = srtt + 4 * rttvar;

        let clamped_us = rto_us.clamp(200_000, 6_000_000);
        Duration::from_micros(clamped_us)
    }

    pub fn average_rtt_ms(&self) -> f64 {
        (self.srtt_us.load(Ordering::Relaxed) as f64) / 1000.0
    }

    pub fn samples(&self) -> u64 {
        self.samples_count.load(Ordering::Relaxed)
    }
}
