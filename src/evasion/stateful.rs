/// Stateful IP ID Sequence & Authentic Uptime Timestamp Generator
///
/// Features:
/// - Windows: Monotonic atomic counter (+1 to +3 jitter) matching real Windows kernel behavior.
/// - Linux: Always 0 when DF (Don't Fragment) is set, per RFC 6864.
/// - Synthetic Uptime Clock: TSval advances realistically at 1000 Hz from an authentic boot baseline.
/// - Ephemeral Source Port Range: Randomizes source port across a safe range (40,000..65,000).

use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Instant;
use crate::evasion::OsProfile;

pub struct StatefulEvasion {
    monotonic_ip_id: AtomicU16,
    boot_baseline_ticks: u32,
    epoch: Instant,
    min_src_port: u16,
    max_src_port: u16,
}

impl StatefulEvasion {
    pub fn new(min_port: u16, max_port: u16) -> Self {
        // Generate realistic synthetic boot baseline (e.g. system booted 3 to 14 days ago)
        let days_in_ticks = fastrand::u32(250_000_000..1_200_000_000);
        let start_ip_id = fastrand::u16(1000..=30000);

        Self {
            monotonic_ip_id: AtomicU16::new(start_ip_id),
            boot_baseline_ticks: days_in_ticks,
            epoch: Instant::now(),
            min_src_port: min_port.min(max_port).max(1024),
            max_src_port: max_port.max(min_port),
        }
    }

    /// Generate authentic IP ID according to the specific operating system stack
    #[inline(always)]
    pub fn next_ip_id(&self, profile: OsProfile) -> u16 {
        match profile {
            OsProfile::Windows => {
                // Windows uses monotonic increment with slight jitter
                let jitter = fastrand::u16(1..=3);
                self.monotonic_ip_id.fetch_add(jitter, Ordering::Relaxed)
            }
            OsProfile::Linux => {
                // Linux Kernel zeros IP ID when DF flag is enabled (RFC 6864)
                0
            }
            OsProfile::Macos | OsProfile::Freebsd | OsProfile::Android | OsProfile::Random => {
                fastrand::u16(1000..=65535)
            }
        }
    }

    /// Calculate authentic advancing TCP Timestamp (TSval)
    #[inline(always)]
    pub fn current_tsval(&self) -> u32 {
        let elapsed_ms = self.epoch.elapsed().as_millis() as u32;
        self.boot_baseline_ticks.wrapping_add(elapsed_ms)
    }

    /// Pick an ephemeral source port from the configured range
    #[inline(always)]
    pub fn pick_source_port(&self, base_port: u16) -> u16 {
        if self.min_src_port == self.max_src_port {
            return base_port;
        }
        let range = self.max_src_port - self.min_src_port + 1;
        self.min_src_port + (fastrand::u16(0..range))
    }
}
