/// Dual-Stack Exact /24 IPv4 & /64 IPv6 Subnet Cooldown Tracker
///
/// Features:
/// - IPv4: Exact dense 64MB atomic array covering all 16,777,216 /24 subnets (0% hash collisions).
/// - IPv6: 1,048,576 atomic sharded buckets tracking /64 organizational network prefixes.
/// - Guarantees no single /24 (IPv4) or /64 (IPv6) subnet is hit faster than `cooldown_ms`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

const TOTAL_IPV4_SLASH_24: usize = 16_777_216; // 2^24 exact IPv4 subnets
const IPV6_BUCKET_COUNT: usize = 1_048_576;    // 1M shards for IPv6 /64 tracking

pub enum CooldownBackend {
    /// Exact 64MB dense array covering all 16.7M IPv4 /24 subnets
    ExactDense(Vec<AtomicU32>),
    /// 1,048,576 entry compact table (~4MB)
    Compact(Vec<AtomicU32>),
}

pub struct SubnetCooldown {
    cooldown_ms: u32,
    epoch: Instant,
    v4_backend: CooldownBackend,
    v6_buckets: Vec<AtomicU32>,
}

impl SubnetCooldown {
    pub fn new_exact(cooldown_ms: u32) -> Self {
        let mut v4_buckets = Vec::with_capacity(TOTAL_IPV4_SLASH_24);
        for _ in 0..TOTAL_IPV4_SLASH_24 {
            v4_buckets.push(AtomicU32::new(0));
        }

        let mut v6_buckets = Vec::with_capacity(IPV6_BUCKET_COUNT);
        for _ in 0..IPV6_BUCKET_COUNT {
            v6_buckets.push(AtomicU32::new(0));
        }

        Self {
            cooldown_ms,
            epoch: Instant::now(),
            v4_backend: CooldownBackend::ExactDense(v4_buckets),
            v6_buckets,
        }
    }

    pub fn new_compact(cooldown_ms: u32) -> Self {
        let size = 1_048_576;
        let mut v4_buckets = Vec::with_capacity(size);
        for _ in 0..size {
            v4_buckets.push(AtomicU32::new(0));
        }

        let mut v6_buckets = Vec::with_capacity(size);
        for _ in 0..size {
            v6_buckets.push(AtomicU32::new(0));
        }

        Self {
            cooldown_ms,
            epoch: Instant::now(),
            v4_backend: CooldownBackend::Compact(v4_buckets),
            v6_buckets,
        }
    }

    pub fn new(cooldown_ms: u32) -> Self {
        Self::new_exact(cooldown_ms)
    }

    #[inline(always)]
    fn get_now_ms(&self) -> u32 {
        (self.epoch.elapsed().as_millis() as u32).wrapping_add(1)
    }

    /// Check if target IP is allowed to be probed right now (IPv4 /24 or IPv6 /64)
    #[inline(always)]
    pub fn allow_and_touch(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.allow_and_touch_v4(v4),
            IpAddr::V6(v6) => self.allow_and_touch_v6(v6),
        }
    }

    #[inline(always)]
    pub fn allow_and_touch_v4(&self, ip: Ipv4Addr) -> bool {
        if self.cooldown_ms == 0 {
            return true;
        }

        let ip_u32 = u32::from(ip);
        let subnet_24 = (ip_u32 >> 8) as usize;

        let cell = match &self.v4_backend {
            CooldownBackend::ExactDense(dense) => &dense[subnet_24],
            CooldownBackend::Compact(compact) => {
                let mask = compact.len() - 1;
                let idx = (subnet_24 ^ (subnet_24 >> 10)) & mask;
                &compact[idx]
            }
        };

        let now_ms = self.get_now_ms();
        let last_hit = cell.load(Ordering::Relaxed);

        if last_hit != 0 && now_ms.saturating_sub(last_hit) < self.cooldown_ms {
            return false;
        }

        match cell.compare_exchange(last_hit, now_ms, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    #[inline(always)]
    pub fn allow_and_touch_v6(&self, ip: Ipv6Addr) -> bool {
        if self.cooldown_ms == 0 {
            return true;
        }

        // Extract 64-bit routing prefix
        let octets = ip.octets();
        let prefix_64 = u64::from_be_bytes([
            octets[0], octets[1], octets[2], octets[3],
            octets[4], octets[5], octets[6], octets[7],
        ]);

        let mask = self.v6_buckets.len() - 1;
        let idx = ((prefix_64 ^ (prefix_64 >> 32)) as usize) & mask;
        let cell = &self.v6_buckets[idx];

        let now_ms = self.get_now_ms();
        let last_hit = cell.load(Ordering::Relaxed);

        if last_hit != 0 && now_ms.saturating_sub(last_hit) < self.cooldown_ms {
            return false;
        }

        match cell.compare_exchange(last_hit, now_ms, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => true,
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_subnet_cooldown_v4_v6() {
        let cd = SubnetCooldown::new_compact(100);
        let ip1 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 20));
        assert!(cd.allow_and_touch(ip1));
        assert!(!cd.allow_and_touch(ip2));

        let v6_1 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x1, 0, 0, 0, 0, 1));
        let v6_2 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x1, 0, 0, 0, 0, 2)); // same /64
        let v6_3 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x2, 0, 0, 0, 0, 1)); // diff /64

        assert!(cd.allow_and_touch(v6_1));
        assert!(!cd.allow_and_touch(v6_2));
        assert!(cd.allow_and_touch(v6_3));
    }
}
