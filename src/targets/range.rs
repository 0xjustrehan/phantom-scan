/// Memory-Efficient Dual-Stack (IPv4 & IPv6) Target Space Model with IPv6 Prefix Sampling
///
/// Supports arbitrary CIDRs, ranges, and IPv6 large-prefix sampling (/64, /48, /56)
/// into a contiguous index space [0..Total-1] with zero heap overhead during scanning.

use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::str::FromStr;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

#[derive(Debug, Clone)]
pub struct Ipv4Block {
    pub start_ip: u32,
    pub count: u64,
    pub cumulative_base: u64,
}

#[derive(Debug, Clone)]
pub struct TargetSpace {
    pub v4_blocks: Vec<Ipv4Block>,
    pub v6_addrs: Vec<Ipv6Addr>,
    pub total_ips: u64,
    pub ports: Vec<u16>,
    pub total_targets: u64,
}

impl TargetSpace {
    pub fn new(target_list: &[String], ports: Vec<u16>) -> Result<Self, String> {
        Self::with_v6_sample_size(target_list, ports, 256)
    }

    pub fn with_v6_sample_size(target_list: &[String], ports: Vec<u16>, v6_samples: usize) -> Result<Self, String> {
        if ports.is_empty() {
            return Err("At least one port must be specified".to_string());
        }

        let mut v4_ranges: Vec<(u32, u64)> = Vec::new();
        let mut v6_addrs: Vec<Ipv6Addr> = Vec::new();

        for entry in target_list {
            let clean = entry.trim();
            if clean.is_empty() || clean.starts_with('#') {
                continue;
            }

            // Global aliases: whole IPv4 Internet
            if clean.eq_ignore_ascii_case("world")
                || clean.eq_ignore_ascii_case("internet")
                || clean.eq_ignore_ascii_case("global")
                || clean == "0/0"
            {
                v4_ranges.push((0, 1u64 << 32));
                continue;
            }

            if clean.contains(':') {
                // IPv6 target
                if clean.contains('/') {
                    let net = Ipv6Net::from_str(clean)
                        .map_err(|e| format!("Invalid IPv6 CIDR '{}': {}", clean, e))?;
                    let host_bits = 128 - net.prefix_len();

                    if host_bits <= 12 {
                        // Small prefix (<= 4096 hosts) -> scan exhaustively
                        for addr in net.hosts() {
                            v6_addrs.push(addr);
                        }
                    } else {
                        // Large prefix (/64, /48, etc.) -> sample common services + pseudorandom hosts
                        let base_octets = net.addr().octets();
                        let common_suffixes: &[u128] = &[
                            1, 2, 3, 4, 10, 20, 21, 22, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3389, 8080, 8443,
                            0xdeadbeef, 0xcafe, 0x1000, 0x2000,
                        ];

                        // Add common service host IDs
                        let base_u128 = u128::from_be_bytes(base_octets);
                        for &suffix in common_suffixes {
                            let sampled = base_u128 | suffix;
                            v6_addrs.push(Ipv6Addr::from(sampled));
                        }

                        // Add randomized hosts to reach sample count
                        let samples_remaining = v6_samples.saturating_sub(common_suffixes.len());
                        let host_mask = if host_bits >= 128 { u128::MAX } else { (1u128 << host_bits) - 1 };

                        for _ in 0..samples_remaining {
                            let rand_host: u128 = ((fastrand::u64(..) as u128) << 64) | (fastrand::u64(..) as u128);
                            let sampled = (base_u128 & !host_mask) | (rand_host & host_mask);
                            v6_addrs.push(Ipv6Addr::from(sampled));
                        }
                    }
                } else {
                    let addr = Ipv6Addr::from_str(clean)
                        .map_err(|e| format!("Invalid IPv6 address '{}': {}", clean, e))?;
                    v6_addrs.push(addr);
                }
            } else if clean.contains('-') {
                // IPv4 range notation: 1.1.1.1-1.1.1.50
                let parts: Vec<&str> = clean.split('-').collect();
                if parts.len() == 2 {
                    let start = Ipv4Addr::from_str(parts[0].trim())
                        .map_err(|e| format!("Invalid start IP '{}': {}", parts[0], e))?;
                    let end = Ipv4Addr::from_str(parts[1].trim())
                        .map_err(|e| format!("Invalid end IP '{}': {}", parts[1], e))?;
                    let s_u32 = u32::from(start);
                    let e_u32 = u32::from(end);
                    if s_u32 <= e_u32 {
                        v4_ranges.push((s_u32, (e_u32 - s_u32 + 1) as u64));
                    }
                }
            } else if clean.contains('/') {
                // IPv4 CIDR notation
                let net = Ipv4Net::from_str(clean)
                    .map_err(|e| format!("Invalid CIDR '{}': {}", clean, e))?;
                let start = u32::from(net.network());
                let full_count = if net.prefix_len() == 0 {
                    1u64 << 32
                } else {
                    1u64 << (32 - net.prefix_len())
                };
                v4_ranges.push((start, full_count));
            } else {
                // Single IPv4
                let ip = Ipv4Addr::from_str(clean)
                    .map_err(|e| format!("Invalid IP '{}': {}", clean, e))?;
                v4_ranges.push((u32::from(ip), 1));
            }
        }

        if v4_ranges.is_empty() && v6_addrs.is_empty() {
            return Err("No valid target IPs or CIDRs provided".to_string());
        }

        v4_ranges.sort_by_key(|&(start, _)| start);
        v6_addrs.sort_unstable();
        v6_addrs.dedup();

        let mut v4_blocks = Vec::new();
        let mut total_ips = 0u64;

        for (start, count) in v4_ranges {
            v4_blocks.push(Ipv4Block {
                start_ip: start,
                count,
                cumulative_base: total_ips,
            });
            total_ips += count;
        }

        total_ips += v6_addrs.len() as u64;
        let total_targets = total_ips.saturating_mul(ports.len() as u64);

        Ok(Self {
            v4_blocks,
            v6_addrs,
            total_ips,
            ports,
            total_targets,
        })
    }

    pub fn from_file<P: AsRef<Path>>(path: P, ports: Vec<u16>) -> io::Result<Self> {
        Self::from_file_with_v6_samples(path, ports, 256)
    }

    pub fn from_file_with_v6_samples<P: AsRef<Path>>(path: P, ports: Vec<u16>, v6_samples: usize) -> io::Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut targets = Vec::new();

        for line in reader.lines() {
            let line = line?;
            let clean = line.trim();
            if !clean.is_empty() && !clean.starts_with('#') {
                targets.push(clean.to_string());
            }
        }

        Self::with_v6_sample_size(&targets, ports, v6_samples).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
    }

    #[inline]
    pub fn get_target(&self, flat_index: u64) -> (IpAddr, u16) {
        let num_ports = self.ports.len() as u64;
        let port_idx = (flat_index % num_ports) as usize;
        let ip_index = flat_index / num_ports;

        let v4_total_ips: u64 = self.v4_blocks.iter().map(|b| b.count).sum();

        if ip_index < v4_total_ips {
            let block_idx = match self
                .v4_blocks
                .binary_search_by_key(&ip_index, |b| b.cumulative_base)
            {
                Ok(idx) => idx,
                Err(idx) => idx.saturating_sub(1),
            };

            let block = &self.v4_blocks[block_idx];
            let offset = ip_index - block.cumulative_base;
            let ip_u32 = block.start_ip.wrapping_add(offset as u32);
            (IpAddr::V4(Ipv4Addr::from(ip_u32)), self.ports[port_idx])
        } else {
            let v6_idx = (ip_index - v4_total_ips) as usize;
            (IpAddr::V6(self.v6_addrs[v6_idx]), self.ports[port_idx])
        }
    }
}

pub fn parse_ports(port_str: &str) -> Result<Vec<u16>, String> {
    let clean = port_str.trim().to_lowercase();
    let mut ports = Vec::new();

    if clean == "common" || clean == "top" {
        return Ok(vec![80, 443, 8080, 8443, 22, 21, 25, 3389, 445, 110, 993, 995, 1433, 3306, 5432, 6379, 27017]);
    }
    if clean == "all" || clean == "1-65535" || clean == "0-65535" {
        return Ok((1..=65535).collect());
    }
    if clean == "rdp" || clean == "nla" {
        return Ok(vec![3389]);
    }
    if clean == "ssh" {
        return Ok(vec![22]);
    }
    if clean == "web" {
        return Ok(vec![80, 443, 8080, 8443]);
    }
    if clean == "smb" {
        return Ok(vec![445]);
    }

    for part in port_str.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        if part.contains('-') {
            let bounds: Vec<&str> = part.split('-').collect();
            if bounds.len() == 2 {
                let start: u16 = bounds[0].trim().parse().map_err(|e| format!("Invalid port: {}", e))?;
                let end: u16 = bounds[1].trim().parse().map_err(|e| format!("Invalid port: {}", e))?;
                let start = start.max(1);
                if start <= end {
                    for p in start..=end {
                        ports.push(p);
                    }
                }
            }
        } else {
            let p: u16 = part.parse().map_err(|e| format!("Invalid port '{}': {}", part, e))?;
            ports.push(p);
        }
    }

    ports.sort_unstable();
    ports.dedup();
    if ports.is_empty() {
        Err("No valid ports parsed".to_string())
    } else {
        Ok(ports)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_world_target_parsing() {
        let ts = TargetSpace::new(&["world".to_string()], vec![80]).unwrap();
        assert_eq!(ts.total_ips, 4_294_967_296);
        assert_eq!(ts.total_targets, 4_294_967_296);

        let ts2 = TargetSpace::new(&["0.0.0.0/0".to_string()], vec![80]).unwrap();
        assert_eq!(ts2.total_ips, 4_294_967_296);

        let ts3 = TargetSpace::new(&["internet".to_string()], vec![80]).unwrap();
        assert_eq!(ts3.total_ips, 4_294_967_296);
    }

    #[test]
    fn test_all_ports_parsing() {
        let ports = parse_ports("all").unwrap();
        assert_eq!(ports.len(), 65535);
        assert_eq!(ports[0], 1);
        assert_eq!(ports[65534], 65535);

        let ports2 = parse_ports("0-65535").unwrap();
        assert_eq!(ports2.len(), 65535);
        assert_eq!(ports2[0], 1);

        let ports3 = parse_ports("1-65535").unwrap();
        assert_eq!(ports3.len(), 65535);
    }
}
