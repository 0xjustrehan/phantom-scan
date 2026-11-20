/// Dual-Stack High-Performance O(1) Binary Prefix Trie for IPv4 & IPv6 CIDR Exclusion
///
/// Fast lookup with zero dynamic allocations during scanning.
/// Prevents scanning known honeypot traps, military ranges, and abuse monitoring nets.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

#[derive(Default)]
struct TrieNode {
    is_blocked: bool,
    children: [Option<Box<TrieNode>>; 2],
}

pub struct BlacklistTrie {
    v4_root: TrieNode,
    v6_root: TrieNode,
    total_blocked_prefixes: usize,
}

impl BlacklistTrie {
    pub fn new() -> Self {
        Self {
            v4_root: TrieNode::default(),
            v6_root: TrieNode::default(),
            total_blocked_prefixes: 0,
        }
    }

    pub fn insert_v4_cidr(&mut self, net: &Ipv4Net) {
        let ip_u32 = u32::from(net.addr());
        let prefix_len = net.prefix_len();

        let mut current = &mut self.v4_root;
        for i in 0..prefix_len {
            if current.is_blocked {
                return;
            }
            let bit = ((ip_u32 >> (31 - i)) & 1) as usize;
            if current.children[bit].is_none() {
                current.children[bit] = Some(Box::new(TrieNode::default()));
            }
            current = current.children[bit].as_mut().unwrap();
        }

        current.is_blocked = true;
        current.children[0] = None;
        current.children[1] = None;
        self.total_blocked_prefixes += 1;
    }

    pub fn insert_v6_cidr(&mut self, net: &Ipv6Net) {
        let octets = net.addr().octets();
        let prefix_len = net.prefix_len() as usize;

        let mut current = &mut self.v6_root;
        for i in 0..prefix_len {
            if current.is_blocked {
                return;
            }
            let byte_idx = i / 8;
            let bit_idx = 7 - (i % 8);
            let bit = ((octets[byte_idx] >> bit_idx) & 1) as usize;

            if current.children[bit].is_none() {
                current.children[bit] = Some(Box::new(TrieNode::default()));
            }
            current = current.children[bit].as_mut().unwrap();
        }

        current.is_blocked = true;
        current.children[0] = None;
        current.children[1] = None;
        self.total_blocked_prefixes += 1;
    }

    pub fn insert_str(&mut self, s: &str) -> Result<(), String> {
        let clean = s.trim();
        if clean.is_empty() || clean.starts_with('#') {
            return Ok(());
        }

        if clean.contains(':') {
            // IPv6
            let net = if clean.contains('/') {
                Ipv6Net::from_str(clean).map_err(|e| format!("Invalid IPv6 CIDR '{}': {}", clean, e))?
            } else {
                let addr = Ipv6Addr::from_str(clean).map_err(|e| format!("Invalid IPv6 '{}': {}", clean, e))?;
                Ipv6Net::new(addr, 128).map_err(|e| format!("Invalid prefix: {}", e))?
            };
            self.insert_v6_cidr(&net);
        } else {
            // IPv4
            let net = if clean.contains('/') {
                Ipv4Net::from_str(clean).map_err(|e| format!("Invalid IPv4 CIDR '{}': {}", clean, e))?
            } else {
                let addr = Ipv4Addr::from_str(clean).map_err(|e| format!("Invalid IPv4 '{}': {}", clean, e))?;
                Ipv4Net::new(addr, 32).map_err(|e| format!("Invalid prefix: {}", e))?
            };
            self.insert_v4_cidr(&net);
        }

        Ok(())
    }

    #[inline(always)]
    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.is_blocked_v4(v4),
            IpAddr::V6(v6) => self.is_blocked_v6(v6),
        }
    }

    #[inline(always)]
    pub fn is_blocked_v4(&self, ip: Ipv4Addr) -> bool {
        let ip_u32 = u32::from(ip);
        let mut current = &self.v4_root;

        for i in 0..32 {
            if current.is_blocked {
                return true;
            }
            let bit = ((ip_u32 >> (31 - i)) & 1) as usize;
            match &current.children[bit] {
                Some(next) => current = next,
                None => return false,
            }
        }
        current.is_blocked
    }

    #[inline(always)]
    pub fn is_blocked_v6(&self, ip: Ipv6Addr) -> bool {
        let octets = ip.octets();
        let mut current = &self.v6_root;

        for i in 0..128 {
            if current.is_blocked {
                return true;
            }
            let byte_idx = i / 8;
            let bit_idx = 7 - (i % 8);
            let bit = ((octets[byte_idx] >> bit_idx) & 1) as usize;

            match &current.children[bit] {
                Some(next) => current = next,
                None => return false,
            }
        }
        current.is_blocked
    }

    pub fn len(&self) -> usize {
        self.total_blocked_prefixes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dual_blacklist_trie() {
        let mut trie = BlacklistTrie::new();
        trie.insert_str("10.0.0.0/8").unwrap();
        trie.insert_str("2001:db8::/32").unwrap();
        trie.insert_str("fe80::/10").unwrap();

        assert!(trie.is_blocked(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
        assert!(!trie.is_blocked(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));

        assert!(trie.is_blocked(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x1, 0, 0, 0, 0, 1))));
        assert!(trie.is_blocked(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))));
        assert!(!trie.is_blocked(IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 1))));
    }
}
