pub mod feeds;
pub mod trie;

pub use feeds::FeedManager;
pub use trie::BlacklistTrie;

use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;

/// High-risk ranges: US Military (DoD), Intelligence, and Federal ranges that trigger immediate ISP abuse/legal complaints
pub const MILITARY_DOD_RANGES: &[&str] = &[
    "6.0.0.0/8",      // US Army Information Systems
    "11.0.0.0/8",     // DoD Intel Information Systems
    "21.0.0.0/8",     // DDN-RVN
    "22.0.0.0/8",     // Defense Information Systems Agency
    "26.0.0.0/8",     // Defense Information Systems Agency
    "28.0.0.0/8",     // DSI-North
    "29.0.0.0/8",     // Defense Information Systems Agency
    "30.0.0.0/8",     // Defense Information Systems Agency
    "33.0.0.0/8",     // DLA Systems Automation Center
    "55.0.0.0/8",     // DoD Network Information Center
    "214.0.0.0/8",    // US-DOD
    "215.0.0.0/8",    // US-DOD
];

/// Non-routable, multicast, link-local, loopback IPv4 & IPv6
pub const RESERVED_RANGES: &[&str] = &[
    // IPv4 Reserved
    "0.0.0.0/8",          // Current network
    "127.0.0.0/8",        // Loopback
    "169.254.0.0/16",     // Link-Local
    "192.0.0.0/24",       // IETF Protocol Assignments
    "192.0.2.0/24",       // TEST-NET-1
    "198.18.0.0/15",      // Network benchmark tests
    "198.51.100.0/24",    // TEST-NET-2
    "203.0.113.0/24",     // TEST-NET-3
    "224.0.0.0/4",        // Multicast
    "240.0.0.0/4",        // Reserved
    "255.255.255.255/32", // Limited Broadcast
    // IPv6 Reserved
    "::1/128",            // IPv6 Loopback
    "::/128",             // Unspecified
    "fe80::/10",          // Link-Local
    "ff00::/8",           // Multicast
    "2001:db8::/32",      // Documentation
    "100::/64",           // Discard
];

/// RFC 1918 & RFC 4193 Private Ranges
pub const PRIVATE_RANGES: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",      // Carrier-Grade NAT
    "fc00::/7",           // IPv6 Unique Local Address (ULA)
];

/// Known automated honeypot & sensor monitoring subnets (AbuseIPDB traps, GreyNoise, Shadowserver, Censys)
pub const HONEYPOT_SENSOR_RANGES: &[&str] = &[
    "162.142.125.0/24",  // Censys scanner
    "167.94.138.0/24",   // Censys scanner
    "167.94.145.0/24",   // Censys scanner
    "167.94.146.0/24",   // Censys scanner
    "167.248.133.0/24",  // Censys scanner
    "71.6.135.0/24",     // Shadowserver Foundation
    "71.6.165.0/24",     // Shadowserver Foundation
    "71.6.167.0/24",     // Shadowserver Foundation
    "66.240.236.0/24",   // Shadowserver Foundation
    "184.105.139.0/24",  // Shadowserver Foundation
    "184.105.247.0/24",  // Shadowserver Foundation
    "198.20.69.0/24",    // Shadowserver Foundation
    "198.20.70.0/24",    // Shadowserver Foundation
    "185.180.143.0/24",  // Honeypot farm
    "185.220.101.0/24",  // Known trap subnets
];

pub fn build_default_blacklist(scan_private: bool) -> BlacklistTrie {
    let mut trie = BlacklistTrie::new();

    for cidr in MILITARY_DOD_RANGES {
        let _ = trie.insert_str(cidr);
    }

    for cidr in RESERVED_RANGES {
        let _ = trie.insert_str(cidr);
    }

    for cidr in HONEYPOT_SENSOR_RANGES {
        let _ = trie.insert_str(cidr);
    }

    if !scan_private {
        for cidr in PRIVATE_RANGES {
            let _ = trie.insert_str(cidr);
        }
    }

    trie
}

pub fn load_exclude_file<P: AsRef<Path>>(trie: &mut BlacklistTrie, path: P) -> io::Result<usize> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut count = 0;

    for line in reader.lines() {
        let line = line?;
        let clean = line.trim();
        if clean.is_empty() || clean.starts_with('#') {
            continue;
        }
        if trie.insert_str(clean).is_ok() {
            count += 1;
        }
    }

    Ok(count)
}
