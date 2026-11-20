/// Stateless Cryptographic SYN-Cookie Generator for IPv4 & IPv6
///
/// Encodes target identity into the 32-bit TCP Sequence Number using BLAKE3.
/// Allows zero-state operation: we never store pending connections in memory,
/// yet we can instantly verify whether an incoming SYN-ACK is a legitimate response.

use std::net::IpAddr;

#[derive(Clone)]
pub struct SynCookie {
    secret: [u8; 32],
}

impl SynCookie {
    pub fn new() -> Self {
        let mut secret = [0u8; 32];
        for chunk in secret.chunks_mut(8) {
            let rand_val = fastrand::u64(..);
            chunk.copy_from_slice(&rand_val.to_le_bytes()[..chunk.len()]);
        }
        Self { secret }
    }

    pub fn with_seed(seed: [u8; 32]) -> Self {
        Self { secret: seed }
    }

    /// Generate 32-bit Initial Sequence Number (ISN) for IPv4 or IPv6
    #[inline]
    pub fn generate_seq(&self, src_ip: IpAddr, dst_ip: IpAddr, src_port: u16, dst_port: u16) -> u32 {
        let mut hasher = blake3::Hasher::new_keyed(&self.secret);
        match src_ip {
            IpAddr::V4(v4) => hasher.update(&v4.octets()),
            IpAddr::V6(v6) => hasher.update(&v6.octets()),
        };
        match dst_ip {
            IpAddr::V4(v4) => hasher.update(&v4.octets()),
            IpAddr::V6(v6) => hasher.update(&v6.octets()),
        };
        hasher.update(&src_port.to_be_bytes());
        hasher.update(&dst_port.to_be_bytes());
        let hash = hasher.finalize();
        let bytes: [u8; 4] = hash.as_bytes()[0..4].try_into().unwrap();
        u32::from_be_bytes(bytes)
    }

    /// Verify an incoming SYN-ACK acknowledgment number
    /// Target acknowledges with ack_seq = seq + 1
    #[inline]
    pub fn verify_ack(&self, src_ip: IpAddr, dst_ip: IpAddr, src_port: u16, dst_port: u16, ack_seq: u32) -> bool {
        let expected_seq = self.generate_seq(src_ip, dst_ip, src_port, dst_port);
        ack_seq.wrapping_sub(1) == expected_seq
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_syn_cookie_roundtrip_v4() {
        let cookie = SynCookie::new();
        let src_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let src_port = 45123;
        let dst_port = 3389;

        let seq = cookie.generate_seq(src_ip, dst_ip, src_port, dst_port);
        let ack = seq.wrapping_add(1);

        assert!(cookie.verify_ack(src_ip, dst_ip, src_port, dst_port, ack));
        assert!(!cookie.verify_ack(src_ip, dst_ip, src_port, dst_port, ack.wrapping_add(1)));
        assert!(!cookie.verify_ack(src_ip, dst_ip, src_port, 80, ack));
    }

    #[test]
    fn test_syn_cookie_roundtrip_v6() {
        let cookie = SynCookie::new();
        let src_ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let dst_ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let src_port = 54321;
        let dst_port = 443;

        let seq = cookie.generate_seq(src_ip, dst_ip, src_port, dst_port);
        let ack = seq.wrapping_add(1);

        assert!(cookie.verify_ack(src_ip, dst_ip, src_port, dst_port, ack));
    }
}
