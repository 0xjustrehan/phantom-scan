/// High-Speed Wire Packet Parser for Incoming IPv4/IPv6 SYN-ACK and RST responses

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone)]
pub struct TcpResponse {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub is_syn_ack: bool,
    pub is_rst: bool,
    pub window_size: u16,
    pub ts_ecr: Option<u32>,
}

pub struct PacketParser;

impl PacketParser {
    /// Parse an incoming raw IPv4 or IPv6 TCP packet
    pub fn parse_ip_packet(packet: &[u8]) -> Option<TcpResponse> {
        if packet.is_empty() {
            return None;
        }

        let version = (packet[0] >> 4) & 0x0f;
        if version == 4 {
            Self::parse_ipv4(packet)
        } else if version == 6 {
            Self::parse_ipv6(packet)
        } else {
            None
        }
    }

    fn parse_ipv4(packet: &[u8]) -> Option<TcpResponse> {
        if packet.len() < 20 {
            return None;
        }

        let ihl = (packet[0] & 0x0f) as usize * 4;
        if packet.len() < ihl + 20 {
            return None;
        }

        if packet[9] != 6 {
            return None; // Not TCP
        }

        let src_ip = IpAddr::V4(Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]));

        Self::parse_tcp(&packet[ihl..], src_ip, dst_ip)
    }

    fn parse_ipv6(packet: &[u8]) -> Option<TcpResponse> {
        if packet.len() < 40 + 20 {
            return None;
        }

        if packet[6] != 6 {
            return None; // Next Header != TCP
        }

        let mut src_octets = [0u8; 16];
        let mut dst_octets = [0u8; 16];
        src_octets.copy_from_slice(&packet[8..24]);
        dst_octets.copy_from_slice(&packet[24..40]);

        let src_ip = IpAddr::V6(Ipv6Addr::from(src_octets));
        let dst_ip = IpAddr::V6(Ipv6Addr::from(dst_octets));

        Self::parse_tcp(&packet[40..], src_ip, dst_ip)
    }

    fn parse_tcp(tcp: &[u8], src_ip: IpAddr, dst_ip: IpAddr) -> Option<TcpResponse> {
        if tcp.len() < 20 {
            return None;
        }

        let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
        let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
        let seq_num = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
        let ack_num = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
        let data_offset = ((tcp[12] >> 4) as usize) * 4;
        let flags = tcp[13];
        let window_size = u16::from_be_bytes([tcp[14], tcp[15]]);

        let is_syn_ack = (flags & 0x12) == 0x12; // SYN + ACK
        let is_rst = (flags & 0x04) != 0;         // RST

        // Parse TCP Options to extract Timestamp TSecr for RTT calculation
        let mut ts_ecr = None;
        if data_offset > 20 && tcp.len() >= data_offset {
            let options = &tcp[20..data_offset];
            let mut i = 0;
            while i < options.len() {
                match options[i] {
                    0 => break, // EOL
                    1 => i += 1, // NOP
                    8 if i + 10 <= options.len() => {
                        // Timestamp option (Kind 8, Length 10)
                        if options[i + 1] == 10 {
                            let ecr = u32::from_be_bytes([
                                options[i + 6],
                                options[i + 7],
                                options[i + 8],
                                options[i + 9],
                            ]);
                            ts_ecr = Some(ecr);
                            break;
                        }
                        i += options[i + 1] as usize;
                    }
                    _ => {
                        if i + 1 < options.len() && options[i + 1] >= 2 {
                            i += options[i + 1] as usize;
                        } else {
                            break;
                        }
                    }
                }
            }
        }

        Some(TcpResponse {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            seq_num,
            ack_num,
            is_syn_ack,
            is_rst,
            window_size,
            ts_ecr,
        })
    }
}
