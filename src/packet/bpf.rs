/// Classic Berkeley Packet Filter (cBPF) Bytecode Generator
///
/// Compiles in-kernel packet filtering rules for SO_ATTACH_FILTER on Linux.
/// Filters incoming traffic in kernel space before copying to userspace ring buffers:
/// - Supports both IPv4 (0x0800) and IPv6 (0x86dd)
/// - Checks IP Protocol == TCP (6)
/// - Matches Destination Port in range [min_port..max_port]
/// - Checks TCP Flags == SYN+ACK (0x12)

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SockFprog {
    pub len: u16,
    pub filter: *const SockFilter,
}

pub struct BpfCompiler;

impl BpfCompiler {
    /// Generate Dual-Stack (IPv4 & IPv6) BPF bytecode for Layer 2 (AF_PACKET Ethernet frames)
    /// Matches EtherType 0x0800 (IPv4) OR 0x86dd (IPv6), IP Proto TCP,
    /// TCP dest port in range [min_port..max_port], and flags = SYN+ACK (0x12)
    pub fn compile_l2_filter(min_port: u16, max_port: u16) -> Vec<SockFilter> {
        let is_single_port = min_port == max_port;

        if is_single_port {
            vec![
                // 0: Load EtherType: ldh [12]
                SockFilter { code: 0x28, jt: 0, jf: 0, k: 12 },
                // 1: Check if IPv4 (0x0800): if true -> 2, if false -> 9 (IPv6 path, offset 7)
                SockFilter { code: 0x15, jt: 0, jf: 7, k: 0x0800 },

                // --- IPv4 Path ---
                // 2: Load IP protocol: ldb [23] (14 + 9)
                SockFilter { code: 0x30, jt: 0, jf: 0, k: 23 },
                // 3: Check if TCP (6): if true -> 4, if false -> 18 (DROP, offset 14)
                SockFilter { code: 0x15, jt: 0, jf: 14, k: 6 },
                // 4: Load IP header length into X: ldxb 4*([14]&0xf)
                SockFilter { code: 0xb1, jt: 0, jf: 0, k: 14 },
                // 5: Load TCP destination port: ldh [X + 16] (14 + 2)
                SockFilter { code: 0x48, jt: 0, jf: 0, k: 16 },
                // 6: Check if dest port == min_port: if true -> 7, if false -> 18 (DROP, offset 11)
                SockFilter { code: 0x15, jt: 0, jf: 11, k: min_port as u32 },
                // 7: Load TCP flags: ldb [X + 27] (14 + 13)
                SockFilter { code: 0x50, jt: 0, jf: 0, k: 27 },
                // 8: Jump to common flags validation at index 15 (offset 6)
                SockFilter { code: 0x05, jt: 0, jf: 0, k: 6 },

                // --- IPv6 Path ---
                // 9: Check if IPv6 (0x86dd): if true -> 10, if false -> 18 (DROP, offset 8)
                SockFilter { code: 0x15, jt: 0, jf: 8, k: 0x86dd },
                // 10: Load IPv6 Next Header: ldb [20] (14 + 6)
                SockFilter { code: 0x30, jt: 0, jf: 0, k: 20 },
                // 11: Check if TCP (6): if true -> 12, if false -> 18 (DROP, offset 6)
                SockFilter { code: 0x15, jt: 0, jf: 6, k: 6 },
                // 12: Load TCP dest port for IPv6: ldh [56] (14 + 40 + 2)
                SockFilter { code: 0x28, jt: 0, jf: 0, k: 56 },
                // 13: Check if dest port == min_port: if true -> 14, if false -> 18 (DROP, offset 4)
                SockFilter { code: 0x15, jt: 0, jf: 4, k: min_port as u32 },
                // 14: Load TCP flags for IPv6: ldb [67] (14 + 40 + 13)
                SockFilter { code: 0x30, jt: 0, jf: 0, k: 67 },

                // --- Common Flags Validation ---
                // 15: Mask with 0x12 (SYN+ACK)
                SockFilter { code: 0x54, jt: 0, jf: 0, k: 0x12 },
                // 16: Check if flags & 0x12 == 0x12: if true -> 17 (KEEP, jt=0), if false -> 18 (DROP, jf=1)
                SockFilter { code: 0x15, jt: 0, jf: 1, k: 0x12 },
                // 17: Keep packet: ret #65535
                SockFilter { code: 0x06, jt: 0, jf: 0, k: 65535 },
                // 18: Drop packet: ret #0
                SockFilter { code: 0x06, jt: 0, jf: 0, k: 0 },
            ]
        } else {
            // Port range matching [min_port..max_port]
            vec![
                // 0: Load EtherType: ldh [12]
                SockFilter { code: 0x28, jt: 0, jf: 0, k: 12 },
                // 1: Check IPv4 (0x0800): if true -> 2, if false -> 10 (IPv6 path, offset 8)
                SockFilter { code: 0x15, jt: 0, jf: 8, k: 0x0800 },

                // --- IPv4 Path ---
                // 2: Load IP protocol: ldb [23] (14 + 9)
                SockFilter { code: 0x30, jt: 0, jf: 0, k: 23 },
                // 3: Check TCP (6): if true -> 4, if false -> 20 (DROP, offset 16)
                SockFilter { code: 0x15, jt: 0, jf: 16, k: 6 },
                // 4: Load IP header length: ldxb 4*([14]&0xf)
                SockFilter { code: 0xb1, jt: 0, jf: 0, k: 14 },
                // 5: Load TCP destination port: ldh [X + 16] (14 + 2)
                SockFilter { code: 0x48, jt: 0, jf: 0, k: 16 },
                // 6: Check port >= min_port: if true -> 7, if false -> 20 (DROP, offset 13)
                SockFilter { code: 0x35, jt: 0, jf: 13, k: min_port as u32 },
                // 7: Check port <= max_port: if port > max_port -> 20 (DROP, offset 12), if <= -> 8
                SockFilter { code: 0x25, jt: 12, jf: 0, k: max_port as u32 },
                // 8: Load TCP flags: ldb [X + 27]
                SockFilter { code: 0x50, jt: 0, jf: 0, k: 27 },
                // 9: Jump to flags mask at index 17 (offset 7)
                SockFilter { code: 0x05, jt: 0, jf: 0, k: 7 },

                // --- IPv6 Path ---
                // 10: Check IPv6 (0x86dd): if true -> 11, if false -> 20 (DROP, offset 9)
                SockFilter { code: 0x15, jt: 0, jf: 9, k: 0x86dd },
                // 11: Load IPv6 Next Header: ldb [20]
                SockFilter { code: 0x30, jt: 0, jf: 0, k: 20 },
                // 12: Check TCP (6): if true -> 13, if false -> 20 (DROP, offset 7)
                SockFilter { code: 0x15, jt: 0, jf: 7, k: 6 },
                // 13: Load TCP dest port for IPv6: ldh [56] (14 + 40 + 2)
                SockFilter { code: 0x28, jt: 0, jf: 0, k: 56 },
                // 14: Check port >= min_port: if true -> 15, if false -> 20 (DROP, offset 5)
                SockFilter { code: 0x35, jt: 0, jf: 5, k: min_port as u32 },
                // 15: Check port <= max_port: if port > max_port -> 20 (DROP, offset 4), if <= -> 16
                SockFilter { code: 0x25, jt: 4, jf: 0, k: max_port as u32 },
                // 16: Load TCP flags for IPv6: ldb [67]
                SockFilter { code: 0x30, jt: 0, jf: 0, k: 67 },

                // --- Common Flags Validation ---
                // 17: Mask with 0x12 (SYN+ACK)
                SockFilter { code: 0x54, jt: 0, jf: 0, k: 0x12 },
                // 18: Check if flags & 0x12 == 0x12: if true -> 19 (KEEP, jt=0), if false -> 20 (DROP, jf=1)
                SockFilter { code: 0x15, jt: 0, jf: 1, k: 0x12 },
                // 19: Keep packet: ret #65535
                SockFilter { code: 0x06, jt: 0, jf: 0, k: 65535 },
                // 20: Drop packet: ret #0
                SockFilter { code: 0x06, jt: 0, jf: 0, k: 0 },
            ]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bpf_compiler_sizes() {
        let single = BpfCompiler::compile_l2_filter(54321, 54321);
        assert_eq!(single.len(), 19);
        assert_eq!(single[16].code, 0x15);
        assert_eq!(single[16].jt, 0); // Jumps to 17 (KEEP)
        assert_eq!(single[16].jf, 1); // Jumps to 18 (DROP)
        assert_eq!(single[17].k, 65535); // KEEP
        assert_eq!(single[18].k, 0); // DROP

        let range = BpfCompiler::compile_l2_filter(40000, 50000);
        assert_eq!(range.len(), 21);
        assert_eq!(range[18].code, 0x15);
        assert_eq!(range[18].jt, 0); // Jumps to 19 (KEEP)
        assert_eq!(range[18].jf, 1); // Jumps to 20 (DROP)
        assert_eq!(range[19].k, 65535); // KEEP
        assert_eq!(range[20].k, 0); // DROP
    }
}
