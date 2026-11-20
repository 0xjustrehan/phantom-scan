/// Layer 2 Interface, MAC Address, and Routing Auto-Discovery for Linux
///
/// Discovers:
/// - Target network interface name & ifindex
/// - Local interface hardware MAC address (src_mac)
/// - Default Gateway IP and hardware MAC address from /proc/net/route & /proc/net/arp

use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub struct L2InterfaceInfo {
    pub ifname: String,
    pub ifindex: i32,
    pub src_mac: [u8; 6],
    pub gateway_mac: [u8; 6],
    pub src_ip_v4: Option<Ipv4Addr>,
}

pub struct L2Resolver;

impl L2Resolver {
    /// Automatically discover the local outbound IP address
    pub fn get_local_ip() -> Option<std::net::IpAddr> {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
        socket.connect("8.8.8.8:80").ok()?;
        Some(socket.local_addr().ok()?.ip())
    }

    /// Parse MAC address from string like "00:11:22:33:44:55" or "00-11-22-33-44-55"
    pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
        let clean = s.trim().replace('-', ":");
        let parts: Vec<&str> = clean.split(':').collect();
        if parts.len() != 6 {
            return None;
        }

        let mut mac = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            mac[i] = u8::from_str_radix(part, 16).ok()?;
        }
        Some(mac)
    }

    /// Format MAC address to string "aa:bb:cc:dd:ee:ff"
    pub fn format_mac(mac: &[u8; 6]) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        )
    }

    /// Attempt to query local IPv4 address for interface
    pub fn get_interface_ipv4(ifname: &str) -> Option<Ipv4Addr> {
        #[cfg(target_os = "linux")]
        {
            unsafe {
                let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();
                if libc::getifaddrs(&mut ifaddrs) != 0 || ifaddrs.is_null() {
                    return None;
                }
                let mut curr = ifaddrs;
                let mut found_ip = None;
                while !curr.is_null() {
                    let entry = &*curr;
                    if !entry.ifa_name.is_null() && !entry.ifa_addr.is_null() {
                        let name = std::ffi::CStr::from_ptr(entry.ifa_name).to_string_lossy();
                        if name == ifname && (*entry.ifa_addr).sa_family == libc::AF_INET as libc::sa_family_t {
                            let sin = &*(entry.ifa_addr as *const libc::sockaddr_in);
                            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
                            found_ip = Some(ip);
                            break;
                        }
                    }
                    curr = entry.ifa_next;
                }
                libc::freeifaddrs(ifaddrs);
                found_ip
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = ifname;
            None
        }
    }

    /// Read interface MAC from /sys/class/net/<ifname>/address
    pub fn read_interface_mac(ifname: &str) -> io::Result<[u8; 6]> {
        let path = format!("/sys/class/net/{}/address", ifname);
        let content = std::fs::read_to_string(&path)?;
        Self::parse_mac(&content).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, format!("Invalid MAC in {}", path))
        })
    }

    /// Read default route from /proc/net/route to find interface name and gateway IPv4
    pub fn read_default_gateway_route() -> io::Result<(String, Ipv4Addr)> {
        let file = File::open("/proc/net/route")?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line?;
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                let ifname = parts[0];
                let dest = parts[1];
                let gateway_hex = parts[2];

                // Default route has destination 00000000
                if dest == "00000000" && gateway_hex != "00000000" {
                    if let Ok(gw_u32) = u32::from_str_radix(gateway_hex, 16) {
                        let gw_ip = Ipv4Addr::from(u32::from_be(gw_u32));
                        return Ok((ifname.to_string(), gw_ip));
                    }
                }
            }
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No default route found in /proc/net/route",
        ))
    }

    /// Read gateway MAC from /proc/net/arp
    pub fn read_arp_gateway_mac(gateway_ip: Ipv4Addr) -> io::Result<[u8; 6]> {
        let file = File::open("/proc/net/arp")?;
        let reader = BufReader::new(file);
        let gw_str = gateway_ip.to_string();

        for line in reader.lines() {
            let line = line?;
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 && parts[0] == gw_str {
                let mac_str = parts[3];
                if let Some(mac) = Self::parse_mac(mac_str) {
                    if mac != [0, 0, 0, 0, 0, 0] {
                        return Ok(mac);
                    }
                }
            }
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("No ARP entry found for gateway {}", gateway_ip),
        ))
    }

    /// Complete Layer 2 Resolution with CLI overrides
    pub fn resolve_l2(
        ifname_override: Option<&str>,
        src_mac_override: Option<&str>,
        gw_mac_override: Option<&str>,
    ) -> io::Result<L2InterfaceInfo> {
        #[cfg(target_os = "linux")]
        {
            let (ifname, gw_ip) = match ifname_override {
                Some(name) => {
                    let gw = Self::read_default_gateway_route()
                        .map(|(_, g)| g)
                        .unwrap_or(Ipv4Addr::new(192, 168, 1, 1));
                    (name.to_string(), gw)
                }
                None => Self::read_default_gateway_route().unwrap_or_else(|_| {
                    ("eth0".to_string(), Ipv4Addr::new(192, 168, 1, 1))
                }),
            };

            // Get ifindex
            let c_ifname = std::ffi::CString::new(ifname.clone())?;
            let ifindex = unsafe { libc::if_nametoindex(c_ifname.as_ptr()) as i32 };
            if ifindex <= 0 {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("Interface '{}' not found", ifname),
                ));
            }

            // Source MAC
            let src_mac = if let Some(m) = src_mac_override.and_then(Self::parse_mac) {
                m
            } else {
                Self::read_interface_mac(&ifname).unwrap_or([0x00, 0x15, 0x5d, 0x01, 0x02, 0x03])
            };

            // Gateway MAC
            let gateway_mac = if let Some(m) = gw_mac_override.and_then(Self::parse_mac) {
                m
            } else {
                Self::read_arp_gateway_mac(gw_ip).unwrap_or([0xff, 0xff, 0xff, 0xff, 0xff, 0xff])
            };

            Ok(L2InterfaceInfo {
                ifname,
                ifindex,
                src_mac,
                gateway_mac,
                src_ip_v4: None,
            })
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = (ifname_override, src_mac_override, gw_mac_override);
            Ok(L2InterfaceInfo {
                ifname: "eth0".to_string(),
                ifindex: 1,
                src_mac: [0x00, 0x15, 0x5d, 0x01, 0x02, 0x03],
                gateway_mac: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                src_ip_v4: None,
            })
        }
    }
}
