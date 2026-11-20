/// Protocol-Specific Intelligence Probes
///
/// Deep Service Fingerprinting for:
/// - RDP (3389): TPKT/X.224 negotiation (NLA, CredSSP, SSL, RDSTLS)
/// - SMB (445): SMB2 Negotiate Protocol (Windows Build, Samba)
/// - SSH (22): Protocol identification banner
/// - HTTP/HTTPS (80, 443, 8080, 8443): Status, Server header, and <title> extraction
/// - MySQL (3306): Handshake packet version parsing
/// - PostgreSQL (5432): SSLRequest / Startup probe
/// - Redis (6379): PING / INFO response
/// - MSSQL (1433): TDS Pre-Login PDU
/// - VNC (5900): RFB protocol version
/// - FTP / SMTP / POP3 / IMAP: Greeting banner

use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

pub struct BannerGrabber;

impl BannerGrabber {
    pub async fn grab_banner(target: SocketAddr, timeout_dur: Duration) -> Option<String> {
        let stream = timeout(timeout_dur, TcpStream::connect(target)).await.ok()?.ok()?;
        let (mut reader, mut writer) = stream.into_split();

        match target.port() {
            // ── Port 3389: RDP ────────────────────────────────────────────────
            3389 => {
                let rdp_cr = [
                    0x03, 0x00, 0x00, 0x13, // TPKT header (len = 19)
                    0x0e,                   // X.224 Length
                    0xe0,                   // Connection Request
                    0x00, 0x00, 0x00, 0x00, 0x00,
                    // RDP Negotiation Request (RDP_NEG_REQ)
                    0x01, 0x00, 0x08, 0x00,
                    0x03, 0x00, 0x00, 0x00, // PROTOCOL_SSL (0x01) | PROTOCOL_HYBRID / NLA (0x02)
                ];

                let _ = writer.write_all(&rdp_cr).await;
                let mut buf = [0u8; 256];
                if let Ok(Ok(n)) = timeout(timeout_dur, reader.read(&mut buf)).await {
                    if n >= 11 && buf[0] == 0x03 {
                        if n >= 19 && buf[11] == 0x02 {
                            let proto = u32::from_le_bytes([buf[15], buf[16], buf[17], buf[18]]);
                            let desc = match proto {
                                0x00 => "RDP [Standard RDP Encryption]",
                                0x01 => "RDP [SSL/TLS]",
                                0x02 => "RDP [NLA / CredSSP]",
                                0x03 => "RDP [SSL + NLA]",
                                0x04 => "RDP [RDSTLS]",
                                _ => "RDP",
                            };
                            return Some(desc.to_string());
                        }
                        return Some("RDP [Standard]".to_string());
                    }
                }
                Some("RDP".to_string())
            }

            // ── Port 445: SMB ─────────────────────────────────────────────────
            445 | 139 => {
                // SMB2 Negotiate Protocol Request
                let smb2_neg = [
                    0x00, 0x00, 0x00, 0x68, // NetBIOS header
                    0xfe, 0x53, 0x4d, 0x42, // SMB2 Header: "\xFESMB"
                    0x40, 0x00, 0x00, 0x00, // Header length (64)
                    0x00, 0x00, 0x00, 0x00, // Credit charge
                    0x00, 0x00, 0x00, 0x00, // Status
                    0x00, 0x00,             // Command: Negotiate (0)
                    0x00, 0x00,             // Credits
                    0x00, 0x00, 0x00, 0x00, // Flags
                    0x00, 0x00, 0x00, 0x00, // Next command
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Message ID
                    0x00, 0x00, 0x00, 0x00, // Process ID
                    0x00, 0x00, 0x00, 0x00, // Tree ID
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Session ID
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
                    // Negotiate Request: Dialect count (2), Security mode, Capabilities
                    0x24, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00,
                    0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x02, 0x02, // Dialect 0x0202 (SMB 2.0.2)
                    0x10, 0x02, // Dialect 0x0210 (SMB 2.1)
                ];

                let _ = writer.write_all(&smb2_neg).await;
                let mut buf = [0u8; 512];
                if let Ok(Ok(n)) = timeout(timeout_dur, reader.read(&mut buf)).await {
                    if n >= 68 && &buf[4..8] == b"\xfeSMB" {
                        let dialect = u16::from_le_bytes([buf[68], buf[69]]);
                        let dialect_str = match dialect {
                            0x0202 => "SMB 2.0.2",
                            0x0210 => "SMB 2.1",
                            0x0300 => "SMB 3.0",
                            0x0302 => "SMB 3.0.2",
                            0x0311 => "SMB 3.1.1 (Windows 10/11/Server)",
                            _ => "SMB2",
                        };
                        return Some(format!("SMB [{}]", dialect_str));
                    }
                }
                Some("SMB".to_string())
            }

            // ── Port 22: SSH ──────────────────────────────────────────────────
            22 => {
                let mut buf = [0u8; 256];
                if let Ok(Ok(n)) = timeout(timeout_dur, reader.read(&mut buf)).await {
                    let banner = String::from_utf8_lossy(&buf[..n]).trim().to_string();
                    if !banner.is_empty() {
                        return Some(banner);
                    }
                }
                Some("SSH".to_string())
            }

            // ── Port 80, 8080, 8000, 8888, 443, 8443: HTTP ───────────────────
            80 | 8080 | 8000 | 8888 | 443 | 8443 => {
                let http_req = format!(
                    "GET / HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\nConnection: close\r\n\r\n",
                    target.ip()
                );
                let _ = writer.write_all(http_req.as_bytes()).await;
                let mut buf = [0u8; 2048];
                if let Ok(Ok(n)) = timeout(timeout_dur, reader.read(&mut buf)).await {
                    let resp = String::from_utf8_lossy(&buf[..n]);
                    let mut server = None;
                    let mut title = None;

                    for line in resp.lines() {
                        let lower = line.to_lowercase();
                        if lower.starts_with("server:") {
                            server = Some(line.splitn(2, ':').nth(1).unwrap_or("").trim().to_string());
                        }
                    }

                    if let Some(pos) = resp.to_lowercase().find("<title>") {
                        if let Some(end) = resp.to_lowercase()[pos..].find("</title>") {
                            let t = &resp[pos + 7..pos + end];
                            title = Some(t.trim().to_string());
                        }
                    }

                    if target.port() == 443 || target.port() == 8443 {
                        if resp.contains("400") || resp.to_lowercase().contains("https") {
                            return Some("HTTPS [TLS Supported]".to_string());
                        }
                    }

                    let first_line = resp.lines().next().unwrap_or("HTTP").trim();
                    let mut parts: Vec<String> = Vec::new();
                    parts.push(first_line.to_string());
                    if let Some(s) = server {
                        parts.push(s);
                    }
                    if let Some(t) = title {
                        parts.push(t);
                    }
                    return Some(parts.join(" | "));
                }
                if target.port() == 443 || target.port() == 8443 {
                    Some("HTTPS".to_string())
                } else {
                    Some("HTTP".to_string())
                }
            }

            // ── Port 3306: MySQL ──────────────────────────────────────────────
            3306 => {
                let mut buf = [0u8; 256];
                if let Ok(Ok(n)) = timeout(timeout_dur, reader.read(&mut buf)).await {
                    if n >= 5 && buf[4] == 0x0a {
                        // Protocol version 10
                        if let Some(null_pos) = buf[5..n].iter().position(|&b| b == 0) {
                            let version = String::from_utf8_lossy(&buf[5..5 + null_pos]);
                            return Some(format!("MySQL [{}]", version.trim()));
                        }
                    }
                }
                Some("MySQL".to_string())
            }

            // ── Port 5432: PostgreSQL ─────────────────────────────────────────
            5432 => {
                // SSLRequest: length 8, code 80877103
                let ssl_req = [0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f];
                let _ = writer.write_all(&ssl_req).await;
                let mut buf = [0u8; 8];
                if let Ok(Ok(n)) = timeout(timeout_dur, reader.read(&mut buf)).await {
                    if n > 0 {
                        if buf[0] == b'S' {
                            return Some("PostgreSQL [SSL Supported]".to_string());
                        } else if buf[0] == b'N' {
                            return Some("PostgreSQL [SSL Not Supported]".to_string());
                        }
                    }
                }
                Some("PostgreSQL".to_string())
            }

            // ── Port 6379: Redis ──────────────────────────────────────────────
            6379 => {
                let _ = writer.write_all(b"INFO\r\n").await;
                let mut buf = [0u8; 512];
                if let Ok(Ok(n)) = timeout(timeout_dur, reader.read(&mut buf)).await {
                    let resp = String::from_utf8_lossy(&buf[..n]);
                    for line in resp.lines() {
                        if line.starts_with("redis_version:") {
                            return Some(format!("Redis [{}]", line.trim()));
                        }
                    }
                    if resp.starts_with("-NOAUTH") {
                        return Some("Redis [Auth Required]".to_string());
                    }
                    if resp.starts_with("+PONG") {
                        return Some("Redis".to_string());
                    }
                }
                Some("Redis".to_string())
            }

            // ── Port 1433: MSSQL ──────────────────────────────────────────────
            1433 => {
                // TDS Pre-Login Packet
                let tds_prelogin = [
                    0x12, 0x01, 0x00, 0x2f, 0x00, 0x00, 0x01, 0x00,
                    0x00, 0x00, 0x1a, 0x00, 0x06, 0x01, 0x00, 0x20,
                    0x00, 0x01, 0x02, 0x00, 0x21, 0x00, 0x01, 0x03,
                    0x00, 0x22, 0x00, 0x04, 0x04, 0x00, 0x26, 0x00,
                    0x01, 0xff, 0x0c, 0x00, 0x08, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ];
                let _ = writer.write_all(&tds_prelogin).await;
                let mut buf = [0u8; 128];
                if let Ok(Ok(n)) = timeout(timeout_dur, reader.read(&mut buf)).await {
                    if n >= 8 && buf[0] == 0x04 {
                        return Some("MSSQL [TDS Response]".to_string());
                    }
                }
                Some("MSSQL".to_string())
            }

            // ── Port 5900-5905: VNC ───────────────────────────────────────────
            5900..=5905 => {
                let mut buf = [0u8; 64];
                if let Ok(Ok(n)) = timeout(timeout_dur, reader.read(&mut buf)).await {
                    let banner = String::from_utf8_lossy(&buf[..n]).trim().to_string();
                    if banner.starts_with("RFB") {
                        return Some(format!("VNC [{}]", banner));
                    }
                }
                Some("VNC".to_string())
            }

            // ── Generic Banner ────────────────────────────────────────────────
            _ => {
                let _ = writer.write_all(b"\r\n\r\n").await;
                let mut buf = [0u8; 256];
                if let Ok(Ok(n)) = timeout(Duration::from_millis(700), reader.read(&mut buf)).await {
                    let s = String::from_utf8_lossy(&buf[..n]).trim().to_string();
                    if !s.is_empty() {
                        return Some(s);
                    }
                }
                None
            }
        }
    }
}
