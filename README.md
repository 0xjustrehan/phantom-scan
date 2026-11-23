# 👻 PHANTOM-SCAN v0.3.3

> **Next-Generation Multi-Threaded Wire-Speed Network Scanner in Rust**  
> *Engineered to surpass masscan in speed, with built-in Anti-AbuseIPDB, OS Fingerprint Camouflage, Linux AF_PACKET Zero-Copy (PACKET_MMAP), and Zero-Drop Dual-Stack BPF.*

---

## ⚡ Feature Matrix vs Masscan

| Capability | Masscan | Phantom-Scan v0.3.0 |
| :--- | :--- | :--- |
| **TX Engine** | Single-threaded packet generator | **Multi-threaded independent raw sockets & Zero-Copy AF_PACKET (PACKET_MMAP rings)** |
| **Layer 2 Auto-Discovery** | Hardcoded/manual configuration | **Automatic interface `ifindex`, local MAC, and default gateway ARP resolution** |
| **Subnet Anti-Abuse** | Hits same `/24` repeatedly in bursts | **Exact 16,777,216 `/24` Cooldown Ring (0% collisions, 64MB RAM) + `/64` IPv6 tracking** |
| **Packet Camouflage** | Static `Window=1024`, no TCP options | **Windows 11, Linux, macOS, FreeBSD, Android Profiles + Advancing Synthetic Uptime TSval** |
| **IP ID Dynamics** | Static or sequential | **Stateful RFC 6864: Monotonic Windows IP ID, Linux ID = 0, pseudo-random others** |
| **Drop Prevention** | Standard raw socket (drops under load) | **16MB Kernel RX Ring + Dual-Stack cBPF In-Kernel Filter** |
| **Post-Scan Drain & Retries**| Static hardcoded delay (3-10 sec) | **Adaptive RTT Estimator (Jacobson/Karels RFC 6298) + Automatic Retransmission Pass** |
| **Service Intelligence**| Port open only | **Stateless SYN-Cookie + Bounded Async Banner Pool (RDP NLA/TLS/CredSSP, SMB2, SSH, HTTP, MySQL, Redis)**|
| **Dual-Stack** | IPv4 only | **Full IPv4 & IPv6 Dual-Stack (Blackrock + BLAKE3 Cookies + IPv6 Prefix Sampling)** |
| **Threat Exclusion** | Manual `--excludefile` | **Embedded Radix Trie + Automated 24h Threat Feed Cache (Spamhaus, FireHOL, Blocklist.de, GreyNoise)** |
| **Portability** | Requires C dependencies | **Pure Rust: Cross-compiles to Windows MSVC & Linux Musl** |

---

## 🛡️ Anti-AbuseIPDB Architecture

### 1. Exact 16,777,216 Subnet Cooldown (`--cooldown-ms`)
Automated abuse engines (Fail2ban, CrowdSec, Honeypot APIs) fire when $\ge 3$ probes hit the same `/24` or `/16` within seconds.
`phantom-scan` maintains a direct dense array covering every `/24` subnet on the planet ($2^{24} = 16,777,216$ cells):
* **Guaranteed 0% collisions:** Every `/24` prefix has its own atomic timestamp cell.
* Direct memory indexing: `(ip >> 8)` ($<1$ nanosecond memory lookup).
* Probes to the same organization are safely interleaved across other continents.
* Use `--compact-cooldown` for memory-constrained devices (4MB).

### 2. Authentic OS Fingerprint Synthesis (`--profile`)
Honeypots (Cowrie, Dionaea) and IDS (Suricata, Zeek) immediately flag masscan's `Window=1024` with no options. `phantom-scan` crafts authentic client packets:
* **`--profile windows`:** TTL 128, Window 64240, MSS 1460, NOP, WScale(8), NOP, NOP, SACK Permitted.
* **`--profile linux`:** TTL 64, IP ID 0 (RFC 6864), Window 65495, MSS 1460, SACK Permitted, Timestamps, NOP, WScale(7).
* **`--profile macos`:** TTL 64, Window 65535, MSS 1440, NOP, WScale(6), NOP, NOP, Timestamps, SACK, EOL.
* **`--profile freebsd` / `--profile android`:** Genuine BSD and mobile TCP signatures.
* **`--randomize-stack`:** Adds network hop jitter to TTL and permutes compatible TCP option sequences.
* **`--source-port-range 40000-65000`:** Ephemeral source port randomization with BLAKE3 cookie cryptographic binding.

### 3. Automated Threat Feeds & Honeypot Drop (`--update-feeds`)
Automatically checks cache age on startup ($>24\text{h}$) and refreshes in the background, or run manually:
```bash
phantom-scan --update-feeds
```
Downloads and indexes 30,000+ verified honeypot and threat prefixes directly into the dual-stack prefix trie:
* Spamhaus DROP & EDROP lists
* FireHOL Level 1 & AbuseIPDB sensor networks
* GreenSnow & GreyNoise observatory ranges
* Blocklist.de Attacker Netsets
* US Military & DoD ranges (`6.0.0.0/8`, `11.0.0.0/8`, `21.0.0.0/8`, etc.)

---

## ⚡ Zero-Copy AF_PACKET Kernel-Bypass Engine

On Linux, `phantom-scan` provides true line-rate zero-copy kernel bypass via `PACKET_MMAP`:
1. **L2 Auto-Discovery (`-I`, `--gateway-mac`, `--source-mac`):** Resolves interface name, `ifindex`, hardware MAC, and default gateway ARP MAC.
2. **Multi-Threaded `PACKET_TX_RING`:** Spawns independent TX sender threads, each mapping a private 4MB ring buffer bound to `ifindex`.
3. **Batch DMA Injection:** Formats wire Ethernet frames directly into mapped memory; kicks transmissions with a single `send()` syscall every 64 frames.
4. **Zero-Drop 16MB `PACKET_RX_RING`:** In-kernel dual-stack cBPF filter drops 99.99% of wire traffic in kernel interrupt space before copying to userspace.
5. **Retransmission Pass (`--retries 1`):** Tracks unanswered targets and triggers a paced re-probe pass at the observed Jacobson/Karels RTO.

---

## 🚀 CLI Examples

```bash
# 1. Update threat feeds (Spamhaus, GreyNoise, AbuseIPDB, Blocklist.de)
phantom-scan --update-feeds

# 2. Linux AF_PACKET Zero-Copy line-rate scan with PACKET_FANOUT multi-queue TX & banner grabbing
phantom-scan -t 192.168.1.0/24 -p 3389 -b -m af-packet -S 192.168.1.100 --tx-threads 16 --fanout-mode lb -r 250000

# 3. Multi-threaded wire-speed scan with Windows stack morphing & source port range
phantom-scan -f targets.txt -p 3389,445 -r 50000 --profile windows --source-port-range 40000-60000 -m raw-syn -S 192.168.1.100

# 4. Large-scale scan with exact /24 anti-abuse cooldown (3,000ms) and retry pass
phantom-scan -f targets.txt -p 3389 -r 100000 --cooldown-ms 3000 --retries 1 -o open_hosts.txt

# 5. IPv6 dual-stack scan with random host sampling per /64 prefix
phantom-scan -t 2606:4700::/64 -p 80,443 --v6-samples 512 -m stealth-async -o v6_web.txt

# 6. Universal high-throughput async engine (works on any cloud VPS without root)
phantom-scan -f subnets.txt -p rdp,ssh,web -b -r 25000 -o live_services.txt

# 7. Output in JSON Lines with timestamps & service banners
phantom-scan -f targets.txt -p 3389 -b --json -o results.jsonl

# 8. Quick RDP NLA Scan (filters and outputs confirmed CredSSP/NLA hosts as IP:PORT)
phantom-scan -f targets.txt --quick-nla -o nla_targets.txt

# 9. Quick SSH Scan (outputs clean IP:PORT for piping into downstream tools)
phantom-scan -f targets.txt --quick-ssh -o ssh_targets.txt
```
