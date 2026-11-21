use clap::Parser;
use crate::evasion::OsProfile;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "phantom-scan",
    version = "0.3.0",
    about = "Next-Gen Multi-Threaded Wire-Speed Scanner in Rust • AF_PACKET Zero-Copy • Anti-AbuseIPDB • OS Camouflage"
)]
pub struct Cli {
    /// Target CIDR(s), IP range(s), or single IP (e.g. '192.168.1.0/24', '1.1.1.1-1.1.1.50', '2606:4700::/120')
    #[arg(short = 't', long = "target")]
    pub target: Option<String>,

    /// Path to file containing target IPs or CIDRs (one per line, IPv4 and IPv6)
    #[arg(short = 'f', long = "targets-file")]
    pub targets_file: Option<String>,

    /// Target BGP Country (2-letter ISO, e.g. 'US', 'DE', 'RU') or Region ('europe', 'slavic', 'asia', 'north_america', 'south_america', 'africa', 'oceania')
    #[arg(short = 'C', long = "country")]
    pub country: Option<String>,

    /// Comma-separated country codes to exclude from target region (e.g. 'RU,BY')
    #[arg(long = "exclude-country")]
    pub exclude_country: Option<String>,

    /// Download and refresh live BGP Country-to-CIDR routing table from iptoasn.com and exit
    #[arg(long = "update-geo")]
    pub update_geo: bool,

    /// Launch interactive Terminal UI (TUI) wizard mode
    #[arg(short = 'i', long = "tui")]
    pub tui: bool,

    /// Target ports: '3389', '80,443', '1-1024', 'common', 'rdp', 'ssh'
    #[arg(short = 'p', long = "ports", default_value = "3389")]
    pub ports: String,

    /// Transmission rate in packets per second (pps)
    #[arg(short = 'r', long = "rate", default_value = "10000")]
    pub rate: u64,

    /// Scanning engine mode: 'stealth-async' (universal, safe), 'raw-syn' (wire-speed), or 'af-packet' (zero-copy Linux)
    #[arg(short = 'm', long = "mode", default_value = "stealth-async")]
    pub mode: String,

    /// Anti-AbuseIPDB cooldown per /24 subnet in milliseconds (0 = disabled, standard line-rate like masscan)
    #[arg(short = 'c', long = "cooldown-ms", default_value = "0")]
    pub cooldown_ms: u32,

    /// Use compact 4MB cooldown table instead of exact 64MB dense table
    #[arg(long = "compact-cooldown")]
    pub compact_cooldown: bool,

    /// TCP stack fingerprint profile: 'windows', 'linux', 'macos', 'freebsd', 'android', 'random'
    #[arg(long = "profile", default_value = "random")]
    pub profile: OsProfile,

    /// Randomize TCP options ordering and jitter TTL (+/- 2 hops)
    #[arg(long = "randomize-stack")]
    pub randomize_stack: bool,

    /// Grab service banner after confirmed SYN-ACK (RDP version/NLA, SSH, HTTP, SMB, MySQL, Redis)
    #[arg(short = 'b', long = "banner")]
    pub banner: bool,

    /// Output file for discovered open hosts (e.g. 'open_rdp.txt')
    #[arg(short = 'o', long = "output", default_value = "open_targets.txt")]
    pub output_file: String,

    /// Output results as JSON Lines format with timestamps and service banners
    #[arg(long = "json")]
    pub json: bool,

    /// File containing CIDR prefixes to exclude from scanning
    #[arg(long = "exclude-file")]
    pub exclude_file: Option<String>,

    /// Comma-separated CIDRs to exclude
    #[arg(short = 'e', long = "exclude")]
    pub exclude: Option<String>,

    /// Allow scanning RFC 1918 private subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
    #[arg(long = "scan-private")]
    pub scan_private: bool,

    /// Number of dedicated TX sender threads for raw-syn mode (default: CPU cores)
    #[arg(long = "tx-threads", default_value_t = num_cpus::get())]
    pub tx_threads: usize,

    /// Max concurrent asynchronous connections (for stealth-async mode)
    #[arg(long = "concurrency", default_value = "4096")]
    pub concurrency: usize,

    /// Socket timeout in milliseconds (for stealth-async mode)
    #[arg(long = "timeout-ms", default_value = "1500")]
    pub timeout_ms: u64,

    /// Local source IPv4 address to bind (for raw-syn / af-packet mode)
    #[arg(short = 'S', long = "source-ip")]
    pub source_ip: Option<String>,

    /// Local source IPv6 address to bind (for raw-syn mode)
    #[arg(long = "source-ip-v6")]
    pub source_ip_v6: Option<String>,

    /// Number of random host samples per large IPv6 prefix (/64, /48)
    #[arg(long = "v6-samples", default_value = "256")]
    pub v6_samples: usize,

    /// Source port (or base port) for raw-syn mode
    #[arg(long = "source-port", default_value = "54321")]
    pub source_port: u16,

    /// Ephemeral source port range (e.g. '40000-65000') for per-packet port randomization
    #[arg(long = "source-port-range")]
    pub source_port_range: Option<String>,

    /// Retransmission passes for unanswered probes (e.g. 1)
    #[arg(long = "retries", default_value = "0")]
    pub retries: usize,

    /// Network interface to bind for AF_PACKET / raw socket (e.g. 'eth0', 'ens33', 'wlan0')
    #[arg(short = 'I', long = "interface")]
    pub interface: Option<String>,

    /// Gateway MAC address override for AF_PACKET (e.g. '00:11:22:33:44:55')
    #[arg(long = "gateway-mac")]
    pub gateway_mac: Option<String>,

    /// Source hardware MAC address override for AF_PACKET (e.g. 'aa:bb:cc:dd:ee:ff')
    #[arg(long = "source-mac")]
    pub source_mac: Option<String>,

    /// AF_PACKET fanout load-balancing mode: 'lb', 'hash', 'cpu', 'rollover'
    #[arg(long = "fanout-mode", default_value = "lb")]
    pub fanout_mode: String,

    /// Enable threat intelligence & honeypot feed exclusion (Spamhaus, FireHOL, Blocklist.de)
    #[arg(long = "threat-feeds")]
    pub threat_feeds: bool,

    /// Download and update threat intelligence feeds (Spamhaus DROP, AbuseIPDB, GreyNoise) and exit
    #[arg(long = "update-feeds")]
    pub update_feeds: bool,

    /// Disable automatic background threat-feed refresh on startup
    #[arg(long = "no-auto-feeds")]
    pub no_auto_feeds: bool,

    /// Launch the desktop graphical user interface (GUI)
    #[arg(long = "gui")]
    pub gui: bool,

    /// Force command-line interface (CLI) mode
    #[arg(long = "cli")]
    pub cli: bool,
}
