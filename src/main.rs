#![allow(dead_code, unused_imports)]
#![cfg_attr(windows, windows_subsystem = "windows")]

mod banner;
mod blacklist;
mod cli;
mod controller;
mod crypto;
mod evasion;
mod packet;
mod scanner;
mod targets;
pub mod geo;
pub mod tui;
pub mod gui;

use std::fs::OpenOptions;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::{Duration, Instant};

use clap::Parser;
use colored::*;
use mimalloc::MiMalloc;
use tokio::sync::mpsc;

use crate::blacklist::{build_default_blacklist, load_exclude_file, FeedManager};
use crate::cli::Cli;
use crate::crypto::SynCookie;
use crate::evasion::SubnetCooldown;
use crate::scanner::af_packet::AfPacketScanner;
#[cfg(target_os = "linux")]
use crate::scanner::af_packet::LinuxAfPacketEngine;
use crate::scanner::raw_syn::{RawSynScanner, RawSynScannerConfig, ScanHit};
use crate::scanner::stealth_async::{AsyncScanner, AsyncScannerConfig};
use crate::targets::{parse_ports, TargetSpace};

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

fn print_banner() {
    let banner = r#"
 ╔═══════════════════════════════════════════════════════════════════════════╗
 ║   ____  _                 _                                               ║
 ║  |  _ \| |__   __ _ _ __ | |_ ___  _ __ ___         ___  ___ __ _ _ __   ║
 ║  | |_) | '_ \ / _` | '_ \| __/ _ \| '_ ` _ \ _____ / __|/ __/ _` | '_ \  ║
 ║  |  __/| | | | (_| | | | | || (_) | | | | | |_____|\__ \ (_| (_| | | | | ║
 ║  |_|   |_| |_|\__,_|_| |_|\__\___/|_| |_| |_|      |___/\___\__,_|_| |_| ║
 ║                                                                           ║
 ║    Next-Gen Multi-Threaded Wire-Speed Scanner • AF_PACKET Zero-Copy       ║
 ║                   OS Camouflage • Zero-RAM Syn-Cookies                    ║
 ║                 High-Speed Wire Engine • Zero-Copy Layer 2                ║
 ╚═══════════════════════════════════════════════════════════════════════════╝
"#;
    println!("{}", banner.bright_cyan().bold());
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::Console::{AttachConsole, ATTACH_PARENT_PROCESS};
        let _ = AttachConsole(ATTACH_PARENT_PROCESS);
    }

    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut args = Cli::parse();

    // Handle Quick Presets
    if args.quick_nla {
        args.ports = "3389".to_string();
        args.banner = true;
        args.nla_only = true;
        args.bare = true;
        if args.output_file == "open_targets.txt" {
            args.output_file = "NLA.txt".to_string();
        }
    }

    if args.quick_ssh {
        args.ports = "22".to_string();
        args.bare = true;
        if args.output_file == "open_targets.txt" {
            args.output_file = "SSH.txt".to_string();
        }
    }

    if args.ports.eq_ignore_ascii_case("nla") {
        args.ports = "3389".to_string();
        args.banner = true;
        args.nla_only = true;
        args.bare = true;
        if args.output_file == "open_targets.txt" {
            args.output_file = "NLA.txt".to_string();
        }
    }

    if args.ports.eq_ignore_ascii_case("ssh") {
        args.ports = "22".to_string();
        args.bare = true;
        if args.output_file == "open_targets.txt" {
            args.output_file = "SSH.txt".to_string();
        }
    }

    if args.nla_only {
        args.banner = true;
    }

    let _raw_args: Vec<String> = std::env::args().collect();
    let has_scan_target = args.target.is_some() || args.targets_file.is_some() || args.country.is_some() || args.update_feeds || args.update_geo;

    #[cfg(windows)]
    let should_launch_gui = !args.cli && !args.tui && (args.gui || (!has_scan_target && _raw_args.len() <= 1));

    #[cfg(not(windows))]
    let should_launch_gui = args.gui;

    if should_launch_gui {
        if let Err(e) = crate::gui::run_gui() {
            eprintln!("{} Failed to initialize native GUI: {}", "[!]".red().bold(), e);
            #[cfg(windows)]
            unsafe {
                use windows_sys::Win32::System::Console::AllocConsole;
                let _ = AllocConsole();
            }
            eprintln!("{} Falling back to interactive Terminal UI (TUI)...", "[*]".yellow());
            print_banner();
            match crate::tui::run_interactive_wizard(args).await {
                Ok(configured) => {
                    args = configured;
                }
                Err(err) => {
                    eprintln!("{} Interactive wizard aborted: {}", "[!]".red().bold(), err);
                    std::process::exit(1);
                }
            }
        } else {
            return Ok(());
        }
    }

    // Handle BGP Geo database update
    if args.update_geo {
        print_banner();
        if let Err(e) = crate::geo::GeoDatabase::download_database().await {
            eprintln!("{} Failed to download BGP Geo database: {}", "[!]".red().bold(), e);
            std::process::exit(1);
        }
        return Ok(());
    }

    // Handle Threat Feeds update
    if args.update_feeds {
        print_banner();
        if let Err(e) = FeedManager::update_feeds().await {
            eprintln!("{} Failed to update threat feeds: {}", "[!]".red().bold(), e);
            std::process::exit(1);
        }
        return Ok(());
    }

    // Interactive TUI mode: launched explicitly via --tui/-i, or on Linux when no target is provided
    let is_interactive = args.tui || (!has_scan_target && !should_launch_gui);
    if is_interactive {
        print_banner();
        match crate::tui::run_interactive_wizard(args).await {
            Ok(configured) => {
                args = configured;
            }
            Err(e) => {
                eprintln!("{} TUI wizard aborted: {}", "[!]".red().bold(), e);
                std::process::exit(1);
            }
        }
    } else {
        print_banner();
    }

    // Resolve Country BGP targets if specified via CLI
    if let Some(ref country_target) = args.country {
        let excludes: Vec<String> = args.exclude_country
            .as_deref()
            .map(|s| s.split(',').map(|c| c.trim().to_string()).collect())
            .unwrap_or_default();
        println!("{} Resolving live BGP routing prefixes for '{}'...", "[*]".cyan(), country_target.yellow());
        match crate::geo::GeoDatabase::fetch_cidrs(country_target, &excludes).await {
            Ok((label, cidrs)) => {
                let out_ranges = format!("{}_ranges.txt", label.to_lowercase());
                let mut f = std::fs::File::create(&out_ranges)?;
                for c in &cidrs {
                    writeln!(f, "{}", c)?;
                }
                println!("{} Saved {} CIDR blocks to {}", "[+]".green().bold(), cidrs.len().to_string().yellow().bold(), out_ranges.cyan());
                args.targets_file = Some(out_ranges);
                args.target = None;
            }
            Err(e) => {
                eprintln!("{} Failed to resolve BGP country CIDRs: {}", "[!]".red().bold(), e);
                std::process::exit(1);
            }
        }
    }

    let has_resolved_target = args.target.is_some() || args.targets_file.is_some();
    if !has_resolved_target {
        println!("{} No targets specified. Run with -h for help, -i for interactive TUI, or --gui for graphical interface.", "[*]".yellow());
        println!("Example: phantom-scan -t 192.168.1.0/24 -p 3389 -r 10000");
        println!("         phantom-scan -C slavic -p 3389 -r 25000");
        return Ok(());
    }

    // 1. Auto-refresh stale threat feeds on startup if enabled
    if args.threat_feeds && !args.no_auto_feeds && FeedManager::is_cache_stale() {
        FeedManager::auto_refresh_if_stale().await;
    }

    // 2. Parse Ports
    let ports = match parse_ports(&args.ports) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{} Error parsing ports: {}", "[!]".red().bold(), e);
            std::process::exit(1);
        }
    };

    // 3. Build Target Space
    let target_space = if let Some(ref file_path) = args.targets_file {
        println!("{} Loading targets from file: {}", "[*]".cyan(), file_path.yellow());
        match TargetSpace::from_file(file_path, ports.clone()) {
            Ok(ts) => ts,
            Err(e) => {
                eprintln!("{} Failed to load targets file: {}", "[!]".red().bold(), e);
                std::process::exit(1);
            }
        }
    } else if let Some(ref target_str) = args.target {
        let targets: Vec<String> = target_str.split(',').map(|s| s.trim().to_string()).collect();
        match TargetSpace::with_v6_sample_size(&targets, ports.clone(), args.v6_samples) {
            Ok(ts) => ts,
            Err(e) => {
                eprintln!("{} Failed to parse target(s): {}", "[!]".red().bold(), e);
                std::process::exit(1);
            }
        }
    } else {
        eprintln!("{} Error: Must specify either -t/--target or -f/--targets-file", "[!]".red().bold());
        std::process::exit(1);
    };

    // 4. Build Blacklist Trie
    let mut blacklist = build_default_blacklist(args.scan_private);
    if args.threat_feeds {
        let cached_feeds_count = FeedManager::load_cached_feeds(&mut blacklist);
        if cached_feeds_count > 0 {
            println!("{} Loaded {} threat intelligence & honeypot subnets from cache", 
                "[*]".cyan(), 
                cached_feeds_count.to_string().yellow().bold()
            );
        }
    }

    if let Some(ref ex_file) = args.exclude_file {
        match load_exclude_file(&mut blacklist, ex_file) {
            Ok(count) => println!("{} Loaded {} exclusion CIDRs from {}", "[*]".cyan(), count.to_string().yellow(), ex_file),
            Err(e) => eprintln!("{} Warning: Failed to load exclude file {}: {}", "[!]".yellow(), ex_file, e),
        }
    }
    if let Some(ref ex_str) = args.exclude {
        for cidr in ex_str.split(',') {
            let _ = blacklist.insert_str(cidr);
        }
    }

    // 5. Initialize Cooldown Ring (Memory Pressure Guard)
    let cooldown = if args.compact_cooldown {
        println!("{} Initializing Compact Cooldown Table (1M shards, ~4MB RAM)...", "[*]".cyan());
        SubnetCooldown::new_compact(args.cooldown_ms)
    } else {
        println!("{} Initializing Exact /24 Subnet Cooldown Ring (16.7M IPv4 + 1M IPv6 shards, 64MB RAM)...", "[*]".cyan());
        SubnetCooldown::new_exact(args.cooldown_ms)
    };

    let cookie = SynCookie::new();
    let seed = fastrand::u64(..);

    // 6. Print Summary
    println!("{} Targets: {} Hosts | Total Probes: {}", 
        "[*]".green().bold(), 
        target_space.total_ips.to_string().yellow().bold(), 
        target_space.total_targets.to_string().yellow().bold()
    );
    println!("{} Ports: {:?} | Target Rate: {:.2}-kpps ({} pps)", 
        "[*]".green().bold(), 
        ports, 
        (args.rate as f64) / 1000.0,
        args.rate.to_string().cyan().bold()
    );
    if args.cooldown_ms == 0 {
        println!("{} Anti-Abuse Cooldown: {}", 
            "[*]".green().bold(), 
            "DISABLED (Unrestricted wire-speed like masscan)".yellow().bold()
        );
    } else {
        println!("{} Anti-Abuse Cooldown: {}ms per /24 (IPv4) & /64 (IPv6)", 
            "[*]".green().bold(), 
            args.cooldown_ms.to_string().cyan().bold()
        );
    }
    println!("{} Stack Fingerprint Profile: {:?} (Randomize: {})", 
        "[*]".green().bold(), 
        args.profile,
        args.randomize_stack.to_string().yellow()
    );
    println!("{} Banner Grabbing: {}", 
        "[*]".green().bold(), 
        if args.banner { "ENABLED (Bounded Pool)".bright_green().bold() } else { "DISABLED".yellow() }
    );
    if args.nla_only {
        println!("{} NLA / CredSSP Filter: {}", 
            "[*]".green().bold(), 
            "ENABLED (Strictly save verified NLA targets)".bright_cyan().bold()
        );
    }
    if args.bare {
        println!("{} Output Format: {}", 
            "[*]".green().bold(), 
            "Bare IP:PORT (clean output ready for spraying/pipelines)".bright_yellow().bold()
        );
    }
    println!("{} Output Destination: {}", 
        "[*]".green().bold(), 
        args.output_file.yellow().bold()
    );
    println!("{} Engine Mode: {}", 
        "[*]".green().bold(), 
        args.mode.to_uppercase().bright_magenta().bold()
    );
    println!("───────────────────────────────────────────────────────────────────────────");

    // 7. Setup High-Throughput Realtime Streaming Output Writer (Immediate Flush on Hit)
    let (tx, mut rx) = mpsc::unbounded_channel::<ScanHit>();
    let out_file_path = args.output_file.clone();
    let is_json = args.json;
    let nla_only = args.nla_only;
    let bare_mode = args.bare;

    let writer_handle = tokio::spawn(async move {
        let file = match OpenOptions::new().create(true).append(true).open(&out_file_path) {
            Ok(f) => f,
            Err(e) => {
                eprintln!("{} Failed to open output file: {}", "[!]".red().bold(), e);
                return;
            }
        };

        let mut writer = std::io::BufWriter::with_capacity(64 * 1024, file);

        // Dedicated real-time NLA and SSH streams if main output file is not already writing to them
        let mut nla_stream = if out_file_path != "NLA.txt" {
            OpenOptions::new().create(true).append(true).open("NLA.txt").ok()
                .map(|f| std::io::BufWriter::new(f))
        } else {
            None
        };

        let mut ssh_stream = if out_file_path != "SSH.txt" {
            OpenOptions::new().create(true).append(true).open("SSH.txt").ok()
                .map(|f| std::io::BufWriter::new(f))
        } else {
            None
        };

        while let Some(hit) = rx.recv().await {
            let is_nla = hit.port == 3389 && crate::banner::BannerGrabber::is_nla_capable(hit.banner.as_deref());
            let is_ssh = hit.port == 22;

            // If NLA filter is active on main output, only save targets with confirmed NLA / CredSSP capability
            if nla_only && !is_nla {
                continue;
            }

            if is_json {
                let json_line = serde_json::to_string(&serde_json::json!({
                    "ip": hit.ip.to_string(),
                    "port": hit.port,
                    "banner": hit.banner,
                    "timestamp": hit.timestamp.to_rfc3339()
                })).unwrap();
                let _ = writeln!(writer, "{}", json_line);
            } else if bare_mode {
                let _ = writeln!(writer, "{}:{}", hit.ip, hit.port);
            } else {
                if let Some(ref b) = hit.banner {
                    let _ = writeln!(writer, "{}:{} [{}]", hit.ip, hit.port, b);
                } else {
                    let _ = writeln!(writer, "{}:{}", hit.ip, hit.port);
                }
            }
            // Flush main writer immediately right after getting hit
            let _ = writer.flush();

            // Right after getting hit: immediately write and flush to NLA.txt / SSH.txt
            if is_nla {
                if let Some(ref mut nw) = nla_stream {
                    let _ = writeln!(nw, "{}:{}", hit.ip, hit.port);
                    let _ = nw.flush();
                }
            } else if is_ssh {
                if let Some(ref mut sw) = ssh_stream {
                    let _ = writeln!(sw, "{}:{}", hit.ip, hit.port);
                    let _ = sw.flush();
                }
            }
        }
        let _ = writer.flush();
        if let Some(ref mut nw) = nla_stream {
            let _ = nw.flush();
        }
        if let Some(ref mut sw) = ssh_stream {
            let _ = sw.flush();
        }
    });

    let start_time = Instant::now();

    // 8. Run Engine
    let mode_lower = args.mode.to_lowercase();
    if mode_lower == "raw-syn" || mode_lower == "af-packet" {
        let mut src_v4 = args.source_ip.as_ref().and_then(|s| Ipv4Addr::from_str(s).ok());
        let src_v6 = args.source_ip_v6.as_ref().and_then(|s| Ipv6Addr::from_str(s).ok());

        if src_v4.is_none() && src_v6.is_none() {
            if let Some(IpAddr::V4(auto_v4)) = crate::scanner::l2::L2Resolver::get_local_ip() {
                println!("{} Auto-detected local source IP: {}", "[*]".cyan(), auto_v4.to_string().yellow());
                src_v4 = Some(auto_v4);
            } else {
                eprintln!("{} Error: Raw mode requires -S/--source-ip (e.g. -S 192.168.1.100)", "[!]".red().bold());
                std::process::exit(1);
            }
        }

        let port_range = args.source_port_range.as_ref().and_then(|r| {
            let parts: Vec<&str> = r.split('-').collect();
            if parts.len() == 2 {
                let min: u16 = parts[0].trim().parse().ok()?;
                let max: u16 = parts[1].trim().parse().ok()?;
                Some((min, max))
            } else {
                None
            }
        });

        let gw_mac = args.gateway_mac.as_deref().and_then(crate::scanner::l2::L2Resolver::parse_mac);
        let src_mac = args.source_mac.as_deref().and_then(crate::scanner::l2::L2Resolver::parse_mac);

        let raw_cfg = RawSynScannerConfig {
            src_ip_v4: src_v4,
            src_ip_v6: src_v6,
            src_port: args.source_port,
            src_port_range: port_range,
            rate_limit_pps: args.rate,
            profile: args.profile,
            tx_threads: args.tx_threads,
            grab_banner: args.banner,
            randomize_options: args.randomize_stack,
            retries: args.retries,
            interface: args.interface.clone(),
            gateway_mac: gw_mac,
            source_mac: src_mac,
            fanout_mode: args.fanout_mode.clone(),
        };

        let target_space_arc = std::sync::Arc::new(target_space);
        let blacklist_arc = std::sync::Arc::new(blacklist);
        let cooldown_arc = std::sync::Arc::new(cooldown);
        let cookie_arc = std::sync::Arc::new(cookie);

        if mode_lower == "af-packet" {
            #[cfg(target_os = "linux")]
            {
                println!("{} Launching Linux AF_PACKET Zero-Copy Ring Engine...", "[*]".bright_green().bold());
                if let Err(e) = LinuxAfPacketEngine::run(
                    std::sync::Arc::clone(&target_space_arc),
                    std::sync::Arc::clone(&blacklist_arc),
                    std::sync::Arc::clone(&cooldown_arc),
                    std::sync::Arc::clone(&cookie_arc),
                    raw_cfg.clone(),
                    tx.clone(),
                    seed,
                ) {
                    eprintln!("{} AF_PACKET error: {}. Falling back to multi-threaded raw-syn.", "[!]".red().bold(), e);
                    let raw_scanner = RawSynScanner::new_with_arcs(
                        target_space_arc,
                        blacklist_arc,
                        cooldown_arc,
                        cookie_arc,
                        raw_cfg,
                    );
                    println!("{} Launching multi-threaded wire-speed injection ({} TX threads)...", 
                        "[*]".bright_green().bold(), 
                        args.tx_threads.to_string().yellow().bold()
                    );
                    if let Err(e) = raw_scanner.run(tx.clone(), seed) {
                        eprintln!("{} Raw socket error: {}. Falling back to stealth-async engine.", "[!]".red().bold(), e);
                    }
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                println!("{} AF_PACKET is Linux-specific. Switching to multi-threaded raw-syn...", "[*]".yellow());
                let raw_scanner = RawSynScanner::new_with_arcs(
                    target_space_arc,
                    blacklist_arc,
                    cooldown_arc,
                    cookie_arc,
                    raw_cfg,
                );
                let _ = raw_scanner.run(tx.clone(), seed);
            }
        } else {
            let raw_scanner = RawSynScanner::new_with_arcs(
                target_space_arc,
                blacklist_arc,
                cooldown_arc,
                cookie_arc,
                raw_cfg,
            );
            println!("{} Launching multi-threaded wire-speed injection ({} TX threads)...", 
                "[*]".bright_green().bold(), 
                args.tx_threads.to_string().yellow().bold()
            );
            if let Err(e) = raw_scanner.run(tx.clone(), seed) {
                eprintln!("{} Raw socket error: {}. Falling back to stealth-async engine.", "[!]".red().bold(), e);
            }
        }
        drop(tx);
    } else {
        let async_cfg = AsyncScannerConfig {
            concurrency: args.concurrency,
            timeout_ms: args.timeout_ms,
            rate_limit_pps: args.rate,
            grab_banner: args.banner,
        };

        let scanner = AsyncScanner::new(
            target_space,
            blacklist,
            cooldown,
            seed,
            async_cfg,
        );

        println!("{} Starting multi-threaded asynchronous scanner...", "[*]".bright_green().bold());
        tokio::select! {
            _ = scanner.run(tx) => {},
            _ = tokio::signal::ctrl_c() => {
                println!("\n{} Ctrl+C received, gracefully flushing and stopping...", "[!]".yellow().bold());
            }
        }
    }

    let _ = writer_handle.await;

    let elapsed = start_time.elapsed();
    println!("───────────────────────────────────────────────────────────────────────────");
    println!("{} Scan completed in {:.2?} seconds.", "[+]".green().bold(), elapsed.as_secs_f64());
    println!("{} Results saved to: {}", "[+]".green().bold(), args.output_file.yellow());

    Ok(())
}
