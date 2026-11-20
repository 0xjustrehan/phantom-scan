/// State Management and Engine Orchestration for Phantom Scan GUI
///
/// Drives live multi-threaded scanning, real metrics calculation,
/// keyboard shortcut dispatching, and virtualized results table filtering.

use chrono::{DateTime, Local};
use crossbeam_channel::{Receiver, Sender};
use eframe::egui::{self, Key, Modifiers};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::banner::BannerPool;
use crate::blacklist::{build_default_blacklist, load_exclude_file, BlacklistTrie, FeedManager};
use crate::controller::{GlobalRateController, RetransmitManager, RttEstimator};
use crate::crypto::{Blackrock, SynCookie};
use crate::evasion::{OsProfile, StatefulEvasion, SubnetCooldown};
use crate::gui::config::GuiConfig;
use crate::packet::PacketBuilder;
use crate::scanner::af_packet::AfPacketScanner;
#[cfg(target_os = "linux")]
use crate::scanner::af_packet::LinuxAfPacketEngine;
use crate::scanner::l2::L2Resolver;
use crate::scanner::raw_syn::{RawSynScanner, RawSynScannerConfig, ScanHit};
use crate::scanner::stealth_async::{AsyncScanner, AsyncScannerConfig};
use crate::targets::{parse_ports, TargetSpace};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanStatus {
    Idle,
    Scanning,
    Paused,
    Draining,
    Done,
    Error,
}

#[derive(Debug, Clone)]
pub struct LogLine {
    pub timestamp: DateTime<Local>,
    pub level: &'static str,
    pub text: String,
}

#[derive(Debug, Clone, Default)]
pub struct LiveMetrics {
    pub probes_sent: u64,
    pub total_targets: u64,
    pub hits_count: u64,
    pub current_pps: u64,
    pub average_rtt_ms: f64,
    pub blacklist_skips: u64,
    pub cooldown_skips: u64,
    pub eta_secs: Option<u64>,
}

pub struct AppState {
    pub config: GuiConfig,
    pub status: ScanStatus,
    pub status_text: String,

    // Live Results & Table Model
    pub results: Vec<ScanHit>,
    pub filtered_indices: Vec<usize>,
    pub filter_query: String,
    pub selected_index: Option<usize>,

    // Real Metrics
    pub metrics: LiveMetrics,
    pub logs: Vec<LogLine>,

    // Runtime Channel Handles
    pub hit_rx: Option<Receiver<ScanHit>>,
    pub log_rx: Option<Receiver<LogLine>>,
    pub stop_flag: Option<Arc<AtomicBool>>,
    pub pause_flag: Option<Arc<AtomicBool>>,
    pub probes_counter: Option<Arc<std::sync::atomic::AtomicU64>>,
    pub total_targets_atom: Option<Arc<std::sync::atomic::AtomicU64>>,
    pub status_rx: Option<Receiver<ScanStatus>>,

    pub scan_start_time: Option<Instant>,
    pub last_stats_tick: Instant,
    pub last_probes_count: u64,
    pub show_options_modal: bool,

    // Live Geo-BGP Downloader & Routing State
    pub show_geo_modal: bool,
    pub geo_region_input: String,
    pub geo_exclude_input: String,
    pub geo_loading: bool,
    pub geo_status_msg: String,
    pub geo_rx: Option<Receiver<Result<(String, Vec<String>), String>>>,
}

impl AppState {
    pub fn new() -> Self {
        let mut state = Self {
            config: GuiConfig::load_or_default(),
            status: ScanStatus::Idle,
            status_text: "IDLE".to_string(),
            results: Vec::with_capacity(100_000),
            filtered_indices: Vec::with_capacity(100_000),
            filter_query: String::new(),
            selected_index: None,
            metrics: LiveMetrics::default(),
            logs: Vec::with_capacity(10_000),
            hit_rx: None,
            log_rx: None,
            stop_flag: None,
            pause_flag: None,
            probes_counter: None,
            total_targets_atom: None,
            status_rx: None,
            scan_start_time: None,
            last_stats_tick: Instant::now(),
            last_probes_count: 0,
            show_options_modal: false,
            show_geo_modal: false,
            geo_region_input: "slavic".to_string(),
            geo_exclude_input: String::new(),
            geo_loading: false,
            geo_status_msg: String::new(),
            geo_rx: None,
        };

        state.append_log("INFO", "Phantom Scan ready. Configure target and start scan.".to_string());
        state
    }

    pub fn append_log(&mut self, level: &'static str, text: String) {
        self.logs.push(LogLine {
            timestamp: Local::now(),
            level,
            text,
        });
    }

    pub fn update_filter(&mut self) {
        let q = self.filter_query.trim().to_lowercase();
        if q.is_empty() {
            self.filtered_indices = (0..self.results.len()).collect();
        } else {
            self.filtered_indices = self
                .results
                .iter()
                .enumerate()
                .filter(|(_, h)| {
                    let ip = h.ip.to_string();
                    let port = h.port.to_string();
                    let banner = h.banner.as_deref().unwrap_or("").to_lowercase();
                    ip.contains(&q) || port.contains(&q) || banner.contains(&q)
                })
                .map(|(i, _)| i)
                .collect();
        }
    }

    /// Process live incoming channel events from scanner thread
    pub fn poll_updates(&mut self) {
        // Drain status
        if let Some(ref rx) = self.status_rx {
            while let Ok(status) = rx.try_recv() {
                self.status = status;
                if status == ScanStatus::Done {
                    self.status_text = "DONE".to_string();
                    self.metrics.current_pps = 0;
                    self.metrics.eta_secs = None;
                } else if status == ScanStatus::Error {
                    self.status_text = "ERROR".to_string();
                    self.metrics.current_pps = 0;
                    self.metrics.eta_secs = None;
                }
            }
        }

        // Live probes counter & target count
        if let Some(ref pc) = self.probes_counter {
            self.metrics.probes_sent = pc.load(Ordering::Relaxed);
        }
        if let Some(ref tt) = self.total_targets_atom {
            let total = tt.load(Ordering::Relaxed);
            if total > 0 {
                self.metrics.total_targets = total;
            }
        }

        // Drain hits
        if let Some(ref rx) = self.hit_rx {
            let mut new_hits = 0;
            while let Ok(hit) = rx.try_recv() {
                self.results.push(hit);
                new_hits += 1;
            }
            if new_hits > 0 {
                self.metrics.hits_count = self.results.len() as u64;
                self.update_filter();
            }
        }

        // Drain logs
        if let Some(ref rx) = self.log_rx {
            while let Ok(line) = rx.try_recv() {
                self.logs.push(line);
            }
        }

        // Drain Geo-BGP results
        if let Some(ref rx) = self.geo_rx {
            if let Ok(res) = rx.try_recv() {
                self.geo_loading = false;
                match res {
                    Ok((label, cidrs)) => {
                        let out_path = format!("{}_ranges.txt", label.to_lowercase());
                        if let Ok(mut file) = File::create(&out_path) {
                            for c in &cidrs {
                                let _ = writeln!(file, "{}", c);
                            }
                        }
                        self.config.target = cidrs.join("\n");
                        self.config.targets_file = out_path.clone();
                        self.append_log("INFO", format!("Geo-BGP: Decomposed {} CIDR blocks for {} into {}", cidrs.len(), label, out_path));
                        self.geo_status_msg = format!("Loaded {} CIDRs", cidrs.len());
                        self.show_geo_modal = false;
                    }
                    Err(e) => {
                        self.append_log("ERROR", format!("Geo-BGP fetch failed: {}", e));
                        self.geo_status_msg = format!("Error: {}", e);
                    }
                }
            }
        }

        // 1-second metric calculation
        if self.status == ScanStatus::Scanning || self.status == ScanStatus::Draining {
            if self.last_stats_tick.elapsed() >= Duration::from_millis(1000) {
                let sent = self.metrics.probes_sent;
                let delta = sent.saturating_sub(self.last_probes_count);
                self.last_probes_count = sent;
                self.metrics.current_pps = delta;

                if self.metrics.total_targets > 0 && delta > 0 {
                    let rem = self.metrics.total_targets.saturating_sub(sent);
                    self.metrics.eta_secs = Some(rem / delta);
                }

                self.last_stats_tick = Instant::now();
            }
        }
    }

    /// Keyboard hotkeys handler: F5/Ctrl+Enter=Start, Esc=Stop, Ctrl+S=Save, Ctrl+L=Clear, Ctrl+O=Load
    pub fn handle_hotkeys(&mut self, ctx: &egui::Context) {
        ctx.input(|i| {
            // Start: F5 or Ctrl+Enter
            if i.key_pressed(Key::F5) || (i.modifiers.command && i.key_pressed(Key::Enter)) {
                if self.status == ScanStatus::Idle || self.status == ScanStatus::Done || self.status == ScanStatus::Error {
                    self.start_scan();
                }
            }

            // Stop: Escape
            if i.key_pressed(Key::Escape) {
                if self.status == ScanStatus::Scanning || self.status == ScanStatus::Paused {
                    self.stop_scan();
                }
            }

            // Save: Ctrl+S
            if i.modifiers.command && i.key_pressed(Key::S) {
                if let Some(path) = rfd::FileDialog::new()
                    .set_title("Save Discovered Hosts")
                    .set_file_name("open_targets.txt")
                    .save_file()
                {
                    let _ = self.export_results("txt", &path, false);
                }
            }

            // Clear: Ctrl+L
            if i.modifiers.command && i.key_pressed(Key::L) {
                self.clear_results();
            }

            // Load targets: Ctrl+O
            if i.modifiers.command && i.key_pressed(Key::O) {
                if let Some(path) = rfd::FileDialog::new().set_title("Load Target File").pick_file() {
                    self.config.targets_file = path.display().to_string();
                }
            }
        });
    }

    pub fn start_scan(&mut self) {
        if self.status == ScanStatus::Scanning || self.status == ScanStatus::Draining {
            return;
        }

        self.config.save_to_disk();

        let cfg = self.config.clone();
        let (hit_tx, hit_rx) = crossbeam_channel::unbounded::<ScanHit>();
        let (log_tx, log_rx) = crossbeam_channel::unbounded::<LogLine>();
        let (status_tx, status_rx) = crossbeam_channel::unbounded::<ScanStatus>();
        let stop_flag = Arc::new(AtomicBool::new(false));
        let pause_flag = Arc::new(AtomicBool::new(false));
        let probes_counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let total_targets_atom = Arc::new(std::sync::atomic::AtomicU64::new(0));

        self.hit_rx = Some(hit_rx);
        self.log_rx = Some(log_rx);
        self.status_rx = Some(status_rx);
        self.stop_flag = Some(Arc::clone(&stop_flag));
        self.pause_flag = Some(Arc::clone(&pause_flag));
        self.probes_counter = Some(Arc::clone(&probes_counter));
        self.total_targets_atom = Some(Arc::clone(&total_targets_atom));

        self.results.clear();
        self.filtered_indices.clear();
        self.metrics = LiveMetrics::default();
        self.scan_start_time = Some(Instant::now());
        self.last_stats_tick = Instant::now();
        self.last_probes_count = 0;

        self.status = ScanStatus::Scanning;
        self.status_text = "SCANNING".to_string();

        let target_str = cfg.target.clone();
        let ports_str = cfg.ports.clone();
        let mode_str = cfg.mode.clone();

        self.append_log("INFO", format!("Starting scan: targets='{}' ports='{}' mode={}", target_str.replace('\n', " "), ports_str, mode_str));

        thread::spawn(move || {
            let log_msg = |level: &'static str, text: String| {
                let _ = log_tx.send(LogLine {
                    timestamp: Local::now(),
                    level,
                    text,
                });
            };

            // 1. Parse Ports
            let ports = match parse_ports(&cfg.ports) {
                Ok(p) => p,
                Err(e) => {
                    log_msg("ERROR", format!("Failed to parse ports: {}", e));
                    let _ = status_tx.send(ScanStatus::Error);
                    return;
                }
            };

            // 2. Build Target Space (check on-screen text first)
            let target_space = if !cfg.target.trim().is_empty() {
                let cleaned_lines: Vec<String> = cfg
                    .target
                    .lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty())
                    .collect();

                match TargetSpace::with_v6_sample_size(&cleaned_lines, ports.clone(), cfg.v6_samples) {
                    Ok(ts) => ts,
                    Err(e) => {
                        log_msg("ERROR", format!("Failed to parse targets: {}", e));
                        let _ = status_tx.send(ScanStatus::Error);
                        return;
                    }
                }
            } else if !cfg.targets_file.trim().is_empty() {
                match TargetSpace::from_file_with_v6_samples(&cfg.targets_file, ports.clone(), cfg.v6_samples) {
                    Ok(ts) => ts,
                    Err(e) => {
                        log_msg("ERROR", format!("Failed to read target file: {}", e));
                        let _ = status_tx.send(ScanStatus::Error);
                        return;
                    }
                }
            } else {
                log_msg("ERROR", "No targets entered.".to_string());
                let _ = status_tx.send(ScanStatus::Error);
                return;
            };

            total_targets_atom.store(target_space.total_targets, Ordering::Relaxed);

            // 3. Blacklist Trie & Threat Feeds
            let mut blacklist = build_default_blacklist(cfg.scan_private);
            let cached = FeedManager::load_cached_feeds(&mut blacklist);
            if cached > 0 {
                log_msg("INFO", format!("Loaded {} threat prefixes from cache.", cached));
            }

            if !cfg.exclude_file.trim().is_empty() {
                let _ = load_exclude_file(&mut blacklist, &cfg.exclude_file);
            }
            for line in cfg.exclude.lines() {
                let clean = line.trim();
                if !clean.is_empty() {
                    let _ = blacklist.insert_str(clean);
                }
            }

            // 4. Cooldown Ring
            let cooldown = if cfg.compact_cooldown {
                SubnetCooldown::new_compact(cfg.cooldown_ms)
            } else {
                SubnetCooldown::new_exact(cfg.cooldown_ms)
            };

            let cookie = SynCookie::new();
            let seed = fastrand::u64(..);

            log_msg("INFO", format!("Target space initialized: {} probes to dispatch.", target_space.total_targets));

            // Bridge internal tokio channel to GUI crossbeam channel + optional file output
            let (tokio_tx, mut tokio_rx) = tokio::sync::mpsc::unbounded_channel::<ScanHit>();
            let hit_tx_clone = hit_tx.clone();
            let log_tx_clone = log_tx.clone();
            let output_file_path = cfg.output_file.clone();
            let write_jsonl = cfg.jsonl;

            thread::spawn(move || {
                let mut out_file = if !output_file_path.trim().is_empty() {
                    OpenOptions::new().create(true).append(true).open(&output_file_path).ok()
                } else {
                    None
                };

                while let Some(hit) = tokio_rx.blocking_recv() {
                    let banner_str = hit.banner.as_deref().unwrap_or("OPEN");
                    let _ = log_tx_clone.send(LogLine {
                        timestamp: Local::now(),
                        level: "HIT",
                        text: format!("OPEN {}:{} [{}]", hit.ip, hit.port, banner_str),
                    });

                    // Write to output file if configured
                    if let Some(ref mut f) = out_file {
                        if write_jsonl {
                            let json = serde_json::json!({
                                "ip": hit.ip.to_string(),
                                "port": hit.port,
                                "banner": hit.banner,
                                "timestamp": hit.timestamp.to_rfc3339()
                            });
                            let _ = writeln!(f, "{}", json);
                        } else {
                            if let Some(ref b) = hit.banner {
                                let _ = writeln!(f, "{}:{} [{}]", hit.ip, hit.port, b);
                            } else {
                                let _ = writeln!(f, "{}:{}", hit.ip, hit.port);
                            }
                        }
                    }

                    let _ = hit_tx_clone.send(hit);
                }
            });

            // 5. Execute Selected Engine
            let mode_lower = cfg.mode.to_lowercase();
            if mode_lower == "stealth-async" {
                let async_cfg = AsyncScannerConfig {
                    concurrency: cfg.concurrency,
                    timeout_ms: cfg.timeout_ms,
                    rate_limit_pps: cfg.rate,
                    grab_banner: cfg.banner,
                };
                let scanner = AsyncScanner::new(
                    target_space,
                    blacklist,
                    cooldown,
                    seed,
                    async_cfg,
                );

                let stop_clone = Arc::clone(&stop_flag);
                let probes_clone = Arc::clone(&probes_counter);
                if let Ok(rt) = tokio::runtime::Builder::new_multi_thread().enable_all().build() {
                    rt.block_on(async {
                        scanner.run_with_cancel(tokio_tx, Some(stop_clone), Some(probes_clone)).await;
                    });
                }
            } else {
                let mut src_v4 = if !cfg.source_ip.trim().is_empty() { cfg.source_ip.trim().parse().ok() } else { None };
                let src_v6 = if !cfg.source_ip_v6.trim().is_empty() { cfg.source_ip_v6.trim().parse().ok() } else { None };

                // Auto-detect local source IP if not provided
                if src_v4.is_none() && src_v6.is_none() {
                    if let Some(IpAddr::V4(auto_ip)) = L2Resolver::get_local_ip() {
                        log_msg("INFO", format!("Auto-detected local source IP: {}", auto_ip));
                        src_v4 = Some(auto_ip);
                    }
                }

                let port_range = if !cfg.source_port_range.trim().is_empty() {
                    let p: Vec<&str> = cfg.source_port_range.split('-').collect();
                    if p.len() == 2 {
                        Some((p[0].trim().parse().unwrap_or(40000), p[1].trim().parse().unwrap_or(65000)))
                    } else { None }
                } else { None };

                let gw_mac = L2Resolver::parse_mac(&cfg.gateway_mac);
                let src_mac = L2Resolver::parse_mac(&cfg.source_mac);

                let profile = match cfg.profile.to_lowercase().as_str() {
                    "windows" => OsProfile::Windows,
                    "linux" => OsProfile::Linux,
                    "macos" => OsProfile::Macos,
                    "freebsd" => OsProfile::Freebsd,
                    "android" => OsProfile::Android,
                    _ => OsProfile::Random,
                };

                let raw_cfg = RawSynScannerConfig {
                    src_ip_v4: src_v4,
                    src_ip_v6: src_v6,
                    src_port: cfg.source_port,
                    src_port_range: port_range,
                    rate_limit_pps: cfg.rate,
                    profile,
                    tx_threads: cfg.tx_threads,
                    grab_banner: cfg.banner,
                    randomize_options: cfg.randomize_stack,
                    retries: cfg.retries,
                    interface: if cfg.interface.is_empty() { None } else { Some(cfg.interface.clone()) },
                    gateway_mac: gw_mac,
                    source_mac: src_mac,
                    fanout_mode: cfg.fanout_mode.clone(),
                };

                if mode_lower == "af-packet" {
                    #[cfg(target_os = "linux")]
                    {
                        log_msg("INFO", "Running AF_PACKET zero-copy ring engine...".to_string());
                        if let Err(e) = LinuxAfPacketEngine::run(
                            Arc::new(target_space),
                            Arc::new(blacklist),
                            Arc::new(cooldown),
                            Arc::new(cookie),
                            raw_cfg,
                            tokio_tx,
                            seed,
                        ) {
                            log_msg("ERROR", format!("AF_PACKET error: {}", e));
                            let _ = status_tx.send(ScanStatus::Error);
                            return;
                        }
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        log_msg("WARN", "AF_PACKET requires Linux. Running raw-syn engine...".to_string());
                        let raw_scanner = RawSynScanner::new(target_space, blacklist, cooldown, cookie, raw_cfg);
                        let stop_clone = Arc::clone(&stop_flag);
                        let probes_clone = Arc::clone(&probes_counter);
                        if let Err(e) = raw_scanner.run_with_cancel(tokio_tx, seed, Some(stop_clone), Some(probes_clone)) {
                            log_msg("ERROR", format!("Raw-SYN error: {}", e));
                            let _ = status_tx.send(ScanStatus::Error);
                            return;
                        }
                    }
                } else {
                    let raw_scanner = RawSynScanner::new(target_space, blacklist, cooldown, cookie, raw_cfg);
                    let stop_clone = Arc::clone(&stop_flag);
                    let probes_clone = Arc::clone(&probes_counter);
                    if let Err(e) = raw_scanner.run_with_cancel(tokio_tx, seed, Some(stop_clone), Some(probes_clone)) {
                        log_msg("ERROR", format!("Raw-SYN error: {}", e));
                        let _ = status_tx.send(ScanStatus::Error);
                        return;
                    }
                }
            }

            log_msg("INFO", "Scan complete. All network buffers drained.".to_string());
            let _ = status_tx.send(ScanStatus::Done);
        });
    }

    pub fn toggle_pause(&mut self) {
        if self.status == ScanStatus::Scanning {
            if let Some(ref flag) = self.pause_flag {
                flag.store(true, Ordering::Relaxed);
                self.status = ScanStatus::Paused;
                self.status_text = "PAUSED".to_string();
                self.append_log("WARN", "Scan paused by operator.".to_string());
            }
        } else if self.status == ScanStatus::Paused {
            if let Some(ref flag) = self.pause_flag {
                flag.store(false, Ordering::Relaxed);
                self.status = ScanStatus::Scanning;
                self.status_text = "SCANNING".to_string();
                self.append_log("INFO", "Scan resumed.".to_string());
            }
        }
    }

    pub fn stop_scan(&mut self) {
        if self.status == ScanStatus::Scanning || self.status == ScanStatus::Paused {
            if let Some(ref flag) = self.stop_flag {
                flag.store(true, Ordering::Relaxed);
                self.status = ScanStatus::Draining;
                self.status_text = "DRAINING".to_string();
                self.append_log("WARN", "Stop initiated. Draining packets...".to_string());
            }
        }
    }

    pub fn clear_results(&mut self) {
        self.results.clear();
        self.filtered_indices.clear();
        self.metrics.hits_count = 0;
        self.append_log("INFO", "Results cleared.".to_string());
    }

    pub fn exclude_subnet(&mut self, ip: IpAddr) {
        match ip {
            IpAddr::V4(v4) => {
                let oct = v4.octets();
                let cidr = format!("{}.{}.{}.0/24", oct[0], oct[1], oct[2]);
                if !self.config.exclude.contains(&cidr) {
                    if !self.config.exclude.is_empty() && !self.config.exclude.ends_with('\n') {
                        self.config.exclude.push('\n');
                    }
                    self.config.exclude.push_str(&cidr);
                    self.append_log("INFO", format!("Added exclusion: {}", cidr));
                }
            }
            IpAddr::V6(v6) => {
                let seg = v6.segments();
                let cidr = format!("{:x}:{:x}:{:x}:{:x}::/64", seg[0], seg[1], seg[2], seg[3]);
                if !self.config.exclude.contains(&cidr) {
                    if !self.config.exclude.is_empty() && !self.config.exclude.ends_with('\n') {
                        self.config.exclude.push('\n');
                    }
                    self.config.exclude.push_str(&cidr);
                    self.append_log("INFO", format!("Added exclusion: {}", cidr));
                }
            }
        }
    }

    pub fn export_results(&self, format: &str, path: &Path, only_filtered: bool) -> std::io::Result<usize> {
        let mut file = File::create(path)?;
        let items: Vec<&ScanHit> = if only_filtered {
            self.filtered_indices.iter().filter_map(|&i| self.results.get(i)).collect()
        } else {
            self.results.iter().collect()
        };

        for hit in &items {
            match format.to_lowercase().as_str() {
                "json" | "jsonl" => {
                    let json = serde_json::json!({
                        "ip": hit.ip.to_string(),
                        "port": hit.port,
                        "banner": hit.banner,
                        "timestamp": hit.timestamp.to_rfc3339()
                    });
                    writeln!(file, "{}", json)?;
                }
                "csv" => {
                    let b = hit.banner.as_deref().unwrap_or("").replace('"', "\"\"");
                    writeln!(file, "\"{}\",{},\"{}\",\"{}\"", hit.ip, hit.port, b, hit.timestamp.to_rfc3339())?;
                }
                _ => {
                    if let Some(ref b) = hit.banner {
                        writeln!(file, "{}:{} [{}]", hit.ip, hit.port, b)?;
                    } else {
                        writeln!(file, "{}:{}", hit.ip, hit.port)?;
                    }
                }
            }
        }

        Ok(items.len())
    }

    pub fn trigger_geo_fetch(&mut self) {
        if self.geo_loading {
            return;
        }
        self.geo_loading = true;
        self.geo_status_msg = "Downloading & parsing live BGP table...".to_string();

        let target = self.geo_region_input.trim().to_string();
        let excludes: Vec<String> = self.geo_exclude_input
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        let (tx, rx) = crossbeam_channel::bounded(1);
        self.geo_rx = Some(rx);

        thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build();
            let res = match rt {
                Ok(runtime) => runtime.block_on(async {
                    crate::geo::GeoDatabase::fetch_cidrs(&target, &excludes).await
                }),
                Err(e) => Err(format!("Runtime error: {}", e)),
            };
            let _ = tx.send(res);
        });
    }
}
