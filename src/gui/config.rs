/// Persistent Configuration for Phantom Scan (1:1 CLI Flag Mirror)
///
/// Automatically persisted to `~/.phantom-scan/gui.toml`.

use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuiConfig {
    // Left Panel: Targets & Ports
    pub target: String,
    pub targets_file: String,
    pub ports: String,
    pub port_preset: String,
    pub exclude: String,
    pub exclude_file: String,
    pub scan_private: bool,
    pub v6_samples: usize,
    pub banner: bool,
    pub nla_only: bool,
    pub bare: bool,
    pub jsonl: bool,
    pub output_file: String,

    // Right Panel: Engine & Evasion
    pub mode: String, // "stealth-async", "raw-syn", "af-packet"
    pub rate: u64,
    pub tx_threads: usize,
    pub fanout_mode: String, // "lb", "hash", "cpu", "rollover"
    pub retries: usize,

    pub profile: String, // "Windows", "Linux", "macOS", "FreeBSD", "Android", "Random"
    pub randomize_stack: bool,
    pub source_port: u16,
    pub source_port_range: String,
    pub cooldown_ms: u32,
    pub compact_cooldown: bool,

    // Source / L2
    pub source_ip: String,
    pub source_ip_v6: String,
    pub interface: String,
    pub gateway_mac: String,
    pub source_mac: String,

    // Advanced
    pub auto_feeds: bool,
    pub concurrency: usize,
    pub timeout_ms: u64,

    // View Preferences
    pub show_log: bool,
}

impl Default for GuiConfig {
    fn default() -> Self {
        #[cfg(target_os = "linux")]
        let default_mode = "af-packet".to_string();
        #[cfg(not(target_os = "linux"))]
        let default_mode = "stealth-async".to_string();

        Self {
            target: "192.168.1.0/24".to_string(),
            targets_file: "".to_string(),
            ports: "3389".to_string(),
            port_preset: "RDP".to_string(),
            exclude: "".to_string(),
            exclude_file: "".to_string(),
            scan_private: true,
            v6_samples: 256,
            banner: true,
            nla_only: false,
            bare: false,
            jsonl: false,
            output_file: "open_targets.txt".to_string(),

            mode: default_mode,
            rate: 10000,
            tx_threads: num_cpus::get(),
            fanout_mode: "lb".to_string(),
            retries: 0,

            profile: "Random".to_string(),
            randomize_stack: true,
            source_port: 54321,
            source_port_range: "40000-65000".to_string(),
            cooldown_ms: 0,
            compact_cooldown: false,

            source_ip: "".to_string(),
            source_ip_v6: "".to_string(),
            interface: "eth0".to_string(),
            gateway_mac: "".to_string(),
            source_mac: "".to_string(),

            auto_feeds: true,
            concurrency: 4096,
            timeout_ms: 1500,

            show_log: false,
        }
    }
}

impl GuiConfig {
    pub fn config_path() -> Option<PathBuf> {
        let home = std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .ok()?;
        let mut dir = PathBuf::from(home);
        dir.push(".phantom-scan");
        let _ = fs::create_dir_all(&dir);
        dir.push("gui.toml");
        Some(dir)
    }

    pub fn load_or_default() -> Self {
        if let Some(path) = Self::config_path() {
            if path.exists() {
                if let Ok(mut file) = File::open(&path) {
                    let mut content = String::new();
                    if file.read_to_string(&mut content).is_ok() {
                        if let Ok(cfg) = toml::from_str::<GuiConfig>(&content) {
                            return cfg;
                        }
                    }
                }
            }
        }
        Self::default()
    }

    pub fn save_to_disk(&self) {
        if let Some(path) = Self::config_path() {
            if let Ok(serialized) = toml::to_string_pretty(self) {
                if let Ok(mut file) = File::create(&path) {
                    let _ = file.write_all(serialized.as_bytes());
                }
            }
        }
    }

    /// Generate exact 1:1 CLI command string
    pub fn to_cli_string(&self) -> String {
        let mut parts = vec!["phantom-scan".to_string()];

        if !self.targets_file.trim().is_empty() {
            parts.push(format!("-f \"{}\"", self.targets_file.trim()));
        } else if !self.target.trim().is_empty() {
            let single_line = self.target.lines().map(|l| l.trim()).filter(|l| !l.is_empty()).collect::<Vec<_>>().join(",");
            parts.push(format!("-t \"{}\"", single_line));
        }

        if !self.ports.trim().is_empty() {
            parts.push(format!("-p {}", self.ports.trim()));
        }

        parts.push(format!("-r {}", self.rate));
        parts.push(format!("-m {}", self.mode));

        if self.cooldown_ms > 0 {
            parts.push(format!("--cooldown-ms {}", self.cooldown_ms));
        }

        if self.compact_cooldown {
            parts.push("--compact-cooldown".to_string());
        }

        if self.profile != "Random" {
            parts.push(format!("--profile {}", self.profile.to_lowercase()));
        }

        if self.randomize_stack {
            parts.push("--randomize-stack".to_string());
        }

        if self.banner {
            parts.push("-b".to_string());
        }

        if self.nla_only {
            parts.push("--nla-only".to_string());
        }

        if self.bare {
            parts.push("--bare".to_string());
        }

        if self.scan_private {
            parts.push("--scan-private".to_string());
        }

        if self.tx_threads != num_cpus::get() {
            parts.push(format!("--tx-threads {}", self.tx_threads));
        }

        if !self.source_ip.trim().is_empty() {
            parts.push(format!("-S {}", self.source_ip.trim()));
        }

        if !self.source_ip_v6.trim().is_empty() {
            parts.push(format!("--source-ip-v6 {}", self.source_ip_v6.trim()));
        }

        if !self.source_port_range.trim().is_empty() {
            parts.push(format!("--source-port-range {}", self.source_port_range.trim()));
        } else if self.source_port != 54321 {
            parts.push(format!("--source-port {}", self.source_port));
        }

        if self.retries > 0 {
            parts.push(format!("--retries {}", self.retries));
        }

        if self.mode == "af-packet" {
            if !self.interface.trim().is_empty() && self.interface != "eth0" {
                parts.push(format!("-I {}", self.interface.trim()));
            }
            if !self.gateway_mac.trim().is_empty() {
                parts.push(format!("--gateway-mac \"{}\"", self.gateway_mac.trim()));
            }
            if !self.source_mac.trim().is_empty() {
                parts.push(format!("--source-mac \"{}\"", self.source_mac.trim()));
            }
            if self.fanout_mode != "lb" {
                parts.push(format!("--fanout-mode {}", self.fanout_mode));
            }
        }

        if !self.exclude.trim().is_empty() {
            let single_line = self.exclude.lines().map(|l| l.trim()).filter(|l| !l.is_empty()).collect::<Vec<_>>().join(",");
            parts.push(format!("-e \"{}\"", single_line));
        }

        if !self.exclude_file.trim().is_empty() {
            parts.push(format!("--exclude-file \"{}\"", self.exclude_file.trim()));
        }

        if !self.auto_feeds {
            parts.push("--no-auto-feeds".to_string());
        }

        if self.jsonl {
            parts.push("--json".to_string());
        }

        if !self.output_file.trim().is_empty() && self.output_file != "open_targets.txt" {
            parts.push(format!("-o \"{}\"", self.output_file.trim()));
        }

        parts.join(" ")
    }
}
