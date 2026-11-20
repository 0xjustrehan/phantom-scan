/// High-Performance Async Stealth TCP Scanner with Sampled Progress & Rate Pacing
///
/// Multi-threaded epoll/kqueue/IOCP async engine.
/// Dual-stack IPv4 & IPv6 with exact subnet cooldown and expanded banner grabber.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use indicatif::{ProgressBar, ProgressStyle};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::banner::BannerGrabber;
use crate::blacklist::BlacklistTrie;
use crate::controller::GlobalRateController;
use crate::crypto::Blackrock;
use crate::evasion::SubnetCooldown;
use crate::scanner::raw_syn::ScanHit;
use crate::targets::TargetSpace;

pub struct AsyncScannerConfig {
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub rate_limit_pps: u64,
    pub grab_banner: bool,
}

pub struct AsyncScanner {
    target_space: Arc<TargetSpace>,
    blacklist: Arc<BlacklistTrie>,
    cooldown: Arc<SubnetCooldown>,
    blackrock: Arc<Blackrock>,
    rate_controller: Arc<GlobalRateController>,
    config: AsyncScannerConfig,
}

impl AsyncScanner {
    pub fn new(
        target_space: TargetSpace,
        blacklist: BlacklistTrie,
        cooldown: SubnetCooldown,
        seed: u64,
        config: AsyncScannerConfig,
    ) -> Self {
        let total = target_space.total_targets;
        let pps = config.rate_limit_pps;
        Self {
            target_space: Arc::new(target_space),
            blacklist: Arc::new(blacklist),
            cooldown: Arc::new(cooldown),
            blackrock: Arc::new(Blackrock::new(total, seed)),
            rate_controller: Arc::new(GlobalRateController::new(pps)),
            config,
        }
    }

    pub async fn run(self, result_tx: mpsc::UnboundedSender<ScanHit>) {
        self.run_with_cancel(result_tx, None, None).await;
    }

    pub async fn run_with_cancel(
        self,
        result_tx: mpsc::UnboundedSender<ScanHit>,
        cancel_flag: Option<Arc<AtomicBool>>,
        probes_counter: Option<Arc<AtomicU64>>,
    ) {
        let total_targets = self.target_space.total_targets;
        let progress = Arc::new(ProgressBar::new(total_targets));
        progress.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) | Rate: {per_sec} | Hits: {msg} | ETA: {eta}")
                .unwrap()
                .progress_chars("#>-"),
        );

        let shared_index = Arc::new(AtomicU64::new(0));
        let hits_counter = Arc::new(AtomicU64::new(0));
        let stop_flag = Arc::new(AtomicBool::new(false));

        let num_workers = self.config.concurrency.min(num_cpus::get() * 256).max(64);
        let mut handles = Vec::with_capacity(num_workers);

        for _ in 0..num_workers {
            let target_space = Arc::clone(&self.target_space);
            let blacklist = Arc::clone(&self.blacklist);
            let cooldown = Arc::clone(&self.cooldown);
            let blackrock = Arc::clone(&self.blackrock);
            let shared_index = Arc::clone(&shared_index);
            let hits = Arc::clone(&hits_counter);
            let stop = Arc::clone(&stop_flag);
            let cancel = cancel_flag.clone();
            let probes_counter_worker = probes_counter.clone();
            let progress = Arc::clone(&progress);
            let rate_controller = Arc::clone(&self.rate_controller);
            let tx = result_tx.clone();
            let timeout_dur = Duration::from_millis(self.config.timeout_ms);
            let grab_banner = self.config.grab_banner;

            handles.push(tokio::spawn(async move {
                let chunk_size = 32u64;

                loop {
                    if stop.load(Ordering::Relaxed) || cancel.as_ref().map_or(false, |f| f.load(Ordering::Relaxed)) {
                        break;
                    }

                    let start_idx = shared_index.fetch_add(chunk_size, Ordering::Relaxed);
                    if start_idx >= total_targets {
                        break;
                    }

                    let end_idx = (start_idx + chunk_size).min(total_targets);
                    let actual_count = end_idx - start_idx;

                    // LEASE BATCH ONCE PER CHUNK
                    let (leased_count, start_nano) = rate_controller.lease_batch(actual_count);
                    let interval = rate_controller.packet_interval_nanos();

                    for i in 0..leased_count {
                        let idx = start_idx + i;
                        let scheduled_time = start_nano + i * interval;
                        rate_controller.pace_packet(scheduled_time);

                        let permuted = blackrock.shuffle(idx);
                        let (target_ip, target_port) = target_space.get_target(permuted);

                        if blacklist.is_blocked(target_ip) {
                            continue;
                        }

                        if !cooldown.allow_and_touch(target_ip) {
                            continue;
                        }

                        let socket_addr = SocketAddr::new(target_ip, target_port);
                        match timeout(timeout_dur, TcpStream::connect(socket_addr)).await {
                            Ok(Ok(_stream)) => {
                                let count = hits.fetch_add(1, Ordering::Relaxed) + 1;
                                progress.set_message(format!("{}", count));

                                let banner = if grab_banner {
                                    BannerGrabber::grab_banner(socket_addr, Duration::from_millis(1800)).await
                                } else {
                                    None
                                };

                                let hit = ScanHit {
                                    ip: target_ip,
                                    port: target_port,
                                    banner,
                                    timestamp: chrono::Utc::now(),
                                };
                                let _ = tx.send(hit);
                            }
                            _ => {}
                        }
                    }

                    // Sampled progress increment
                    progress.inc(actual_count);
                    if let Some(ref pc) = probes_counter_worker {
                        pc.fetch_add(actual_count, Ordering::Relaxed);
                    }
                }
            }));
        }

        for h in handles {
            let _ = h.await;
        }

        progress.finish_with_message(format!("Complete! Total hits: {}", hits_counter.load(Ordering::Relaxed)));
    }
}
