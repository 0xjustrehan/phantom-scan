/// High-Performance Multi-Threaded Wire-Speed Raw SYN Scanner with Retransmit Pass
///
/// Features:
/// - Multi-Core TX Engine with independent socket descriptors per thread.
/// - Exact Rate Pacing: Single atomic lease per chunk via Leased Batch Token Bucket.
/// - Real Per-Packet RTT: Cyclic sequence timestamp ring + TCP Timestamp TSecr extraction.
/// - Bounded Banner Worker Pool: Zero thread explosion.
/// - Stateful Evasion: Advancing synthetic uptime TSval + monotonic Windows IP ID + ephemeral source ports.
/// - Retransmission Engine: Automatically re-probes unanswered targets based on observed RTT.
/// - BPF Filter on Linux: Discards non-SYN-ACK packets in kernel space.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use indicatif::{ProgressBar, ProgressStyle};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::sync::mpsc;

use crate::banner::BannerPool;
use crate::blacklist::BlacklistTrie;
use crate::controller::{GlobalRateController, RetransmitManager, RttEstimator};
use crate::crypto::{Blackrock, SynCookie};
use crate::evasion::{OsProfile, StatefulEvasion, SubnetCooldown};
use crate::packet::{PacketBuilder, PacketParser};
use crate::targets::TargetSpace;

#[derive(Debug, Clone)]
pub struct ScanHit {
    pub ip: IpAddr,
    pub port: u16,
    pub banner: Option<String>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone)]
pub struct RawSynScannerConfig {
    pub src_ip_v4: Option<Ipv4Addr>,
    pub src_ip_v6: Option<Ipv6Addr>,
    pub src_port: u16,
    pub src_port_range: Option<(u16, u16)>,
    pub rate_limit_pps: u64,
    pub profile: OsProfile,
    pub tx_threads: usize,
    pub grab_banner: bool,
    pub randomize_options: bool,
    pub retries: usize,
    pub interface: Option<String>,
    pub gateway_mac: Option<[u8; 6]>,
    pub source_mac: Option<[u8; 6]>,
    pub fanout_mode: String,
}

pub struct RawSynScanner {
    target_space: Arc<TargetSpace>,
    blacklist: Arc<BlacklistTrie>,
    cooldown: Arc<SubnetCooldown>,
    cookie: Arc<SynCookie>,
    rtt_estimator: Arc<RttEstimator>,
    rate_controller: Arc<GlobalRateController>,
    retransmit_manager: Arc<RetransmitManager>,
    stateful_evasion: Arc<StatefulEvasion>,
    config: RawSynScannerConfig,
}

impl RawSynScanner {
    pub fn new(
        target_space: TargetSpace,
        blacklist: BlacklistTrie,
        cooldown: SubnetCooldown,
        cookie: SynCookie,
        config: RawSynScannerConfig,
    ) -> Self {
        Self::new_with_arcs(
            Arc::new(target_space),
            Arc::new(blacklist),
            Arc::new(cooldown),
            Arc::new(cookie),
            config,
        )
    }

    pub fn new_with_arcs(
        target_space: Arc<TargetSpace>,
        blacklist: Arc<BlacklistTrie>,
        cooldown: Arc<SubnetCooldown>,
        cookie: Arc<SynCookie>,
        config: RawSynScannerConfig,
    ) -> Self {
        let pps = config.rate_limit_pps;
        let (min_port, max_port) = config.src_port_range.unwrap_or((config.src_port, config.src_port));
        let retries = config.retries;

        Self {
            target_space,
            blacklist,
            cooldown,
            cookie,
            rtt_estimator: Arc::new(RttEstimator::new()),
            rate_controller: Arc::new(GlobalRateController::new(pps)),
            retransmit_manager: Arc::new(RetransmitManager::new(retries)),
            stateful_evasion: Arc::new(StatefulEvasion::new(min_port, max_port)),
            config,
        }
    }

    fn create_tx_socket(is_v6: bool) -> std::io::Result<Socket> {
        let domain = if is_v6 { Domain::IPV6 } else { Domain::IPV4 };

        #[cfg(unix)]
        let socket = {
            let proto = libc::IPPROTO_RAW;
            Socket::new(domain, Type::RAW, Some(Protocol::from(proto)))?
        };

        #[cfg(windows)]
        let socket = {
            let proto = windows_sys::Win32::Networking::WinSock::IPPROTO_RAW as i32;
            let s = Socket::new(domain, Type::RAW, Some(Protocol::from(proto)))?;
            if !is_v6 {
                s.set_header_included_v4(true)?;
            }
            s
        };

        socket.set_send_buffer_size(8 * 1024 * 1024)?;
        Ok(socket)
    }

    fn create_rx_socket(bind_ip: IpAddr) -> std::io::Result<Socket> {
        let domain = match bind_ip {
            IpAddr::V4(_) => Domain::IPV4,
            IpAddr::V6(_) => Domain::IPV6,
        };

        #[cfg(unix)]
        let socket = {
            let proto = libc::IPPROTO_TCP;
            let s = Socket::new(domain, Type::RAW, Some(Protocol::from(proto)))?;
            let _ = s.set_recv_buffer_size(16 * 1024 * 1024);

            #[cfg(target_os = "linux")]
            Self::attach_linux_bpf_filter(&s);

            s
        };

        #[cfg(windows)]
        let socket = {
            let s = match bind_ip {
                IpAddr::V4(v4) => {
                    let sock = Socket::new(domain, Type::RAW, Some(Protocol::from(windows_sys::Win32::Networking::WinSock::IPPROTO_IP as i32)))?;
                    let addr = SocketAddrV4::new(v4, 0);
                    sock.bind(&addr.into())?;
                    sock
                }
                IpAddr::V6(v6) => {
                    let sock = Socket::new(domain, Type::RAW, Some(Protocol::from(windows_sys::Win32::Networking::WinSock::IPPROTO_IPV6 as i32)))?;
                    let addr = std::net::SocketAddrV6::new(v6, 0, 0, 0);
                    sock.bind(&addr.into())?;
                    sock
                }
            };
            let _ = s.set_recv_buffer_size(16 * 1024 * 1024);
            s
        };

        socket.set_nonblocking(true)?;
        Ok(socket)
    }

    #[cfg(all(unix, target_os = "linux"))]
    fn attach_linux_bpf_filter(socket: &Socket) {
        use std::os::unix::io::AsRawFd;
        #[repr(C)]
        struct SockFilter { code: u16, jt: u8, jf: u8, k: u32 }
        #[repr(C)]
        struct SockFprog { len: u16, filter: *const SockFilter }

        let bpf_code = [
            SockFilter { code: 0x30, jt: 0, jf: 0, k: 9 },
            SockFilter { code: 0x15, jt: 0, jf: 5, k: 6 },
            SockFilter { code: 0xb1, jt: 0, jf: 0, k: 0 },
            SockFilter { code: 0x50, jt: 0, jf: 0, k: 13 },
            SockFilter { code: 0x54, jt: 0, jf: 0, k: 0x12 },
            SockFilter { code: 0x15, jt: 1, jf: 0, k: 0x12 },
            SockFilter { code: 0x06, jt: 0, jf: 0, k: 0 },
            SockFilter { code: 0x06, jt: 0, jf: 0, k: 65535 },
        ];

        let prog = SockFprog {
            len: bpf_code.len() as u16,
            filter: bpf_code.as_ptr(),
        };

        unsafe {
            let _ = libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ATTACH_FILTER,
                &prog as *const _ as *const libc::c_void,
                std::mem::size_of::<SockFprog>() as libc::socklen_t,
            );
        }
    }

    pub fn run(self, result_tx: mpsc::UnboundedSender<ScanHit>, seed: u64) -> std::io::Result<()> {
        self.run_with_cancel(result_tx, seed, None, None)
    }

    pub fn run_with_cancel(
        self,
        result_tx: mpsc::UnboundedSender<ScanHit>,
        seed: u64,
        cancel_flag: Option<Arc<AtomicBool>>,
        probes_counter: Option<Arc<AtomicU64>>,
    ) -> std::io::Result<()> {
        let total_targets = self.target_space.total_targets;
        let progress = Arc::new(ProgressBar::new(total_targets));
        progress.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) | Rate: {per_sec} | Hits: {msg} | RTT: {prefix} | ETA: {eta}")
                .unwrap()
                .progress_chars("#>-"),
        );

        let hits_counter = Arc::new(AtomicU64::new(0));
        let rx_stop = Arc::new(AtomicBool::new(false));
        let tx_stop = Arc::new(AtomicBool::new(false));

        // 1. Setup Banner Pool
        let (banner_pool, banner_worker_handle) = if self.config.grab_banner {
            let (pool, handle) = BannerPool::spawn(128, 1800, result_tx.clone());
            (Some(pool), Some(handle))
        } else {
            (None, None)
        };

        // 2. Setup RX Sniffer
        let primary_rx_ip = self.config.src_ip_v4.map(IpAddr::V4)
            .or_else(|| self.config.src_ip_v6.map(IpAddr::V6))
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "No valid source IP provided"))?;

        let rx_socket = Self::create_rx_socket(primary_rx_ip)?;
        let cookie_rx = Arc::clone(&self.cookie);
        let hits_rx = Arc::clone(&hits_counter);
        let progress_rx = Arc::clone(&progress);
        let rx_stop_clone = Arc::clone(&rx_stop);
        let rtt_est = Arc::clone(&self.rtt_estimator);
        let rate_ctrl_rx = Arc::clone(&self.rate_controller);
        let retransmit_mgr = Arc::clone(&self.retransmit_manager);
        let tx_out = result_tx.clone();
        let src_v4 = self.config.src_ip_v4.map(IpAddr::V4);
        let src_v6 = self.config.src_ip_v6.map(IpAddr::V6);

        let rx_handle = thread::spawn(move || {
            let mut buf = [0u8; 65535];
            let uninit_buf = unsafe {
                std::slice::from_raw_parts_mut(
                    buf.as_mut_ptr() as *mut std::mem::MaybeUninit<u8>,
                    buf.len(),
                )
            };

            let mut idle_spins = 0u32;
            while !rx_stop_clone.load(Ordering::Relaxed) {
                match rx_socket.recv(uninit_buf) {
                    Ok(len) if len > 0 => {
                        idle_spins = 0;
                        if let Some(resp) = PacketParser::parse_ip_packet(&buf[..len]) {
                            let is_our_ip = Some(resp.dst_ip) == src_v4 || Some(resp.dst_ip) == src_v6;
                            if is_our_ip && resp.is_syn_ack {
                                if cookie_rx.verify_ack(resp.dst_ip, resp.src_ip, resp.dst_port, resp.src_port, resp.ack_num) {
                                    let count = hits_rx.fetch_add(1, Ordering::Relaxed) + 1;
                                    progress_rx.set_message(format!("{}", count));

                                    // Mark target answered in retransmit manager
                                    retransmit_mgr.mark_answered(resp.src_ip, resp.src_port);

                                    if let Some(rtt_us) = rtt_est.ring.calculate_rtt_us(resp.ack_num, resp.ts_ecr) {
                                        rtt_est.record_sample(rtt_us);
                                        rate_ctrl_rx.ramp_up();
                                        progress_rx.set_prefix(format!("{:.1}ms", rtt_est.average_rtt_ms()));
                                    }

                                    let hit = ScanHit {
                                        ip: resp.src_ip,
                                        port: resp.src_port,
                                        banner: None,
                                        timestamp: chrono::Utc::now(),
                                    };

                                    if let Some(ref pool) = banner_pool {
                                        if !pool.submit(hit.clone()) {
                                            let _ = tx_out.send(hit);
                                        }
                                    } else {
                                        let _ = tx_out.send(hit);
                                    }
                                }
                            }
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        idle_spins += 1;
                        if idle_spins < 100 {
                            std::hint::spin_loop();
                        } else if idle_spins < 1000 {
                            thread::yield_now();
                        } else {
                            thread::sleep(Duration::from_micros(20));
                        }
                    }
                    Err(_) => {
                        thread::sleep(Duration::from_micros(200));
                    }
                    _ => {}
                }
            }
        });

        // 3. Multi-Threaded TX Injection Engine
        let num_tx_workers = self.config.tx_threads.max(1).min(num_cpus::get() * 2);
        let shared_index = Arc::new(AtomicU64::new(0));
        let blackrock = Arc::new(Blackrock::new(total_targets, seed));

        let mut tx_handles = Vec::with_capacity(num_tx_workers);

        for _ in 0..num_tx_workers {
            let tx_v4 = self.config.src_ip_v4.map(|_| Self::create_tx_socket(false)).transpose()?;
            let tx_v6 = self.config.src_ip_v6.map(|_| Self::create_tx_socket(true)).transpose()?;

            let shared_index = Arc::clone(&shared_index);
            let blackrock = Arc::clone(&blackrock);
            let target_space = Arc::clone(&self.target_space);
            let blacklist = Arc::clone(&self.blacklist);
            let cooldown = Arc::clone(&self.cooldown);
            let cookie = Arc::clone(&self.cookie);
            let rtt_estimator = Arc::clone(&self.rtt_estimator);
            let rate_controller = Arc::clone(&self.rate_controller);
            let stateful = Arc::clone(&self.stateful_evasion);
            let progress = Arc::clone(&progress);
            let tx_stop = Arc::clone(&tx_stop);
            let cancel_clone = cancel_flag.clone();
            let probes_clone = probes_counter.clone();
            let src_v4 = self.config.src_ip_v4;
            let src_v6 = self.config.src_ip_v6;
            let base_src_port = self.config.src_port;
            let profile = self.config.profile;
            let randomize_opts = self.config.randomize_options;

            tx_handles.push(thread::spawn(move || {
                let mut pkt_buffer = [0u8; 128];
                let chunk_size = 64u64;

                while !tx_stop.load(Ordering::Relaxed) && !cancel_clone.as_ref().map_or(false, |f| f.load(Ordering::Relaxed)) {
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

                        // Stateful evasion: dynamic advancing TSval + stateful IP ID + ephemeral source port
                        let tsval = stateful.current_tsval();
                        let ip_id = stateful.next_ip_id(profile);
                        let stack = profile.build_stack(tsval, ip_id, randomize_opts);
                        let src_port = stateful.pick_source_port(base_src_port);

                        match target_ip {
                            IpAddr::V4(dst_v4) => {
                                if let (Some(ref sock), Some(src_ip)) = (&tx_v4, src_v4) {
                                    let seq = cookie.generate_seq(IpAddr::V4(src_ip), target_ip, src_port, target_port);
                                    rtt_estimator.ring.record_tx(seq);

                                    let pkt_len = PacketBuilder::build_syn_packet(
                                        &mut pkt_buffer,
                                        src_ip,
                                        dst_v4,
                                        src_port,
                                        target_port,
                                        seq,
                                        stack.ip_id,
                                        stack.ttl,
                                        stack.window_size,
                                        &stack.options,
                                    );

                                    let dest_addr = SocketAddrV4::new(dst_v4, target_port);
                                    if let Err(ref e) = sock.send_to(&pkt_buffer[..pkt_len], &dest_addr.into()) {
                                        if e.kind() == std::io::ErrorKind::WouldBlock {
                                            rate_controller.backoff();
                                        }
                                    }
                                }
                            }
                            IpAddr::V6(dst_v6) => {
                                if let (Some(ref sock), Some(src_ip)) = (&tx_v6, src_v6) {
                                    let seq = cookie.generate_seq(IpAddr::V6(src_ip), target_ip, src_port, target_port);
                                    rtt_estimator.ring.record_tx(seq);

                                    let pkt_len = PacketBuilder::build_ipv6_syn_packet(
                                        &mut pkt_buffer,
                                        src_ip,
                                        dst_v6,
                                        src_port,
                                        target_port,
                                        seq,
                                        stack.ttl,
                                        stack.window_size,
                                        &stack.options,
                                    );

                                    let dest_addr = SocketAddr::new(IpAddr::V6(dst_v6), target_port);
                                    let _ = sock.send_to(&pkt_buffer[..pkt_len], &dest_addr.into());
                                }
                            }
                        }
                    }

                    progress.inc(actual_count);
                    if let Some(ref pc) = probes_clone {
                        pc.fetch_add(actual_count, Ordering::Relaxed);
                    }
                }
            }));
        }

        for h in tx_handles {
            let _ = h.join();
        }

        // 4. Adaptive Post-Scan Drain
        let drain_dur = self.rtt_estimator.adaptive_drain_duration();
        thread::sleep(drain_dur);

        // 5. Retransmission Pass (if enabled)
        let is_cancelled = cancel_flag.as_ref().map_or(false, |f| f.load(Ordering::Relaxed));
        if self.config.retries > 0 && !is_cancelled {
            let mut unanswered: Vec<(IpAddr, u16)> = Vec::new();
            for i in 0..total_targets {
                let (ip, port) = self.target_space.get_target(i);
                if !self.retransmit_manager.is_answered(ip, port) {
                    unanswered.push((ip, port));
                }
            }

            if !unanswered.is_empty() {
                println!(
                    "\n[*] Retransmission pass 1/{}: probing {} unanswered targets at RTO {:.1}ms...",
                    self.config.retries,
                    unanswered.len(),
                    self.rtt_estimator.average_rtt_ms()
                );

                let retry_sock_v4 = self.config.src_ip_v4.and_then(|_| Self::create_tx_socket(false).ok());
                let retry_sock_v6 = self.config.src_ip_v6.and_then(|_| Self::create_tx_socket(true).ok());
                let mut retry_buf = [0u8; 128];

                for (target_ip, target_port) in unanswered {
                    if cancel_flag.as_ref().map_or(false, |f| f.load(Ordering::Relaxed)) {
                        break;
                    }
                    let tsval = self.stateful_evasion.current_tsval();
                    let ip_id = self.stateful_evasion.next_ip_id(self.config.profile);
                    let stack = self.config.profile.build_stack(tsval, ip_id, self.config.randomize_options);
                    let src_port = self.stateful_evasion.pick_source_port(self.config.src_port);

                    match target_ip {
                        IpAddr::V4(dst_v4) => {
                            if let (Some(ref sock), Some(src_v4)) = (&retry_sock_v4, self.config.src_ip_v4) {
                                let seq = self.cookie.generate_seq(IpAddr::V4(src_v4), target_ip, src_port, target_port);
                                self.rtt_estimator.ring.record_tx(seq);
                                let len = PacketBuilder::build_syn_packet(
                                    &mut retry_buf,
                                    src_v4,
                                    dst_v4,
                                    src_port,
                                    target_port,
                                    seq,
                                    ip_id,
                                    stack.ttl,
                                    stack.window_size,
                                    &stack.options,
                                );
                                let dest = SocketAddr::new(IpAddr::V4(dst_v4), target_port);
                                let _ = sock.send_to(&retry_buf[..len], &dest.into());
                            }
                        }
                        IpAddr::V6(dst_v6) => {
                            if let (Some(ref sock), Some(src_v6)) = (&retry_sock_v6, self.config.src_ip_v6) {
                                let seq = self.cookie.generate_seq(IpAddr::V6(src_v6), target_ip, src_port, target_port);
                                self.rtt_estimator.ring.record_tx(seq);
                                let len = PacketBuilder::build_ipv6_syn_packet(
                                    &mut retry_buf,
                                    src_v6,
                                    dst_v6,
                                    src_port,
                                    target_port,
                                    seq,
                                    stack.ttl,
                                    stack.window_size,
                                    &stack.options,
                                );
                                let dest = SocketAddr::new(IpAddr::V6(dst_v6), target_port);
                                let _ = sock.send_to(&retry_buf[..len], &dest.into());
                            }
                        }
                    }
                    thread::sleep(Duration::from_micros(50));
                }
                thread::sleep(self.rtt_estimator.adaptive_drain_duration());
            }
        }

        rx_stop.store(true, Ordering::Relaxed);
        let _ = rx_handle.join();

        if let Some(handle) = banner_worker_handle {
            handle.abort();
        }

        progress.finish_with_message(format!(
            "Finished! Hits: {} | Avg RTT: {:.1}ms ({} samples)",
            hits_counter.load(Ordering::Relaxed),
            self.rtt_estimator.average_rtt_ms(),
            self.rtt_estimator.samples()
        ));

        Ok(())
    }
}
