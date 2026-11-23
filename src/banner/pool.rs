/// Bounded Async Banner Worker Pool
///
/// Prevents unbound thread/task explosion. Raw sniffer thread pushes confirmed SYN-ACKs
/// into a bounded ring channel. A fixed pool of async workers connects and probes banners.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};

use crate::banner::BannerGrabber;
use crate::scanner::raw_syn::ScanHit;

pub struct BannerPool {
    tx: mpsc::Sender<ScanHit>,
}

impl BannerPool {
    pub fn spawn(
        workers_count: usize,
        timeout_ms: u64,
        out_tx: mpsc::UnboundedSender<ScanHit>,
    ) -> (Self, tokio::task::JoinHandle<()>) {
        let (tx, rx) = mpsc::channel::<ScanHit>(100_000);
        let rx = Arc::new(Mutex::new(rx));
        let timeout_dur = Duration::from_millis(timeout_ms);

        let handle = tokio::spawn(async move {
            let mut set = tokio::task::JoinSet::new();

            for _ in 0..workers_count {
                let worker_rx = Arc::clone(&rx);
                let worker_out = out_tx.clone();

                set.spawn(async move {
                    loop {
                        let hit = {
                            let mut lock = worker_rx.lock().await;
                            lock.recv().await
                        };

                        match hit {
                            Some(mut item) => {
                                let target = SocketAddr::new(item.ip, item.port);
                                let banner = BannerGrabber::grab_banner(target, timeout_dur).await;
                                item.banner = banner;
                                let _ = worker_out.send(item);
                            }
                            None => break,
                        }
                    }
                });
            }

            while let Some(_) = set.join_next().await {}
        });

        (Self { tx }, handle)
    }

    #[inline]
    pub fn submit(&self, hit: ScanHit) -> bool {
        self.tx.try_send(hit).is_ok()
    }
}
