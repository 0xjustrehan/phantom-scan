/// Retransmission Controller for Unanswered Probes
///
/// Executes an optional second pass over targets that did not respond in the initial scan.
/// Paced at the observed network RTO to capture hosts affected by transient packet drops.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use parking_lot::RwLock;

pub struct RetransmitManager {
    max_retries: usize,
    answered_targets: Arc<RwLock<HashSet<(IpAddr, u16)>>>,
}

impl RetransmitManager {
    pub fn new(max_retries: usize) -> Self {
        Self {
            max_retries,
            answered_targets: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    #[inline]
    pub fn mark_answered(&self, ip: IpAddr, port: u16) {
        self.answered_targets.write().insert((ip, port));
    }

    #[inline]
    pub fn is_answered(&self, ip: IpAddr, port: u16) -> bool {
        self.answered_targets.read().contains(&(ip, port))
    }

    pub fn retries_enabled(&self) -> bool {
        self.max_retries > 0
    }
}
