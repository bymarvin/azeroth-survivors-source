//! Test-only visibility into the guest-apply queue, so offline tests can
//! check the bounded queue without a game. No game memory is touched here.

use crate::hook::APPLY_QUEUE;

/// Push validated packets exactly as the guest IPC pump does (bounded).
pub fn queue_for_apply(packets: Vec<(u16, Vec<u8>)>, cap: usize) {
    if let Ok(mut q) = APPLY_QUEUE.lock() {
        for p in packets {
            if q.len() >= cap {
                q.pop_front();
            }
            q.push_back(p);
        }
    }
}

pub fn apply_queue_len() -> usize {
    APPLY_QUEUE.lock().map(|q| q.len()).unwrap_or(0)
}

pub fn drain_apply_queue() -> Vec<(u16, Vec<u8>)> {
    APPLY_QUEUE.lock().map(|mut q| q.drain(..).collect()).unwrap_or_default()
}
