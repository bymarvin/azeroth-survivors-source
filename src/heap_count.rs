//! The DLL's own heap use, counted at its allocator (the system allocator underneath, unchanged): live bytes, peak, allocations.
//! The periodic report logs it next to the hook counts, so a run shows how much of the game process's growth is ours
//! (soak 19.10.2026: ~18-24 MB/min private bytes in play, game or DLL unknown). Two relaxed atomics per allocation; no locks, no I/O.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};

pub struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static FREES: AtomicU64 = AtomicU64::new(0);

fn grew(size: usize) {
    let now = LIVE.fetch_add(size, Relaxed) + size;
    PEAK.fetch_max(now, Relaxed);
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc(layout);
        if !p.is_null() {
            grew(layout.size());
            ALLOCATIONS.fetch_add(1, Relaxed);
        }
        p
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc_zeroed(layout);
        if !p.is_null() {
            grew(layout.size());
            ALLOCATIONS.fetch_add(1, Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        System.dealloc(p, layout);
        LIVE.fetch_sub(layout.size(), Relaxed);
        FREES.fetch_add(1, Relaxed);
    }
    unsafe fn realloc(&self, p: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let q = System.realloc(p, layout, new_size);
        if !q.is_null() {
            if new_size >= layout.size() {
                grew(new_size - layout.size());
            } else {
                LIVE.fetch_sub(layout.size() - new_size, Relaxed);
            }
        }
        q
    }
}

/// (live bytes, peak bytes, allocations, frees)
pub fn stats() -> (usize, usize, u64, u64) {
    (LIVE.load(Relaxed), PEAK.load(Relaxed), ALLOCATIONS.load(Relaxed), FREES.load(Relaxed))
}

/// One line for the periodic report: "dll heap: live 12.3 MB, peak 15.0 MB, allocations 123456 (frees 120000)".
pub fn summary() -> String {
    let (live, peak, allocations, frees) = stats();
    format!("dll heap: live {:.1} MB, peak {:.1} MB, allocations {allocations} (frees {frees})", live as f64 / 1048576.0, peak as f64 / 1048576.0)
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_counter_follows_allocations_and_frees() {
        let (before, _, a0, f0) = super::stats();
        let block = vec![0u8; 4 << 20];
        let (during, peak, a1, _) = super::stats();
        assert!(during >= before + (4 << 20) - 65536, "live grew by the block: {before} -> {during}"); // other test threads allocate too
        assert!(peak >= during && a1 > a0);
        drop(block);
        let (after, _, _, f1) = super::stats();
        assert!(after + (4 << 20) <= during + 65536, "the free is counted: {during} -> {after}");
        assert!(f1 > f0);
        assert!(super::summary().starts_with("dll heap: live "));
        println!("[  OK  ] dll heap counter: {}", super::summary());
    }
}
