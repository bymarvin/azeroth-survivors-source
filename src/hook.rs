//! Hooks and their handlers. Two kinds:
//!
//! * **WRITE** — a typed detour (`extern "system"`, integer ABI known and
//!   reviewed) that wraps the original call to measure its own time and the
//!   time inside WRITE, and records the gap between calls. Pushes nothing.
//! * **TICK** — a context stub (`stub.rs`): it observes entry without knowing
//!   the ABI, reads the native server pointer (rcx) and pushes an 8-byte
//!   record into a lock-free ring for the consumer thread. The game thread
//!   never waits: no lock, no allocation, no I/O in the handler.
//!
//! Both trampolines come from MinHook, which suspends the other game threads
//! and relocates any instruction pointer inside the patched bytes while it
//! installs the jump, so no thread can execute half-patched code.

use crate::ring::Ring;
use crate::stub::Context;
use crate::{context_stub, hook};
use core::arch::x86_64::_rdtsc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::OnceLock;

pub const KIND_TICK: u32 = 1;

/// Ring the consumer thread drains. Sized in lib.rs before hooks are enabled.
pub static TICK_RING: OnceLock<Ring> = OnceLock::new();

// ---- WRITE: measuring typed detour -----------------------------------------

type WriteFn = unsafe extern "system" fn(usize, usize, usize, usize) -> usize;

pub static WRITE_ORIGINAL: AtomicUsize = AtomicUsize::new(0);

pub const GAP_MS: [f64; 5] = [16.7, 33.3, 50.0, 100.0, 250.0];
pub static GAP_TICKS: [AtomicU64; 5] = [const { AtomicU64::new(u64::MAX) }; 5];

pub struct Window {
    pub calls: AtomicU64,
    pub inner_sum: AtomicU64,
    pub inner_max: AtomicU64,
    pub over_sum: AtomicU64,
    pub over_max: AtomicU64,
    pub gap_max: AtomicU64,
    pub gaps_over: [AtomicU64; 5],
}

impl Window {
    const fn new() -> Window {
        Window {
            calls: AtomicU64::new(0),
            inner_sum: AtomicU64::new(0),
            inner_max: AtomicU64::new(0),
            over_sum: AtomicU64::new(0),
            over_max: AtomicU64::new(0),
            gap_max: AtomicU64::new(0),
            gaps_over: [const { AtomicU64::new(0) }; 5],
        }
    }
}

pub static WINDOW: Window = Window::new();
static LAST_ENTRY: AtomicU64 = AtomicU64::new(0);

#[derive(Default, Clone, Copy)]
pub struct Snapshot {
    pub calls: u64,
    pub inner_sum: u64,
    pub inner_max: u64,
    pub over_sum: u64,
    pub over_max: u64,
    pub gap_max: u64,
    pub gaps_over: [u64; 5],
}

pub fn take() -> Snapshot {
    let w = &WINDOW;
    let mut gaps_over = [0; 5];
    for (slot, counter) in gaps_over.iter_mut().zip(&w.gaps_over) {
        *slot = counter.swap(0, Relaxed);
    }
    Snapshot {
        calls: w.calls.swap(0, Relaxed),
        inner_sum: w.inner_sum.swap(0, Relaxed),
        inner_max: w.inner_max.swap(0, Relaxed),
        over_sum: w.over_sum.swap(0, Relaxed),
        over_max: w.over_max.swap(0, Relaxed),
        gap_max: w.gap_max.swap(0, Relaxed),
        gaps_over,
    }
}

#[inline(always)]
fn ticks() -> u64 {
    unsafe { _rdtsc() }
}

// ---- WRITE capture (host side of the co-op slice) ---------------------------
//
// Off unless a co-op session enables it. At WRITE entry the game has already
// enciphered this batch, so the connection holds its *end* cipher state. We
// copy the batch bytes, the 40-byte key and that end state into a ring; the
// network thread decrypts there. Same reads and checks as visibility_bridge.py
// at its WRITE breakpoint: one connection, live flag, server→client queue.

pub const KIND_BATCH: u32 = 2;
/// Batch record prefix: key (40) + end index (1) + end previous (1) + connection (8).
pub const BATCH_PREFIX: usize = crate::cipher::KEY_LEN + 2 + 8;
pub const MAX_CAPTURE: usize = 256 * 1024;

pub static CAPTURE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// `server.connections` vector offset for this build (profile field 0x918).
pub static CONNECTIONS_OFFSET: AtomicUsize = AtomicUsize::new(0);
pub static BATCH_RING: OnceLock<Ring> = OnceLock::new();
pub static BATCH_TOO_LARGE: AtomicU64 = AtomicU64::new(0);

// Connection struct offsets, unchanged across the supported builds
// (hardcoded the same way in visibility_bridge.py, accepted on 0.93.1).
const CONN_LIVE: usize = 0x30;
const CONN_SERVER_KEY: usize = 0x31;
const CONN_SERVER_END: usize = 0x59;
const CONN_SERVER_QUEUE: usize = 0x90;

#[inline(always)]
unsafe fn read_u64(address: usize) -> u64 {
    core::ptr::read_unaligned(address as *const u64)
}

/// Runs on the game thread at WRITE entry when capture is on. Never blocks and
/// never allocates: a fixed stack buffer for the prefix, the payload copied
/// straight from the game buffer into the ring.
unsafe fn capture_batch(queue: usize, data: usize, length: usize) {
    let server = TICK_SERVER.load(Relaxed) as usize;
    let offset = CONNECTIONS_OFFSET.load(Relaxed);
    let Some(ring) = BATCH_RING.get() else { return };
    if server == 0 || offset == 0 {
        return;
    }
    let (pointer, count) = (read_u64(server + offset) as usize, read_u64(server + offset + 8));
    if count != 1 || pointer == 0 {
        return;
    }
    let connection = pointer;
    if *((connection + CONN_LIVE) as *const u8) != 1 {
        return;
    }
    if queue != read_u64(connection + CONN_SERVER_QUEUE) as usize + 0x10 {
        return;
    }
    if length > MAX_CAPTURE {
        BATCH_TOO_LARGE.fetch_add(1, Relaxed);
        return;
    }
    let key = core::slice::from_raw_parts((connection + CONN_SERVER_KEY) as *const u8, crate::cipher::KEY_LEN);
    let end = core::slice::from_raw_parts((connection + CONN_SERVER_END) as *const u8, 2);
    let connection_bytes = (connection as u64).to_le_bytes();
    let bytes = core::slice::from_raw_parts(data as *const u8, length);
    ring.push_parts(KIND_BATCH, ticks(), &[key, end, &connection_bytes, bytes]);
}

// ---- read-only feed of the local player (client direction + SERIALIZE bootstrap) ----
//
// On with AZCOOP_OBSERVE=1. Same connection lookup and guards as `capture_batch`; the
// client direction is the queue the server fills with the player's own packets.

pub static FEED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
pub static FEED_RING: OnceLock<Ring> = OnceLock::new();
const CONN_CLIENT_QUEUE: usize = 0x88;
const CONN_CLIENT_KEY: usize = 0x5B;
const CONN_CLIENT_STATE: usize = 0x83;

unsafe fn feed_client_batch(queue: usize, data: usize, length: usize) {
    let server = TICK_SERVER.load(Relaxed) as usize;
    let offset = CONNECTIONS_OFFSET.load(Relaxed);
    let Some(ring) = FEED_RING.get() else { return };
    if server == 0 || offset == 0 || length == 0 || length > MAX_CAPTURE {
        return;
    }
    let (pointer, count) = (read_u64(server + offset) as usize, read_u64(server + offset + 8));
    if count != 1 || pointer == 0 || *((pointer + CONN_LIVE) as *const u8) != 1 {
        return;
    }
    if queue != read_u64(pointer + CONN_CLIENT_QUEUE) as usize + 0x10 {
        return;
    }
    let key = core::slice::from_raw_parts((pointer + CONN_CLIENT_KEY) as *const u8, crate::cipher::KEY_LEN);
    let state = core::slice::from_raw_parts((pointer + CONN_CLIENT_STATE) as *const u8, 2);
    let connection = (pointer as u64).to_le_bytes();
    let bytes = core::slice::from_raw_parts(data as *const u8, length);
    ring.push_parts(crate::feed::KIND_CLIENT, ticks(), &[key, state, &connection, bytes]);
}

/// Test hook: runs the client-direction capture on explicit arguments.
pub unsafe fn feed_client_batch_for_test(queue: usize, data: usize, length: usize) {
    feed_client_batch(queue, data, length)
}

pub static SERIALIZE_TRAMPOLINE: AtomicUsize = AtomicUsize::new(0);
/// SERIALIZE is observe id 19.
context_stub!(serialize_stub, 19u64, hook::serialize_handler, hook::SERIALIZE_TRAMPOLINE);

/// Counts the call (observe) and copies the two bootstrap packets the host needs: the login
/// template (0xA9 of the verified local-player shape) and the name reply (0x51). The packet
/// struct is the game's own at rdx: body pointer at +8, size at +16, opcode (u16) at +24.
pub extern "C" fn serialize_handler(ctx: *const Context) {
    let ctx = unsafe { &*ctx };
    crate::observe::note(ctx);
    if !FEED.load(Relaxed) || ctx.rdx == 0 {
        return;
    }
    let Some(ring) = FEED_RING.get() else { return };
    unsafe {
        let packet = ctx.rdx as usize;
        let (body, size, opcode) = (read_u64(packet + 8) as usize, read_u64(packet + 16) as usize, core::ptr::read_unaligned((packet + 24) as *const u16));
        if body == 0 || size == 0 || size > MAX_CAPTURE {
            return;
        }
        let bytes = core::slice::from_raw_parts(body as *const u8, size);
        let wanted = opcode == 0x51 || (opcode == 0xA9 && bytes.starts_with(&crate::feed::TEMPLATE_PREFIX));
        if wanted {
            ring.push_parts(crate::feed::KIND_SERIALIZE, ticks(), &[&opcode.to_le_bytes(), &(size as u32).to_le_bytes(), bytes]);
        }
    }
}

// ---- WRITE guest apply (OFF by default) -------------------------------------
//
// Appends validated remote co-op packets to the guest's own outgoing batch,
// the way visibility_bridge.py does at WRITE. On only with AZCOOP_APPLY=1 in a
// co-op session. It rebuilds the batch with net::inject_into_batch (tested
// byte-identical to the reference), keeps it in a reusable scratch buffer,
// advances the connection's cipher boundary so the game's next batch stays in
// sync, and forwards WRITE with the rebuilt buffer/length.

pub static APPLY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// Validated remote packets waiting to be appended (filled by the guest IPC
/// pump after accept_world; bounded by the pump).
pub static APPLY_QUEUE: std::sync::Mutex<std::collections::VecDeque<(u16, Vec<u8>)>> =
    std::sync::Mutex::new(std::collections::VecDeque::new());
pub static APPLIED_PACKETS: AtomicU64 = AtomicU64::new(0);
/// (connection, our cipher end after the last rebuilt batch); None until the
/// first rebuilt batch on that connection.
static APPLY_STATE: std::sync::Mutex<(usize, Option<crate::cipher::CipherState>)> =
    std::sync::Mutex::new((0, None));
static APPLY_SCRATCH: std::sync::Mutex<Vec<u8>> = std::sync::Mutex::new(Vec::new());

/// Same connection lookup and guards as `capture_batch`.
unsafe fn live_connection(queue: usize) -> Option<usize> {
    let server = TICK_SERVER.load(Relaxed) as usize;
    let offset = CONNECTIONS_OFFSET.load(Relaxed);
    if server == 0 || offset == 0 {
        return None;
    }
    let (pointer, count) = (read_u64(server + offset) as usize, read_u64(server + offset + 8));
    if count != 1 || pointer == 0 || *((pointer + CONN_LIVE) as *const u8) != 1 {
        return None;
    }
    if queue != read_u64(pointer + CONN_SERVER_QUEUE) as usize + 0x10 {
        return None;
    }
    Some(pointer)
}

/// With apply on and remote packets pending, rebuild this batch with them and
/// return the (pointer, length) to forward. The scratch buffer lock is held by
/// the caller across the forwarded call, so the pointer stays valid.
unsafe fn apply_batch(queue: usize, data: usize, length: usize, scratch: &mut Vec<u8>) -> Option<(usize, usize)> {
    let connection = live_connection(queue)?;
    if length > MAX_CAPTURE {
        return None;
    }
    let inject: Vec<(u16, Vec<u8>)> = {
        let mut q = APPLY_QUEUE.lock().ok()?;
        if q.is_empty() {
            return None;
        }
        q.drain(..).collect()
    };
    let mut key = [0u8; crate::cipher::KEY_LEN];
    key.copy_from_slice(core::slice::from_raw_parts((connection + CONN_SERVER_KEY) as *const u8, crate::cipher::KEY_LEN));
    let conn_end = crate::cipher::CipherState {
        index: *((connection + CONN_SERVER_END) as *const u8),
        previous: *((connection + CONN_SERVER_END + 1) as *const u8),
    };
    let existing = core::slice::from_raw_parts(data as *const u8, length);

    let mut state = APPLY_STATE.lock().ok()?;
    let batch_start = if state.0 == connection { state.1 } else { None };
    let (rebuilt, new_end) = crate::net::inject_into_batch(existing, &key, batch_start, conn_end, &inject).ok()?;
    if rebuilt.len() > MAX_CAPTURE {
        return None;
    }
    // Keep the game's cipher boundary in step with the longer batch, and
    // remember it as the start state of the next batch on this connection.
    *((connection + CONN_SERVER_END) as *mut u8) = new_end.index;
    *((connection + CONN_SERVER_END + 1) as *mut u8) = new_end.previous;
    *state = (connection, Some(new_end));
    APPLIED_PACKETS.fetch_add(inject.len() as u64, Relaxed);

    scratch.clear();
    scratch.extend_from_slice(&rebuilt);
    Some((scratch.as_ptr() as usize, scratch.len()))
}

pub unsafe extern "system" fn write_detour(rcx: usize, rdx: usize, r8: usize, r9: usize) -> usize {
    let entry = ticks();
    if crate::OBSERVING.load(Relaxed) {
        crate::observe::note_thread(crate::observe::SLOT_WRITE);
    }
    if CAPTURE.load(Relaxed) {
        capture_batch(rcx, rdx, r8);
    }
    if FEED.load(Relaxed) {
        feed_client_batch(rcx, rdx, r8);
    }
    let original: WriteFn = core::mem::transmute(WRITE_ORIGINAL.load(Relaxed));
    let before = ticks();
    // Guest apply may substitute the batch for the forwarded call; the scratch
    // lock is held across the call so the pointer stays valid.
    let mut scratch = if APPLY.load(Relaxed) { APPLY_SCRATCH.lock().ok() } else { None };
    let (call_rdx, call_r8) = match scratch.as_mut().and_then(|s| apply_batch(rcx, rdx, r8, s)) {
        Some(sub) => sub,
        None => (rdx, r8),
    };
    let result = original(rcx, call_rdx, call_r8, r9);
    drop(scratch);
    let after = ticks();

    let w = &WINDOW;
    w.calls.fetch_add(1, Relaxed);
    let inner = after.wrapping_sub(before);
    w.inner_sum.fetch_add(inner, Relaxed);
    w.inner_max.fetch_max(inner, Relaxed);
    let previous = LAST_ENTRY.swap(entry, Relaxed);
    if previous != 0 && entry > previous {
        let gap = entry - previous;
        w.gap_max.fetch_max(gap, Relaxed);
        for (limit, counter) in GAP_TICKS.iter().zip(&w.gaps_over) {
            if gap > limit.load(Relaxed) {
                counter.fetch_add(1, Relaxed);
            }
        }
    }
    let overhead = before.wrapping_sub(entry) + ticks().wrapping_sub(after);
    w.over_sum.fetch_add(overhead, Relaxed);
    w.over_max.fetch_max(overhead, Relaxed);
    result
}

// ---- TICK: context stub + handler ------------------------------------------

pub static TICK_TRAMPOLINE: AtomicUsize = AtomicUsize::new(0);
pub static TICK_SEEN: AtomicU64 = AtomicU64::new(0);
pub static TICK_SERVER: AtomicU64 = AtomicU64::new(0);

context_stub!(tick_stub, KIND_TICK as u64, hook::tick_handler, hook::TICK_TRAMPOLINE);

/// Runs on the game thread at every TICK. Reads only the server pointer (rcx)
/// and pushes an 8-byte record; everything else is left to the consumer.
pub extern "C" fn tick_handler(ctx: *const Context) {
    let ctx = unsafe { &*ctx };
    TICK_SEEN.fetch_add(1, Relaxed);
    if crate::OBSERVING.load(Relaxed) {
        crate::observe::note_thread(crate::observe::SLOT_TICK);
    }
    TICK_SERVER.store(ctx.rcx, Relaxed);
    if let Some(ring) = TICK_RING.get() {
        ring.push(KIND_TICK, ticks(), &ctx.rcx.to_le_bytes());
    }
}
