//! Lock-free byte ring: game threads push records, one consumer thread pops.
//!
//! Producers never wait. A push that finds the ring full, or another
//! producer in the middle of a push, drops the record and counts it. WRITE
//! takes its own spin lock, so in practice there is one producer at a time;
//! the producer flag only makes a rare concurrent call safe, not slow.
//!
//! Record layout (8-byte aligned): u32 payload length, u32 kind, u64 TSC,
//! payload, padding. Positions only grow; `& mask` maps them into the buffer.

use std::cell::UnsafeCell;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::*};

const HEADER: usize = 16;

pub struct Ring {
    buffer: Box<[UnsafeCell<u8>]>,
    mask: usize,
    /// Consumer position (bytes consumed).
    head: AtomicUsize,
    /// Producer position (bytes published).
    tail: AtomicUsize,
    producing: AtomicBool,
    pub pushed: AtomicU64,
    pub dropped: AtomicU64,
}

// Bytes are handed over through the Release/Acquire pair on `tail`/`head`.
unsafe impl Sync for Ring {}

pub struct Record {
    pub kind: u32,
    pub tsc: u64,
}

impl Ring {
    /// `capacity` is rounded up to a power of two (at least 64 bytes).
    pub fn new(capacity: usize) -> Ring {
        let capacity = capacity.max(64).next_power_of_two();
        Ring {
            buffer: (0..capacity).map(|_| UnsafeCell::new(0)).collect(),
            mask: capacity - 1,
            head: AtomicUsize::new(0),
            tail: AtomicUsize::new(0),
            producing: AtomicBool::new(false),
            pushed: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        }
    }

    pub fn capacity(&self) -> usize {
        self.mask + 1
    }

    fn record_size(payload: usize) -> usize {
        (HEADER + payload + 7) & !7
    }

    unsafe fn copy_in(&self, position: usize, bytes: &[u8]) {
        let start = position & self.mask;
        let first = bytes.len().min(self.capacity() - start);
        let base = self.buffer.as_ptr() as *mut u8;
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), base.add(start), first);
        std::ptr::copy_nonoverlapping(bytes.as_ptr().add(first), base, bytes.len() - first);
    }

    unsafe fn copy_out(&self, position: usize, out: &mut [u8]) {
        let start = position & self.mask;
        let first = out.len().min(self.capacity() - start);
        let base = self.buffer.as_ptr() as *const u8;
        std::ptr::copy_nonoverlapping(base.add(start), out.as_mut_ptr(), first);
        std::ptr::copy_nonoverlapping(base, out.as_mut_ptr().add(first), out.len() - first);
    }

    /// Pushes one record; never blocks, never allocates. False = dropped.
    pub fn push(&self, kind: u32, tsc: u64, payload: &[u8]) -> bool {
        self.push_parts(kind, tsc, &[payload])
    }

    /// Pushes one record whose payload is the concatenation of `parts`, copied
    /// straight into the ring (no temporary buffer on the producer's stack).
    pub fn push_parts(&self, kind: u32, tsc: u64, parts: &[&[u8]]) -> bool {
        let length: usize = parts.iter().map(|p| p.len()).sum();
        let size = Self::record_size(length);
        if size > self.capacity() || self.producing.swap(true, Acquire) {
            self.dropped.fetch_add(1, Relaxed);
            return false;
        }
        let tail = self.tail.load(Relaxed);
        let head = self.head.load(Acquire);
        if self.capacity() - (tail - head) < size {
            self.producing.store(false, Release);
            self.dropped.fetch_add(1, Relaxed);
            return false;
        }
        let mut header = [0u8; HEADER];
        header[0..4].copy_from_slice(&(length as u32).to_le_bytes());
        header[4..8].copy_from_slice(&kind.to_le_bytes());
        header[8..16].copy_from_slice(&tsc.to_le_bytes());
        unsafe {
            self.copy_in(tail, &header);
            let mut at = tail + HEADER;
            for part in parts {
                self.copy_in(at, part);
                at += part.len();
            }
        }
        self.tail.store(tail + size, Release);
        self.producing.store(false, Release);
        self.pushed.fetch_add(1, Relaxed);
        true
    }

    /// Pops one record into `payload` (single consumer only).
    pub fn pop(&self, payload: &mut Vec<u8>) -> Option<Record> {
        let head = self.head.load(Relaxed);
        if self.tail.load(Acquire) == head {
            return None;
        }
        let mut header = [0u8; HEADER];
        unsafe { self.copy_out(head, &mut header) };
        let length = u32::from_le_bytes(header[0..4].try_into().unwrap()) as usize;
        let kind = u32::from_le_bytes(header[4..8].try_into().unwrap());
        let tsc = u64::from_le_bytes(header[8..16].try_into().unwrap());
        payload.clear();
        payload.resize(length, 0);
        unsafe { self.copy_out(head + HEADER, payload) };
        self.head.store(head + Self::record_size(length), Release);
        Some(Record { kind, tsc })
    }
}
