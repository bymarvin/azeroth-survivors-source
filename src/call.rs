//! Injected native calls: the in-process form of the Python's `Native.call_before`.
//!
//! The debugger rewrote the stopped thread's registers so that it ran one game function, with a
//! return address on an `int3` page (`call_return`) so that it noticed the end of the call. Here
//! the same call is made on the game thread itself, through a small thunk whose `call` is followed by
//! a known instruction: that instruction's address is `call_return`. A hook that fires inside the
//! call and finds `call_return` at the top of its stack knows that the game is entering the very
//! function the bridge called (and not one the game called on its own), exactly the test the
//! Python makes (`q(client.memory(rsp), 8) == client.call_return`).

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

/// Registers, float arguments and stack arguments of one call (Windows x64).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct CallFrame {
    /// Absolute address of the function.
    pub entry: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub r8: u64,
    pub r9: u64,
    /// Low 64 bits of XMM1..XMM3 (a float argument sits in the low 32 bits).
    pub xmm1: u64,
    pub xmm2: u64,
    pub xmm3: u64,
    /// Arguments from the fifth on: `stack[0]` is `[rsp+0x20]` before the `call`, i.e. `[entry_rsp+0x28]`.
    pub stack: [u64; 8],
    /// Out: rax after the call.
    pub rax: u64,
}

pub const OFF_ENTRY: usize = 0;
pub const OFF_RCX: usize = 8;
pub const OFF_RDX: usize = 16;
pub const OFF_R8: usize = 24;
pub const OFF_R9: usize = 32;
pub const OFF_XMM1: usize = 40;
pub const OFF_XMM2: usize = 48;
pub const OFF_XMM3: usize = 56;
pub const OFF_STACK: usize = 64;
pub const OFF_RAX: usize = 128;

/// The address a call made by [`run`] returns to (set by the thunk before each call).
pub static RETURN_SITE: AtomicU64 = AtomicU64::new(0);

/// `thunk(frame)`: runs `frame.entry` with the registers and stack arguments of `frame`.
///
/// # Safety
/// `frame.entry` must be a function that is safe to call right now with these arguments (game thread,
/// game lock held), and `frame` must be valid.
#[unsafe(naked)]
pub unsafe extern "C" fn run(frame: *mut CallFrame) {
    core::arch::naked_asm!(
        "push rbp",
        "mov rbp, rsp",
        "push rbx",
        "push rsi",
        "sub rsp, 0x60", // 32 bytes of shadow space + 8 stack arguments; keeps rsp 16-aligned at the call
        "mov rbx, rcx",
        "mov rax, [rbx + {stack}]",
        "mov [rsp + 0x20], rax",
        "mov rax, [rbx + {stack} + 8]",
        "mov [rsp + 0x28], rax",
        "mov rax, [rbx + {stack} + 16]",
        "mov [rsp + 0x30], rax",
        "mov rax, [rbx + {stack} + 24]",
        "mov [rsp + 0x38], rax",
        "mov rax, [rbx + {stack} + 32]",
        "mov [rsp + 0x40], rax",
        "mov rax, [rbx + {stack} + 40]",
        "mov [rsp + 0x48], rax",
        "mov rax, [rbx + {stack} + 48]",
        "mov [rsp + 0x50], rax",
        "mov rax, [rbx + {stack} + 56]",
        "mov [rsp + 0x58], rax",
        "movq xmm1, qword ptr [rbx + {xmm1}]",
        "movq xmm2, qword ptr [rbx + {xmm2}]",
        "movq xmm3, qword ptr [rbx + {xmm3}]",
        "mov rcx, [rbx + {rcx}]",
        "mov rdx, [rbx + {rdx}]",
        "mov r8, [rbx + {r8}]",
        "mov r9, [rbx + {r9}]",
        "lea rsi, [rip + 2f]",
        "mov [rip + {site}], rsi",
        "mov rax, [rbx + {entry}]",
        "call rax",
        "2:",
        "mov [rbx + {out}], rax",
        "add rsp, 0x60",
        "pop rsi",
        "pop rbx",
        "pop rbp",
        "ret",
        stack = const OFF_STACK,
        xmm1 = const OFF_XMM1,
        xmm2 = const OFF_XMM2,
        xmm3 = const OFF_XMM3,
        rcx = const OFF_RCX,
        rdx = const OFF_RDX,
        r8 = const OFF_R8,
        r9 = const OFF_R9,
        entry = const OFF_ENTRY,
        out = const OFF_RAX,
        site = sym RETURN_SITE,
    )
}

impl CallFrame {
    pub fn new(entry: u64) -> CallFrame {
        CallFrame { entry, ..Default::default() }
    }

    /// Runs the call and returns rax.
    ///
    /// # Safety
    /// See [`run`].
    pub unsafe fn call(&mut self) -> u64 {
        // the flight recorder shows an injected call that never came back
        crate::crash::note(crate::crash::Kind::CallStart, crate::crash::rva(self.entry), self.rcx);
        unsafe { run(self) };
        crate::crash::note(crate::crash::Kind::CallEnd, crate::crash::rva(self.entry), self.rax);
        self.rax
    }

    pub fn return_site() -> u64 {
        RETURN_SITE.load(Relaxed)
    }
}

pub fn f32_bits(value: f32) -> u64 {
    value.to_bits() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    static SEEN: [AtomicU64; 12] = [const { AtomicU64::new(0) }; 12];

    /// A stand-in game function that records exactly what it was called with.
    #[unsafe(naked)]
    unsafe extern "system" fn probe() {
        core::arch::naked_asm!(
            "mov rax, [rsp]",
            "mov [rip + {s0}], rax",
            "mov [rip + {s1}], rcx",
            "mov [rip + {s2}], rdx",
            "mov [rip + {s3}], r8",
            "mov [rip + {s4}], r9",
            "movq rax, xmm1",
            "mov [rip + {s5}], rax",
            "movq rax, xmm2",
            "mov [rip + {s6}], rax",
            "movq rax, xmm3",
            "mov [rip + {s7}], rax",
            "mov rax, [rsp + 0x28]",
            "mov [rip + {s8}], rax",
            "mov rax, [rsp + 0x30]",
            "mov [rip + {s9}], rax",
            "mov rax, [rsp + 0x38]",
            "mov [rip + {s10}], rax",
            "mov rax, [rsp + 0x40]",
            "mov [rip + {s11}], rax",
            "mov rax, 0x1122334455667788",
            "ret",
            s0 = sym SEEN_0, s1 = sym SEEN_1, s2 = sym SEEN_2, s3 = sym SEEN_3, s4 = sym SEEN_4, s5 = sym SEEN_5,
            s6 = sym SEEN_6, s7 = sym SEEN_7, s8 = sym SEEN_8, s9 = sym SEEN_9, s10 = sym SEEN_10, s11 = sym SEEN_11,
        )
    }

    static SEEN_0: AtomicU64 = AtomicU64::new(0);
    static SEEN_1: AtomicU64 = AtomicU64::new(0);
    static SEEN_2: AtomicU64 = AtomicU64::new(0);
    static SEEN_3: AtomicU64 = AtomicU64::new(0);
    static SEEN_4: AtomicU64 = AtomicU64::new(0);
    static SEEN_5: AtomicU64 = AtomicU64::new(0);
    static SEEN_6: AtomicU64 = AtomicU64::new(0);
    static SEEN_7: AtomicU64 = AtomicU64::new(0);
    static SEEN_8: AtomicU64 = AtomicU64::new(0);
    static SEEN_9: AtomicU64 = AtomicU64::new(0);
    static SEEN_10: AtomicU64 = AtomicU64::new(0);
    static SEEN_11: AtomicU64 = AtomicU64::new(0);

    fn seen() -> Vec<u64> {
        [&SEEN_0, &SEEN_1, &SEEN_2, &SEEN_3, &SEEN_4, &SEEN_5, &SEEN_6, &SEEN_7, &SEEN_8, &SEEN_9, &SEEN_10, &SEEN_11].iter().map(|s| s.load(Relaxed)).collect()
    }

    fn begin(name: &str) -> std::time::Instant {
        println!("[ .... ] {name}");
        std::time::Instant::now()
    }

    #[test]
    fn a_call_places_registers_float_and_stack_arguments_like_the_debugger_did() {
        let name = "call thunk: rcx/rdx/r8/r9, xmm1-3, stack arguments and the known return site";
        let started = begin(name);
        let _ = &SEEN;
        let mut frame = CallFrame::new(probe as usize as u64);
        frame.rcx = 0x11;
        frame.rdx = 0x22;
        frame.r8 = 0x33;
        frame.r9 = 0x44;
        frame.xmm1 = f32_bits(1.5);
        frame.xmm2 = f32_bits(-2.25);
        frame.xmm3 = f32_bits(8.0);
        frame.stack[..4].copy_from_slice(&[0xA5, 0xA6, 0xA7, 0xA8]);
        let rax = unsafe { frame.call() };
        assert_eq!(rax, 0x1122334455667788, "the return value is kept");
        let s = seen();
        assert_eq!(s[0], CallFrame::return_site(), "the callee returns to the thunk's known site");
        assert!(s[0] != 0);
        assert_eq!(&s[1..5], &[0x11, 0x22, 0x33, 0x44]);
        assert_eq!(&s[5..8], &[f32_bits(1.5), f32_bits(-2.25), f32_bits(8.0)]);
        assert_eq!(&s[8..12], &[0xA5, 0xA6, 0xA7, 0xA8], "the fifth and later arguments sit at [rsp+0x28] on entry");
        assert_eq!(frame.rax, rax);
        // many calls: the stack stays balanced and callee-saved registers survive
        let mut sum = 0u64;
        for i in 0..10_000u64 {
            frame.rcx = i;
            sum = sum.wrapping_add(unsafe { frame.call() } ^ i);
        }
        assert_eq!(sum, (0..10_000u64).fold(0u64, |a, i| a.wrapping_add(0x1122334455667788 ^ i)));
        println!("[  OK  ] {name} ({:.1} ms, 10 000 balanced calls)", started.elapsed().as_secs_f64() * 1000.0);
    }
}
