//! ABI-independent entry stubs ("context hooks").
//!
//! A typed Rust detour must know the exact signature (integer vs. float
//! registers, stack arguments, return register). A context stub does not: it
//! saves every volatile register (rax, rcx, rdx, r8–r11, xmm0–xmm5, flags),
//! calls a Rust handler with a read-only `Context`, restores the registers
//! bit for bit and jumps to the MinHook trampoline, so the original function
//! runs with exactly the state it was called with. Non-volatile registers are
//! preserved by the handler itself (Win64 ABI). This is the same view the
//! debugger had through CONTEXT, without stopping the thread.

use core::mem::offset_of;

#[repr(C, align(16))]
pub struct Context {
    pub xmm: [u128; 6],
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub rflags: u64,
    /// rsp at hook entry: `[rsp_entry]` is the caller's return address.
    pub rsp_entry: u64,
    pub id: u64,
    /// Read-write stubs only: non-zero makes the stub return to the caller at once with `result` in
    /// rax instead of running the original function (the original is then never entered).
    pub skip: u64,
    pub result: u64,
    /// Read-write stubs only: the callee-saved registers as the caller left them (the original function
    /// sees them unchanged). `rbp` is the caller's frame pointer, not the stub's.
    pub rbx: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
}

impl Context {
    pub fn xmm_f64(&self, index: usize) -> f64 {
        f64::from_bits(self.xmm[index] as u64)
    }
    pub fn return_address(&self) -> u64 {
        unsafe { *(self.rsp_entry as *const u64) }
    }
}

pub const CONTEXT_SIZE: usize = core::mem::size_of::<Context>();
pub const OFF_XMM: usize = offset_of!(Context, xmm);
pub const OFF_RAX: usize = offset_of!(Context, rax);
pub const OFF_RCX: usize = offset_of!(Context, rcx);
pub const OFF_RDX: usize = offset_of!(Context, rdx);
pub const OFF_R8: usize = offset_of!(Context, r8);
pub const OFF_R9: usize = offset_of!(Context, r9);
pub const OFF_R10: usize = offset_of!(Context, r10);
pub const OFF_R11: usize = offset_of!(Context, r11);
pub const OFF_RFLAGS: usize = offset_of!(Context, rflags);
pub const OFF_RSP: usize = offset_of!(Context, rsp_entry);
pub const OFF_ID: usize = offset_of!(Context, id);
pub const OFF_SKIP: usize = offset_of!(Context, skip);
pub const OFF_RESULT: usize = offset_of!(Context, result);
pub const OFF_RBX: usize = offset_of!(Context, rbx);
pub const OFF_RBP: usize = offset_of!(Context, rbp);
pub const OFF_RSI: usize = offset_of!(Context, rsi);
pub const OFF_RDI: usize = offset_of!(Context, rdi);
pub const OFF_R12: usize = offset_of!(Context, r12);
pub const OFF_R13: usize = offset_of!(Context, r13);
pub const OFF_R14: usize = offset_of!(Context, r14);
pub const OFF_R15: usize = offset_of!(Context, r15);

/// Defines `$name`: a naked entry stub that calls `$handler(&Context)` with
/// `id = $id`, then jumps through the trampoline pointer in `$trampoline`
/// (a `static AtomicUsize`, set before the hook is enabled).
#[macro_export]
macro_rules! context_stub {
    ($name:ident, $id:expr, $handler:path, $trampoline:path) => {
        #[unsafe(naked)]
        pub unsafe extern "C" fn $name() {
            core::arch::naked_asm!(
                // Frame: rbp = entry rsp - 8. Context + 32 bytes shadow space,
                // 16-byte aligned (Context is align(16)).
                "push rbp",
                "mov rbp, rsp",
                "sub rsp, {frame}",
                "and rsp, -16",
                "mov [rsp + 32 + {rax}], rax",
                "pushfq",
                "pop rax",
                "mov [rsp + 32 + {rflags}], rax",
                "mov [rsp + 32 + {rcx}], rcx",
                "mov [rsp + 32 + {rdx}], rdx",
                "mov [rsp + 32 + {r8}], r8",
                "mov [rsp + 32 + {r9}], r9",
                "mov [rsp + 32 + {r10}], r10",
                "mov [rsp + 32 + {r11}], r11",
                "movdqa [rsp + 32 + {xmm} + 0], xmm0",
                "movdqa [rsp + 32 + {xmm} + 16], xmm1",
                "movdqa [rsp + 32 + {xmm} + 32], xmm2",
                "movdqa [rsp + 32 + {xmm} + 48], xmm3",
                "movdqa [rsp + 32 + {xmm} + 64], xmm4",
                "movdqa [rsp + 32 + {xmm} + 80], xmm5",
                "lea rax, [rbp + 8]",
                "mov [rsp + 32 + {rsp_entry}], rax",
                "mov qword ptr [rsp + 32 + {id}], {hook_id}",
                "lea rcx, [rsp + 32]",
                "cld",
                "call {handler}",
                "movdqa xmm0, [rsp + 32 + {xmm} + 0]",
                "movdqa xmm1, [rsp + 32 + {xmm} + 16]",
                "movdqa xmm2, [rsp + 32 + {xmm} + 32]",
                "movdqa xmm3, [rsp + 32 + {xmm} + 48]",
                "movdqa xmm4, [rsp + 32 + {xmm} + 64]",
                "movdqa xmm5, [rsp + 32 + {xmm} + 80]",
                "mov rcx, [rsp + 32 + {rcx}]",
                "mov rdx, [rsp + 32 + {rdx}]",
                "mov r8, [rsp + 32 + {r8}]",
                "mov r9, [rsp + 32 + {r9}]",
                "mov r10, [rsp + 32 + {r10}]",
                "mov r11, [rsp + 32 + {r11}]",
                "push qword ptr [rsp + 32 + {rflags}]",
                "popfq",
                "mov rax, [rsp + 32 + {rax}]",
                "mov rsp, rbp",
                "pop rbp",
                "jmp qword ptr [rip + {trampoline}]",
                frame = const $crate::stub::CONTEXT_SIZE + 32 + 16,
                xmm = const $crate::stub::OFF_XMM,
                rax = const $crate::stub::OFF_RAX,
                rcx = const $crate::stub::OFF_RCX,
                rdx = const $crate::stub::OFF_RDX,
                r8 = const $crate::stub::OFF_R8,
                r9 = const $crate::stub::OFF_R9,
                r10 = const $crate::stub::OFF_R10,
                r11 = const $crate::stub::OFF_R11,
                rflags = const $crate::stub::OFF_RFLAGS,
                rsp_entry = const $crate::stub::OFF_RSP,
                id = const $crate::stub::OFF_ID,
                hook_id = const $id,
                handler = sym $handler,
                trampoline = sym $trampoline,
            )
        }
    };
}

/// Like [`context_stub`], but the handler gets a *writable* `Context`: whatever it leaves in
/// rax, rcx, rdx, r8-r11, xmm0-5 and the flags is what the original function sees, and setting
/// `skip` returns to the caller straight away with `result` in rax (the original never runs).
/// Stack arguments are reachable through `rsp_entry` and may be written directly.
#[macro_export]
macro_rules! context_stub_rw {
    ($name:ident, $id:expr, $handler:path, $trampoline:path) => {
        #[unsafe(naked)]
        pub unsafe extern "C" fn $name() {
            core::arch::naked_asm!(
                "push rbp",
                "mov rbp, rsp",
                "sub rsp, {frame}",
                "and rsp, -16",
                "mov [rsp + 32 + {rax}], rax",
                "pushfq",
                "pop rax",
                "mov [rsp + 32 + {rflags}], rax",
                "mov [rsp + 32 + {rcx}], rcx",
                "mov [rsp + 32 + {rdx}], rdx",
                "mov [rsp + 32 + {r8}], r8",
                "mov [rsp + 32 + {r9}], r9",
                "mov [rsp + 32 + {r10}], r10",
                "mov [rsp + 32 + {r11}], r11",
                "movdqa [rsp + 32 + {xmm} + 0], xmm0",
                "movdqa [rsp + 32 + {xmm} + 16], xmm1",
                "movdqa [rsp + 32 + {xmm} + 32], xmm2",
                "movdqa [rsp + 32 + {xmm} + 48], xmm3",
                "movdqa [rsp + 32 + {xmm} + 64], xmm4",
                "movdqa [rsp + 32 + {xmm} + 80], xmm5",
                "lea rax, [rbp + 8]",
                "mov [rsp + 32 + {rsp_entry}], rax",
                "mov qword ptr [rsp + 32 + {id}], {hook_id}",
                "mov qword ptr [rsp + 32 + {skip}], 0",
                "mov qword ptr [rsp + 32 + {result}], 0",
                "mov [rsp + 32 + {rbx}], rbx",
                "mov rax, [rbp]",
                "mov [rsp + 32 + {rbp0}], rax",
                "mov [rsp + 32 + {rsi}], rsi",
                "mov [rsp + 32 + {rdi}], rdi",
                "mov [rsp + 32 + {r12}], r12",
                "mov [rsp + 32 + {r13}], r13",
                "mov [rsp + 32 + {r14}], r14",
                "mov [rsp + 32 + {r15}], r15",
                "lea rcx, [rsp + 32]",
                "cld",
                "call {handler}",
                "movdqa xmm0, [rsp + 32 + {xmm} + 0]",
                "movdqa xmm1, [rsp + 32 + {xmm} + 16]",
                "movdqa xmm2, [rsp + 32 + {xmm} + 32]",
                "movdqa xmm3, [rsp + 32 + {xmm} + 48]",
                "movdqa xmm4, [rsp + 32 + {xmm} + 64]",
                "movdqa xmm5, [rsp + 32 + {xmm} + 80]",
                "cmp qword ptr [rsp + 32 + {skip}], 0",
                "jne 2f",
                "mov rcx, [rsp + 32 + {rcx}]",
                "mov rdx, [rsp + 32 + {rdx}]",
                "mov r8, [rsp + 32 + {r8}]",
                "mov r9, [rsp + 32 + {r9}]",
                "mov r10, [rsp + 32 + {r10}]",
                "mov r11, [rsp + 32 + {r11}]",
                "push qword ptr [rsp + 32 + {rflags}]",
                "popfq",
                "mov rax, [rsp + 32 + {rax}]",
                "mov rsp, rbp",
                "pop rbp",
                "jmp qword ptr [rip + {trampoline}]",
                "2:",
                "mov rax, [rsp + 32 + {result}]",
                "mov rsp, rbp",
                "pop rbp",
                "ret",
                frame = const $crate::stub::CONTEXT_SIZE + 32 + 16,
                xmm = const $crate::stub::OFF_XMM,
                rax = const $crate::stub::OFF_RAX,
                rcx = const $crate::stub::OFF_RCX,
                rdx = const $crate::stub::OFF_RDX,
                r8 = const $crate::stub::OFF_R8,
                r9 = const $crate::stub::OFF_R9,
                r10 = const $crate::stub::OFF_R10,
                r11 = const $crate::stub::OFF_R11,
                rflags = const $crate::stub::OFF_RFLAGS,
                rsp_entry = const $crate::stub::OFF_RSP,
                id = const $crate::stub::OFF_ID,
                skip = const $crate::stub::OFF_SKIP,
                result = const $crate::stub::OFF_RESULT,
                rbx = const $crate::stub::OFF_RBX,
                rbp0 = const $crate::stub::OFF_RBP,
                rsi = const $crate::stub::OFF_RSI,
                rdi = const $crate::stub::OFF_RDI,
                r12 = const $crate::stub::OFF_R12,
                r13 = const $crate::stub::OFF_R13,
                r14 = const $crate::stub::OFF_R14,
                r15 = const $crate::stub::OFF_R15,
                hook_id = const $id,
                handler = sym $handler,
                trampoline = sym $trampoline,
            )
        }
    };
}
