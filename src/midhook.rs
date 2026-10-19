//! Breakpoint hooks for the hook sites in the middle of a function.
//!
//! The Python debugger put an `int3` on every reviewed site, and every reviewed site decides the
//! next instruction itself: the handler leaves `RIP` where the game must continue (the mid-function
//! sites emulate the instruction they replace). A 5-byte jump cannot do that safely in the middle of a
//! function, because another branch may land inside the overwritten bytes. So the same technique runs
//! in process: one byte `int3`, a vectored exception handler that hands the handler the thread's
//! full CONTEXT (the same registers, in the same layout, as the debugger gave it) and resumes at the
//! `RIP` it leaves behind.
//!
//! A handler that leaves `RIP` on the site (or panics) falls back to single-stepping the original
//! instruction: the byte is restored for one step and the breakpoint is put back in the single-step
//! exception.

use crate::proc::Local;
use azcoop_bridge::regs::{Regs, CONTEXT_SIZE, RIP};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, AtomicUsize, Ordering::*};
use windows_sys::Win32::System::Diagnostics::Debug::{AddVectoredExceptionHandler, EXCEPTION_POINTERS};

type Result<T> = std::result::Result<T, String>;

pub const MAX_SITES: usize = 16;
const EXCEPTION_BREAKPOINT: u32 = 0x8000_0003;
const EXCEPTION_SINGLE_STEP: u32 = 0x8000_0004;
const CONTINUE_EXECUTION: i32 = -1;
const CONTINUE_SEARCH: i32 = 0;
const TRAP_FLAG: u32 = 0x100;

struct Slot {
    address: AtomicUsize,
    original: AtomicU8,
    enabled: AtomicBool,
    id: AtomicU32,
}

static SLOTS: [Slot; MAX_SITES] = [const { Slot { address: AtomicUsize::new(0), original: AtomicU8::new(0), enabled: AtomicBool::new(false), id: AtomicU32::new(0) } }; MAX_SITES];
static COUNT: AtomicUsize = AtomicUsize::new(0);

/// Called with the site's id and the thread's registers (`RIP` = the site). The handler leaves in `RIP`
/// where the thread continues.
pub type Handler = fn(id: u32, regs: &mut Regs);
static HANDLER: AtomicUsize = AtomicUsize::new(0);
static INSTALLED: AtomicBool = AtomicBool::new(false);

thread_local! {
    /// The site whose breakpoint is waiting to be put back after a single step.
    static REARM: Cell<usize> = const { Cell::new(0) };
}

/// Sets the handler (once) and registers the vectored exception handler (once).
pub fn install_handler(handler: Handler) -> Result<()> {
    HANDLER.store(handler as usize, SeqCst);
    if !INSTALLED.swap(true, SeqCst) {
        let registered = unsafe { AddVectoredExceptionHandler(1, Some(veh)) };
        if registered.is_null() {
            INSTALLED.store(false, SeqCst);
            return Err("cannot register the vectored exception handler".into());
        }
    }
    Ok(())
}

/// Puts a breakpoint on `address`; returns the slot to remove it with.
pub fn add_site(local: &Local, address: usize, id: u32) -> Result<usize> {
    let index = COUNT.fetch_add(1, SeqCst);
    if index >= MAX_SITES {
        COUNT.store(MAX_SITES, SeqCst);
        return Err("too many breakpoint sites".into());
    }
    let original = local.read(address, 1)?[0];
    if original == 0xCC {
        return Err(format!("{address:#x} already holds a breakpoint"));
    }
    let slot = &SLOTS[index];
    slot.address.store(address, SeqCst);
    slot.original.store(original, SeqCst);
    slot.id.store(id, SeqCst);
    slot.enabled.store(true, SeqCst);
    if let Err(e) = local.patch_at(address, &[0xCC]) {
        slot.enabled.store(false, SeqCst);
        return Err(e);
    }
    Ok(index)
}

/// Takes the breakpoint off again (the original byte is restored).
pub fn remove_site(local: &Local, slot: usize) -> Result<()> {
    let slot = &SLOTS[slot];
    if !slot.enabled.swap(false, SeqCst) {
        return Ok(());
    }
    local.patch_at(slot.address.load(SeqCst), &[slot.original.load(SeqCst)])
}

/// The site at `address`, if it is enabled.
fn find(address: usize) -> Option<&'static Slot> {
    SLOTS[..COUNT.load(SeqCst).min(MAX_SITES)].iter().find(|s| s.enabled.load(SeqCst) && s.address.load(SeqCst) == address)
}

fn patch_byte(address: usize, byte: u8) {
    if let Ok(local) = Local::game() {
        let _ = local.patch_at(address, &[byte]);
    }
}

unsafe extern "system" fn veh(info: *mut EXCEPTION_POINTERS) -> i32 {
    let (record, context) = unsafe { (&*(*info).ExceptionRecord, (*info).ContextRecord) };
    match record.ExceptionCode as u32 {
        EXCEPTION_BREAKPOINT => {
            let address = record.ExceptionAddress as usize;
            let Some(slot) = find(address) else { return CONTINUE_SEARCH };
            let bytes = unsafe { std::slice::from_raw_parts_mut(context as *mut u8, CONTEXT_SIZE) };
            let mut regs = Regs::from_context(bytes);
            regs.set_q(RIP, address as u64);
            let handler = HANDLER.load(SeqCst);
            let id = slot.id.load(SeqCst);
            let outcome = if handler == 0 {
                Err(())
            } else {
                let handler: Handler = unsafe { std::mem::transmute::<usize, Handler>(handler) };
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler(id, &mut regs))).map_err(|_| ())
            };
            if outcome.is_err() || regs.q(RIP) == address as u64 {
                // Run the original instruction for one step, then put the breakpoint back.
                patch_byte(address, slot.original.load(SeqCst));
                REARM.with(|r| r.set(address));
                regs.set_eflags(regs.eflags() | TRAP_FLAG);
                regs.set_q(RIP, address as u64);
            }
            regs.write_context(bytes);
            CONTINUE_EXECUTION
        }
        EXCEPTION_SINGLE_STEP => {
            let address = REARM.with(|r| r.replace(0));
            if address == 0 {
                return CONTINUE_SEARCH;
            }
            if find(address).is_some() {
                patch_byte(address, 0xCC);
            }
            CONTINUE_EXECUTION
        }
        _ => CONTINUE_SEARCH,
    }
}

/// The breakpoint handler is process-wide: tests that install their own take turns.
#[cfg(test)]
pub(crate) static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use azcoop_bridge::regs::{RAX, RCX, RDX};
    use windows_sys::Win32::System::Memory::{VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_READWRITE};

    fn begin(name: &str) -> std::time::Instant {
        println!("[ .... ] {name}");
        std::time::Instant::now()
    }

    fn code(bytes: &[u8]) -> usize {
        let address = unsafe { VirtualAlloc(std::ptr::null(), 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) } as usize;
        assert!(address != 0);
        unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), address as *mut u8, bytes.len()) };
        let mut old = 0u32;
        assert!(unsafe { VirtualProtect(address as *const _, 4096, PAGE_EXECUTE_READWRITE, &mut old) } != 0);
        address
    }

    static SEEN_RCX: AtomicUsize = AtomicUsize::new(0);
    static SEEN_STEP: AtomicUsize = AtomicUsize::new(0);
    static TARGET_A: AtomicUsize = AtomicUsize::new(0);
    static TARGET_B: AtomicUsize = AtomicUsize::new(0);

    fn handler(id: u32, regs: &mut Regs) {
        match id {
            // redirect: continue at another instruction and change registers
            1 => {
                SEEN_RCX.store(regs.q(RCX) as usize, SeqCst);
                regs.set_q(RDX, 0x77);
                regs.set_q(RIP, TARGET_A.load(SeqCst) as u64);
            }
            // leave RIP alone: the original instruction runs
            2 => {
                SEEN_STEP.fetch_add(1, SeqCst);
            }
            // panic: the original instruction runs as well
            3 => panic!("handler failure"),
            _ => {}
        }
    }

    #[test]
    fn a_breakpoint_hook_redirects_rewrites_registers_and_falls_back_to_the_original_instruction() {
        let name = "midhook: int3 site redirects, rewrites registers, steps over the original, survives a panic";
        let started = begin(name);
        let _turn = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        install_handler(handler).unwrap();
        let local = Local::with_image(0, 0);
        // site 1: `mov eax, 1; ret`, redirected to `lea rax,[rdx]; ret` (so rax shows the rdx the handler wrote)
        let alt = code(&[0x48, 0x8D, 0x02, 0xC3]); // lea rax, [rdx]; ret
        TARGET_A.store(alt, SeqCst);
        let site1 = code(&[0xB8, 1, 0, 0, 0, 0xC3]);
        let slot1 = add_site(&local, site1, 1).unwrap();
        let call = |address: usize, rcx: u64| -> u64 { unsafe { std::mem::transmute::<usize, extern "system" fn(u64) -> u64>(address)(rcx) } };
        assert_eq!(call(site1, 0x55), 0x77, "the handler's RDX and RIP were applied");
        assert_eq!(SEEN_RCX.load(SeqCst), 0x55, "and it saw the caller's RCX");
        // site 2: the handler leaves RIP: `mov eax, 2; ret` still runs, every time
        let site2 = code(&[0xB8, 2, 0, 0, 0, 0xC3]);
        let slot2 = add_site(&local, site2, 2).unwrap();
        for _ in 0..50 {
            assert_eq!(call(site2, 0), 2);
        }
        assert_eq!(SEEN_STEP.load(SeqCst), 50, "the breakpoint is put back after each single step");
        // site 3: the handler panics: the game code still runs
        let site3 = code(&[0xB8, 3, 0, 0, 0, 0xC3]);
        let slot3 = add_site(&local, site3, 3).unwrap();
        assert_eq!(call(site3, 0), 3);
        assert_eq!(call(site3, 0), 3);
        // removed: the original code runs without a hook
        remove_site(&local, slot1).unwrap();
        assert_eq!(call(site1, 9), 1);
        remove_site(&local, slot2).unwrap();
        remove_site(&local, slot3).unwrap();
        let _ = (RAX, TARGET_B.load(SeqCst));
        println!("[  OK  ] {name} ({:.1} ms)", started.elapsed().as_secs_f64() * 1000.0);
    }
}
