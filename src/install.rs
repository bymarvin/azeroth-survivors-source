//! Safe hook installation and removal via MinHook.
//!
//! MinHook suspends every other thread in the process while it writes a jump,
//! and if a suspended thread's instruction pointer sits inside the bytes being
//! overwritten it moves that IP onto the equivalent spot in the relocated
//! trampoline. So no game thread ever runs half-patched code. We enable all
//! queued hooks in one `apply_queued`, i.e. one suspend/resume of the process.
//!
//! `uninstall` disables and removes every hook (another single suspend) and is
//! also the kill switch: after it returns, the game runs the original code.

use minhook::MinHook;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};

/// One installed hook: target address and the trampoline slot to fill.
pub struct HookSpec {
    pub name: &'static str,
    pub target: usize,
    pub detour: usize,
    pub trampoline: &'static AtomicUsize,
}

static INSTALLED: AtomicBool = AtomicBool::new(false);
static TARGETS: std::sync::Mutex<Vec<usize>> = std::sync::Mutex::new(Vec::new());

/// Creates every hook (filling its trampoline slot), then enables them all in
/// one process-wide suspend. On any error nothing stays enabled.
pub fn install(specs: &[HookSpec]) -> Result<(), String> {
    for spec in specs {
        let original = unsafe { MinHook::create_hook(spec.target as *mut c_void, spec.detour as *mut c_void) }
            .map_err(|e| format!("create {} hook: {e:?}", spec.name))?;
        spec.trampoline.store(original as usize, Relaxed);
        unsafe { MinHook::queue_enable_hook(spec.target as *mut c_void) }
            .map_err(|e| format!("queue {} hook: {e:?}", spec.name))?;
    }
    unsafe { MinHook::apply_queued() }.map_err(|e| format!("apply hooks: {e:?}"))?;
    *TARGETS.lock().unwrap() = specs.iter().map(|s| s.target).collect();
    INSTALLED.store(true, Relaxed);
    Ok(())
}

/// Kill switch: disables and removes all hooks in one suspend. Idempotent.
pub fn uninstall() {
    if !INSTALLED.swap(false, Relaxed) {
        return;
    }
    let targets = std::mem::take(&mut *TARGETS.lock().unwrap());
    for target in &targets {
        let _ = unsafe { MinHook::queue_disable_hook(*target as *mut c_void) };
    }
    let _ = unsafe { MinHook::apply_queued() };
    for target in &targets {
        let _ = unsafe { MinHook::remove_hook(*target as *mut c_void) };
    }
}

