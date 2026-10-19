//! The hook stubs of the engine: one read-write context stub per function-entry hook, and the
//! breakpoint handler of the mid-function sites. Each turns the machine state into the bridge's
//! [`Regs`] (the CONTEXT view of the Python debugger), runs the event, and applies what the
//! bridge decided.

use crate::engine::{self, run_hook, Outcome, ENTRY_HOOKS, MID_HOOKS};
use crate::install::HookSpec;
use crate::log::Log;
use crate::midhook;
use crate::observe;
use crate::stub::Context;
use azcoop_bridge::client::Hook;
use azcoop_bridge::regs::{self, Regs};
use std::sync::atomic::{AtomicUsize, Ordering::*};

/// The slot of a hook in the thread bookkeeping of the observation log (the observe tables name hooks by position).
fn thread_slot(hook: Hook) -> usize {
    match hook {
        Hook::Write => observe::SLOT_WRITE,
        Hook::Tick => observe::SLOT_TICK,
        other => observe::NAMES.iter().position(|n| *n == other.name()).unwrap_or(0),
    }
}

/// Machine state at a function entry as the bridge's registers. `rip` is the hooked function's address.
fn regs_from(ctx: &Context, rip: u64) -> Regs {
    let mut r = Regs::default();
    r.set_q(regs::RAX, ctx.rax);
    r.set_q(regs::RCX, ctx.rcx);
    r.set_q(regs::RDX, ctx.rdx);
    r.set_q(regs::RBX, ctx.rbx);
    r.set_q(regs::RSP, ctx.rsp_entry);
    r.set_q(regs::RBP, ctx.rbp);
    r.set_q(regs::RSI, ctx.rsi);
    r.set_q(regs::RDI, ctx.rdi);
    r.set_q(regs::R8, ctx.r8);
    r.set_q(regs::R9, ctx.r9);
    r.set_q(regs::R10, ctx.r10);
    r.set_q(regs::R11, ctx.r11);
    r.set_q(regs::R12, ctx.r12);
    r.set_q(regs::R13, ctx.r13);
    r.set_q(regs::R14, ctx.r14);
    r.set_q(regs::R15, ctx.r15);
    r.set_q(regs::RIP, rip);
    r.set_eflags(ctx.rflags as u32);
    for (lane, value) in r.xmm.iter_mut().zip(ctx.xmm.iter()) {
        *lane = value.to_le_bytes();
    }
    r
}

/// Applies the changes the bridge made to the registers that the stub restores.
fn apply(regs: &Regs, before: &Regs, ctx: &mut Context, rip: u64) {
    let changed = |offset: usize| regs.q(offset) != before.q(offset);
    if changed(regs::RAX) {
        ctx.rax = regs.q(regs::RAX);
    }
    if changed(regs::RCX) {
        ctx.rcx = regs.q(regs::RCX);
    }
    if changed(regs::RDX) {
        ctx.rdx = regs.q(regs::RDX);
    }
    if changed(regs::R8) {
        ctx.r8 = regs.q(regs::R8);
    }
    if changed(regs::R9) {
        ctx.r9 = regs.q(regs::R9);
    }
    if changed(regs::R10) {
        ctx.r10 = regs.q(regs::R10);
    }
    if changed(regs::R11) {
        ctx.r11 = regs.q(regs::R11);
    }
    for (value, (now, was)) in ctx.xmm.iter_mut().zip(regs.xmm.iter().zip(before.xmm.iter())) {
        if now != was {
            *value = u128::from_le_bytes(*now);
        }
    }
    if regs.eflags() != before.eflags() {
        ctx.rflags = regs.eflags() as u64;
    }
    // The callee-saved registers cannot be changed at an entry; the stub does not restore them.
    for offset in [regs::RBX, regs::RBP, regs::RSI, regs::RDI, regs::R12, regs::R13, regs::R14, regs::R15] {
        debug_assert_eq!(regs.q(offset), before.q(offset), "a handler changed a callee-saved register");
    }
    // Skipping the function: the bridge returned to the caller (`RIP = [rsp]; RSP += 8`).
    if regs.q(regs::RIP) != rip {
        ctx.skip = 1;
        ctx.result = regs.q(regs::RAX);
    }
}

/// Where each entry hook's function starts (base + rva), by index into [`ENTRY_HOOKS`].
static ENTRY_ADDRESS: [AtomicUsize; ENTRY_HOOKS.len()] = [const { AtomicUsize::new(0) }; ENTRY_HOOKS.len()];

extern "C" fn entry_handler(ctx: *mut Context) {
    let ctx = unsafe { &mut *ctx };
    let index = ctx.id as usize;
    let hook = ENTRY_HOOKS[index];
    if engine::disabled(hook) {
        return;
    }
    let rip = ENTRY_ADDRESS[index].load(Relaxed) as u64;
    let mut regs = regs_from(ctx, rip);
    let before = regs.clone();
    observe::note_thread(thread_slot(hook));
    if run_hook(hook, &mut regs) == Outcome::Handled {
        apply(&regs, &before, ctx, rip);
    }
}

macro_rules! entry_stubs {
    ($($id:literal $stub:ident $trampoline:ident),* $(,)?) => {
        $(
            static $trampoline: AtomicUsize = AtomicUsize::new(0);
            crate::context_stub_rw!($stub, $id, entry_handler, $trampoline);
        )*
        fn stub_for(index: usize) -> (usize, &'static AtomicUsize) {
            match index {
                $( $id => ($stub as *const () as usize, &$trampoline), )*
                _ => unreachable!("entry hook index out of range"),
            }
        }
    };
}

entry_stubs! {
    0 stub_tick TRAMP_TICK, 1 stub_serialize TRAMP_SERIALIZE, 2 stub_write TRAMP_WRITE, 3 stub_pause TRAMP_PAUSE,
    4 stub_resume TRAMP_RESUME, 5 stub_start TRAMP_START, 6 stub_award_xp TRAMP_AWARD_XP, 7 stub_choose TRAMP_CHOOSE,
    8 stub_move TRAMP_MOVE, 9 stub_hurt TRAMP_HURT, 10 stub_spawn TRAMP_SPAWN, 11 stub_find_spawn TRAMP_FIND_SPAWN,
    12 stub_remove_loot TRAMP_REMOVE_LOOT, 13 stub_apply_effect TRAMP_APPLY_EFFECT, 14 stub_ui_command TRAMP_UI_COMMAND,
    15 stub_map_select TRAMP_MAP_SELECT,
}

/// The breakpoint sites that are installed (slot per mid hook), to take a disabled hook off.
static MID_SLOTS: [AtomicUsize; MID_HOOKS.len()] = [const { AtomicUsize::new(usize::MAX) }; MID_HOOKS.len()];

/// A disabled mid-function hook gets its original byte back; an entry hook only stops reacting.
pub fn hook_disabled(hook: Hook) {
    if let Some(i) = MID_HOOKS.iter().position(|h| *h == hook) {
        let slot = MID_SLOTS[i].swap(usize::MAX, SeqCst);
        if slot != usize::MAX {
            if let Some(shared) = engine::shared() {
                let _ = midhook::remove_site(&shared.local, slot);
            }
        }
    }
}

/// The breakpoint handler: `id` indexes [`MID_HOOKS`].
fn mid_handler(id: u32, regs: &mut Regs) {
    let hook = MID_HOOKS[id as usize];
    observe::note_thread(thread_slot(hook));
    if engine::disabled(hook) {
        return; // RIP stays on the site: the original instruction runs
    }
    run_hook(hook, regs);
}

/// Creates every hook. Entry hooks go in through MinHook in one process-wide suspend, the
/// mid-function sites get their breakpoint afterwards.
pub fn install_all(shared: &engine::Shared, log: &Log) -> Result<(), String> {
    let natives = |hook: Hook| -> usize { shared.hook_address(hook) as usize };
    let mut specs = Vec::new();
    for (index, hook) in ENTRY_HOOKS.iter().enumerate() {
        let address = natives(*hook);
        if address == 0 {
            if *hook == Hook::MapSelect {
                continue;
            }
            return Err(format!("no address for {}", hook.name()));
        }
        ENTRY_ADDRESS[index].store(address, SeqCst);
        let (detour, trampoline) = stub_for(index);
        specs.push(HookSpec { name: hook.name(), target: address, detour, trampoline });
    }
    midhook::install_handler(mid_handler)?;
    crate::install::install(&specs).map_err(|e| {
        crate::install::uninstall();
        e
    })?;
    for (index, hook) in MID_HOOKS.iter().enumerate() {
        if natives(*hook) == 0 && *hook == Hook::MenuLogin {
            continue; // no menu contract in this build
        }
        match midhook::add_site(&shared.local, natives(*hook), index as u32) {
            Ok(slot) => MID_SLOTS[index].store(slot, SeqCst),
            Err(e) => {
                log.warn(&format!("breakpoint site {}: {e}", hook.name()));
                return Err(e);
            }
        }
    }
    Ok(())
}

/// Test support: the same installation over stand-in functions.
#[cfg(test)]
pub fn install_for_test(entry: &[(Hook, usize)], mid: &[(Hook, usize)]) -> Result<(), String> {
    let mut specs = Vec::new();
    for (hook, address) in entry {
        let index = ENTRY_HOOKS.iter().position(|h| h == hook).ok_or("not an entry hook")?;
        ENTRY_ADDRESS[index].store(*address, SeqCst);
        let (detour, trampoline) = stub_for(index);
        specs.push(HookSpec { name: hook.name(), target: *address, detour, trampoline });
    }
    midhook::install_handler(mid_handler)?;
    crate::install::install(&specs)?;
    let local = &engine::shared().ok_or("engine not set up")?.local;
    for (hook, address) in mid {
        let index = MID_HOOKS.iter().position(|h| h == hook).ok_or("not a mid hook")?;
        MID_SLOTS[index].store(midhook::add_site(local, *address, index as u32)?, SeqCst);
    }
    Ok(())
}

/// Test support: takes the stand-in hooks off again.
#[cfg(test)]
pub fn uninstall_for_test() {
    crate::install::uninstall();
    if let Some(shared) = engine::shared() {
        for slot in &MID_SLOTS {
            let s = slot.swap(usize::MAX, SeqCst);
            if s != usize::MAX {
                let _ = midhook::remove_site(&shared.local, s);
            }
        }
    }
}
