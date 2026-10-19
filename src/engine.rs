//! The in-process co-op core: the bridge wired to the running game.
//!
//! The Python bridge was a debugger: it stopped the game at each reviewed address, read and rewrote
//! the thread's registers, ran game functions by hijacking the thread, and let it go on. Here every
//! piece has an in-process form:
//!
//! * **entry hooks** (`stub::context_stub_rw!` through MinHook) give the handler the registers at
//!   the function entry and let it skip the function or change its arguments;
//! * **mid-function sites** (`midhook`, `int3` plus a vectored exception handler) give it the full CONTEXT;
//! * **injected calls** (`call::run`) run a game function on the game thread itself, with a return
//!   address the hooks recognise, and the hook that asked for the call runs again afterwards (the
//!   Python restored the registers and let the breakpoint fire again);
//! * everything the bridge reads or writes in the game goes through [`Live`], the [`Client`] of this process.
//!
//! Hooks may fire inside an injected call (the game enters the very function that was called, or
//! functions it calls). They are handled by the same bridge, re-entrantly on the same thread, like
//! the Python's single bridge object handled nested breakpoints. A hook that arrives on another
//! thread while the bridge is busy is passed through unchanged.

use crate::call::{f32_bits, CallFrame};
use crate::log::Log;
use crate::proc::Local;
use azcoop_bridge::bridge::{Bridge, Build};
use azcoop_bridge::client::{CallSpec, Client, Hook};
use azcoop_bridge::regs::{self, Regs};
use azcoop_game::builds::Variant;
use azcoop_game::profile::Profile;
use azcoop_game::readers::GameFields;
use azcoop_logic::{Detail, Event};
use azcoop_patch::{Ctx, Image};
use std::cell::UnsafeCell;
use std::collections::HashMap;
use std::io::Read;
use std::os::windows::fs::FileExt;
use std::path::Path;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering::*};
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

pub type Result<T> = std::result::Result<T, String>;

/// Pass limit of one hook event (a hook that keeps asking for calls).
pub const MAX_PASSES: usize = 4096;
/// `play_limits`: the largest damage a call may carry.
const MAX_DAMAGE: f64 = 1e12;
const MAX_COUNTER: u64 = 0xFFFF_FFFF;

pub const HOOK_COUNT: usize = 28;

// ---- global state ---------------------------------------------------------------------------------------

/// Everything [`Live`] needs. Set once at install time; mutable parts are atomics or behind a mutex.
pub struct Shared {
    pub local: Local,
    pub number: u32,
    pub log: &'static Log,
    pub profile: Profile,
    pub variant: Variant,
    pub image: std::sync::Arc<DiskImage>,
    natives: Mutex<Natives>,
    pub started: Instant,
    pub loading: Mutex<LoadingWatch>,
}

struct Natives {
    /// The unpatched entry of each hook: base + rva (0: not in the profile).
    entries: [u64; HOOK_COUNT],
    owned: HashMap<Vec<u8>, u64>,
    defeat_ui: u64,
    pause_ui: [u64; 2],
    /// Argument records for calls (an effect, a spawn position): one at a time.
    scratch: u64,
}

static SHARED: OnceLock<Shared> = OnceLock::new();
static SERVER: AtomicU64 = AtomicU64::new(0);
/// The game is inside a call this bridge injected (`client.saved_context is not None`).
static SAVED: AtomicBool = AtomicBool::new(false);
static REQUEST: AtomicBool = AtomicBool::new(false);
/// A call was made during the current pass: the hook runs again.
static CALL_MADE: AtomicBool = AtomicBool::new(false);
static DISABLED: [AtomicBool; HOOK_COUNT] = [const { AtomicBool::new(false) }; HOOK_COUNT];
static ACTIVE: AtomicBool = AtomicBool::new(false);

pub static STAT_EVENTS: AtomicU64 = AtomicU64::new(0);
pub static STAT_CALLS: AtomicU64 = AtomicU64::new(0);
pub static STAT_RETRIES: AtomicU64 = AtomicU64::new(0);
pub static STAT_BUSY: AtomicU64 = AtomicU64::new(0);
pub static STAT_FAULTS: AtomicU64 = AtomicU64::new(0);
pub static STAT_NESTED: AtomicU64 = AtomicU64::new(0);
pub static STAT_BY_HOOK: [AtomicU64; HOOK_COUNT] = [const { AtomicU64::new(0) }; HOOK_COUNT];

/// What the engine drives: the bridge (and, in tests, a script).
pub trait HookHandler {
    /// A menu event before the game server exists (the first TICK has not come): only the party menu's Enter wait lives here.
    fn menu(&mut self, _client: &mut dyn Client, _hook: Hook, _regs: &mut Regs) -> Result<()> {
        Ok(())
    }
    fn set_clock(&mut self, now: f64);
    fn handle(&mut self, client: &mut dyn Client, hook: Hook, regs: &mut Regs) -> Result<()>;
}

impl HookHandler for Bridge {
    fn set_clock(&mut self, now: f64) {
        self.now = now;
        self.perf = now;
    }
    fn handle(&mut self, client: &mut dyn Client, hook: Hook, regs: &mut Regs) -> Result<()> {
        self.on_hook(client, hook, regs)
    }
}

struct HandlerCell(UnsafeCell<Option<Box<dyn HookHandler>>>);
unsafe impl Sync for HandlerCell {}
static HANDLER: HandlerCell = HandlerCell(UnsafeCell::new(None));

pub fn shared() -> Option<&'static Shared> {
    SHARED.get()
}

pub fn is_active() -> bool {
    ACTIVE.load(Relaxed)
}

pub fn disabled(hook: Hook) -> bool {
    DISABLED[hook as usize].load(Relaxed)
}

/// Seconds on the bridge clock (`time.monotonic()`).
fn clock() -> f64 {
    shared().map_or(0.0, |s| s.started.elapsed().as_secs_f64())
}

// ---- the executable on disk ---------------------------------------------------------------------------------

/// The build's own code, read from the executable on disk when needed (the Python's `candidate.get_data`).
pub struct DiskImage {
    file: std::fs::File,
    sections: Vec<azcoop_game::pe::Section>,
}

impl DiskImage {
    pub fn open(path: &Path) -> Result<DiskImage> {
        let file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let mut header = vec![0u8; 0x1000];
        let mut reader = &file;
        reader.read_exact(&mut header).map_err(|e| format!("{}: {e}", path.display()))?;
        let sections = azcoop_game::pe::Pe::parse(&header)?.sections;
        Ok(DiskImage { file, sections })
    }
}

impl Image for DiskImage {
    fn bytes(&self, rva: u64, len: usize) -> azcoop_patch::Result<Vec<u8>> {
        let section = self
            .sections
            .iter()
            .find(|s| rva >= s.virtual_address as u64 && rva < s.virtual_address as u64 + s.virtual_size.max(s.raw_size) as u64)
            .ok_or_else(|| format!("RVA {rva:#x} is in no section"))?;
        let inside = rva - section.virtual_address as u64;
        if inside + len as u64 > section.raw_size as u64 {
            return Err(format!("RVA {rva:#x}+{len} is not file-backed"));
        }
        let mut out = vec![0u8; len];
        let mut done = 0;
        while done < len {
            let n = self.file.seek_read(&mut out[done..], section.raw_offset as u64 + inside + done as u64).map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("executable ended early".into());
            }
            done += n;
        }
        Ok(out)
    }
}

struct SharedImage(std::sync::Arc<DiskImage>);
impl Image for SharedImage {
    fn bytes(&self, rva: u64, len: usize) -> azcoop_patch::Result<Vec<u8>> {
        self.0.bytes(rva, len)
    }
}

// ---- the game's log: has this player's loading screen cleared? --------------------------------------------------

/// The Python read `stderr.log` of each game for `loading screen: cleared (`. In process the game's
/// stderr is this process's stderr; when the launcher redirected it to a file, that file is tailed.
pub struct LoadingWatch {
    path: Option<std::path::PathBuf>,
    offset: u64,
    cleared: bool,
}

impl LoadingWatch {
    pub fn new(game: &Path) -> LoadingWatch {
        let path = std::env::var_os("AZCOOP_STDERR_LOG")
            .map(std::path::PathBuf::from)
            .or_else(stderr_file)
            .or_else(|| Some(game.join("stderr.log")).filter(|p| p.is_file()));
        let cleared = std::env::var_os("AZCOOP_LOADED").is_some_and(|v| v == "1");
        LoadingWatch { path, offset: 0, cleared }
    }

    pub fn poll(&mut self) -> bool {
        if self.cleared {
            return true;
        }
        let Some(path) = &self.path else { return false };
        let Ok(file) = std::fs::File::open(path) else { return false };
        let mut buffer = vec![0u8; 1 << 20];
        let Ok(n) = file.seek_read(&mut buffer, self.offset) else { return false };
        buffer.truncate(n);
        // Retain enough overlap if a log line is still being written.
        self.offset = (self.offset + n as u64).saturating_sub(128);
        if buffer.windows(25).any(|w| w == b"loading screen: cleared (") {
            self.cleared = true;
        }
        self.cleared
    }

    pub fn describe(&self) -> String {
        match (&self.path, self.cleared) {
            (_, true) => "already cleared".into(),
            (Some(p), false) => format!("watching {}", p.display()),
            (None, false) => "no log file to watch (set AZCOOP_STDERR_LOG or AZCOOP_LOADED=1)".into(),
        }
    }
}

fn stderr_file() -> Option<std::path::PathBuf> {
    use windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;
    use windows_sys::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE};
    unsafe {
        let handle = GetStdHandle(STD_ERROR_HANDLE);
        if handle.is_null() || handle as isize == -1 {
            return None;
        }
        let mut buffer = vec![0u16; 4096];
        let n = GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), buffer.len() as u32, 0) as usize;
        if n == 0 || n >= buffer.len() {
            return None;
        }
        let text = String::from_utf16_lossy(&buffer[..n]);
        let path = std::path::PathBuf::from(text.strip_prefix(r"\\?\").unwrap_or(&text));
        path.is_file().then_some(path)
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---- injected calls ------------------------------------------------------------------------------------------

fn unhex(text: &str) -> Result<Vec<u8>> {
    if text.len() % 2 != 0 {
        return Err("odd hex".into());
    }
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|e| e.to_string())).collect()
}

fn detail<'a>(spec: &'a CallSpec, key: &str) -> Option<&'a Detail> {
    spec.details.iter().find(|(k, _)| *k == key).map(|(_, v)| v)
}

fn number_detail(spec: &CallSpec, key: &str) -> Option<f64> {
    match detail(spec, key) {
        Some(Detail::Num(x)) => Some(*x),
        _ => None,
    }
}

/// The argument checks at the top of `Native.call_before`.
fn validate(spec: &CallSpec, image_base: u64, image_size: u64) -> Result<()> {
    let allowed = |h: Hook| {
        matches!(
            h,
            Hook::Pause | Hook::Resume | Hook::Start | Hook::AwardXp | Hook::Choose | Hook::Damage | Hook::Hurt | Hook::DefeatUi | Hook::UiCommand
                | Hook::Spawn | Hook::SpawnLoot | Hook::RemoveLoot | Hook::OfferChoices | Hook::ApplyEffect | Hook::ApplyDot | Hook::SpawnBoss
        )
    };
    let owned = spec.hook.is_none() && matches!(detail(spec, "entry_code"), Some(Detail::Text(t)) if (2..=8192).contains(&t.len()));
    if !owned && !spec.hook.is_some_and(allowed) {
        return Err("Unsupported or nested native call".into());
    }
    let damage = number_detail(spec, "damage");
    match spec.hook {
        Some(Hook::SpawnBoss) if !(image_base <= spec.second && spec.second < image_base + image_size - 0x58) => return Err("Unverified boss definition".into()),
        Some(Hook::Damage | Hook::Hurt | Hook::ApplyDot) if !damage.is_some_and(|d| d.is_finite() && 0.0 < d && d <= MAX_DAMAGE) => return Err("Invalid native damage".into()),
        Some(Hook::Spawn) => {
            let position_ok = matches!(detail(spec, "position"), Some(Detail::List(p)) if p.len() == 3 && p.iter().all(|v| v.is_finite()));
            if !position_ok || spec.second > 11 {
                return Err("Invalid native mirror spawn".into());
            }
        }
        Some(Hook::OfferChoices) if spec.second > 2 => return Err("Invalid native choice kind".into()),
        Some(Hook::ApplyEffect) => {
            let effect = match detail(spec, "effect") {
                Some(Detail::Text(t)) => unhex(t)?,
                _ => return Err("Invalid native enemy effect".into()),
            };
            let spell = number_detail(spec, "spell").unwrap_or(0.0);
            if effect.len() != 12 || !(0.0..=MAX_COUNTER as f64).contains(&spell) {
                return Err("Invalid native enemy effect".into());
            }
            let kind = u32::from_le_bytes(effect[..4].try_into().unwrap());
            let value = f32::from_le_bytes(effect[4..8].try_into().unwrap()) as f64;
            let duration = f32::from_le_bytes(effect[8..12].try_into().unwrap()) as f64;
            let timed = matches!(kind, 1 | 10);
            if !matches!(kind, 1 | 2 | 3 | 4 | 10)
                || !value.is_finite()
                || !(0.0..=if timed { 1.0 } else { 3600.0 }).contains(&value)
                || (timed && !(duration.is_finite() && (0.0..=3600.0).contains(&duration)))
            {
                return Err("Unsupported native enemy effect".into());
            }
        }
        _ => {}
    }
    if number_detail(spec, "ui_only").is_some_and(|v| v != 0.0) && !matches!(spec.hook, Some(Hook::Pause | Hook::Resume)) {
        return Err("Only pause UI can bypass gameplay state".into());
    }
    Ok(())
}

/// The native stack frame PAUSE and RESUME open with; the pause-UI stub repeats it and jumps behind it.
pub(crate) fn pause_ui_prefix() -> Vec<u8> {
    azcoop_patch::hx("55 56 57 53 4881ec88000000 488dac2480000000 48c74500feffffff")
}

/// The prologue check of the pause-UI stub, against the build's own bytes from the exe on disk: in memory PAUSE/RESUME carry our
/// MinHook jump over their first bytes (the Python line skipped only byte 0, its int3). Soak 19.10.2026: the old check read live
/// memory and failed at every pause-UI call (a shared pause while a teammate is downed), which stopped that player's core.
pub(crate) fn pause_ui_prologue_ok(image: &dyn Image, rva: u64) -> Result<bool> {
    let prefix = pause_ui_prefix();
    Ok(image.bytes(rva, prefix.len())? == prefix)
}

impl Shared {
    fn base(&self) -> u64 {
        self.local.base as u64
    }

    /// base + rva of a hook (0: the profile does not name it).
    pub fn hook_address(&self, hook: Hook) -> u64 {
        self.natives.lock().map_or(0, |n| n.entries[hook as usize])
    }

    fn ctx(&self) -> Ctx<'_> {
        // The image trait object lives as long as the shared state.
        Ctx { variant: self.variant, profile: &self.profile, image: &*self.image }
    }

    /// Resolves the entry of a call and builds its registers (the register setup of `Native.call_before`).
    fn frame_for(&self, spec: &CallSpec) -> Result<CallFrame> {
        validate(spec, self.base(), self.local.image_size as u64)?;
        let mut natives = self.natives.lock().map_err(|_| "natives lock poisoned".to_string())?;
        let ui_only = number_detail(spec, "ui_only").is_some_and(|v| v != 0.0);
        let entry = match spec.hook {
            None => {
                let Some(Detail::Text(text)) = detail(spec, "entry_code") else { return Err("owned call without entry code".into()) };
                let code = unhex(text)?;
                if let Some(&address) = natives.owned.get(&code) {
                    address
                } else {
                    let address = self.local.exec_alloc(&code, None)? as u64;
                    natives.owned.insert(code, address);
                    address
                }
            }
            Some(Hook::DefeatUi) => {
                if natives.defeat_ui == 0 {
                    let code = azcoop_patch::ui::defeat_ui_code(&self.ctx(), self.base())?;
                    natives.defeat_ui = self.local.exec_alloc(&code, None)? as u64;
                }
                natives.defeat_ui
            }
            Some(hook @ (Hook::Pause | Hook::Resume)) if ui_only => {
                let slot = (hook == Hook::Resume) as usize;
                if natives.pause_ui[slot] == 0 {
                    // Same native stack frame, followed by its owned JSON allocation path.
                    let prefix = pause_ui_prefix();
                    let entry = natives.entries[hook as usize];
                    if !pause_ui_prologue_ok(&*self.image, entry - self.base())? {
                        return Err("Native pause UI prologue changed".into());
                    }
                    let target = self.base() + self.ctx().rva(if hook == Hook::Pause { 0x53F186E } else { 0x53F5FDB })?;
                    let mut code = prefix;
                    code.extend_from_slice(&[0x48, 0x89, 0xCE, 0xFF, 0x25, 0, 0, 0, 0]);
                    code.extend_from_slice(&target.to_le_bytes());
                    natives.pause_ui[slot] = self.local.exec_alloc(&code, None)? as u64;
                }
                natives.pause_ui[slot]
            }
            Some(hook) => {
                let entry = natives.entries[hook as usize];
                if entry == 0 {
                    return Err(format!("the profile has no {} entry", hook.name()));
                }
                entry
            }
        };
        if natives.scratch == 0 {
            natives.scratch = self.local.alloc(4096)? as u64;
        }
        let scratch = natives.scratch;
        let mut frame = CallFrame::new(entry);
        frame.rcx = spec.argument;
        frame.rdx = spec.second;
        let damage = number_detail(spec, "damage").unwrap_or(0.0);
        match spec.hook {
            Some(Hook::ApplyEffect) => {
                let Some(Detail::Text(effect)) = detail(spec, "effect") else { unreachable!("validated") };
                self.local.write(scratch as usize, &unhex(effect)?)?;
                frame.r8 = scratch;
                frame.stack[0] = number_detail(spec, "spell").unwrap_or(0.0) as u64;
            }
            Some(Hook::Damage) => {
                frame.xmm2 = f32_bits(damage as f32);
                frame.r9 = 0; // Basic melee, no spell ID.
                frame.stack[..3].copy_from_slice(&[0, 0, 1]);
            }
            Some(Hook::Hurt) => {
                frame.xmm1 = f32_bits(damage as f32);
                frame.r8 = spec.second;
                frame.r9 = number_detail(spec, "melee").map_or(1, |m| (m != 0.0) as u64);
            }
            Some(Hook::Spawn) => {
                let Some(Detail::List(p)) = detail(spec, "position") else { unreachable!("validated") };
                let mut record = 1u32.to_le_bytes().to_vec();
                for v in p {
                    record.extend_from_slice(&(*v as f32).to_le_bytes());
                }
                self.local.write(scratch as usize, &record)?;
                frame.r8 = scratch;
            }
            Some(Hook::SpawnLoot) => {
                let Some(Detail::List(p)) = detail(spec, "position") else { return Err("Invalid native loot spawn".into()) };
                let amount = number_detail(spec, "amount").unwrap_or(1.0);
                if p.len() != 3 || !p.iter().all(|v| v.is_finite()) || spec.second > 2 || !(1.0..=MAX_COUNTER as f64).contains(&amount) {
                    return Err("Invalid native loot spawn".into());
                }
                let mut record = Vec::new();
                for v in p {
                    record.extend_from_slice(&(*v as f32).to_le_bytes());
                }
                self.local.write(scratch as usize, &record)?;
                frame.r8 = amount as u64;
                frame.r9 = scratch;
            }
            Some(Hook::OfferChoices) => frame.r8 = 1,
            Some(Hook::ApplyDot) => return Err("periodic damage is not ported".into()),
            _ => {}
        }
        Ok(frame)
    }
}

// ---- the Client of this process --------------------------------------------------------------------------------

/// Events before which the process heap is validated (`native_heap_check`).
const HEAP_CHECK_AT: [&str; 5] = ["native_start", "team_defeat_shown", "completed_run_transition", "leave_requested", "native_world_restarted"];

/// The game this process runs, as the bridge sees it.
pub struct Live;

impl Client for Live {
    fn number(&self) -> u32 {
        shared().map_or(1, |s| s.number)
    }
    fn base(&self) -> u64 {
        shared().map_or(0, |s| s.base())
    }
    fn server(&self) -> u64 {
        SERVER.load(Relaxed)
    }
    fn set_server(&mut self, server: u64) {
        SERVER.store(server, Relaxed);
    }
    fn memory(&mut self, address: u64, len: usize) -> Result<Vec<u8>> {
        shared().ok_or("engine is not installed")?.local.read(address as usize, len)
    }
    fn put(&mut self, address: u64, data: &[u8]) -> Result<()> {
        crate::crash::note_own(b'W', address, data.len() as u64);
        shared().ok_or("engine is not installed")?.local.write(address as usize, data)
    }
    fn patch(&mut self, address: u64, data: &[u8]) -> Result<()> {
        crate::crash::note(crate::crash::Kind::Patch, crate::crash::rva(address), data.len() as u64);
        crate::crash::note_own(b'P', address, data.len() as u64);
        shared().ok_or("engine is not installed")?.local.patch_at(address as usize, data)
    }
    fn allocate(&mut self, size: usize) -> Result<u64> {
        let address = shared().ok_or("engine is not installed")?.local.alloc(size).map(|a| a as u64)?;
        crate::crash::note_own(b'A', address, size as u64);
        Ok(address)
    }
    fn executable_buffer(&mut self, code: &[u8], near: Option<u64>) -> Result<u64> {
        let address = shared().ok_or("engine is not installed")?.local.exec_alloc(code, near.map(|a| a as usize)).map(|a| a as u64)?;
        crate::crash::note_own(b'X', address, code.len() as u64);
        Ok(address)
    }
    fn image(&self) -> Rc<dyn Image> {
        Rc::new(SharedImage(shared().expect("engine is installed").image.clone()))
    }
    fn loading_cleared(&mut self, _number: u32) -> bool {
        shared().is_some_and(|s| s.loading.lock().map(|mut w| w.poll()).unwrap_or(false))
    }
    fn saved_context(&self) -> bool {
        SAVED.load(Relaxed)
    }
    fn call_is_request(&self) -> bool {
        REQUEST.load(Relaxed)
    }
    fn call_return(&self) -> u64 {
        CallFrame::return_site()
    }
    fn disable_hook(&mut self, hook: Hook) {
        DISABLED[hook as usize].store(true, Relaxed);
        crate::entry::hook_disabled(hook);
    }
    fn call_before(&mut self, _regs: &mut Regs, call: CallSpec) -> Result<()> {
        if SAVED.load(Relaxed) {
            return Err("Unsupported or nested native call".into());
        }
        let shared = shared().ok_or("engine is not installed")?;
        let mut frame = shared.frame_for(&call)?;
        crate::crash::note_own(b'C', call.hook.map_or(0xFFFF, |h| h as u64), call.argument);
        REQUEST.store(number_detail(&call, "request").is_some_and(|v| v != 0.0), Relaxed);
        SAVED.store(true, SeqCst);
        // The game function runs on this thread, under the game lock the hook already holds.
        unsafe { frame.call() };
        SAVED.store(false, SeqCst);
        REQUEST.store(false, Relaxed);
        CALL_MADE.store(true, Relaxed);
        STAT_CALLS.fetch_add(1, Relaxed);
        Ok(())
    }
    fn record(&mut self, event: Event) {
        crate::control::tee(&event); // the launcher's events (relay mode), independent of the log
        // Heap self-check at the moments a guest's heap corruption showed up (2-PC crash reports: a few ms after New hero after a team
        // defeat, and at world entry): before the game acts on them.
        if HEAP_CHECK_AT.contains(&event.name.as_str()) {
            let (ok, ms) = crate::crash::heap_check(&event.name);
            self.record(Event::new("native_heap_check").text("reason", &event.name).num("ok", ok as u8 as f64).num("ms", (ms * 10.0).round() / 10.0));
        }
        let Some(shared) = shared() else { return };
        let mut text = event.name.clone();
        for (key, value) in &event.details {
            text.push(' ');
            text.push_str(key);
            text.push('=');
            match value {
                Detail::Num(x) if x.fract() == 0.0 && x.abs() < 1e15 => text.push_str(&format!("{}", *x as i64)),
                Detail::Num(x) => text.push_str(&format!("{x}")),
                Detail::Text(t) if t.len() > 80 => text.push_str(&format!("{}…", &t[..80])),
                Detail::Text(t) => text.push_str(t),
                Detail::List(l) => text.push_str(&format!("{l:?}")),
                Detail::Items(l) => text.push_str(&format!("{l:?}")),
            }
        }
        shared.log.info(&format!("event {text}"));
    }
}

// ---- re-entrancy ---------------------------------------------------------------------------------------------

static OWNER: AtomicU32 = AtomicU32::new(0);
static DEPTH: AtomicU32 = AtomicU32::new(0);

struct Lock {
    nested: bool,
}

impl Lock {
    /// The bridge belongs to one thread at a time; the same thread may enter again (a hook inside an
    /// injected call). Another thread waits a little and then gives up (its event is passed through).
    fn acquire() -> Option<Lock> {
        let tid = unsafe { windows_sys::Win32::System::Threading::GetCurrentThreadId() };
        if OWNER.load(SeqCst) == tid {
            DEPTH.fetch_add(1, SeqCst);
            return Some(Lock { nested: true });
        }
        let deadline = Instant::now() + std::time::Duration::from_millis(50);
        loop {
            if OWNER.compare_exchange(0, tid, SeqCst, SeqCst).is_ok() {
                DEPTH.store(1, SeqCst);
                return Some(Lock { nested: false });
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::yield_now();
        }
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        if DEPTH.fetch_sub(1, SeqCst) == 1 {
            OWNER.store(0, SeqCst);
        }
    }
}

// ---- running one hook event --------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The bridge handled the event; the registers carry what it decided.
    Handled,
    /// Not handled: the game runs the code the hook replaced, unchanged.
    Passed,
}

fn handler() -> Option<&'static mut dyn HookHandler> {
    unsafe { (*HANDLER.0.get()).as_deref_mut() }
}

/// `Bridge.__call__(client, rva, context)` for one event, including the retry the debugger did after
/// each injected call.
pub fn run_hook(hook: Hook, regs: &mut Regs) -> Outcome {
    crate::crash::enter_hook(hook as u32, regs.q(regs::RSP));
    let outcome = run_hook_inner(hook, regs);
    crate::crash::leave_hook(hook as u32, (outcome == Outcome::Handled) as u64);
    outcome
}

fn run_hook_inner(hook: Hook, regs: &mut Regs) -> Outcome {
    if !ACTIVE.load(Relaxed) || DISABLED[hook as usize].load(Relaxed) {
        return Outcome::Passed;
    }
    let Some(shared) = shared() else { return Outcome::Passed };
    if SERVER.load(Relaxed) == 0 {
        if hook == Hook::Tick {
            SERVER.store(regs.q(regs::RCX), Relaxed);
        } else if hook == Hook::UiCommand {
            // the native Enter of the menu: a guest holds it until the host's map is known (`PartyMenu`), before any server exists
            let Some(_lock) = Lock::acquire() else { return Outcome::Passed };
            let Some(handler) = handler() else { return Outcome::Passed };
            handler.set_clock(clock());
            let original = regs.clone();
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler.menu(&mut Live, hook, regs)));
            return match outcome {
                Ok(Ok(())) => Outcome::Handled,
                Ok(Err(reason)) => fault(shared, hook, &reason, regs, original),
                Err(_) => fault(shared, hook, "panic in the bridge", regs, original),
            };
        } else if !matches!(hook, Hook::MapSelect | Hook::MenuLogin) {
            return Outcome::Passed; // the menu's map selection and login come before the game server exists
        }
    }
    let Some(_lock) = Lock::acquire() else {
        STAT_BUSY.fetch_add(1, Relaxed);
        return Outcome::Passed;
    };
    if _lock.nested {
        STAT_NESTED.fetch_add(1, Relaxed);
    }
    STAT_EVENTS.fetch_add(1, Relaxed);
    STAT_BY_HOOK[hook as usize].fetch_add(1, Relaxed);
    let original = regs.clone();
    for pass in 0..MAX_PASSES {
        CALL_MADE.store(false, Relaxed);
        let Some(handler) = handler() else { return Outcome::Passed };
        handler.set_clock(clock());
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handler.handle(&mut Live, hook, regs)));
        match outcome {
            Ok(Ok(())) => {}
            Ok(Err(reason)) => return fault(shared, hook, &reason, regs, original),
            Err(_) => return fault(shared, hook, "panic in the bridge", regs, original),
        }
        if !CALL_MADE.load(Relaxed) {
            return Outcome::Handled;
        }
        STAT_RETRIES.fetch_add(1, Relaxed);
        if pass + 1 == MAX_PASSES {
            shared.log.warn(&format!("hook {}: {MAX_PASSES} passes in one event, letting the game go on", hook.name()));
        }
    }
    Outcome::Handled
}

/// A handler failed: the Python raised and the run ended. Here the game must go on, so the bridge
/// stops for good and every hook passes through (the game runs vanilla code from here on).
fn fault(shared: &Shared, hook: Hook, reason: &str, regs: &mut Regs, original: Regs) -> Outcome {
    STAT_FAULTS.fetch_add(1, Relaxed);
    ACTIVE.store(false, SeqCst);
    shared.log.failed(&format!("hook {}", hook.name()), &format!("{reason}; the co-op core stops, the game continues unmodified"));
    *regs = original;
    Outcome::Passed
}

// ---- installation ---------------------------------------------------------------------------------------------

/// The hooks of NativeCombatBridge on an updated build, in the order of `native_probe.run`.
pub const ENTRY_HOOKS: [Hook; 16] = [
    Hook::Tick, Hook::Serialize, Hook::Write, Hook::Pause, Hook::Resume, Hook::Start, Hook::AwardXp, Hook::Choose, Hook::Move,
    Hook::Hurt, Hook::Spawn, Hook::FindSpawn, Hook::RemoveLoot, Hook::ApplyEffect, Hook::UiCommand, Hook::MapSelect,
];
pub const MID_HOOKS: [Hook; 6] = [Hook::EnemyAoe, Hook::GroundAoe, Hook::EnemyTarget, Hook::HudDeliver, Hook::BossDeath, Hook::MenuLogin];

/// The instruction a mid-function site replaces: its opcode bytes (the displacements differ per build; the
/// Python compared a build's bytes with its own) and its length.
pub(crate) fn mid_site_shape(hook: Hook, variant: Variant) -> Option<(Vec<u8>, usize)> {
    Some(match hook {
        Hook::EnemyAoe => (azcoop_patch::hx("0f82"), 6),
        Hook::GroundAoe => (azcoop_patch::hx("72"), 2),
        Hook::EnemyTarget => (azcoop_patch::hx("f2"), 8),
        Hook::HudDeliver => (azcoop_patch::hx("ff5020"), 3),
        // the login's map check: `jnz +disp8` (the menu contract's `expected` is 75 xx)
        Hook::MenuLogin => (azcoop_patch::hx("75"), 2),
        // 47e4 family: INC DWORD [RSI+boss count]; 0.84.3: MOV RAX,[RBP+frame slot]
        Hook::BossDeath if variant.is_47e4() => (azcoop_patch::hx("ff86"), 6),
        Hook::BossDeath => (azcoop_patch::hx("488b85"), 7),
        _ => return None,
    })
}

pub struct Settings {
    pub number: u32,
    pub players: u32,
}

impl Settings {
    pub fn from_env() -> Settings {
        let number = std::env::var("AZCOOP_PLAYER").ok().and_then(|v| v.parse().ok()).filter(|n| (1..=4).contains(n)).unwrap_or(1);
        let players = std::env::var("COOP_PLAYERS").ok().and_then(|v| v.parse().ok()).filter(|n| (1..=4).contains(n)).unwrap_or(1);
        Settings { number, players }
    }
}

/// Builds the bridge for this game and puts every hook in. Boot-log lines go to `log`.
pub fn install(log: &'static Log, game: &Path, exe: &Path, sha256: &str, release: &Path) -> Result<()> {
    let settings = Settings::from_env();
    let step = "co-op core: profile and build";
    let started = log.begin(step);
    let variant = Variant::from_sha256(sha256)?;
    let reviewed_path = game.join("reconstruction").join("reviewed-hooks.json");
    let reviewed_text = std::fs::read_to_string(&reviewed_path).map_err(|e| format!("{}: {e}", reviewed_path.display()))?;
    let profile = load_profile(game, release, &reviewed_text, sha256)?;
    let fields = GameFields::resolve(&profile)?;
    let connections = profile.field("server", 0x918)? as u64;
    let totem_vector = profile.field("game", 0x5C0)? as u64;
    let raw = azcoop_game::profile::RawGameFields::resolve(&profile, variant)?;
    log.ok(step, started, &format!("{} ({}), player {} of {}", variant.name(), profile.release_version, settings.number, settings.players));

    let step = "co-op core: bridge";
    let started = log.begin(step);
    let local = Local::game()?;
    let image = std::sync::Arc::new(DiskImage::open(exe)?);
    let build = Build { variant, fields, connections, totem_vector, raw, profile: profile.clone() };
    let mut bridge = Bridge::new(build, settings.players)?;
    bridge.trace_defeat_ui = true;
    // finding a crash: AZCOOP_SKIP_PATCHES=guards,host_world,spawn_balance,guest_gate,guest_tick leaves those code patches out,
    // AZCOOP_DISABLE_HOOKS=SPAWN,FIND_SPAWN,... lets those hooks pass through unchanged
    if std::env::var("AZCOOP_AUTO_TALENT").is_ok_and(|v| v == "1") {
        bridge.auto_talent = true;
        log.warn("level-up choices are made by the core (AZCOOP_AUTO_TALENT=1, trials only)");
    }
    // the zone is known from the start (a trial with autostart has no map choice, like the launcher's diagnostic autostart)
    if let Ok(zone) = std::env::var("AZCOOP_HOST_MAP") {
        match azcoop_bridge::menu::ALL_ZONES.iter().find(|z| **z == zone.trim()) {
            Some(z) => {
                bridge.host_map = Some(z.to_string());
                log.warn(&format!("host map preset to {z} (AZCOOP_HOST_MAP)"));
            }
            None => log.warn(&format!("AZCOOP_HOST_MAP: unknown zone {zone}")),
        }
    }
    if let Ok(list) = std::env::var("AZCOOP_SKIP_PATCHES") {
        bridge.skip_patches = list.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        log.warn(&format!("code patches left out (AZCOOP_SKIP_PATCHES): {:?}", bridge.skip_patches));
    }
    if let Ok(list) = std::env::var("AZCOOP_DISABLE_HOOKS") {
        for name in list.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            match Hook::from_name(name) {
                Some(hook) => {
                    DISABLED[hook as usize].store(true, SeqCst);
                    log.warn(&format!("hook {name} passes through (AZCOOP_DISABLE_HOOKS)"));
                }
                None => log.warn(&format!("AZCOOP_DISABLE_HOOKS: unknown hook {name}")),
            }
        }
    }
    let image_size = local.image_size as u64;
    let mut entries = [0u64; HOOK_COUNT];
    for hook in Hook::ALL {
        if let Some(h) = profile.hooks.get(hook.name()) {
            entries[*hook as usize] = local.base as u64 + h.rva;
        }
    }
    // the login branch is not a reviewed hook of its own: its address is part of the menu contract
    if let Some(login) = profile.menu.as_ref().and_then(|m| m.login.as_ref()) {
        entries[Hook::MenuLogin as usize] = local.base as u64 + login.branch;
    }
    let shared = Shared {
        local,
        number: settings.number,
        log,
        profile,
        variant,
        image: image.clone(),
        natives: Mutex::new(Natives { entries, owned: HashMap::new(), defeat_ui: 0, pause_ui: [0; 2], scratch: 0 }),
        started: Instant::now(),
        loading: Mutex::new(LoadingWatch::new(game)),
    };
    log.ok(step, started, &format!("loading screen: {}", shared.loading.lock().unwrap().describe()));
    crate::crash::set_game_base(shared.local.base as u64);
    SHARED.set(shared).map_err(|_| "engine installed twice".to_string())?;
    unsafe { *HANDLER.0.get() = Some(Box::new(crate::peers::OnlineHandler::new(bridge, settings.number, settings.players, image_size))) };

    // verify every site against the executable on disk before anything is written
    let step = "co-op core: verify hook sites";
    let started = log.begin(step);
    let shared = shared_ref();
    let mut sites = 0;
    for hook in ENTRY_HOOKS.iter().chain(MID_HOOKS.iter()) {
        let address = shared.natives.lock().unwrap().entries[*hook as usize];
        let Some(rva) = (address != 0).then(|| address - shared.base()) else {
            if matches!(hook, Hook::MapSelect | Hook::MenuLogin) {
                continue; // the party menu is optional: without its hooks the host map is simply never published
            }
            return Err(format!("the profile has no {} hook", hook.name()));
        };
        let length = mid_site_shape(*hook, variant).map_or(16, |(_, length)| length);
        let live = shared.local.read(address as usize, length)?;
        if live != image.bytes(rva, length)? {
            return Err(format!("{} at {rva:#x} differs from the executable on disk: {}", hook.name(), hex(&live)));
        }
        if let Some((opcode, _)) = mid_site_shape(*hook, variant) {
            if !live.starts_with(&opcode) {
                return Err(format!("{} at {rva:#x} is {} (expected an instruction starting {})", hook.name(), hex(&live), hex(&opcode)));
            }
        }
        sites += 1;
    }
    log.ok(step, started, &format!("{sites} sites"));

    let step = "co-op core: install hooks";
    let started = log.begin(step);
    ACTIVE.store(true, SeqCst);
    if let Err(e) = crate::entry::install_all(shared, log) {
        ACTIVE.store(false, SeqCst);
        return Err(e);
    }
    log.ok(step, started, &format!("{} entry hooks, {} breakpoint sites", ENTRY_HOOKS.len(), MID_HOOKS.len()));
    Ok(())
}

/// The release profile of this executable: the file the DLL's profile lookup found, else any
/// `reconstruction/release-*.json` that names the executable and parses as an adapter profile.
fn load_profile(game: &Path, first: &Path, reviewed: &str, sha256: &str) -> Result<Profile> {
    let mut candidates = vec![first.to_path_buf()];
    if let Ok(entries) = std::fs::read_dir(game.join("reconstruction")) {
        let mut releases: Vec<_> = entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("release-") && n.ends_with(".json")))
            .collect();
        releases.sort();
        candidates.extend(releases);
    }
    let mut errors = Vec::new();
    for path in candidates {
        match std::fs::read_to_string(&path).map_err(|e| e.to_string()).and_then(|text| Profile::parse(&text, reviewed)) {
            Ok(profile) if profile.sha256 == sha256 => return Ok(profile),
            Ok(_) => errors.push(format!("{}: names another executable", path.display())),
            Err(e) => errors.push(format!("{}: {e}", path.display())),
        }
    }
    Err(format!("no adapter profile for this executable: {}", errors.join("; ")))
}

fn shared_ref() -> &'static Shared {
    SHARED.get().expect("installed")
}

/// One line for the periodic report.
pub fn summary() -> String {
    let by_hook: Vec<String> = Hook::ALL
        .iter()
        .filter(|h| STAT_BY_HOOK[**h as usize].load(Relaxed) > 0)
        .map(|h| format!("{} {}", h.name(), STAT_BY_HOOK[*h as usize].load(Relaxed)))
        .collect();
    format!(
        "engine {}: events {} (nested {}, busy {}), calls {}, retries {}, faults {} | {}",
        if is_active() { "active" } else { "stopped" },
        STAT_EVENTS.load(Relaxed),
        STAT_NESTED.load(Relaxed),
        STAT_BUSY.load(Relaxed),
        STAT_CALLS.load(Relaxed),
        STAT_RETRIES.load(Relaxed),
        STAT_FAULTS.load(Relaxed),
        by_hook.join(", ")
    )
}

/// Test support: an engine over stand-in functions and a scripted handler.
#[cfg(test)]
pub mod testing {
    use super::*;

    static ONCE: std::sync::Once = std::sync::Once::new();

    /// Sets the engine up once per test process (the state is global); later calls only swap the handler.
    pub fn setup(entries: [u64; HOOK_COUNT], handler: Box<dyn HookHandler>) {
        ONCE.call_once(|| {
            let log: &'static Log = Box::leak(Box::new(Log::open(&std::env::temp_dir().join("azcoop-engine-test.log"))));
            let local = Local::game().expect("test process image");
            let profile = Profile { sha256: String::new(), release_version: String::new(), hooks: Default::default(), fields: Default::default(), addresses: Default::default(), dispatch_guards: Vec::new(), menu: None, patches: Default::default() };
            let image = std::sync::Arc::new(DiskImage::open(&std::env::current_exe().unwrap()).expect("test exe on disk"));
            let shared = Shared {
                local,
                number: 1,
                log,
                profile,
                variant: Variant::V0931,
                image,
                natives: Mutex::new(Natives { entries: [0; HOOK_COUNT], owned: HashMap::new(), defeat_ui: 0, pause_ui: [0; 2], scratch: 0 }),
                started: Instant::now(),
                loading: Mutex::new(LoadingWatch::new(Path::new("."))),
            };
            assert!(SHARED.set(shared).is_ok());
        });
        shared_ref().natives.lock().unwrap().entries = entries;
        unsafe { *HANDLER.0.get() = Some(handler) };
        SERVER.store(0x1234_0000, SeqCst);
        SAVED.store(false, SeqCst);
        ACTIVE.store(true, SeqCst);
        for d in &DISABLED {
            d.store(false, SeqCst);
        }
    }

    pub fn active() -> bool {
        ACTIVE.load(SeqCst)
    }
}
