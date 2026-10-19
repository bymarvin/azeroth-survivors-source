//! Crash diagnostics for the in-process core.
//!
//! A game that dies without an error report leaves nothing behind unless the core wrote something first, so three things run all
//! the time:
//!
//! * a **flight recorder**: a ring of the last 8192 hook events in a file-backed memory mapping (`azcoop-flight.bin`). The operating
//!   system writes the pages out even if the process is killed, so the last hooks before a `TerminateProcess` or a fast fail are
//!   in the file. `tools/pack/flight.py` prints it.
//! * an **exception handler** (vectored, first chance, plus the unhandled-exception filter): for an access violation, a stack overflow,
//!   an illegal instruction and the like it writes the code, the address with module and RVA, the thread and the last hooks to
//!   `azcoop-crash.log`, and a minidump `azcoop-crash-<n>.dmp` when the fault is in our code, in a hook, or unhandled.
//! * a **panic hook** and a **process-detach note** in the log, so a Rust panic or a normal `ExitProcess` is told apart from a kill.

use crate::log::Log;
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, Ordering::*};
use std::sync::OnceLock;
use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, WriteFile, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ};
use windows_sys::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, SetUnhandledExceptionFilter, EXCEPTION_POINTERS, MINIDUMP_EXCEPTION_INFORMATION,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleFileNameW, GetModuleHandleExW, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT};
use windows_sys::Win32::System::Memory::{CreateFileMappingW, MapViewOfFile, FILE_MAP_ALL_ACCESS, PAGE_READWRITE};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetCurrentProcessId, GetCurrentThreadId};

/// "" for player 1, "-p2" ... for the others: two games in one folder (the two-window trial) must not write the same files.
pub fn player_suffix() -> String {
    match std::env::var("AZCOOP_PLAYER").ok().and_then(|v| v.parse::<u32>().ok()) {
        Some(n) if n > 1 => format!("-p{n}"),
        _ => String::new(),
    }
}

pub const RECORDS: usize = 8192;
pub const RECORD_BYTES: usize = 32;
const HEADER: usize = 64;
const MAGIC: u64 = 0x5448_4749_4c46_5a41; // "AZFLIGHT"

/// What a record is about.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    HookEnter = 1,
    HookExit = 2,
    CallStart = 3,
    CallEnd = 4,
    Patch = 5,
    Note = 6,
}

static MAP: AtomicPtr<u8> = AtomicPtr::new(std::ptr::null_mut());
static NEXT: AtomicU64 = AtomicU64::new(0);
static LOG: OnceLock<&'static Log> = OnceLock::new();
static CRASH_FILE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static DIR: OnceLock<PathBuf> = OnceLock::new();
static OWN_BASE: AtomicU64 = AtomicU64::new(0);
static OWN_END: AtomicU64 = AtomicU64::new(0);
static REPORTED: AtomicU32 = AtomicU32::new(0);
static DUMPED: AtomicBool = AtomicBool::new(false);
static EXITING: AtomicBool = AtomicBool::new(false);
static GAME_BASE: AtomicU64 = AtomicU64::new(0);
/// The buffers the core allocated in the game (kind 'c' code / 'd' data, address, size), in allocation order: a fault inside one of
/// them is told apart from a fault in the game or in the DLL.
static BUFFERS: std::sync::Mutex<Vec<(char, u64, usize)>> = std::sync::Mutex::new(Vec::new());

/// The last [`OWN_SLOTS`] writes, patches, allocations and native calls of the core: (sequence, kind, address, size, tick). A heap corruption
/// shows up far from its cause; the crash report lists what the core touched last.
pub const OWN_SLOTS: usize = 64;
static OWN_SEQ: AtomicU64 = AtomicU64::new(0);
static OWN_RING: [[AtomicU64; 4]; OWN_SLOTS] = [const { [const { AtomicU64::new(0) }; 4] }; OWN_SLOTS];

/// One own action: `kind` is W (write), P (code patch), A (allocation), X (executable buffer), C (native call), U (UI command buffer).
pub fn note_own(kind: u8, address: u64, size: u64) {
    let n = OWN_SEQ.fetch_add(1, Relaxed) + 1;
    let slot = &OWN_RING[(n as usize) % OWN_SLOTS];
    slot[1].store(address, Relaxed);
    slot[2].store(size, Relaxed);
    slot[3].store(tick(), Relaxed);
    slot[0].store((n << 8) | kind as u64, Release);
}

/// The own actions, oldest first, as text (`#seq kind address+size`, rva for addresses in the game image).
pub fn own_tail() -> Vec<String> {
    let mut rows: Vec<(u64, u8, u64, u64)> = OWN_RING
        .iter()
        .filter_map(|s| {
            let head = s[0].load(Acquire);
            (head != 0).then(|| (head >> 8, head as u8, s[1].load(Relaxed), s[2].load(Relaxed)))
        })
        .collect();
    rows.sort_by_key(|r| r.0);
    let base = GAME_BASE.load(Relaxed);
    rows.iter()
        .map(|(n, kind, address, size)| {
            let place = if base != 0 && *address >= base && *address < base + 0x1000_0000 { format!("rva {:#x}", address - base) } else { format!("{address:#x}") };
            format!("own #{n} {} {place} +{size}{}", *kind as char, buffer_report(*address))
        })
        .collect()
}

fn own_report() {
    let rows = own_tail();
    if !rows.is_empty() {
        crash_line(&format!("the core's last {} writes/patches/calls (oldest first):", rows.len()));
        for row in rows {
            crash_line(&format!("    {row}"));
        }
    }
}

pub fn note_buffer(kind: char, address: u64, size: usize) {
    if let Ok(mut b) = BUFFERS.try_lock() {
        b.push((kind, address, size));
    }
    note(Kind::Note, 0xB0F0_0000 | kind as u64, address);
}

fn buffer_report(address: u64) -> String {
    let Ok(b) = BUFFERS.try_lock() else { return String::new() };
    for (i, (kind, start, size)) in b.iter().enumerate() {
        if address >= *start && address < start + (*size).max(1) as u64 {
            return format!(", inside our buffer #{i} ({} at {start:#x} + {:#x}, {size} bytes)", if *kind == 'c' { "code" } else { "data" }, address - start);
        }
    }
    String::new()
}

/// The game's image base, so that addresses in the recorder read as RVAs.
pub fn set_game_base(base: u64) {
    GAME_BASE.store(base, Relaxed);
    let map = MAP.load(SeqCst);
    if !map.is_null() {
        unsafe { (map.add(48) as *mut u64).write(base) };
    }
}

/// An address as an RVA of the game image when it lies below 4 GiB above the base (what a record can hold).
pub fn rva(address: u64) -> u64 {
    address.wrapping_sub(GAME_BASE.load(Relaxed))
}

thread_local! {
    /// The hook this thread is inside (0: none).
    static IN_HOOK: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn tick() -> u64 {
    let mut t = 0i64;
    unsafe { windows_sys::Win32::System::Performance::QueryPerformanceCounter(&mut t) };
    t as u64
}

/// Opens the flight recorder file and installs the handlers. Safe to call once; later calls do nothing.
pub fn init(dir: &Path, log: &'static Log) {
    if LOG.set(log).is_err() {
        return;
    }
    let _ = DIR.set(dir.to_path_buf());
    unsafe {
        let mut module: *mut c_void = std::ptr::null_mut();
        if GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, init as usize as *const u16, &mut module as *mut _ as *mut _) != 0 && !module.is_null() {
            let base = module as u64;
            OWN_BASE.store(base, Relaxed);
            // size of image from the PE header
            let e_lfanew = *((base + 0x3C) as *const u32) as u64;
            let size = *((base + e_lfanew + 24 + 56) as *const u32) as u64;
            OWN_END.store(base + size, Relaxed);
        }
        // flight recorder: file-backed mapping
        let path = wide(&dir.join(format!("azcoop-flight{}.bin", player_suffix())).to_string_lossy());
        let file = CreateFileW(path.as_ptr(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, std::ptr::null(), CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, std::ptr::null_mut());
        if file != INVALID_HANDLE_VALUE {
            let size = (HEADER + RECORDS * RECORD_BYTES) as u64;
            let mapping = CreateFileMappingW(file, std::ptr::null(), PAGE_READWRITE, (size >> 32) as u32, size as u32, std::ptr::null());
            if !mapping.is_null() {
                let view = MapViewOfFile(mapping, FILE_MAP_ALL_ACCESS, 0, 0, size as usize);
                if !view.Value.is_null() {
                    let p = view.Value as *mut u8;
                    (p as *mut u64).write(MAGIC);
                    (p.add(8) as *mut u32).write(RECORDS as u32);
                    (p.add(12) as *mut u32).write(RECORD_BYTES as u32);
                    (p.add(16) as *mut u32).write(GetCurrentProcessId());
                    (p.add(24) as *mut u64).write(tick());
                    let mut freq = 0i64;
                    windows_sys::Win32::System::Performance::QueryPerformanceFrequency(&mut freq);
                    (p.add(32) as *mut u64).write(freq as u64);
                    MAP.store(p, SeqCst);
                }
                // the mapping object may go; the view keeps the section alive
                CloseHandle(mapping);
            }
            CloseHandle(file);
        }
        // crash log: a raw handle, no locks
        let crash = wide(&dir.join(format!("azcoop-crash{}.log", player_suffix())).to_string_lossy());
        let h = CreateFileW(crash.as_ptr(), GENERIC_WRITE, FILE_SHARE_READ, std::ptr::null(), CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, std::ptr::null_mut());
        if h != INVALID_HANDLE_VALUE {
            CRASH_FILE.store(h, SeqCst);
        }
        AddVectoredExceptionHandler(1, Some(vectored));
        SetUnhandledExceptionFilter(Some(unhandled));
    }
    install_panic_hook();
    log.info(&format!("crash diagnostics: flight recorder ({RECORDS} records), exception handler, panic hook; own image {:#x}-{:#x}", OWN_BASE.load(Relaxed), OWN_END.load(Relaxed)));
}

/// Writes one record into the ring. Lock-free; a no-op before [`init`].
#[inline]
pub fn note(kind: Kind, a: u64, b: u64) {
    let map = MAP.load(Relaxed);
    if map.is_null() {
        return;
    }
    let n = NEXT.fetch_add(1, Relaxed);
    let slot = unsafe { map.add(HEADER + (n as usize % RECORDS) * RECORD_BYTES) };
    unsafe {
        // sequence last, so a reader can tell a finished record from one being written
        (slot.add(8) as *mut u64).write(tick());
        (slot.add(16) as *mut u32).write(GetCurrentThreadId());
        (slot.add(20) as *mut u32).write(kind as u32);
        (slot.add(24) as *mut u32).write(a as u32);
        (slot.add(28) as *mut u32).write(b as u32);
        (slot as *mut u64).write(n + 1);
    }
    // the header keeps the newest sequence for the reader
    unsafe { (map.add(40) as *mut u64).write(n + 1) };
}

/// A hook handler started on this thread.
pub fn enter_hook(hook_id: u32, rsp: u64) {
    IN_HOOK.with(|c| c.set(hook_id + 1));
    note(Kind::HookEnter, hook_id as u64, rsp);
}

pub fn leave_hook(hook_id: u32, outcome: u64) {
    note(Kind::HookExit, hook_id as u64, outcome);
    IN_HOOK.with(|c| c.set(0));
}

pub fn in_hook() -> Option<u32> {
    IN_HOOK.with(|c| c.get().checked_sub(1))
}

// ---- reading (for the tool and the tests) -------------------------------------------------------------------

/// A decoded record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub seq: u64,
    pub tick: u64,
    pub thread: u32,
    pub kind: u32,
    pub a: u32,
    pub b: u32,
}

/// The records of a flight file in order, oldest first.
pub fn read_records(bytes: &[u8]) -> Vec<Record> {
    if bytes.len() < HEADER || u64::from_le_bytes(bytes[..8].try_into().unwrap()) != MAGIC {
        return Vec::new();
    }
    let count = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
    let size = u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
    let mut out = Vec::new();
    for i in 0..count {
        let at = HEADER + i * size;
        if at + size > bytes.len() {
            break;
        }
        let s = &bytes[at..at + size];
        let seq = u64::from_le_bytes(s[0..8].try_into().unwrap());
        if seq == 0 {
            continue;
        }
        out.push(Record {
            seq,
            tick: u64::from_le_bytes(s[8..16].try_into().unwrap()),
            thread: u32::from_le_bytes(s[16..20].try_into().unwrap()),
            kind: u32::from_le_bytes(s[20..24].try_into().unwrap()),
            a: u32::from_le_bytes(s[24..28].try_into().unwrap()),
            b: u32::from_le_bytes(s[28..32].try_into().unwrap()),
        });
    }
    out.sort_by_key(|r| r.seq);
    out
}

/// One line for a record, with the hook named.
pub fn describe(r: &Record) -> String {
    let hook = |id: u32| azcoop_bridge::client::Hook::ALL.get(id as usize).map_or("?", |h| h.name());
    match r.kind {
        1 => format!("#{} t{} enter {} rsp..{:x}", r.seq, r.thread, hook(r.a), r.b),
        2 => format!("#{} t{} leave {} outcome {}", r.seq, r.thread, hook(r.a), r.b),
        3 => format!("#{} t{} call start {} arg..{:x}", r.seq, r.thread, hook(r.a), r.b),
        4 => format!("#{} t{} call end {} result {}", r.seq, r.thread, hook(r.a), r.b),
        5 => format!("#{} t{} patch ..{:x} len {}", r.seq, r.thread, r.a, r.b),
        6 => format!("#{} t{} note {} {}", r.seq, r.thread, r.a, r.b),
        k => format!("#{} t{} kind {k} {} {}", r.seq, r.thread, r.a, r.b),
    }
}

/// The last `n` records of the live ring, oldest first (for the crash report).
pub fn tail(n: usize) -> Vec<String> {
    let map = MAP.load(SeqCst);
    if map.is_null() {
        return Vec::new();
    }
    let bytes = unsafe { std::slice::from_raw_parts(map as *const u8, HEADER + RECORDS * RECORD_BYTES) };
    let records = read_records(bytes);
    let from = records.len().saturating_sub(n);
    let freq = u64::from_le_bytes(bytes[32..40].try_into().unwrap()).max(1);
    let last = records.last().map_or(0, |r| r.tick);
    records[from..].iter().map(|r| format!("{} (-{:.1} ms)", describe(r), (last.saturating_sub(r.tick)) as f64 * 1000.0 / freq as f64)).collect()
}

// ---- crash report ---------------------------------------------------------------------------------------------

// ---- crash report schema 2 (analysis/CRASH-REPORT-FORMAT.md of the lobby chat, branch lobby-backlog b799b18) ----------------
// One JSON line `{"event":"native_crash","schema":2,...}` in azcoop-crash<suffix>.log: the faulting module (not only an EXE RVA),
// the access, up to 32 code addresses on the stack with their modules, the loaded modules that are neither the game, ours nor Windows.
// The launcher shim copies the line unchanged into the gameplay log, which the crash upload carries.

struct LoadedModule {
    base: u64,
    end: u64,
    name: String,
    system: bool,
}

/// The lower-case Windows directory with a trailing backslash ("c:\windows\"), for where = system.
fn windows_dir() -> String {
    let mut buffer = [0u16; 512];
    let n = unsafe { windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if n == 0 || n >= buffer.len() {
        return String::new();
    }
    let mut dir = String::from_utf16_lossy(&buffer[..n]).to_lowercase();
    if !dir.ends_with('\\') {
        dir.push('\\');
    }
    dir
}

unsafe fn loaded_modules() -> Vec<LoadedModule> {
    use windows_sys::Win32::System::ProcessStatus::{EnumProcessModulesEx, GetModuleInformation, LIST_MODULES_ALL, MODULEINFO};
    let process = GetCurrentProcess();
    let mut handles: Vec<windows_sys::Win32::Foundation::HMODULE> = vec![std::ptr::null_mut(); 1024];
    let mut needed = 0u32;
    if EnumProcessModulesEx(process, handles.as_mut_ptr(), (handles.len() * std::mem::size_of::<usize>()) as u32, &mut needed, LIST_MODULES_ALL) == 0 {
        return Vec::new();
    }
    let count = (needed as usize / std::mem::size_of::<usize>()).min(handles.len());
    let windows = windows_dir();
    let mut out = Vec::with_capacity(count);
    for &module in &handles[..count] {
        let mut info: MODULEINFO = std::mem::zeroed();
        if GetModuleInformation(process, module, &mut info, std::mem::size_of::<MODULEINFO>() as u32) == 0 {
            continue;
        }
        let mut buffer = [0u16; 1024];
        let n = GetModuleFileNameW(module, buffer.as_mut_ptr(), buffer.len() as u32) as usize;
        let path = String::from_utf16_lossy(&buffer[..n]);
        let name = path.rsplit(['\\', '/']).next().unwrap_or(&path).to_string();
        let system = !windows.is_empty() && path.to_lowercase().starts_with(&windows);
        let base = info.lpBaseOfDll as u64;
        out.push(LoadedModule { base, end: base + info.SizeOfImage as u64, name, system });
    }
    out
}

/// (where, module file name, offset from the module or buffer start) of an address.
fn classify(address: u64, modules: &[LoadedModule]) -> (&'static str, Option<String>, u64) {
    if ours(address) {
        let own = modules.iter().find(|m| m.base == OWN_BASE.load(Relaxed)).map(|m| m.name.clone());
        return ("coop", own.or(Some("avrt.dll".into())), address - OWN_BASE.load(Relaxed));
    }
    if let Ok(buffers) = BUFFERS.try_lock() {
        for (_, start, size) in buffers.iter() {
            if address >= *start && address < start + (*size).max(1) as u64 {
                return ("coop", None, address - start);
            }
        }
    }
    match modules.iter().find(|m| address >= m.base && address < m.end) {
        Some(m) if m.base == GAME_BASE.load(Relaxed) => ("game", Some(m.name.clone()), address - m.base),
        Some(m) if m.system => ("system", Some(m.name.clone()), address - m.base),
        Some(m) => ("other", Some(m.name.clone()), address - m.base),
        None => ("unknown", None, address),
    }
}

/// An address whose page can be executed (a code address on the stack, not data that happens to point into an image).
fn executable(address: u64) -> bool {
    use windows_sys::Win32::System::Memory::{VirtualQuery, MEMORY_BASIC_INFORMATION};
    let mut info: MEMORY_BASIC_INFORMATION = unsafe { std::mem::zeroed() };
    let n = unsafe { VirtualQuery(address as *const c_void, &mut info, std::mem::size_of::<MEMORY_BASIC_INFORMATION>()) };
    n != 0 && info.State == 0x1000 && (info.Protect & 0xF0) != 0 // MEM_COMMIT, PAGE_EXECUTE*
}

fn place(where_: &str, module: &Option<String>, offset: u64) -> serde_json::Value {
    serde_json::json!({"module": module, "offset": format!("{offset:#x}"), "where": where_})
}

/// The schema-2 line and the human traceback line of an exception.
unsafe fn crash_report(info: *const EXCEPTION_POINTERS, first_chance: bool) -> (String, String) {
    let record = &*(*info).ExceptionRecord;
    let code = record.ExceptionCode as u32;
    let fault = record.ExceptionAddress as u64;
    let modules = loaded_modules();
    let game_base = GAME_BASE.load(Relaxed);
    let (where_, module, offset) = classify(fault, &modules);
    let mut line = serde_json::json!({
        "event": "native_crash", "schema": 2,
        "player": std::env::var("AZCOOP_PLAYER").ok().and_then(|v| v.parse::<u32>().ok()).unwrap_or(1),
        "code": format!("{code:08x}"), "first_chance": first_chance,
        "rva": fault.wrapping_sub(game_base),
        "fault": place(where_, &module, offset),
    });
    let mut human = format!("{} native exception {code:08x} at {}+{offset:#x}", if first_chance { "first-chance" } else { "unhandled" },
                            module.clone().unwrap_or_else(|| if where_ == "coop" { "co-op buffer".into() } else { format!("{fault:#x}") }));
    let mut detail = Vec::new();
    if matches!(code, 0xC000_0005 | 0xC000_0006) && record.NumberParameters >= 2 {
        let kind = match record.ExceptionInformation[0] { 0 => "read", 1 => "write", 8 => "execute", _ => "access" };
        let target = record.ExceptionInformation[1] as u64;
        let (_, target_module, _) = classify(target, &modules);
        line["access"] = serde_json::json!({"type": kind, "address": format!("{target:#x}"), "module": target_module});
        detail.push(format!("{kind} {target:#x}"));
    }
    if where_ == "game" {
        detail.push(format!("RVA {offset:#x}"));
    }
    detail.push(format!("game base {game_base:#x}"));
    human.push_str(&format!(" ({})", detail.join("; ")));
    let ctx = (*info).ContextRecord;
    let (mut frames, mut exe_offsets) = (Vec::new(), Vec::new());
    if !ctx.is_null() {
        let rsp = (*ctx).Rsp;
        // 2048 bytes from rsp, but not past the end of the stack's region (a shallow thread: the read would fail as a whole)
        let mut region: windows_sys::Win32::System::Memory::MEMORY_BASIC_INFORMATION = std::mem::zeroed();
        let size = windows_sys::Win32::System::Memory::VirtualQuery(rsp as *const c_void, &mut region, std::mem::size_of_val(&region));
        let room = if size != 0 { (region.BaseAddress as u64 + region.RegionSize as u64).saturating_sub(rsp) as usize } else { 0 };
        let mut stack = vec![0u8; room.min(2048)];
        let mut read = 0usize;
        if !stack.is_empty() && windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(GetCurrentProcess(), rsp as *const _, stack.as_mut_ptr() as *mut _, stack.len(), &mut read) != 0 {
            for sp in (0..read.saturating_sub(7)).step_by(8) {
                let value = u64::from_le_bytes(stack[sp..sp + 8].try_into().unwrap());
                let (w, m, o) = classify(value, &modules);
                if w == "unknown" || !executable(value) {
                    continue;
                }
                if w == "game" && exe_offsets.len() < 32 {
                    exe_offsets.push(o);
                }
                if frames.len() < 32 {
                    let mut frame = place(w, &m, o);
                    frame["sp"] = serde_json::json!(sp);
                    frames.push(frame);
                }
            }
        }
    }
    line["stack_code_offsets"] = serde_json::json!(exe_offsets);
    let mut others: Vec<String> = modules.iter().filter(|m| classify(m.base, &modules).0 == "other").map(|m| m.name.clone()).collect();
    others.sort();
    others.dedup();
    others.truncate(32);
    line["frames"] = serde_json::json!(frames);
    line["modules_other"] = serde_json::json!(others);
    // at most 4 KB: frames first, then the module list
    let mut text = line.to_string();
    while text.len() > 4096 {
        if let Some(f) = line["frames"].as_array_mut().filter(|f| !f.is_empty()) {
            f.pop();
        } else if let Some(m) = line["modules_other"].as_array_mut().filter(|m| !m.is_empty()) {
            m.pop();
        } else {
            break;
        }
        text = line.to_string();
    }
    (text, human)
}

fn crash_json(info: *const EXCEPTION_POINTERS, first_chance: bool) {
    let (line, human) = unsafe { crash_report(info, first_chance) };
    crash_line(&human);
    crash_line(&line);
}

fn crash_line(text: &str) {
    let h = CRASH_FILE.load(SeqCst);
    if !h.is_null() {
        let line = format!("{text}\r\n");
        let mut wrote = 0u32;
        unsafe { WriteFile(h as HANDLE, line.as_ptr(), line.len() as u32, &mut wrote, std::ptr::null_mut()) };
    }
    if let Some(log) = LOG.get() {
        log.try_info(text);
    }
}

/// "module.dll+0xRVA" for an address.
pub fn module_of(address: u64) -> String {
    unsafe {
        let mut module: *mut c_void = std::ptr::null_mut();
        if GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, address as *const u16, &mut module as *mut _ as *mut _) == 0 || module.is_null() {
            return format!("{address:#x} (no module: allocated code or unmapped)");
        }
        let mut buffer = vec![0u16; 1024];
        let n = GetModuleFileNameW(module, buffer.as_mut_ptr(), buffer.len() as u32) as usize;
        let name = String::from_utf16_lossy(&buffer[..n]);
        let short = name.rsplit(['\\', '/']).next().unwrap_or(&name).to_string();
        format!("{short}+{:#x}", address - module as u64)
    }
}

fn code_name(code: u32) -> &'static str {
    match code {
        0xC000_0005 => "ACCESS_VIOLATION",
        0xC000_00FD => "STACK_OVERFLOW",
        0xC000_001D => "ILLEGAL_INSTRUCTION",
        0xC000_0094 => "INTEGER_DIVIDE_BY_ZERO",
        0xC000_0096 => "PRIVILEGED_INSTRUCTION",
        0xC000_0409 => "STACK_BUFFER_OVERRUN (fast fail)",
        0xC000_0374 => "HEAP_CORRUPTION",
        0xC000_0025 => "NONCONTINUABLE_EXCEPTION",
        0xC000_0006 => "IN_PAGE_ERROR",
        0xE06D_7363 => "C++ exception",
        0x4000_0015 => "FATAL_APP_EXIT",
        _ => "exception",
    }
}

fn is_fatal(code: u32) -> bool {
    matches!(code, 0xC000_0005 | 0xC000_00FD | 0xC000_001D | 0xC000_0094 | 0xC000_0096 | 0xC000_0409 | 0xC000_0374 | 0xC000_0025 | 0xC000_0006 | 0x4000_0015)
}

unsafe fn describe_exception(info: *const EXCEPTION_POINTERS, label: &str) -> String {
    let record = &*(*info).ExceptionRecord;
    let code = record.ExceptionCode as u32;
    let address = record.ExceptionAddress as u64;
    let mut text = format!("{label}: {} {code:#010x} at {} thread {}", code_name(code), module_of(address), GetCurrentThreadId());
    if code == 0xC000_0005 && record.NumberParameters >= 2 {
        let kind = match record.ExceptionInformation[0] {
            0 => "read",
            1 => "write",
            8 => "execute",
            _ => "access",
        };
        text.push_str(&format!(", {kind} of {:#x}", record.ExceptionInformation[1]));
    }
    text.push_str(&buffer_report(address));
    if code == 0xC000_0005 && record.NumberParameters >= 2 {
        text.push_str(&buffer_report(record.ExceptionInformation[1] as u64).replace("inside our buffer", "target inside our buffer"));
    }
    if let Some(hook) = in_hook() {
        text.push_str(&format!(", inside hook {}", azcoop_bridge::client::Hook::ALL.get(hook as usize).map_or("?", |h| h.name())));
    }
    let ctx = (*info).ContextRecord;
    if !ctx.is_null() {
        let c = &*ctx;
        text.push_str(&format!(", rip {:#x} rsp {:#x}
    regs rax {:#x} rbx {:#x} rcx {:#x} rdx {:#x} rsi {:#x} rdi {:#x} rbp {:#x} r8 {:#x} r9 {:#x} r10 {:#x} r11 {:#x} r12 {:#x} r13 {:#x} r14 {:#x} r15 {:#x} eflags {:#x}",
            c.Rip, c.Rsp, c.Rax, c.Rbx, c.Rcx, c.Rdx, c.Rsi, c.Rdi, c.Rbp, c.R8, c.R9, c.R10, c.R11, c.R12, c.R13, c.R14, c.R15, c.EFlags));
        // the code around the fault, if it can be read
        let from = c.Rip.saturating_sub(48);
        let mut bytes = vec![0u8; 96];
        let mut done = 0usize;
        if windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory(GetCurrentProcess(), from as *const _, bytes.as_mut_ptr() as *mut _, 96, &mut done) != 0 && done == 96 {
            let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
            text.push_str(&format!("
    code {:#x}..{:#x}: {}", from, from + 96, hex));
            text.push_str(&format!("
    rip is at byte 48 of that line (hex digit 96)"));
        }
    }
    text
}

fn ours(address: u64) -> bool {
    let (b, e) = (OWN_BASE.load(Relaxed), OWN_END.load(Relaxed));
    address >= b && address < e
}

unsafe extern "system" fn vectored(info: *mut EXCEPTION_POINTERS) -> i32 {
    const CONTINUE_SEARCH: i32 = 0;
    let record = &*(*info).ExceptionRecord;
    let code = record.ExceptionCode as u32;
    if is_fatal(code) {
        let address = record.ExceptionAddress as u64;
        note(Kind::Note, code as u64, address);
        let guilty = ours(address) || in_hook().is_some() || module_of(address).contains("no module");
        // first-chance faults are often handled (guard pages, probes): report a few, dump only when the fault looks like ours
        if REPORTED.fetch_add(1, SeqCst) < 12 || code == 0xC000_00FD {
            crash_line(&describe_exception(info, "first-chance"));
            if matches!(code, 0xC000_0374 | 0xC000_0409 | 0xC000_00FD) || guilty {
                crash_json(info, true);
            }
            if guilty || code == 0xC000_0374 {
                for l in tail(24) {
                    crash_line(&format!("    {l}"));
                }
                own_report();
            }
        }
        if code == 0xC000_00FD || (guilty && code != 0xC000_0005) {
            dump(info, "vectored");
        }
    }
    CONTINUE_SEARCH
}

unsafe extern "system" fn unhandled(info: *const EXCEPTION_POINTERS) -> i32 {
    crash_json(info, false);
    crash_line(&describe_exception(info, "UNHANDLED"));
    for l in tail(40) {
        crash_line(&format!("    {l}"));
    }
    own_report();
    dump(info, "unhandled");
    0 // EXCEPTION_CONTINUE_SEARCH: the game's own handling goes on
}

/// A minidump into the pack folder (once per process).
unsafe fn dump(info: *const EXCEPTION_POINTERS, why: &str) {
    if DUMPED.swap(true, SeqCst) {
        return;
    }
    let Some(dir) = DIR.get() else { return };
    let path = wide(&dir.join(format!("azcoop-crash{}-{}.dmp", player_suffix(), GetCurrentProcessId())).to_string_lossy());
    let file = CreateFileW(path.as_ptr(), GENERIC_WRITE, 0, std::ptr::null(), CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, std::ptr::null_mut());
    if file == INVALID_HANDLE_VALUE {
        crash_line("minidump: cannot create the file");
        return;
    }
    let mut exception = MINIDUMP_EXCEPTION_INFORMATION { ThreadId: GetCurrentThreadId(), ExceptionPointers: info as *mut _, ClientPointers: 0 };
    // MiniDumpWithDataSegs | MiniDumpWithIndirectlyReferencedMemory | MiniDumpWithThreadInfo | MiniDumpWithUnloadedModules
    let kind = 0x0000_0001 | 0x0000_0040 | 0x0000_1000 | 0x0000_0020;
    let ok = windows_sys::Win32::System::Diagnostics::Debug::MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), file, kind, &mut exception, std::ptr::null(), std::ptr::null());
    CloseHandle(file);
    crash_line(&format!("minidump ({why}): {}", if ok != 0 { "written" } else { "failed" }));
}

/// Writes a dump of the running process on request (tests, the watchdog).
pub fn dump_now(name: &str) -> bool {
    let Some(dir) = DIR.get().cloned().or_else(|| Some(std::env::temp_dir())) else { return false };
    unsafe {
        let path = wide(&dir.join(name).to_string_lossy());
        let file = CreateFileW(path.as_ptr(), GENERIC_WRITE, 0, std::ptr::null(), CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, std::ptr::null_mut());
        if file == INVALID_HANDLE_VALUE {
            return false;
        }
        let ok = windows_sys::Win32::System::Diagnostics::Debug::MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), file, 0x0000_0001 | 0x0000_1000, std::ptr::null_mut(), std::ptr::null(), std::ptr::null());
        CloseHandle(file);
        ok != 0
    }
}

fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let place = info.location().map(|l| format!("{}:{}", l.file(), l.line())).unwrap_or_default();
        let message = info.payload().downcast_ref::<&str>().map(|s| s.to_string()).or_else(|| info.payload().downcast_ref::<String>().cloned()).unwrap_or_default();
        crash_line(&format!("PANIC in thread {} at {place}: {message}", unsafe { GetCurrentThreadId() }));
        if let Some(hook) = in_hook() {
            crash_line(&format!("    inside hook {}", azcoop_bridge::client::Hook::ALL.get(hook as usize).map_or("?", |h| h.name())));
        }
        previous(info);
    }));
}

/// `AZCOOP_TEST_CRASH=av|overflow|exit|abort|terminate|panic`: ends the process in that way after 400 ms, to check that the
/// diagnostics see it (the end-to-end test and the pack's own trial). Does nothing when the variable is not set.
#[cfg(not(feature = "test-hooks"))]
pub fn test_crash_from_env() {} // shipped builds: no crash switch (and no AZCOOP_TEST_ name in the binary)

#[cfg(feature = "test-hooks")]
pub fn test_crash_from_env() {
    let Ok(how) = std::env::var("AZCOOP_TEST_CRASH") else { return };
    let _ = std::thread::Builder::new().name("azcoop-test-crash".into()).spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(400));
        note(Kind::Note, 0x7E57, 0);
        match how.as_str() {
            "av" => unsafe { std::ptr::write_volatile(0x10usize as *mut u8, 1) },
            "overflow" => {
                fn deeper(n: u64) -> u64 {
                    let pad = [n as u8; 256];
                    std::hint::black_box(&pad);
                    deeper(n + 1) + pad[0] as u64
                }
                std::hint::black_box(deeper(0));
            }
            "exit" => unsafe { windows_sys::Win32::System::Threading::ExitProcess(7) },
            "abort" => std::process::abort(),
            "terminate" => unsafe {
                windows_sys::Win32::System::Threading::TerminateProcess(GetCurrentProcess(), 9);
            },
            "panic" => {
                let _ = std::panic::catch_unwind(|| panic!("test panic for the diagnostics"));
            }
            _ => {}
        }
    });
}

/// `DLL_PROCESS_DETACH`: the process is ending through `ExitProcess` (a kill never gets here). `reserved` is non-null when the process
/// is terminating, null when the DLL is unloaded on its own.
pub fn process_detach(reserved: bool) {
    if LOG.get().is_none() || EXITING.swap(true, SeqCst) {
        return; // never initialised (the inert proxy) or already reported
    }
    crash_line(&format!("process detach ({}): the game is exiting through ExitProcess; last hooks follow", if reserved { "process terminating" } else { "library unloaded" }));
    for l in tail(16) {
        crash_line(&format!("    {l}"));
    }
    own_report();
}

/// `HeapValidate` of the process heap (the game's allocator; a heap corruption crashes it later, far from the cause). Returns whether the
/// heap is intact and how long the walk took. A damaged heap is written to the crash log with the core's last actions, once with a dump.
pub fn heap_check(reason: &str) -> (bool, f64) {
    use windows_sys::Win32::System::Memory::{GetProcessHeap, HeapValidate};
    let started = std::time::Instant::now();
    let ok = unsafe { HeapValidate(GetProcessHeap(), 0, std::ptr::null()) } != 0;
    let ms = started.elapsed().as_secs_f64() * 1000.0;
    note(Kind::Note, 0x4EA9_0000 | ok as u64, (ms * 1000.0) as u64);
    if !ok {
        crash_line(&format!("HEAP DAMAGED at the check '{reason}' ({ms:.1} ms): the corruption happened before this point"));
        for l in tail(24) {
            crash_line(&format!("    {l}"));
        }
        own_report();
        let _ = dump_now("azcoop-heap.dmp");
    }
    (ok, ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_flight_recorder_keeps_the_last_records_in_its_file_and_names_them() {
        // the engine tests write hook records into the same global ring: take turns with them
        let _turn = crate::midhook::TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!("azcoop-flight-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log: &'static Log = Box::leak(Box::new(Log::open(&dir.join("test.log"))));
        init(&dir, log);
        // more than the ring holds: the oldest fall out, the order stays
        for i in 0..(RECORDS as u64 + 100) {
            note(Kind::HookEnter, i % 27, 0x1000 + i);
        }
        enter_hook(5, 0xABCD);
        assert_eq!(in_hook(), Some(5));
        leave_hook(5, 1);
        assert_eq!(in_hook(), None);
        let bytes = std::fs::read(dir.join("azcoop-flight.bin")).unwrap();
        let records = read_records(&bytes);
        assert_eq!(records.len(), RECORDS);
        assert!(records.windows(2).all(|w| w[0].seq + 1 == w[1].seq), "consecutive, oldest first");
        let last = records.last().unwrap();
        assert_eq!((last.kind, last.a, last.b), (2, 5, 1), "the newest record is the hook leaving");
        assert!(describe(last).contains("leave"), "{}", describe(last));
        assert_eq!(records[records.len() - 2].kind, 1);
        let tail = tail(3);
        assert_eq!(tail.len(), 3);
        assert!(tail[2].contains("leave"));
        // the printing tool reads the very same file
        let tool = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tools").join("pack").join("flight.py");
        if let Ok(out) = std::process::Command::new("py").arg("-I").arg(&tool).arg(dir.join("azcoop-flight.bin")).arg("4").output() {
            let text = String::from_utf8_lossy(&out.stdout).to_string();
            assert!(out.status.success(), "flight.py: {text} {}", String::from_utf8_lossy(&out.stderr));
            assert!(text.contains("records") && text.contains("leave") && text.contains("START"), "{text}");
            // hook names agree with the enum (index 5 is START)
            assert_eq!(azcoop_bridge::client::Hook::ALL[5].name(), "START");
        }
    }

    #[test]
    fn the_hook_names_of_the_tool_follow_the_enum() {
        let tool = std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tools").join("pack").join("flight.py")).unwrap();
        let line = tool.lines().find(|l| l.starts_with("HOOKS = ")).unwrap();
        let names: Vec<&str> = line.trim_start_matches("HOOKS = [").trim_end_matches(']').split(',').map(|s| s.trim().trim_matches(char::from(39))).collect();
        let want: Vec<&str> = azcoop_bridge::client::Hook::ALL.iter().map(|h| h.name()).collect();
        assert_eq!(names, want);
    }

    #[test]
    fn the_core_keeps_its_last_actions_and_checks_the_heap() {
        let _turn = crate::midhook::TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        for i in 0..(OWN_SLOTS as u64 + 10) {
            note_own(b'W', 0x5000_0000 + i * 16, 8);
        }
        note_own(b'C', 7, 0x1234);
        let rows = own_tail();
        assert_eq!(rows.len(), OWN_SLOTS, "a ring of the last ones");
        assert!(rows.last().unwrap().contains(" C ") && rows.last().unwrap().contains("+4660"), "newest last: {:?}", rows.last());
        assert!(rows[0].contains(" W "), "{:?}", rows[0]);
        let (ok, ms) = heap_check("test");
        assert!(ok, "the process heap of the test is intact");
        assert!(ms >= 0.0);
    }

    #[test]
    fn a_dump_of_the_running_process_can_be_written_and_addresses_name_their_module() {
        // dumping writes a record into the global ring too: take turns with the test that reads the ring back
        let _turn = crate::midhook::TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let name = format!("azcoop-test-{}.dmp", std::process::id());
        assert!(dump_now(&name));
        let path = DIR.get().cloned().unwrap_or_else(std::env::temp_dir).join(&name); // where dump_now writes (the flight test may have set DIR)
        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        let _ = std::fs::remove_file(&path);
        assert!(size > 1000, "a minidump has content: {size} bytes");
        let here = module_of(the_flight_recorder_keeps_the_last_records_in_its_file_and_names_them as usize as u64);
        assert!(here.contains("+0x"), "{here}");
        assert!(module_of(8).contains("no module"));
        assert_eq!(code_name(0xC000_0005), "ACCESS_VIOLATION");
        assert!(is_fatal(0xC000_0409) && !is_fatal(0x8000_0003));
    }
}
