//! Azeroth Survivors Together co-op native core, measurement prototype.
//!
//! Loaded as avrt.dll from the game folder (the game imports avrt.dll; all
//! real avrt functions are PE forwarders to System32, see build.rs).
//!
//! DllMain only starts one worker thread and returns. Everything else runs
//! in that thread, after the loader lock is released:
//!   1. checks the executable is a supported build by SHA-256 (else: log, do nothing)
//!   2. reads the co-op address profile (data files from the co-op folder)
//!   3. verifies the WRITE and TICK bytes in memory against the reviewed pattern
//!   4. installs the hooks in one process-wide suspend (MinHook): WRITE measures
//!      its own cost, TICK pushes an entry record to a lock-free ring that a
//!      dedicated consumer thread drains; logs every 10 s
//! It never changes game state, memory contents or network traffic.
//! Set AZCOOP_NATIVE_DISABLE=1 to load as a pure forwarder.

#[macro_use]
mod proc;
pub mod heap_count;

/// Counts the DLL's own heap use (heap_count.rs); the system allocator does the work.
#[global_allocator]
static HEAP: heap_count::Counting = heap_count::Counting;
mod stub;
mod hook;
mod install;
mod observe;
pub mod feed;
pub mod ipc_client;
pub mod peers;
pub mod control;
mod log;
pub mod crash;
mod profile;
#[allow(dead_code)]
pub mod cipher;
pub mod hook_state_test_support;
#[allow(dead_code)]
pub mod net;
mod ring;
mod call;
mod engine;
mod entry;
#[cfg(test)]
mod engine_tests;
mod midhook;
#[cfg(test)]
mod tests;

use core::arch::x86_64::{__cpuid, _rdtsc};
use std::ffi::c_void;
use std::io::Read;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;
use std::sync::atomic::Ordering::Relaxed;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use windows_sys::core::BOOL;
use windows_sys::Win32::Foundation::{CloseHandle, HINSTANCE, TRUE};
use windows_sys::Win32::System::LibraryLoader::{DisableThreadLibraryCalls, GetModuleFileNameW, GetModuleHandleW};
use windows_sys::Win32::System::SystemServices::{DLL_PROCESS_ATTACH, DLL_PROCESS_DETACH};
use windows_sys::Win32::System::Threading::{CreateThread, GetCurrentProcessId};

use log::Log;

/// Game builds with a reviewed co-op profile. For 0.84.3 and 0.93.1 the WRITE
/// prologue was checked byte-identical (16.10.2026). 0.95.0 is added on the
/// strength of its release profile; the DLL still verifies the WRITE/TICK entry
/// prologues in memory before hooking and stays inactive if they differ, so an
/// incorrect address can never be hooked.
/// Any other executable: log and stay a pure forwarder.
const SUPPORTED_BUILDS: [(&str, &str); 4] = [
    ("0.84.3", "dc165e348d0a15062f58d83530619b0f57479028a28507f449c8bcffea0fb306"),
    ("0.93.1", "0315cf387f4f807512ac965763ed81ae58e7f20dd94547a7541ee8eae3135f66"),
    ("0.95.0", "7264d50b82a1ecc2b5f0fcf2f29669c2acaa8bb87c058e17898a47a12984ff30"),
    ("0.97.1", "a762d045a8cbcc02a92dcce75bed59ab3216ab45ab546ef0b0b77b1b46ea0fee"),
];
const LOG_NAME: &str = "azeroth-coop-native.log";
const REPORT_SECONDS: u64 = 10;
/// WRITE prologue up to `mov r14, rcx`: push rbp/r14/rsi/rdi/rbx, sub rsp 40h,
/// lea rbp, frame cookie. The detour's ABI assumption rests on these bytes.
/// Byte-identical across 0.84.3 and 0.93.1.
const WRITE_PROLOGUE: [u8; 26] = [
    0x55, 0x41, 0x56, 0x56, 0x57, 0x53, 0x48, 0x83, 0xec, 0x40, 0x48, 0x8d, 0x6c, 0x24, 0x40, 0x48, 0xc7,
    0x45, 0xf8, 0xfe, 0xff, 0xff, 0xff, 0x49, 0x89, 0xce,
];
/// TICK entry: push rbp/r15/r14/r13/r12/rsi/rdi/rbx. These 12 bytes are
/// build-independent (the frame-size constant that follows is not), so they
/// gate that we are at TICK's entry while the address comes from the profile.
const TICK_PROLOGUE: [u8; 12] =
    [0x55, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x56, 0x57, 0x53];

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn DllMain(module: HINSTANCE, reason: u32, _reserved: *mut c_void) -> BOOL {
    if reason == DLL_PROCESS_DETACH {
        crash::process_detach(!_reserved.is_null());
    }
    if reason == DLL_PROCESS_ATTACH {
        // Loader lock is held here: only start the worker, no file or memory work. Without AZCOOP_ENGINE=1 (or the measuring mode
        // AZCOOP_MEASURE=1) nothing at all happens: no thread, no handler, no file, no hashing; the exports forward to the system DLL.
        unsafe {
            DisableThreadLibraryCalls(module);
            if attach_requested() {
                let thread = CreateThread(std::ptr::null(), 0, Some(worker), std::ptr::null(), 0, std::ptr::null_mut());
                if !thread.is_null() {
                    CloseHandle(thread);
                }
            }
        }
    }
    TRUE
}

unsafe extern "system" fn worker(_: *mut c_void) -> u32 {
    if std::env::var_os("AZCOOP_NATIVE_DISABLE").is_some_and(|v| v == "1") {
        return 0;
    }
    // Inert unless a launcher asked for the co-op core (AZCOOP_ENGINE=1) or the old measuring mode (AZCOOP_MEASURE=1): the proxy may
    // sit in the game folder for single player without hooking, handlers, files or threads of its own.
    if !requested() {
        return 0;
    }
    let Some(exe) = executable_path() else { return 0 };
    let game = exe.parent().map(PathBuf::from).unwrap_or_default();
    let log_name = LOG_NAME.replace(".log", &format!("{}.log", crash::player_suffix()));
    let log: &'static Log = Box::leak(Box::new(Log::open_rotating(&game.join(log_name), 3)));
    crash::init(&game, log);
    crash::test_crash_from_env();
    log.info(&format!(
        "azeroth-coop-native {} (avrt.dll proxy), pid {}, exe {}",
        env!("CARGO_PKG_VERSION"),
        GetCurrentProcessId(),
        exe.display()
    ));
    let root = std::env::var("SystemRoot").unwrap_or_default();
    if !root.eq_ignore_ascii_case(env!("AZCOOP_FORWARD_ROOT")) {
        log.warn(&format!("avrt exports forward to {}, but SystemRoot is {root}", env!("AZCOOP_FORWARD_ROOT")));
    }
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(log, &exe, &game)));
    match outcome {
        Ok(Ok(())) => {}
        Ok(Err(reason)) => log.info(&format!("measurement inactive: {reason}; the game runs unmodified")),
        Err(_) => log.failed("worker", "panic; the game runs unmodified"),
    }
    0
}

/// [`requested`] for `DllMain` (loader lock held): the environment is read into a stack buffer, nothing is allocated.
fn attach_requested() -> bool {
    fn is_one(name: &str) -> bool {
        let mut wide = [0u16; 32];
        for (i, c) in name.encode_utf16().enumerate() {
            wide[i] = c;
        }
        let mut value = [0u16; 4];
        let n = unsafe { windows_sys::Win32::System::Environment::GetEnvironmentVariableW(wide.as_ptr(), value.as_mut_ptr(), value.len() as u32) };
        n == 1 && value[0] == u16::from(b'1')
    }
    !is_one("AZCOOP_NATIVE_DISABLE") && (is_one("AZCOOP_ENGINE") || is_one("AZCOOP_MEASURE"))
}

/// The co-op core (`AZCOOP_ENGINE=1`) or the measuring mode (`AZCOOP_MEASURE=1`) is asked for; otherwise the proxy only forwards.
fn requested() -> bool {
    ["AZCOOP_ENGINE", "AZCOOP_MEASURE"].iter().any(|name| std::env::var_os(name).is_some_and(|v| v == "1"))
}

fn executable_path() -> Option<PathBuf> {
    let mut buffer = vec![0u16; 32_768];
    let length = unsafe { GetModuleFileNameW(std::ptr::null_mut(), buffer.as_mut_ptr(), buffer.len() as u32) };
    (length > 0).then(|| std::ffi::OsString::from_wide(&buffer[..length as usize]).into())
}

fn sha256_file(path: &std::path::Path) -> std::io::Result<(String, u64)> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
        total += n as u64;
    }
    let digest = hasher.finalize();
    Ok((digest.iter().map(|b| format!("{b:02x}")).collect(), total))
}

fn run(log: &'static Log, exe: &std::path::Path, game: &std::path::Path) -> Result<(), String> {
    let step = "check game executable SHA-256";
    let started = log.begin(step);
    let (sha256, size) = sha256_file(exe).map_err(|e| {
        log.failed(step, &e.to_string());
        format!("cannot read executable: {e}")
    })?;
    let version = match SUPPORTED_BUILDS.iter().find(|(_, hash)| *hash == sha256) {
        Some(&(version, _)) => version.to_string(),
        None => {
            // Not compiled in: a profile file in the game folder that carries the constants of a build of the 0.95.0 code family
            // (`variant_constants`) is enough; anything else stays untouched and says why.
            let known: Vec<&str> = SUPPORTED_BUILDS.iter().map(|(v, _)| *v).collect();
            let runtime = profile::resolve(game, &sha256)
                .and_then(|resolved| azcoop_game::builds::register_runtime(resolved.json()).map(|variant| (variant, resolved.source.clone())));
            match runtime {
                Ok((variant, source)) => {
                    log.info(&format!("{sha256:.16}… is not compiled in; running it from the profile {} (variant_constants)", source.display()));
                    variant.name().to_string()
                }
                Err(why) => {
                    log.failed(step, &format!("{sha256} is not a supported game build ({}) and no profile describes it: {why}", known.join(", ")));
                    return Err(format!("unsupported game build {sha256:.16}…"));
                }
            }
        }
    };
    log.ok(step, started, &format!("{version}, {:.1} MB", size as f64 / 1e6));

    let step = "read co-op address profile";
    let started = log.begin(step);
    let resolved = profile::resolve(game, &sha256).map_err(|e| {
        log.failed(step, &e);
        "no usable profile".to_string()
    })?;
    log.ok(step, started, &format!("{}", resolved.source.display()));
    if let Some(rva) = resolved.batch_return_rva {
        log.info(&format!("batch call site returns to rva {rva:#x} (adapter contract)"));
    }

    let step = "verify hook bytes in memory";
    let started = log.begin(step);
    let base = unsafe { GetModuleHandleW(std::ptr::null()) } as usize;
    let image_size = unsafe {
        let pe = base + *((base + 0x3c) as *const u32) as usize;
        *((pe + 24 + 56) as *const u32) as u64
    };
    let write = verify_hook(&resolved, base, image_size, "WRITE", &WRITE_PROLOGUE).map_err(|e| {
        log.failed(step, &e);
        e.clone()
    })?;
    let tick = verify_hook(&resolved, base, image_size, "TICK", &TICK_PROLOGUE).map_err(|e| {
        log.failed(step, &e);
        e.clone()
    })?;
    let patterns = if resolved.patterns_authoritative() { "patterns enforced" } else { "prologues (ref patterns informational)" };
    log.ok(step, started, &format!("WRITE {write:#x}, TICK {tick:#x}, {patterns}"));

    let step = "calibrate TSC";
    let started = log.begin(step);
    let invariant = __cpuid(0x8000_0007).edx & (1 << 8) != 0;
    let ticks_per_ns = calibrate();
    for (slot, ms) in hook::GAP_TICKS.iter().zip(hook::GAP_MS) {
        slot.store((ms * 1e6 * ticks_per_ns) as u64, Relaxed);
    }
    log.ok(step, started, &format!("{:.3} GHz, invariant {invariant}", ticks_per_ns));
    if !invariant {
        log.warn("TSC is not invariant: timings are approximate");
    }

    // The game thread hands TICK records to the consumer over this ring; 64 KiB
    // holds a few thousand records, far more than one report window produces.
    // The in-process co-op core replaces the measuring hooks: the bridge runs inside the game.
    if std::env::var_os("AZCOOP_ENGINE").is_some_and(|v| v == "1") {
        let step = "start the co-op core (AZCOOP_ENGINE=1)";
        let started = log.begin(step);
        engine::install(log, game, exe, &sha256, &resolved.source).map_err(|e| {
            log.failed(step, &e);
            e
        })?;
        log.ok(step, started, "bridge and hooks active");
        ENGINE_ON.store(true, Relaxed);
        start_peer_network(log, &sha256);
        report_loop(log, ticks_per_ns);
    }

    let _ = hook::TICK_RING.set(ring::Ring::new(64 * 1024));

    // Host-side WRITE capture for the co-op slice. Needs the build's
    // server.connections offset; stays OFF unless AZCOOP_CAPTURE=1 (a co-op
    // host session switches it on). Off = WRITE only measures.
    match resolved.field("server", 0x918) {
        Ok(offset) => {
            hook::CONNECTIONS_OFFSET.store(offset as usize, Relaxed);
            let _ = hook::BATCH_RING.set(ring::Ring::new(4 << 20));
            let on = std::env::var_os("AZCOOP_CAPTURE").is_some_and(|v| v == "1");
            hook::CAPTURE.store(on, Relaxed);
            log.info(&format!("WRITE capture {} (server.connections at +{offset:#x})", if on { "ON" } else { "off" }));
            // Guest apply writes validated remote packets into our own outgoing
            // batch; the only path that changes game memory. Off by default.
            let apply_on = std::env::var_os("AZCOOP_APPLY").is_some_and(|v| v == "1");
            hook::APPLY.store(apply_on, Relaxed);
            log.info(&format!("WRITE guest apply {}", if apply_on { "ON" } else { "off" }));
        }
        Err(e) => log.warn(&format!("WRITE capture unavailable: {e}")),
    }

    let step = "install hooks (WRITE measuring, TICK observing)";
    let started = log.begin(step);
    let mut specs = vec![
        install::HookSpec {
            name: "WRITE",
            target: write,
            detour: hook::write_detour as *const () as usize,
            trampoline: &hook::WRITE_ORIGINAL,
        },
        install::HookSpec {
            name: "TICK",
            target: tick,
            detour: hook::tick_stub as *const () as usize,
            trampoline: &hook::TICK_TRAMPOLINE,
        },
    ];
    if std::env::var_os("AZCOOP_OBSERVE").is_some_and(|v| v == "1") {
        let _ = hook::FEED_RING.set(ring::Ring::new(4 << 20));
        specs.extend(observe_specs(log, &resolved, base, image_size, &version));
        OBSERVING.store(true, Relaxed);
        hook::FEED.store(true, Relaxed);
        if hook::CONNECTIONS_OFFSET.load(Relaxed) == 0 {
            log.warn("feed: server.connections offset unknown, the client-direction feed stays empty");
        }
    }
    install::install(&specs).map_err(|e| {
        log.failed(step, &e);
        install::uninstall();
        e.clone()
    })?;
    log.ok(step, started, "active (one process-wide suspend)");

    // Co-op IPC thread, only when the launcher started a helper for this game.
    // Without it the DLL stays measure-only, exactly as before.
    maybe_start_ipc(log, &sha256);

    report_loop(log, ticks_per_ns);
}

static FEED_SUMMARY: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());
static ENGINE_ON: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static OBSERVING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Observation hooks (AZCOOP_OBSERVE=1): every reviewed function entry whose bytes in
/// memory equal the pinned golden bytes of this build. Anything else is skipped with a
/// warning, never hooked.
fn observe_specs(log: &Log, resolved: &profile::Resolved, base: usize, image_size: u64, version: &str) -> Vec<install::HookSpec> {
    let mut specs = Vec::new();
    for (id, name) in observe::NAMES.iter().enumerate() {
        let hook = match resolved.hook(name) {
            Ok(h) if h.rva + 24 <= image_size => h,
            Ok(h) => {
                log.warn(&format!("observe {name}: rva {:#x} outside the image, skipped", h.rva));
                continue;
            }
            Err(e) => {
                log.warn(&format!("observe {name}: {e}, skipped"));
                continue;
            }
        };
        let target = base + hook.rva as usize;
        let code = unsafe { std::slice::from_raw_parts(target as *const u8, 24) };
        if !observe::is_function_entry(code) {
            log.info(&format!("observe {name}: {:#x} is not a function entry (mid-function site), left to the debugger", hook.rva));
            continue;
        }
        match observe::golden_bytes(version, name, hook.rva) {
            Some(golden) if golden == code => {}
            Some(_) => {
                log.warn(&format!("observe {name}: bytes at {:#x} differ from the pinned ones, skipped", hook.rva));
                continue;
            }
            None => {
                log.warn(&format!("observe {name}: no pinned bytes for {version} at {:#x}, skipped", hook.rva));
                continue;
            }
        }
        let (trampoline, stub) = if *name == "SERIALIZE" {
            (&hook::SERIALIZE_TRAMPOLINE, hook::serialize_stub as *const () as usize)
        } else {
            observe::slot(id)
        };
        specs.push(install::HookSpec { name, target, detour: stub, trampoline });
    }
    log.info(&format!("observe: {} of {} function entries hooked (counting only)", specs.len(), observe::COUNT));
    specs
}

/// Checks a hook's bytes in memory and returns its absolute address.
///
/// The build-independent `prologue` is always required: it confirms we are at
/// a function entry of the expected shape. The reviewed byte pattern describes
/// the reference build, so it is enforced only when that is the running build
/// (`patterns_authoritative`); otherwise the reviewed-port address in the
/// profile is the trust anchor and the pattern is not checked.
fn verify_hook(
    resolved: &profile::Resolved,
    base: usize,
    image_size: u64,
    name: &str,
    prologue: &[u8],
) -> Result<usize, String> {
    let hook = resolved.hook(name)?;
    let pattern_len = hook.pattern.as_ref().map_or(0, |(p, _)| p.len());
    let length = pattern_len.max(prologue.len());
    if hook.rva + length as u64 > image_size {
        return Err(format!("{name} rva {:#x} is outside the image ({image_size:#x})", hook.rva));
    }
    let target = base + hook.rva as usize;
    let code = unsafe { std::slice::from_raw_parts(target as *const u8, length) };
    if code[..prologue.len()] != *prologue {
        return Err(format!("{name} entry prologue differs from the reviewed function"));
    }
    if resolved.patterns_authoritative() {
        match &hook.pattern {
            Some((pattern, mask)) => {
                if let Some(i) = (0..pattern.len().min(mask.len())).find(|&i| code[i] & mask[i] != pattern[i] & mask[i]) {
                    return Err(format!("{name} differs from the reviewed pattern at byte {i}"));
                }
            }
            None => return Err(format!("{name} has no reviewed pattern for the reference build")),
        }
    }
    Ok(target)
}

/// The in-process core talks to its peers through the helper (`--mode state`): connect to its pipe in the
/// background (the game never waits for it) and hand the link to the engine's handler. Without
/// `AZCOOP_SESSION` the core runs alone (solo host).
fn start_peer_network(log: &'static Log, sha256: &str) {
    let Some(session) = std::env::var("AZCOOP_SESSION").ok().filter(|s| !s.is_empty()) else {
        log.info("co-op network: no AZCOOP_SESSION, the core runs alone");
        return;
    };
    let build = std::env::var("AZCOOP_BUILD").unwrap_or_else(|_| env!("CARGO_PKG_VERSION").to_string());
    let sha = sha256.to_string();
    let pid = unsafe { GetCurrentProcessId() };
    std::thread::Builder::new()
        .name("azcoop-peers-start".into())
        .spawn(move || {
            let step = "co-op network: helper";
            let started = log.begin(step);
            match peers::PeerPipe::connect(&session, &build, &sha, pid, Duration::from_secs(30)) {
                Ok(pipe) => {
                    let role = pipe.role.clone();
                    if peers::publish(pipe) {
                        log.ok(step, started, &format!("linked as {role}"));
                    }
                }
                Err(e) => log.failed(step, &format!("{e}; the core runs alone")),
            }
        })
        .ok();
}

/// Start the co-op IPC thread if the launcher set AZCOOP_SESSION (and
/// AZCOOP_BUILD). Connects to the helper's pipe, does the HELLO handshake, and
/// pumps WORLD for its role. Any failure leaves the DLL measure-only; it never
/// blocks or crashes the game. The actual WORLD source/apply (batch capture)
/// is still parked, so the host sends nothing and the guest only counts.
fn maybe_start_ipc(log: &Log, sha256: &str) {
    let Some(session) = std::env::var("AZCOOP_SESSION").ok().filter(|s| !s.is_empty()) else {
        return;
    };
    let build = std::env::var("AZCOOP_BUILD").unwrap_or_else(|_| env!("CARGO_PKG_VERSION").to_string());
    let sha = sha256.to_string();
    let pid = unsafe { GetCurrentProcessId() };
    log.info(&format!("co-op: AZCOOP_SESSION set, connecting to the helper (build {build})"));
    std::thread::Builder::new()
        .name("azcoop-ipc".into())
        .spawn(move || {
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| ipc_thread(&session, &build, &sha, pid)));
            // The result is surfaced via the 10 s report; nothing here must
            // panic across the FFI boundary.
            let _ = outcome;
        })
        .ok();
}

/// Body of the IPC thread: connect, handshake, pump for the assigned role.
fn ipc_thread(session: &str, build: &str, sha256: &str, pid: u32) -> Result<(), String> {
    // The launcher may start the helper after the game; retry for up to 30 s.
    let deadline = Instant::now() + Duration::from_secs(30);
    let pipe = loop {
        match ipc_client::Pipe::connect(session) {
            Ok(p) => break p,
            Err(e) if Instant::now() < deadline => {
                let _ = e;
                std::thread::sleep(Duration::from_millis(250));
            }
            Err(e) => return Err(format!("helper pipe not available within 30 s: {e}")),
        }
    };
    let mut reader = ipc_client::Reader::new(&pipe);
    let role = ipc_client::handshake(&mut reader, azcoop_proto::transport::PROTOCOL, build, sha256, pid)?;
    IPC_ROLE.store(role_code(&role), Relaxed);
    match role.as_str() {
        "host" => {
            // WORLD source is the capture consumer's outgoing queue.
            ipc_client::pump_host(&mut reader, next_outgoing)
        }
        _ => {
            // Validate each RemoteWorld like receive_state, then queue the packets
            // for the WRITE apply path (only consumed when AZCOOP_APPLY=1).
            let apply: Box<ipc_client::ApplyWorld> = Box::new(|payload| {
                let mut backlog = 0usize;
                if let Ok(packets) = net::accept_world(payload, &mut backlog) {
                    if let Ok(mut q) = hook::APPLY_QUEUE.lock() {
                        // Bounded: drop the oldest beyond the cap, never grow unbounded.
                        for p in packets {
                            if q.len() >= APPLY_QUEUE_MAX {
                                q.pop_front();
                            }
                            q.push_back(p);
                        }
                    }
                }
            });
            ipc_client::pump_guest(&mut reader, &apply)
        }
    }
}

/// 0 none, 1 host, 2 guest - for the report line.
static IPC_ROLE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
fn role_code(role: &str) -> u8 {
    match role {
        "host" => 1,
        "guest" => 2,
        _ => 0,
    }
}

fn calibrate() -> f64 {
    let (t0, c0) = (Instant::now(), unsafe { _rdtsc() });
    std::thread::sleep(Duration::from_millis(250));
    let (c1, elapsed) = (unsafe { _rdtsc() }, t0.elapsed());
    (c1 - c0) as f64 / elapsed.as_nanos() as f64
}

/// Drains the TICK ring on a dedicated thread so the game thread never waits.
/// This is where the network thread will live in step 3; for now it only
/// counts what it receives and keeps the last server pointer.
static DRAINED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
/// WORLD extraction counters (written by the consumer thread only).
static WORLD_STATS: std::sync::Mutex<net::ExtractStats> =
    std::sync::Mutex::new(net::ExtractStats { batches: 0, seeded: 0, resyncs: 0, packets: 0, world_packets: 0, errors: 0 });
/// Extracted WORLD messages waiting to go to the helper (host side). Bounded;
/// when full the oldest are dropped so the consumer never blocks the game.
static OUTGOING: std::sync::Mutex<std::collections::VecDeque<serde_json::Value>> =
    std::sync::Mutex::new(std::collections::VecDeque::new());
const OUTGOING_MAX: usize = 256;
/// Pending remote packets for the guest apply path (bounded).
const APPLY_QUEUE_MAX: usize = 4096;

/// Next WORLD payload for the host IPC pump, or None when the queue is empty.
fn next_outgoing() -> Option<serde_json::Value> {
    OUTGOING.lock().ok().and_then(|mut q| q.pop_front())
}

fn spawn_consumer() {
    std::thread::Builder::new()
        .name("azcoop-consumer".into())
        .spawn(|| {
            let mut payload: Vec<u8> = Vec::with_capacity(64);
            let mut extractor = net::WorldExtractor::default();
            let mut feed = feed::Feed::default();
            loop {
                let Some(ring) = hook::TICK_RING.get() else {
                    std::thread::sleep(Duration::from_millis(50));
                    continue;
                };
                let mut drained_any = false;
                while ring.pop(&mut payload).is_some() {
                    DRAINED.fetch_add(1, Relaxed);
                    drained_any = true;
                }
                // Captured WRITE batches -> WORLD packets -> the outgoing queue
                // the host IPC pump sends. All off the game thread.
                if let Some(batches) = hook::BATCH_RING.get() {
                    let mut fed = false;
                    while batches.pop(&mut payload).is_some() {
                        let world = extractor.feed(&payload);
                        if !world.is_empty() {
                            if let Ok(mut q) = OUTGOING.lock() {
                                if q.len() < OUTGOING_MAX {
                                    q.push_back(net::world_message(&world));
                                }
                            }
                        }
                        fed = true;
                        drained_any = true;
                    }
                    if fed {
                        if let Ok(mut stats) = WORLD_STATS.lock() {
                            *stats = extractor.stats;
                        }
                    }
                }
                if let Some(ring) = hook::FEED_RING.get() {
                    let mut changed = false;
                    while let Some(record) = ring.pop(&mut payload) {
                        match record.kind {
                            feed::KIND_CLIENT => feed.client_record(&payload),
                            feed::KIND_SERIALIZE => feed.serialize_record(&payload),
                            _ => {}
                        }
                        changed = true;
                        drained_any = true;
                    }
                    if changed {
                        if let Ok(mut summary) = FEED_SUMMARY.lock() {
                            *summary = feed.summary();
                        }
                    }
                }
                // Light spin-free poll: the server ticks ~38 Hz, so 2 ms keeps
                // latency low without burning a core.
                if !drained_any {
                    std::thread::sleep(Duration::from_millis(2));
                }
            }
        })
        .ok();
}

fn report_loop(log: &Log, ticks_per_ns: f64) -> ! {
    spawn_consumer();
    let ns = |ticks: u64| ticks as f64 / ticks_per_ns;
    let mut total = hook::Snapshot::default();
    let mut last = Instant::now();
    let mut heap_round = 0u64;
    loop {
        std::thread::sleep(Duration::from_secs(REPORT_SECONDS));
        let w = hook::take();
        if hook::CAPTURE.load(Relaxed) {
            let s = WORLD_STATS.lock().map(|s| *s).unwrap_or_default();
            let (pushed, dropped) =
                hook::BATCH_RING.get().map_or((0, 0), |r| (r.pushed.load(Relaxed), r.dropped.load(Relaxed)));
            let queued = OUTGOING.lock().map(|q| q.len()).unwrap_or(0);
            log.info(&format!(
                "capture: ring pushed {pushed} dropped {dropped} too-large {}, batches {} seeded {} resyncs {} errors {}, packets {} world {}, out-queue {queued}",
                hook::BATCH_TOO_LARGE.load(Relaxed),
                s.batches,
                s.seeded,
                s.resyncs,
                s.errors,
                s.packets,
                s.world_packets,
            ));
        }
        if ENGINE_ON.load(Relaxed) {
            heap_round += 1;
            if heap_round % (60 / REPORT_SECONDS) == 0 {
                let (ok, ms) = crash::heap_check("periodic");
                log.info(&format!("event native_heap_check reason=periodic ok={} ms={ms:.1}", ok as u8));
            }
            log.info(&engine::summary());
            log.info(&format!("threads: {}", observe::thread_summary()));
            log.info(&heap_count::summary());
            continue;
        }
        if OBSERVING.load(Relaxed) {
            log.info(&format!("observe: {}", observe::summary()));
            log.info(&format!("threads: {}", observe::thread_summary()));
            log.info(&heap_count::summary());
            if let Ok(summary) = FEED_SUMMARY.lock() {
                if !summary.is_empty() {
                    log.info(&summary);
                }
            }
        }
        let ring = hook::TICK_RING.get();
        let (pushed, dropped) = ring.map_or((0, 0), |r| {
            (r.pushed.load(Relaxed), r.dropped.load(Relaxed))
        });
        log.info(&format!(
            "TICK: {} seen, ring pushed {} dropped {} drained {}, last server ptr {:#x}",
            hook::TICK_SEEN.load(Relaxed),
            pushed,
            dropped,
            DRAINED.load(Relaxed),
            hook::TICK_SERVER.load(Relaxed),
        ));
        let role = match IPC_ROLE.load(Relaxed) {
            1 => "host",
            2 => "guest",
            _ => "none",
        };
        if role != "none" {
            let pending = hook::APPLY_QUEUE.lock().map(|q| q.len()).unwrap_or(0);
            log.info(&format!(
                "co-op: role {role}, WORLD sent {}, remote msgs {}, packets applied {} pending {pending}",
                ipc_client::SENT.load(Relaxed),
                ipc_client::APPLIED.load(Relaxed),
                hook::APPLIED_PACKETS.load(Relaxed),
            ));
        }
        let seconds = last.elapsed().as_secs_f64();
        last = Instant::now();
        total.calls += w.calls;
        total.inner_sum += w.inner_sum;
        total.over_sum += w.over_sum;
        total.over_max = total.over_max.max(w.over_max);
        total.gap_max = total.gap_max.max(w.gap_max);
        for (t, g) in total.gaps_over.iter_mut().zip(w.gaps_over) {
            *t += g;
        }
        let avg = |sum: u64, calls: u64| if calls == 0 { 0.0 } else { ns(sum) / calls as f64 };
        log.info(&format!(
            "WRITE {seconds:.1}s: {} calls ({:.1}/s), write avg {:.1} us max {:.1} us, \
             hook overhead avg {:.0} ns max {:.0} ns (sum {:.3} ms), gap max {:.1} ms, \
             gaps >16.7/33/50/100/250 ms: {}/{}/{}/{}/{}",
            w.calls,
            w.calls as f64 / seconds,
            avg(w.inner_sum, w.calls) / 1e3,
            ns(w.inner_max) / 1e3,
            avg(w.over_sum, w.calls),
            ns(w.over_max),
            ns(w.over_sum) / 1e6,
            ns(w.gap_max) / 1e6,
            w.gaps_over[0],
            w.gaps_over[1],
            w.gaps_over[2],
            w.gaps_over[3],
            w.gaps_over[4],
        ));
        log.info(&format!(
            "WRITE total: {} calls, hook overhead avg {:.0} ns max {:.0} ns, sum {:.3} ms, write avg {:.1} us, \
             gap max {:.1} ms, gaps >16.7/33/50/100/250 ms: {}/{}/{}/{}/{}",
            total.calls,
            avg(total.over_sum, total.calls),
            ns(total.over_max),
            ns(total.over_sum) / 1e6,
            avg(total.inner_sum, total.calls) / 1e3,
            ns(total.gap_max) / 1e6,
            total.gaps_over[0],
            total.gaps_over[1],
            total.gaps_over[2],
            total.gaps_over[3],
            total.gaps_over[4],
        ));
    }
}
