//! Tests: profile resolution against the read-only reference install, and the
//! detour on a stand-in function with WRITE's signature (pass-through and
//! measured cost per call).

use crate::hook;
use std::hint::black_box;
use std::path::Path;
use std::sync::atomic::Ordering::Relaxed;
use std::time::Instant;

const REFERENCE: &str = r"reference\010";
const REFERENCE_0931: &str = r"reference\0931";

fn begin(name: &str) -> Instant {
    println!("[ .... ] {name}");
    Instant::now()
}
fn ok(name: &str, started: Instant, metric: &str) {
    println!("[  OK  ] {name} ({:.1} ms, {metric})", started.elapsed().as_secs_f64() * 1000.0);
}

#[test]
fn resolves_write_from_reference_profiles() {
    let name = "resolve WRITE from active-hooks.json and release-0.84.3.json";
    let started = begin(name);
    let game = Path::new(REFERENCE);
    if !game.join(r"analysis\active-hooks.json").is_file() {
        println!("[ WARN ] reference install not present, skipped");
        return;
    }
    let active = crate::profile::resolve(game, crate::SUPPORTED_BUILDS[0].1).expect("active profile");
    let write = active.hook("WRITE").expect("WRITE");
    assert_eq!(write.rva, 0x54D60C0, "active-hooks WRITE");
    assert_eq!(active.hook("TICK").expect("TICK").rva, 0x53DBD50, "active-hooks TICK");
    assert_eq!(active.batch_return_rva, Some(0x53dd709));
    assert!(write.pattern.is_some(), "reviewed pattern");

    std::env::set_var("AZCOOP_PROFILE", game.join(r"reconstruction\release-0.84.3.json"));
    let release = crate::profile::resolve(game, crate::SUPPORTED_BUILDS[0].1).expect("release profile");
    std::env::remove_var("AZCOOP_PROFILE");
    assert!(release.source.ends_with("release-0.84.3.json"), "{}", release.source.display());
    assert_eq!(release.hook("WRITE").expect("WRITE").rva, 0x54D60C0, "release-0.84.3 mapping");

    let wrong = crate::profile::resolve(game, &"0".repeat(64));
    assert!(wrong.is_err(), "a profile for another build must be refused");
    ok(name, started, &format!("rva {:#x} from both sources", write.rva));
}

#[test]
fn resolves_write_for_0931() {
    let name = "resolve WRITE for 0.93.1 (release-format active-hooks.json)";
    let started = begin(name);
    let game = Path::new(REFERENCE_0931);
    if !game.join(r"analysis\active-hooks.json").is_file() {
        println!("[ WARN ] 0.93.1 port folder not present, skipped");
        return;
    }
    let resolved = crate::profile::resolve(game, crate::SUPPORTED_BUILDS[1].1).expect("0.93.1 profile");
    let write = resolved.hook("WRITE").expect("WRITE");
    assert_eq!(write.rva, 0x5514E50, "0.93.1 WRITE");
    assert_eq!(resolved.hook("TICK").expect("TICK").rva, 0x53E55A0, "0.93.1 TICK");
    assert_eq!(resolved.batch_return_rva, Some(0x53e7049));
    assert!(write.pattern.is_some(), "reviewed pattern");
    ok(name, started, &format!("rva {:#x} from {}", write.rva, resolved.source.display()));
}

#[inline(never)]
unsafe extern "system" fn stand_in(rcx: usize, rdx: usize, r8: usize, r9: usize) -> usize {
    // Large enough for a 14-byte patch; result depends on every argument.
    let mut acc = black_box(rcx).wrapping_mul(3);
    acc = acc.wrapping_add(black_box(rdx).wrapping_mul(5));
    acc = acc.wrapping_add(black_box(r8).wrapping_mul(7));
    acc.wrapping_add(black_box(r9).wrapping_mul(11))
}

#[test]
fn detour_passes_through_and_measures() {
    // MinHook freezes the other threads while it patches: tests that install hooks take turns
    let _turn = crate::midhook::TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let name = "detour stand-in WRITE, 2 000 000 calls";
    let started = begin(name);
    let direct = unsafe { stand_in(1, 2, 3, 4) };
    let calls = 2_000_000u64;

    let baseline = Instant::now();
    for i in 0..calls as usize {
        black_box(unsafe { stand_in(black_box(i), 2, 3, 4) });
    }
    let baseline = baseline.elapsed().as_nanos() as f64 / calls as f64;

    let ticks_per_ns = crate::calibrate();
    let target = stand_in as *mut std::ffi::c_void;
    let original = unsafe { minhook::MinHook::create_hook(target, hook::write_detour as *mut _).unwrap() };
    hook::WRITE_ORIGINAL.store(original as usize, Relaxed);
    unsafe { minhook::MinHook::enable_hook(target).unwrap() };
    hook::take();
    assert_eq!(unsafe { stand_in(1, 2, 3, 4) }, direct, "arguments and result pass through");

    let hooked = Instant::now();
    for i in 0..calls as usize {
        black_box(unsafe { stand_in(black_box(i), 2, 3, 4) });
    }
    let hooked = hooked.elapsed().as_nanos() as f64 / calls as f64;
    unsafe { minhook::MinHook::disable_hook(target).unwrap() };
    unsafe { minhook::MinHook::remove_hook(target).unwrap() };

    let w = hook::take();
    assert_eq!(w.calls, calls + 1);
    let measured = w.over_sum as f64 / ticks_per_ns / w.calls as f64;
    println!(
        "[ INFO ] direct {baseline:.1} ns/call, hooked {hooked:.1} ns/call, added {:.1} ns/call, \
         detour self-measured overhead avg {measured:.1} ns, max {:.0} ns",
        hooked - baseline,
        w.over_max as f64 / ticks_per_ns
    );
    assert!(hooked - baseline < 1_000.0, "detour must stay far below a microsecond per call");
    ok(name, started, &format!("{:.1} ns added per call", hooked - baseline));
}

#[test]
fn ring_push_pop_and_drop() {
    let name = "ring push/pop, wraparound and full-drop";
    let started = begin(name);
    let ring = crate::ring::Ring::new(256);
    let mut out = Vec::new();
    // Push more small records than fit, across the wrap boundary.
    let mut pushed = 0u64;
    for i in 0..1000u64 {
        if ring.push(7, i, &i.to_le_bytes()) {
            pushed += 1;
            // Drain occasionally so we exercise wraparound, not just fill.
            if i % 3 == 0 {
                let r = ring.pop(&mut out).expect("pop after push");
                assert_eq!(r.kind, 7);
                assert_eq!(out.len(), 8);
            }
        }
    }
    // Remaining records pop in FIFO order with intact payloads.
    let mut last = None;
    while let Some(r) = ring.pop(&mut out) {
        let v = u64::from_le_bytes(out[..8].try_into().unwrap());
        assert_eq!(r.tsc, v, "tsc and payload belong to the same record");
        if let Some(p) = last {
            assert!(v > p, "FIFO order");
        }
        last = Some(v);
    }
    assert_eq!(ring.pushed.load(Relaxed), pushed);
    assert!(ring.dropped.load(Relaxed) > 0, "a 256-byte ring must drop when flooded");
    ok(name, started, &format!("pushed {pushed}, dropped {}", ring.dropped.load(Relaxed)));
}

// Stand-in for TICK: an integer arg in rcx and a float arg in xmm1, so the
// context stub must preserve both for the result to come out unchanged.
#[inline(never)]
unsafe extern "system" fn tick_stand_in(server: u64, scale: f64) -> f64 {
    black_box(server) as f64 * black_box(scale)
}

#[test]
fn context_stub_preserves_abi_and_observes() {
    // MinHook freezes the other threads while it patches: tests that install hooks take turns
    let _turn = crate::midhook::TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let name = "TICK context stub: xmm/int pass-through + server capture";
    let started = begin(name);
    let _guard = FEED_STATE.lock().unwrap_or_else(|e| e.into_inner());
    let direct = unsafe { tick_stand_in(21, 2.0) };
    assert_eq!(direct, 42.0);

    let target = tick_stand_in as *mut std::ffi::c_void;
    let original = unsafe { minhook::MinHook::create_hook(target, hook::tick_stub as *mut _).unwrap() };
    hook::TICK_TRAMPOLINE.store(original as usize, Relaxed);
    let seen_before = hook::TICK_SEEN.load(Relaxed);
    unsafe { minhook::MinHook::enable_hook(target).unwrap() };

    let hooked = unsafe { tick_stand_in(21, 2.0) };
    unsafe { minhook::MinHook::disable_hook(target).unwrap() };
    unsafe { minhook::MinHook::remove_hook(target).unwrap() };

    assert_eq!(hooked, 42.0, "int (rcx) and float (xmm1) arguments pass through the stub");
    assert_eq!(hook::TICK_SEEN.load(Relaxed), seen_before + 1, "handler ran once");
    assert_eq!(hook::TICK_SERVER.load(Relaxed), 21, "handler read the server pointer from rcx");
    ok(name, started, "result 42.0, server captured");
}


// Stand-in for an observed game function: four integer registers, a float in
// xmm1 and a fifth argument on the stack.
#[inline(never)]
unsafe extern "system" fn observed_stand_in(a: u64, scale: f64, c: u64, d: u64, e: u64) -> f64 {
    (black_box(a) + black_box(c) + black_box(d) + black_box(e)) as f64 * black_box(scale)
}

#[test]
fn observation_stub_counts_and_changes_nothing() {
    // MinHook freezes the other threads while it patches: tests that install hooks take turns
    let _turn = crate::midhook::TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let name = "observation stub: counts calls, records arguments, result unchanged";
    let started = begin(name);
    let direct = unsafe { observed_stand_in(1, 0.5, 2, 3, 4) };
    assert_eq!(direct, 5.0);

    let id = 24usize; // UI_COMMAND's slot: no other test touches it
    let (trampoline, stub) = crate::observe::slot(id);
    let target = observed_stand_in as *mut std::ffi::c_void;
    let original = unsafe { minhook::MinHook::create_hook(target, stub as *mut _).unwrap() };
    trampoline.store(original as usize, Relaxed);
    let before = crate::observe::COUNTS[id].load(Relaxed);
    unsafe { minhook::MinHook::enable_hook(target).unwrap() };
    let hooked = unsafe { observed_stand_in(1, 0.5, 2, 3, 4) };
    let again = unsafe { observed_stand_in(10, 2.0, 20, 30, 40) };
    unsafe { minhook::MinHook::disable_hook(target).unwrap() };
    unsafe { minhook::MinHook::remove_hook(target).unwrap() };

    assert_eq!(hooked, 5.0, "register, float and stack arguments pass through");
    assert_eq!(again, 200.0);
    assert_eq!(crate::observe::COUNTS[id].load(Relaxed), before + 2, "two calls counted");
    let last: Vec<u64> = crate::observe::LAST[id].iter().map(|v| v.load(Relaxed)).collect();
    // Win64: rcx = a, rdx unused (the float travels in xmm1), r8 = c, r9 = d.
    assert_eq!((last[0], last[2], last[3]), (10, 20, 30), "last call's rcx, r8, r9");
    assert!(last[4] != 0, "return address recorded");
    assert!(crate::observe::summary().contains("UI_COMMAND"));
    ok(name, started, "2 calls counted, 5.0 and 200.0 unchanged");
}

#[test]
fn observation_table_matches_the_pinned_bytes() {
    let name = "observation table: 25 names, entries recognised, golden bytes found";
    let started = begin(name);
    assert_eq!(crate::observe::NAMES.len(), crate::observe::COUNT);
    // The golden file pins WRITE/TICK too; every observed name must be pinned for all three builds.
    let golden = include_str!("../crates/azcoop-game/tests/golden/hook-bytes.txt");
    for version in ["0.84.3", "0.93.1", "0.95.0"] {
        let mut entries = 0;
        for line in golden.lines().filter(|l| l.starts_with(&format!("{version} "))) {
            let mut parts = line.split_whitespace();
            let (_, hook, rva, bytes) = (parts.next(), parts.next().unwrap(), parts.next().unwrap(), parts.next().unwrap());
            let rva = u64::from_str_radix(rva.trim_start_matches("0x"), 16).unwrap();
            let code: Vec<u8> = (0..bytes.len()).step_by(2).map(|i| u8::from_str_radix(&bytes[i..i + 2], 16).unwrap()).collect();
            if crate::observe::NAMES.contains(&hook) {
                assert_eq!(crate::observe::golden_bytes(version, hook, rva).as_deref(), Some(&code[..]), "{version} {hook}");
                entries += crate::observe::is_function_entry(&code) as usize;
            }
        }
        assert!((18..=21).contains(&entries), "{version}: {entries} observed entries");
    }
    ok(name, started, "75 pinned hooks found, 18-21 entries per build");
}

// ---- feed hooks ----------------------------------------------------------------

static FEED_STATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn client_direction_capture_reads_only_the_client_queue() {
    let name = "feed: client-direction WRITE capture uses the right queue and connection checks";
    let started = begin(name);
    let _guard = FEED_STATE.lock().unwrap_or_else(|e| e.into_inner());
    let _ = hook::FEED_RING.set(crate::ring::Ring::new(1 << 16));
    let ring = hook::FEED_RING.get().unwrap();
    let mut scratch = Vec::new();
    while ring.pop(&mut scratch).is_some() {}

    // A fake connection: live flag, key, cipher state, client/server queue pointers.
    let mut connection = vec![0u8; 0xB0];
    connection[0x30] = 1;
    for i in 0..40 {
        connection[0x5B + i] = (i * 3 + 1) as u8;
    }
    connection[0x83] = 7;
    connection[0x84] = 0x66;
    let (client_queue, server_queue) = (0x7000_0000u64, 0x7100_0000u64);
    connection[0x88..0x90].copy_from_slice(&client_queue.to_le_bytes());
    connection[0x90..0x98].copy_from_slice(&server_queue.to_le_bytes());
    // The server: connections vector {pointer, count} at offset 0x40.
    let mut server = vec![0u8; 0x80];
    server[0x40..0x48].copy_from_slice(&(connection.as_ptr() as u64).to_le_bytes());
    server[0x48..0x50].copy_from_slice(&1u64.to_le_bytes());
    hook::TICK_SERVER.store(server.as_ptr() as u64, Relaxed);
    hook::CONNECTIONS_OFFSET.store(0x40, Relaxed);

    let data = [9u8, 8, 7, 6, 5, 4, 3, 2, 1];
    unsafe { hook::feed_client_batch_for_test(client_queue as usize + 0x10, data.as_ptr() as usize, data.len()) };
    let record = ring.pop(&mut scratch).expect("a client-direction record");
    assert_eq!(record.kind, crate::feed::KIND_CLIENT);
    assert_eq!(&scratch[..40], &connection[0x5B..0x83], "key");
    assert_eq!((scratch[40], scratch[41]), (7, 0x66), "cipher state before the batch");
    assert_eq!(u64::from_le_bytes(scratch[42..50].try_into().unwrap()), connection.as_ptr() as u64);
    assert_eq!(&scratch[50..], &data);
    // The server-direction queue, a dead connection and an oversize batch push nothing.
    unsafe { hook::feed_client_batch_for_test(server_queue as usize + 0x10, data.as_ptr() as usize, data.len()) };
    unsafe { hook::feed_client_batch_for_test(client_queue as usize + 0x10, data.as_ptr() as usize, 0) };
    connection[0x30] = 0;
    unsafe { hook::feed_client_batch_for_test(client_queue as usize + 0x10, data.as_ptr() as usize, data.len()) };
    assert!(ring.pop(&mut scratch).is_none());
    hook::TICK_SERVER.store(0, Relaxed);
    ok(name, started, "1 record, 3 refusals");
}

#[inline(never)]
unsafe extern "system" fn serialize_stand_in(this: u64, packet: *const u8) -> u64 {
    black_box(this) + black_box(packet) as u64 % 7
}

#[test]
fn serialize_stub_copies_only_the_bootstrap_packets() {
    // MinHook freezes the other threads while it patches: tests that install hooks take turns
    let _turn = crate::midhook::TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let name = "feed: SERIALIZE stub copies the template and the name reply, counts every call";
    let started = begin(name);
    let _guard = FEED_STATE.lock().unwrap_or_else(|e| e.into_inner());
    let _ = hook::FEED_RING.set(crate::ring::Ring::new(1 << 16));
    let ring = hook::FEED_RING.get().unwrap();
    let mut scratch = Vec::new();
    while ring.pop(&mut scratch).is_some() {}
    hook::FEED.store(true, Relaxed);

    let target = serialize_stand_in as *mut std::ffi::c_void;
    let original = unsafe { minhook::MinHook::create_hook(target, hook::serialize_stub as *mut _).unwrap() };
    hook::SERIALIZE_TRAMPOLINE.store(original as usize, Relaxed);
    unsafe { minhook::MinHook::enable_hook(target).unwrap() };
    let before = crate::observe::COUNTS[19].load(Relaxed);

    let packet = |body: &Vec<u8>, opcode: u16| {
        let mut p = vec![0u8; 32];
        p[8..16].copy_from_slice(&(body.as_ptr() as u64).to_le_bytes());
        p[16..24].copy_from_slice(&(body.len() as u64).to_le_bytes());
        p[24..26].copy_from_slice(&opcode.to_le_bytes());
        p
    };
    let mut template = crate::feed::TEMPLATE_PREFIX.to_vec();
    template.extend_from_slice(&[0u8; 80]);
    let name_reply = b"nameblob".to_vec();
    let update = vec![1u8; 40];
    let results: Vec<u64> = [(&template, 0xA9u16), (&name_reply, 0x51), (&update, 0xA9), (&template, 0x143)]
        .iter()
        .map(|(body, opcode)| {
            let p = packet(body, *opcode);
            unsafe { serialize_stand_in(5, p.as_ptr()) }
        })
        .collect();
    unsafe { minhook::MinHook::disable_hook(target).unwrap() };
    unsafe { minhook::MinHook::remove_hook(target).unwrap() };
    hook::FEED.store(false, Relaxed);

    assert!(results.iter().all(|r| *r >= 5), "the original ran and returned its value");
    assert_eq!(crate::observe::COUNTS[19].load(Relaxed), before + 4, "every call counted");
    let first = ring.pop(&mut scratch).expect("template record");
    assert_eq!(first.kind, crate::feed::KIND_SERIALIZE);
    assert_eq!(u16::from_le_bytes([scratch[0], scratch[1]]), 0xA9);
    assert_eq!(&scratch[6..], &template[..]);
    let second = ring.pop(&mut scratch).expect("name record");
    assert_eq!((second.kind, u16::from_le_bytes([scratch[0], scratch[1]])), (crate::feed::KIND_SERIALIZE, 0x51));
    assert!(ring.pop(&mut scratch).is_none(), "an ordinary update and a foreign opcode are not copied");
    ok(name, started, "2 of 4 packets copied, 4 counted");
}

// ---- read-write context stub ------------------------------------------------

static RW_TRAMPOLINE_MODIFY: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static RW_TRAMPOLINE_SKIP: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static RW_ORIGINAL_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[inline(never)]
unsafe extern "system" fn rw_modify_target(a: u64, scale: f64, flag: u64) -> f64 {
    black_box(a) as f64 * black_box(scale) + black_box(flag) as f64
}

#[inline(never)]
unsafe extern "system" fn rw_skip_target(a: u64, b: u64) -> u64 {
    RW_ORIGINAL_CALLS.fetch_add(1, Relaxed);
    black_box(a).wrapping_mul(7).wrapping_add(black_box(b))
}

extern "C" fn rw_modify_handler(ctx: *mut crate::stub::Context) {
    let ctx = unsafe { &mut *ctx };
    assert_eq!(ctx.id, 90);
    ctx.rcx = 5; // a
    ctx.xmm[1] = 2.0f64.to_bits() as u128; // scale
    ctx.r8 = 1; // flag
}

extern "C" fn rw_skip_handler(ctx: *mut crate::stub::Context) {
    let ctx = unsafe { &mut *ctx };
    assert_eq!(ctx.id, 91);
    if ctx.rcx == 1 {
        ctx.skip = 1;
        ctx.result = 0x1234_5678_9ABC;
    }
}

crate::context_stub_rw!(rw_modify_stub, 90u64, rw_modify_handler, RW_TRAMPOLINE_MODIFY);
crate::context_stub_rw!(rw_skip_stub, 91u64, rw_skip_handler, RW_TRAMPOLINE_SKIP);

#[test]
fn read_write_stub_rewrites_arguments() {
    // MinHook freezes the other threads while it patches: tests that install hooks take turns
    let _turn = crate::midhook::TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let name = "read-write stub: the handler rewrites rcx, xmm1 and r8 before the original runs";
    let started = begin(name);
    let target = rw_modify_target as *mut std::ffi::c_void;
    let direct = unsafe { rw_modify_target(1, 3.0, 0) };
    assert_eq!(direct, 3.0);
    let original = unsafe { minhook::MinHook::create_hook(target, rw_modify_stub as *mut _).unwrap() };
    RW_TRAMPOLINE_MODIFY.store(original as usize, Relaxed);
    unsafe { minhook::MinHook::enable_hook(target).unwrap() };
    let hooked = unsafe { rw_modify_target(1, 3.0, 0) };
    unsafe { minhook::MinHook::disable_hook(target).unwrap() };
    unsafe { minhook::MinHook::remove_hook(target).unwrap() };
    assert_eq!(hooked, 11.0, "the original saw a=5, scale=2.0, flag=1");
    ok(name, started, "5 * 2.0 + 1 = 11");
}

#[test]
fn read_write_stub_skips_the_original() {
    // MinHook freezes the other threads while it patches: tests that install hooks take turns
    let _turn = crate::midhook::TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let name = "read-write stub: skip returns the handler's result without entering the original";
    let started = begin(name);
    let target = rw_skip_target as *mut std::ffi::c_void;
    let original = unsafe { minhook::MinHook::create_hook(target, rw_skip_stub as *mut _).unwrap() };
    RW_TRAMPOLINE_SKIP.store(original as usize, Relaxed);
    unsafe { minhook::MinHook::enable_hook(target).unwrap() };
    RW_ORIGINAL_CALLS.store(0, Relaxed);
    let skipped = unsafe { rw_skip_target(1, 2) };
    assert_eq!(skipped, 0x1234_5678_9ABC, "result from the handler");
    assert_eq!(RW_ORIGINAL_CALLS.load(Relaxed), 0, "the original was not entered");
    let passed = unsafe { rw_skip_target(2, 3) };
    assert_eq!(passed, 17, "without skip the original runs with its own arguments");
    assert_eq!(RW_ORIGINAL_CALLS.load(Relaxed), 1);
    // many alternating calls: the stack stays balanced and the callee-saved state intact
    let mut sum = 0u64;
    for i in 0..10_000u64 {
        sum = sum.wrapping_add(unsafe { rw_skip_target(1 + (i & 1), i) });
    }
    unsafe { minhook::MinHook::disable_hook(target).unwrap() };
    unsafe { minhook::MinHook::remove_hook(target).unwrap() };
    let expected: u64 = (0..10_000u64).fold(0u64, |acc, i| acc.wrapping_add(if i & 1 == 0 { 0x1234_5678_9ABC } else { (2u64 * 7).wrapping_add(i) }));
    assert_eq!(sum, expected);
    ok(name, started, "10 000 alternating calls balanced");
}

static RW_TRAMPOLINE_NV: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static RW_NV_SEEN: [std::sync::atomic::AtomicU64; 8] = [const { std::sync::atomic::AtomicU64::new(0) }; 8];

#[inline(never)]
unsafe extern "system" fn rw_nv_target() -> u64 {
    black_box(7)
}

extern "C" fn rw_nv_handler(ctx: *mut crate::stub::Context) {
    let ctx = unsafe { &*ctx };
    for (slot, value) in RW_NV_SEEN.iter().zip([ctx.rbx, ctx.rbp, ctx.rsi, ctx.rdi, ctx.r12, ctx.r13, ctx.r14, ctx.r15]) {
        slot.store(value, Relaxed);
    }
}

crate::context_stub_rw!(rw_nv_stub, 92u64, rw_nv_handler, RW_TRAMPOLINE_NV);

#[test]
fn read_write_stub_reports_the_callee_saved_registers_of_the_caller() {
    // MinHook freezes the other threads while it patches: tests that install hooks take turns
    let _turn = crate::midhook::TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let name = "read-write stub: rbx, rbp, rsi, rdi, r12-r15 are the caller's values and survive the call";
    let started = begin(name);
    let target = rw_nv_target as *mut std::ffi::c_void;
    let original = unsafe { minhook::MinHook::create_hook(target, rw_nv_stub as *mut _).unwrap() };
    RW_TRAMPOLINE_NV.store(original as usize, Relaxed);
    unsafe { minhook::MinHook::enable_hook(target).unwrap() };
    let (result, after): (u64, [u64; 8]);
    let mut out = [0u64; 8];
    unsafe {
        let out_ptr = out.as_mut_ptr();
        let rax: u64;
        std::arch::asm!(
            "push rbx", "push rbp", "push rsi", "push rdi", "push r12", "push r13", "push r14", "push r15",
            "mov rbx, 0xB1", "mov rbp, 0xB2", "mov rsi, 0xB3", "mov rdi, 0xB4", "mov r12, 0xB5", "mov r13, 0xB6", "mov r14, 0xB7", "mov r15, 0xB8",
            "sub rsp, 32",
            "call {t}",
            "add rsp, 32",
            "mov [{o}], rbx", "mov [{o} + 8], rbp", "mov [{o} + 16], rsi", "mov [{o} + 24], rdi",
            "mov [{o} + 32], r12", "mov [{o} + 40], r13", "mov [{o} + 48], r14", "mov [{o} + 56], r15",
            "pop r15", "pop r14", "pop r13", "pop r12", "pop rdi", "pop rsi", "pop rbp", "pop rbx",
            t = in(reg) rw_nv_target as usize,
            o = in(reg) out_ptr,
            out("rax") rax,
            clobber_abi("C"),
        );
        result = rax;
        after = out;
    }
    unsafe { minhook::MinHook::disable_hook(target).unwrap() };
    unsafe { minhook::MinHook::remove_hook(target).unwrap() };
    let seen: Vec<u64> = RW_NV_SEEN.iter().map(|s| s.load(Relaxed)).collect();
    assert_eq!(seen, vec![0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8], "the handler saw the caller's registers");
    assert_eq!(after, [0xB1, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8], "and they are unchanged afterwards");
    assert_eq!(result, 7);
    ok(name, started, "8 registers");
}

#[test]
fn the_supported_builds_are_the_ones_of_the_game_crate() {
    let name = "supported builds agree with azcoop-game";
    let started = begin(name);
    let ours: Vec<(&str, &str)> = crate::SUPPORTED_BUILDS.to_vec();
    let theirs: Vec<(&str, &str)> = azcoop_game::builds::SUPPORTED.iter().map(|(_, version, sha)| (*version, *sha)).collect();
    assert_eq!(ours, theirs, "src/lib.rs SUPPORTED_BUILDS and crates/azcoop-game/src/builds.rs SUPPORTED must list the same builds");
    println!("[  OK  ] {name} ({:.1} ms, {} builds)", started.elapsed().as_secs_f64() * 1000.0, ours.len());
}

#[test]
fn the_proxy_stays_inert_unless_a_launcher_asks() {
    let name = "inert without AZCOOP_ENGINE=1";
    let started = begin(name);
    let _turn = crate::midhook::TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let saved: Vec<_> = ["AZCOOP_ENGINE", "AZCOOP_MEASURE"].iter().map(|n| (*n, std::env::var_os(n))).collect();
    for (n, _) in &saved {
        std::env::remove_var(n);
    }
    assert!(!crate::requested(), "no variable: nothing is hooked");
    std::env::set_var("AZCOOP_ENGINE", "0");
    assert!(!crate::requested(), "only the value 1 asks");
    std::env::set_var("AZCOOP_ENGINE", "1");
    assert!(crate::requested());
    std::env::remove_var("AZCOOP_ENGINE");
    std::env::set_var("AZCOOP_MEASURE", "1");
    assert!(crate::requested(), "the measuring mode stays available for tests");
    for (n, v) in saved {
        match v {
            Some(v) => std::env::set_var(n, v),
            None => std::env::remove_var(n),
        }
    }
    println!("[  OK  ] {name} ({:.1} ms)", started.elapsed().as_secs_f64() * 1000.0);
}
