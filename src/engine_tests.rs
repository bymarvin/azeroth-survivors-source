//! The engine glue over stand-in "game" functions: entry stubs, injected calls, retry, nesting,
//! skipping, faults, breakpoint sites. No game and no bridge: a scripted handler plays the bridge.

use crate::engine::{self, testing, HookHandler, HOOK_COUNT};
use azcoop_bridge::client::{CallSpec, Client, Hook};
use azcoop_bridge::regs::{self, Regs};
use azcoop_logic::Detail;
use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering::*};
use std::sync::Mutex;

fn begin(name: &str) -> std::time::Instant {
    println!("[ .... ] {name}");
    std::time::Instant::now()
}

fn ok(name: &str, started: std::time::Instant, detail: &str) {
    println!("[  OK  ] {name} ({:.1} ms, {detail})", started.elapsed().as_secs_f64() * 1000.0);
}

static MOVE_SEEN: AtomicU64 = AtomicU64::new(0);
static MOVE_CALLS: AtomicU64 = AtomicU64::new(0);

/// The stand-in for the MOVE function: records its first argument.
#[inline(never)]
unsafe extern "system" fn game_move(a: u64, b: u64) -> u64 {
    MOVE_SEEN.store(black_box(a), SeqCst);
    MOVE_CALLS.fetch_add(1, SeqCst);
    black_box(b).wrapping_add(1)
}

static HURT_CALLS: AtomicU64 = AtomicU64::new(0);
static HURT_REG0: AtomicU64 = AtomicU64::new(0);
static HURT_REG1: AtomicU64 = AtomicU64::new(0);
static HURT_REG2: AtomicU64 = AtomicU64::new(0);
static HURT_REG3: AtomicU64 = AtomicU64::new(0);
static HURT_REG4: AtomicU64 = AtomicU64::new(0);
static HURT_REG5: AtomicU64 = AtomicU64::new(0);

/// The stand-in for HURT(game, second, attacker, melee) with a float in xmm1.
#[unsafe(naked)]
unsafe extern "system" fn game_hurt() {
    core::arch::naked_asm!(
        "push rbp",
        "mov rbp, rsp",
        "mov [rip + {c}], rcx",
        "mov [rip + {d}], rdx",
        "mov [rip + {e}], r8",
        "mov [rip + {f}], r9",
        "movd eax, xmm1",
        "mov [rip + {g}], rax",
        "mov rax, [rbp + 8]",
        "mov [rip + {h}], rax",
        "lock inc qword ptr [rip + {n}]",
        "mov rax, 0x42",
        "pop rbp",
        "ret",
        c = sym HURT_REG0, d = sym HURT_REG1, e = sym HURT_REG2, f = sym HURT_REG3, g = sym HURT_REG4, h = sym HURT_REG5, n = sym HURT_CALLS,
    )
}

fn hurt_seen() -> [u64; 6] {
    [HURT_REG0.load(SeqCst), HURT_REG1.load(SeqCst), HURT_REG2.load(SeqCst), HURT_REG3.load(SeqCst), HURT_REG4.load(SeqCst), HURT_REG5.load(SeqCst)]
}

type Script = Box<dyn FnMut(&mut dyn Client, Hook, &mut Regs) -> Result<(), String> + Send>;

struct Scripted {
    script: Script,
}

impl HookHandler for Scripted {
    fn set_clock(&mut self, _now: f64) {}
    fn handle(&mut self, client: &mut dyn Client, hook: Hook, regs: &mut Regs) -> Result<(), String> {
        (self.script)(client, hook, regs)
    }
}

fn entries(list: &[(Hook, usize)]) -> [u64; HOOK_COUNT] {
    let mut e = [0u64; HOOK_COUNT];
    for (hook, address) in list {
        e[*hook as usize] = *address as u64;
    }
    e
}

static EVENTS: Mutex<Vec<String>> = Mutex::new(Vec::new());

fn note(text: String) {
    EVENTS.lock().unwrap().push(text);
}

fn take_events() -> Vec<String> {
    std::mem::take(&mut *EVENTS.lock().unwrap())
}

fn top_of_stack(client: &mut dyn Client, regs: &Regs) -> u64 {
    u64::from_le_bytes(client.memory(regs.q(regs::RSP), 8).unwrap()[..8].try_into().unwrap())
}

#[test]
fn the_engine_glue_runs_injected_calls_retries_nests_skips_and_survives_faults() {
    let name = "engine: entry stubs, injected call + retry, nested hook, skip, disable, fault, validation";
    let started = begin(name);
    let _turn = crate::midhook::TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let move_address = game_move as usize;
    let hurt_address = game_hurt as usize;
    let table = entries(&[(Hook::Move, move_address), (Hook::Hurt, hurt_address)]);
    let both = [(Hook::Move, move_address), (Hook::Hurt, hurt_address)];

    // ---- 1. a hook asks for a call; the call runs; the hook runs again and rewrites an argument ----
    let mut asked = false;
    testing::setup(
        table,
        Box::new(Scripted {
            script: Box::new(move |client, hook, regs| {
                match hook {
                    Hook::Move => {
                        note(format!("move saved={}", client.saved_context()));
                        if !asked {
                            asked = true;
                            client.call_before(regs, CallSpec::new(Hook::Hurt, 0x5000, 7).with("damage", Detail::Num(2.5)).with("melee", Detail::Num(1.0)))?;
                        } else {
                            regs.set_q(regs::RCX, 99); // the original now sees a=99
                        }
                    }
                    Hook::Hurt => {
                        let direct = top_of_stack(client, regs) == client.call_return();
                        note(format!("hurt saved={} direct={direct}", client.saved_context()));
                    }
                    _ => {}
                }
                Ok(())
            }),
        }),
    );
    crate::entry::install_for_test(&both, &[]).unwrap();
    take_events();
    let result = unsafe { game_move(black_box(1), black_box(10)) };
    assert_eq!(result, 11);
    assert_eq!(MOVE_SEEN.load(SeqCst), 99, "the original saw the argument the second pass wrote");
    assert_eq!(HURT_CALLS.load(SeqCst), 1, "the injected call ran once");
    let hurt = hurt_seen();
    assert_eq!(hurt[0], 0x5000, "rcx = game");
    assert_eq!(hurt[1], 7, "rdx = second");
    assert_eq!(hurt[2], 7, "r8 = second (the attacker)");
    assert_eq!(hurt[3], 1, "r9 = melee");
    assert_eq!(f32::from_bits(hurt[4] as u32), 2.5, "xmm1 = damage");
    assert_eq!(hurt[5], crate::call::CallFrame::return_site(), "the call returns to the thunk's known site");
    assert_eq!(
        take_events(),
        vec!["move saved=false", "hurt saved=true direct=true", "move saved=false"],
        "order: first pass, the hook inside the injected call (recognised as direct), retry"
    );
    assert!(engine::summary().contains("calls 1"));

    // ---- 2. a hook inside the call may skip the function ----
    HURT_CALLS.store(0, SeqCst);
    let mut asked = false;
    testing::setup(
        table,
        Box::new(Scripted {
            script: Box::new(move |client, hook, regs| {
                match hook {
                    Hook::Move if !asked => {
                        asked = true;
                        client.call_before(regs, CallSpec::new(Hook::Hurt, 1, 2).with("damage", Detail::Num(1.0)))?;
                    }
                    Hook::Hurt => {
                        let top = top_of_stack(client, regs);
                        regs.set_q(regs::RAX, 0xBEEF);
                        regs.skip_with(top);
                    }
                    _ => {}
                }
                Ok(())
            }),
        }),
    );
    assert_eq!(unsafe { game_move(3, 4) }, 5);
    assert_eq!(HURT_CALLS.load(SeqCst), 0, "the skipped function never ran");
    assert_eq!(MOVE_SEEN.load(SeqCst), 3, "the original ran with its own arguments");

    // ---- 3. skipping an entry hook returns the handler's rax and never enters the original ----
    MOVE_CALLS.store(0, SeqCst);
    testing::setup(
        table,
        Box::new(Scripted {
            script: Box::new(|client, hook, regs| {
                if hook == Hook::Move {
                    let top = top_of_stack(client, regs);
                    regs.set_q(regs::RAX, 0xCAFE);
                    regs.skip_with(top);
                }
                Ok(())
            }),
        }),
    );
    assert_eq!(unsafe { game_move(8, 9) }, 0xCAFE);
    assert_eq!(MOVE_CALLS.load(SeqCst), 0);

    // ---- 4. a disabled hook stops reacting ----
    testing::setup(
        table,
        Box::new(Scripted {
            script: Box::new(|client, hook, regs| {
                note("seen".into());
                if hook == Hook::Move {
                    client.disable_hook(Hook::Move);
                    regs.set_q(regs::RCX, 77);
                }
                Ok(())
            }),
        }),
    );
    take_events();
    unsafe { game_move(1, 1) };
    assert_eq!(MOVE_SEEN.load(SeqCst), 77);
    unsafe { game_move(2, 1) };
    assert_eq!(MOVE_SEEN.load(SeqCst), 2, "after disable_hook the original runs untouched");
    assert_eq!(take_events().len(), 1, "and the handler is not called again");

    // ---- 5. a failing handler stops the core and the game goes on unmodified ----
    testing::setup(
        table,
        Box::new(Scripted {
            script: Box::new(|_, hook, regs| {
                if hook == Hook::Move {
                    regs.set_q(regs::RCX, 1234); // half-done work must not leak into the game
                    return Err("boom".into());
                }
                Ok(())
            }),
        }),
    );
    assert!(testing::active());
    assert_eq!(unsafe { game_move(5, 6) }, 7);
    assert_eq!(MOVE_SEEN.load(SeqCst), 5, "the failed event leaves the arguments as the game made them");
    assert!(!testing::active(), "the core stopped");
    assert_eq!(unsafe { game_move(6, 6) }, 7);
    assert_eq!(MOVE_SEEN.load(SeqCst), 6);

    // ---- 6. a validated call: out-of-range arguments are refused like the Python did ----
    let refused = std::sync::Arc::new(Mutex::new(String::new()));
    let seen = refused.clone();
    testing::setup(
        table,
        Box::new(Scripted {
            script: Box::new(move |client, hook, regs| {
                if hook == Hook::Move {
                    let error = client.call_before(regs, CallSpec::new(Hook::Hurt, 1, 2).with("damage", Detail::Num(-1.0))).unwrap_err();
                    *seen.lock().unwrap() = error;
                }
                Ok(())
            }),
        }),
    );
    HURT_CALLS.store(0, SeqCst);
    unsafe { game_move(1, 1) };
    assert_eq!(*refused.lock().unwrap(), "Invalid native damage");
    assert_eq!(HURT_CALLS.load(SeqCst), 0);

    crate::entry::uninstall_for_test();
    ok(name, started, "6 scenarios");
}

#[test]
fn every_hook_site_of_every_build_holds_the_bytes_the_python_expects() {
    use crate::engine::{DiskImage, ENTRY_HOOKS, MID_HOOKS};
    use azcoop_game::builds::Variant;
    use azcoop_patch::Image;
    let name = "engine: hook sites of the three builds match the executables on disk";
    let started = begin(name);
    let reference = std::path::Path::new(r"reference\reconstruction");
    let builds = [
        ("0.84.3", Variant::V0843, r"reference\testgame-0843\AzerothSurvivors.exe", "release-0.84.3.json"),
        ("0.93.1", Variant::V0931, r"reference\testgame-0931\AzerothSurvivors.exe", "release-0315cf38.json"),
        ("0.95.0", Variant::V7264, r"reference\testgame-0950\AzerothSurvivors.exe", "release-7264d50b.json"),
    ];
    let Ok(reviewed) = std::fs::read_to_string(reference.join("reviewed-hooks.json")) else {
        println!("[ WARN ] reference folder not available, skipped");
        return;
    };
    let mut checked = 0;
    for (version, variant, exe, release) in builds {
        let (Ok(release_text), Ok(image)) = (std::fs::read_to_string(reference.join(release)), DiskImage::open(std::path::Path::new(exe))) else {
            println!("[ WARN ] {version}: files not available, skipped");
            continue;
        };
        let profile = azcoop_game::profile::Profile::parse(&release_text, &reviewed).unwrap();
        for hook in ENTRY_HOOKS.iter().chain(MID_HOOKS.iter()) {
            let rva = match (profile.hooks.get(hook.name()), *hook) {
                (Some(h), _) => h.rva,
                (None, azcoop_bridge::client::Hook::MenuLogin) => match profile.menu.as_ref().and_then(|m| m.login.as_ref()) {
                    Some(login) => login.branch,
                    None => continue, // builds without a menu contract have no login hook
                },
                (None, _) => panic!("{version}: no {} hook", hook.name()),
            };
            let _ = variant;
            match engine::mid_site_shape(*hook, variant) {
                Some((opcode, length)) => {
                    let code = image.bytes(rva, length).unwrap();
                    assert!(code.starts_with(&opcode), "{version} {} at {rva:#x}: {:02x?}", hook.name(), code);
                }
                None => {
                    let code = image.bytes(rva, 16).unwrap();
                    // a function entry starts with a push (rbp, r15, r14, ...) as the Python expects
                    assert!(
                        code[0] == 0x55 || (code[0] == 0x41 && (0x54..=0x57).contains(&code[1])) || matches!(code[0], 0x53 | 0x56 | 0x57),
                        "{version} {} at {rva:#x}: {:02x?}",
                        hook.name(),
                        code
                    );
                }
            }
            checked += 1;
        }
    }
    ok(name, started, &format!("{checked} sites"));
}

/// Soak 19.10.2026: the pause-UI stub checked PAUSE's prologue in live memory, where our MinHook jump sits over the first bytes, so
/// every pause-UI call (a shared pause while a teammate is downed) stopped the core. The check reads the exe on disk now.
#[test]
fn the_pause_ui_prologue_is_checked_on_disk_not_under_our_entry_hook() {
    let name = "engine: pause-UI prologue check against the disk image";
    let started = begin(name);
    struct Fake(Vec<u8>);
    impl azcoop_patch::Image for Fake {
        fn bytes(&self, rva: u64, len: usize) -> Result<Vec<u8>, String> {
            let at = rva as usize;
            self.0.get(at..at + len).map(|b| b.to_vec()).ok_or_else(|| "outside".to_string())
        }
    }
    let prefix = crate::engine::pause_ui_prefix();
    let mut disk = vec![0xCCu8; 0x40];
    disk.extend_from_slice(&prefix);
    disk.extend_from_slice(&[0x90; 16]);
    assert!(crate::engine::pause_ui_prologue_ok(&Fake(disk.clone()), 0x40).unwrap(), "the build's own prologue passes");
    // what live memory looks like with MinHook installed: jmp rel32 over the first 5 bytes; the old check read this and failed
    let mut hooked = disk.clone();
    hooked[0x40..0x45].copy_from_slice(&[0xE9, 0x11, 0x22, 0x33, 0x44]);
    assert_ne!(&hooked[0x41..0x40 + prefix.len()], &prefix[1..], "the live bytes behind byte 0 differ under the hook");
    let mut changed = disk.clone();
    changed[0x40 + 5] = 0x90; // another stack size in a new build
    assert!(!crate::engine::pause_ui_prologue_ok(&Fake(changed), 0x40).unwrap(), "a changed build is still refused");
    assert!(crate::engine::pause_ui_prologue_ok(&Fake(disk), 0x1000).is_err(), "outside the image is an error, not a pass");
    ok(name, started, "disk bytes pass, a changed prologue is refused");
}
