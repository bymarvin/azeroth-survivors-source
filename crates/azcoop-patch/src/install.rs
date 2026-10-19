//! The first-TICK installation of the adapter's code patches, in the order and with the
//! checks of the Python's `__call__` blocks (visibility_bridge.py / native_guest_combat.py).
//!
//! Every block verifies the live bytes against the build's expected bytes, allocates
//! executable code for its trampoline, and overwrites the site with a jump (or branch).

use crate::pursuit::pursuit_code;
use crate::recycle::{rbp_operand, recycle_distance_code, recycle_distance_original};
use crate::world::{downed_hazards_code, downed_world_code};
use crate::{absolute_jump, hx, pack_i32, pack_u32, pack_u64, Ctx, Result, Snip, P};
use azcoop_game::builds::reviewed;

/// The game process as the installer sees it (the Python's `client`).
pub trait Process {
    fn base(&self) -> u64;
    /// `client.memory(base + rva, len)`
    fn memory(&mut self, rva: u64, len: usize) -> Result<Vec<u8>>;
    /// `client.patch(base + rva, bytes)`
    fn patch(&mut self, rva: u64, bytes: &[u8]) -> Result<()>;
    /// `client.executable_buffer(code, near=...)`: the buffer is near `rva` when given.
    fn executable_buffer(&mut self, code: &[u8], near: Option<u64>) -> Result<u64>;
    /// `checked(allocate(handle, None, size, ...))`
    fn allocate(&mut self, size: usize) -> Result<u64>;
    /// `client.put(address, bytes)` at an absolute address
    fn put(&mut self, address: u64, bytes: &[u8]) -> Result<()>;
    /// A logged event (`self.record(event=...)`) at this point of the installation.
    fn event(&mut self, _name: &str, _details: &[(&str, Note)]) {}
}

/// A number or a list of numbers in a logged event.
#[derive(Debug, Clone, PartialEq)]
pub enum Note {
    Num(f64),
    List(Vec<f64>),
}

fn verify(p: &mut dyn Process, rva: u64, expected: &[u8], error: &str) -> Result<()> {
    if p.memory(rva, expected.len())? != expected {
        return Err(error.to_string());
    }
    Ok(())
}

/// `absolute_jump(entry) + NOP * pad`
fn jump_pad(entry: u64, pad: usize) -> Vec<u8> {
    let mut out = absolute_jump(entry);
    out.resize(out.len() + pad, 0x90);
    out
}

/// `phase_gate()`
pub fn phase_gate(ctx: &Ctx) -> Result<Vec<u8>> {
    ctx.expected_bytes(0x53DC9F5, &hx("0f85dde10000"))
}

/// `native_branch(legacy_source, legacy_target, opcode, size)`
pub fn native_branch(ctx: &Ctx, source: u64, target: u64, opcode: &[u8], size: usize) -> Result<Vec<u8>> {
    ctx.reviewed_branch(reviewed(source)?, reviewed(target)?, opcode, size)
}

pub struct HostGate {
    pub world_enable: u64,
    pub guest_target: u64,
    pub pursuit_guard: u64,
}

/// The shared-world TICK block of the host: downed-world tick continuation, hazards, pursuit,
/// and for the 47e4 family the path-field guard and recycle distance.
pub fn install_host_world(ctx: &Ctx, p: &mut dyn Process, server: u64, guests: usize) -> Result<HostGate> {
    let base = p.base();
    let gate = Snip::new(&if ctx.is_0843() {
        vec![P::Raw("f3410f10bc24"), P::Mem(0x86C, 4, "r12")]
    } else {
        vec![P::Raw("f3410f10bd"), P::Mem(0x86C, 4, "r13")]
    })
    .fields(ctx, "game", &[if ctx.is_0843() { "r12" } else { "r13" }])?;
    let mut expected = phase_gate(ctx)?;
    expected.extend(gate.bytes);
    let rva = ctx.rva(0x53DC9F5)?;
    verify(p, rva, &expected, "Host tick phase gate does not match verified build")?;
    let world_enable = p.allocate(1)?;
    let code = p.executable_buffer(&downed_world_code(ctx, base, world_enable)?, None)?;
    p.patch(rva, &jump_pad(code, expected.len().saturating_sub(14)))?;

    let rva = ctx.rva(0x53E1B4E)?;
    let expected = ctx.expected_bytes(0x53E1B4E, &hx("498d8588050000 488985e8020000"))?;
    verify(p, rva, &expected, "Native hazard/totem boundary changed")?;
    let code = p.executable_buffer(&downed_hazards_code(ctx, base)?, None)?;
    p.patch(rva, &jump_pad(code, expected.len().saturating_sub(14)))?;

    let guest_target = p.allocate(guests.max(1) * 16)?;
    let pursuit_guard = p.allocate(16)?;
    let rva = ctx.rva(0x53E370A)?;
    let expected = ctx.expected_bytes(0x53E370A, &hx("450f28cf 440f5c8dd0000000 f3450f16e9"))?;
    verify(p, rva, &expected, "Enemy pursuit instructions changed")?;
    let code = p.executable_buffer(&pursuit_code(ctx, base, guest_target, guests as u32, Some((server + 0x10, pursuit_guard)))?, None)?;
    p.patch(rva, &jump_pad(code, expected.len().saturating_sub(14)))?;

    if ctx.is_47e4() {
        // 0.92 steers approaching enemies through a path field that the enemy function rebuilds
        // around the host only. An enemy whose pursuit target is a guest would follow it back to
        // the host, so the field query runs only while the target equals the host position.
        let family = ctx.family()?;
        let [site, resume, skip] = family.path_field;
        let [walls, path, game_slot, target] = family.path_field_slots;
        // cmp qword [rbp+walls],-1 ; je skip ; mov rdx,[rbp+path]
        let mut head = rbp_operand(&hx("4883"), 7, walls)?;
        head.push(0xFF);
        let mut expected = head.clone();
        expected.extend(hx("0f84"));
        expected.extend_from_slice(&pack_i32(skip as i128 - (site as i128 + head.len() as i128 + 6))?);
        expected.extend(rbp_operand(&hx("488b"), 2, path)?);
        verify(p, site, &expected, "Enemy path-field query instructions changed")?;
        // mov rdx,[rbp+path]; push rax; mov rax,[rbp+Game]; mov rax,[rax+host XY]; cmp rax,[rbp+target];
        // pop rax; jne skip; jmp resume
        let mut body = rbp_operand(&hx("488b"), 2, path)?;
        body.extend(hx("50"));
        body.extend(rbp_operand(&hx("488b"), 0, game_slot)?);
        body.extend(hx("488b80"));
        body.extend_from_slice(&pack_u32(ctx.game_field(0x488)? as i128)?);
        body.extend(rbp_operand(&hx("483b"), 0, target)?);
        body.extend(hx("58750e"));
        body.extend(absolute_jump(base + resume));
        let mut code = head;
        code.push(0x74);
        code.push(u8::try_from(body.len()).map_err(|_| "byte must be in range(0, 256)".to_string())?);
        code.extend(body);
        code.extend(absolute_jump(base + skip));
        let entry = p.executable_buffer(&code, None)?;
        p.patch(site, &jump_pad(entry, expected.len().saturating_sub(14)))?;
        p.event("native_path_field_guard", &[("rva", Note::Num(site as f64))]);
        // 0.92 recycles every ordinary enemy farther than 55 from the host; the filter's two
        // distance tests use the nearest living player instead.
        for ((site, after, select), regs) in family.recycle.iter().map(|r| (r[0], r[1], r[2])).zip([(1u8, 2u8, 3u8), (0, 1, 3)]) {
            let mut expected = recycle_distance_original(regs.0, regs.1);
            expected.extend(hx("0f87"));
            expected.extend_from_slice(&pack_i32(select as i128 - (site as i128 + 29))?);
            verify(p, site, &expected, "Enemy recycle distance instructions changed")?;
            let code = recycle_distance_code(guest_target, guests as u32, regs.0, regs.1, regs.2, base + select, base + after)?;
            let entry = p.executable_buffer(&code, None)?;
            p.patch(site, &jump_pad(entry, 15))?;
        }
        p.event("native_recycle_guard", &[("sites", Note::List(family.recycle.iter().map(|r| r[0] as f64).collect()))]);
    }
    Ok(HostGate { world_enable, guest_target, pursuit_guard })
}

/// The shared-world TICK block of a guest: keep the native status/buff update tail, skip the
/// independent world simulation.
pub fn install_guest_gate(ctx: &Ctx, p: &mut dyn Process) -> Result<()> {
    let rva = ctx.rva(0x53DC9F5)?;
    let expected = phase_gate(ctx)?;
    verify(p, rva, &expected, "Guest simulation gate does not match verified build")?;
    p.patch(rva, &native_branch(ctx, 0x53DC9F5, 0x53EA3A8, &[0xE9], 6)?)
}

pub struct SpawnBalance {
    pub spawn_clone: u64,
    pub spawn_option: u64,
    pub spawn_scale: u64,
    pub party_xp_buffer: u64,
    pub gold_counter: u64,
}

/// The host's TICK block after the bridge ran: spawn balance, population cap scaling, the party
/// XP bonus on world pickups and the world gold counter.
pub fn install_spawn_balance(ctx: &Ctx, p: &mut dyn Process) -> Result<SpawnBalance> {
    let base = p.base();
    let spawn_clone = p.allocate(ctx.field("game_extent", 0x8D0)? as usize)?;
    let spawn_option = p.allocate(16)?;
    let spawn_scale = p.allocate(8)?;
    // The single-player arena-center clamp defeats split positioning. Bypass it only for our
    // borrowed spawn context. 47e4's spawn search uses a per-map zone table: not installed there.
    if !ctx.is_47e4() {
        let offset = ctx.rva(0x53FF2DF)?;
        let original = ctx.expected_bytes(0x53FF2DF, &hx("f2410f108680000000 0f28ce 0f5cc8"))?;
        verify(p, offset, &original, "Native arena clamp instructions changed")?;
        let mut code = vec![0x50, 0x48, 0xB8];
        code.extend_from_slice(&pack_u64(spawn_clone as i128)?);
        code.extend(hx("4839c7 58 750e"));
        code.extend(absolute_jump(base + ctx.rva(0x53FF322)?));
        code.extend(&original);
        code.extend(absolute_jump(base + offset + original.len() as u64));
        let entry = p.executable_buffer(&code, None)?;
        p.patch(offset, &jump_pad(entry, 1))?;
    }
    // Scale the native population limit by the same bounded Q16 bonus.
    let offset = ctx.rva(0x53FE96D)?;
    let mut wanted = hx("4839d1 0f839e060000");
    wanted.extend(hx("488b8ed8020000"));
    let original = ctx.expected_bytes(0x53FE96D, &wanted)?;
    let cap_load = original[9..].to_vec();
    verify(p, offset, &original, "Native enemy cap instructions changed")?;
    let mut code = vec![0x50, 0x41, 0x52, 0x49, 0xBA];
    code.extend_from_slice(&pack_u64(spawn_scale as i128)?);
    code.extend(hx("4889d0 490faf02 48c1e810 4801c2 415a 58 4839d1 720e"));
    code.extend(absolute_jump(base + ctx.rva(0x53FF014)?));
    code.extend(&cap_load);
    code.extend(absolute_jump(base + offset + original.len() as u64));
    let entry = p.executable_buffer(&code, None)?;
    p.patch(offset, &jump_pad(entry, 2))?;
    let party_xp_buffer = p.allocate(4)?;
    p.put(party_xp_buffer, &1f32.to_le_bytes())?;
    // Both world pickup paths round only after applying the party bonus.
    for (site, raw) in [(0x53F2416u64, "f30f598624050000e8ec792900f3410f5fc5"), (0x53F32A5, "f30f598624050000e85d6b2900f3410f5fc2")] {
        let original = ctx.reviewed_bytes(site, &hx(raw))?;
        let rva = ctx.reviewed_rva(site)?;
        let address = base + rva;
        verify(p, rva, &original, "Native XP pickup instructions changed")?;
        let mut clamp = original[original.len() - 5..].to_vec();
        if original[original.len() - 9..original.len() - 4] == hx("f30f5f05")[..] {
            // 47e4 path A: MAXSS XMM0,[RIP+disp] cannot be copied; use its absolute operand.
            let relative = i32::from_le_bytes(original[original.len() - 4..].try_into().unwrap()) as i128;
            let operand = address as i128 + original.len() as i128 + relative;
            clamp = vec![0x48, 0xB8];
            clamp.extend_from_slice(&pack_u64(operand)?);
            clamp.extend(hx("f30f5f00"));
        }
        let mut code = vec![0x48, 0xB8];
        code.extend_from_slice(&pack_u64(party_xp_buffer as i128)?);
        code.extend(hx("f30f5900 48b8"));
        code.extend_from_slice(&pack_u64(base as i128 + ctx.reviewed_rva(0x5689E0F)? as i128)?);
        code.extend(hx("ffd0"));
        code.extend(clamp);
        code.extend(absolute_jump(address + original.len() as u64));
        let entry = p.executable_buffer(&code, None)?;
        p.patch(rva, &jump_pad(entry, original.len().saturating_sub(14)))?;
    }
    let gold_counter = p.allocate(8)?;
    // Count only world pickup credits. Chest spending and gold selected as a private reward use
    // different native instructions.
    let gold_instructions = hx("8b8eb8040000 01c1 898eb8040000");
    for legacy in [0x53E75EFu64, 0x53E7D9E, 0x53E7ED8] {
        let offset = ctx.rva(legacy)?;
        let original = ctx.expected_bytes(legacy, &gold_instructions)?;
        verify(p, offset, &original, "Native pickup gold instructions changed")?;
        let (mut prefix, mut suffix) = (hx("9c52 48ba"), hx("480102 5a9d"));
        if ctx.is_0843() && legacy != 0x53E75EF {
            prefix = hx("9c5048b8");
            suffix = hx(if legacy == 0x53E7D9E { "480138589d" } else { "480108589d" });
        }
        let mut code = prefix;
        code.extend_from_slice(&pack_u64(gold_counter as i128)?);
        code.extend(suffix);
        code.extend(&original);
        code.extend(absolute_jump(base + offset + original.len() as u64));
        let entry = p.executable_buffer(&code, None)?;
        p.patch(offset, &absolute_jump(entry))?;
    }
    Ok(SpawnBalance { spawn_clone, spawn_option, spawn_scale, party_xp_buffer, gold_counter })
}

/// The guest's TICK block: no second population cap, native DOT timers/damage/leech kept,
/// enemy AI and world spawning skipped, the simulation gate restored.
pub fn install_guest_tick(ctx: &Ctx, p: &mut dyn Process) -> Result<()> {
    let base = p.base();
    // The host already enforces the scaled population limit. Mirrors have a separate bound.
    let rva = ctx.rva(0x53FE970)?;
    let cap_branch = ctx.expected_bytes(0x53FE970, &hx("0f839e060000"))?;
    verify(p, rva, &cap_branch, "Native mirror cap branch changed")?;
    p.patch(rva, &[0x90; 6])?;
    // The native victory branch needs these borrowed Vec addresses even when our guest path
    // skipped the single-player world/loot section.
    let restore_game = if ctx.is_0843() {
        Snip::new(&[P::Raw("4c8ba5"), P::Mem(0x3E0, 4, "rbp"), P::Raw("498d8424"), P::Mem(0x5E8, 4, "r12"), P::Raw("488985"), P::Mem(0x3C8, 4, "rbp")])
            .fields(ctx, "game", &["r12"])?
            .game_frame(ctx)?
            .bytes
    } else {
        // 47e4: Game in R13; only the &Game.vec(0x5E8) slot is read first after 0x5480c07.
        Snip::new(&[P::Raw("4c8bad"), P::Mem(0x3E0, 4, "rbp"), P::Raw("498d85"), P::Mem(0x5E8, 4, "r13"), P::Raw("488985"), P::Mem(0x3C8, 4, "rbp")])
            .fields(ctx, "game", &["r13"])?
            .game_frame(ctx)?
            .bytes
    };
    let mut code = restore_game;
    code.extend(absolute_jump(base + ctx.rva(0x53EA280)?));
    let restore = p.executable_buffer(&code, None)?;
    let patches: [(u64, Vec<u8>, Vec<u8>); 2] = [
        (ctx.rva(0x53E3381)?, ctx.expected_bytes(0x53E3381, &hx("f30f10862c0100000f2ec70f868e000000"))?, jump_pad(base + ctx.rva(0x53E2EB6)?, 3)),
        (ctx.rva(0x53E6B22)?, ctx.expected_bytes(0x53E6B22, &hx("f20f10be980400008b86a0040000"))?, absolute_jump(restore)),
    ];
    for (rva, expected, mut replacement) in patches {
        verify(p, rva, &expected, "Guest effect/world boundary changed")?;
        if replacement.len() < expected.len() {
            replacement.resize(expected.len(), 0x90);
        }
        p.patch(rva, &replacement)?;
    }
    p.patch(ctx.rva(0x53DC9F5)?, &phase_gate(ctx)?)
}
