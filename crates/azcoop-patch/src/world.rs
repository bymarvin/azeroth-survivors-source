//! Tick continuation code while the host is down, and its helpers:
//! `world_containers_code`, `native_constants_code`, `downed_world_code`, `downed_hazards_code`.

use crate::{absolute_jump, hx, pack_i32, pack_u32, pack_u64, Ctx, Result, Snip, P};

/// The four borrowed container addresses that normally come from player work.
pub fn world_containers_code(ctx: &Ctx) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    if ctx.is_47e4() {
        // Slots read first after the skipped region (liveness, validated on 0.84.3).
        let slots = ctx.family()?.world_slots;
        for (member, slot) in [0x5E8i64, 0x840, 0x818].into_iter().zip(slots) {
            out.extend(hx("498d85"));
            out.extend_from_slice(&pack_u32(ctx.field("game", member)? as i128)?);
            out.extend(hx("488985"));
            out.extend_from_slice(&pack_u32(slot as i128)?);
        }
        return Ok(out);
    }
    for (member, slot) in [(0x5E8i64, 0x3C8i64), (0x5A0, 0x120), (0x840, 0x188), (0x588, 0x2E8)] {
        out.extend(if ctx.is_0843() { hx("498d8424") } else { hx("498d85") });
        out.extend_from_slice(&pack_u32(ctx.field("game", member)? as i128)?);
        out.extend(hx("488985"));
        out.extend_from_slice(&pack_u32(ctx.field("game_update_frame", slot)? as i128)?);
    }
    Ok(out)
}

/// Frame locals holding `&Game.<field>` that the skipped native region would set (`Family::skipped_pointer_locals` of this skip):
/// `lea rax,[r13+field]; mov [rbp+slot],rax` each. Empty for builds without such a local.
pub fn pointer_locals_code(ctx: &Ctx, skip: i64) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    if !ctx.is_47e4() {
        return Ok(out);
    }
    for &[s, slot, field] in ctx.family()?.skipped_pointer_locals {
        if s != skip {
            continue;
        }
        out.extend(hx("498d85"));
        out.extend_from_slice(&pack_u32(ctx.field("game", field)? as i128)?);
        out.extend(hx("488985"));
        out.extend_from_slice(&pack_u32(slot as i128)?);
    }
    Ok(out)
}

/// Register constants normally loaded by the skipped native region.
pub fn native_constants_code(ctx: &Ctx, base: u64) -> Result<Vec<u8>> {
    let mut out = vec![0x48, 0xB8];
    out.extend_from_slice(&pack_u64(base as i128 + ctx.rva(0x5809A24)? as i128)?);
    if ctx.is_47e4() {
        // 47e4 loads the same constant into XMM13 and zeroes XMM15.
        out.extend(hx("f3440f1028"));
        out.extend(hx("450f57ff"));
    } else {
        out.extend(hx("f3440f1038"));
    }
    Ok(out)
}

/// Build-specific tick continuation: a dead host skips only its player actions.
pub fn downed_world_code(ctx: &Ctx, base: u64, enabled: u64) -> Result<Vec<u8>> {
    let hud = absolute_jump(base + ctx.rva(0x53EA3A8)?);
    let clock: Vec<u8> = if ctx.is_47e4() {
        // dt stays in XMM6 for the whole update (movaps xmm6,xmm1 at entry); no frame slot.
        Snip::new(&[P::Raw("f3410f10bd"), P::Mem(0x86C, 4, "r13"), P::Raw("f30f58fe f3410f11bd"), P::Mem(0x86C, 4, "r13")]).fields(ctx, "game", &["r13"])?.bytes
    } else if ctx.is_0843() {
        Snip::new(&[P::Raw("f3410f10bc24"), P::Mem(0x86C, 4, "r12"), P::Raw("f30f58bd"), P::Mem(0x340, 4, "rbp"), P::Raw("f3410f11bc24"), P::Mem(0x86C, 4, "r12")])
            .fields(ctx, "game", &["r12"])?
            .game_frame(ctx)?
            .bytes
    } else {
        Snip::new(&[P::Raw("f3410f10bd"), P::Mem(0x86C, 4, "r13"), P::Raw("f30f58bd"), P::Mem(0x340, 4, "rbp"), P::Raw("f3410f11bd"), P::Mem(0x86C, 4, "r13")])
            .fields(ctx, "game", &["r13"])?
            .game_frame(ctx)?
            .bytes
    };
    // The normal path is selected from the original CMP phase,1 flags.
    let mut normal = clock[..if ctx.is_0843() { 10 } else { 9 }].to_vec();
    normal.extend(absolute_jump(base + ctx.rva(0x53DCA04)?));
    let constant = native_constants_code(ctx, base)?;
    let containers = world_containers_code(ctx)?;
    let mut dead = hx("3c04740e");
    dead.extend(&hud);
    dead.extend([0x48, 0xB8]);
    dead.extend_from_slice(&pack_u64(enabled as i128)?);
    dead.extend(hx("80380174 0e"));
    dead.extend(&hud);
    dead.extend(&clock);
    dead.extend(&constant);
    dead.extend(&containers);
    dead.extend(pointer_locals_code(ctx, 0)?);
    dead.extend(absolute_jump(base + ctx.rva(0x53E1254)?));
    let mut out = vec![0x0F, 0x84];
    out.extend_from_slice(&pack_i32(dead.len() as i128)?);
    out.extend(dead);
    out.extend(normal);
    Ok(out)
}

/// Continue projectile/ground expiry while down, then skip owner-only totems.
pub fn downed_hazards_code(ctx: &Ctx, base: u64) -> Result<Vec<u8>> {
    let original: Vec<u8> = if ctx.is_47e4() {
        // 16 position-independent bytes (movss xmm8,[r13+G]; lea rax,[r13+G]) from the profile.
        ctx.expected_bytes(0x53E1B4E, &hx("498d8588050000 488985e8020000"))?
    } else if ctx.is_0843() {
        Snip::new(&[P::Raw("498d8424"), P::Mem(0x588, 4, "r12"), P::Raw("488985"), P::Mem(0x2E8, 4, "rbp")]).fields(ctx, "game", &["r12"])?.game_frame(ctx)?.bytes
    } else {
        Snip::new(&[P::Raw("498d85"), P::Mem(0x588, 4, "r13"), P::Raw("488985"), P::Mem(0x2E8, 4, "rbp")]).fields(ctx, "game", &["r13"])?.game_frame(ctx)?.bytes
    };
    let mut normal = original;
    normal.extend(absolute_jump(base + ctx.rva(0x53E1B5C)?));
    let constant = native_constants_code(ctx, base)?;
    let phase_test = if ctx.is_0843() {
        Snip::new(&[P::Raw("4180bc24"), P::Mem(0x8CF, 4, "r12"), P::Raw("04")]).fields(ctx, "game", &["r12"])?.bytes
    } else {
        Snip::new(&[P::Raw("4180bd"), P::Mem(0x8CF, 4, "r13"), P::Raw("04")]).fields(ctx, "game", &["r13"])?.bytes
    };
    let mut out = phase_test;
    out.extend([0x0F, 0x84]);
    out.extend_from_slice(&pack_i32(normal.len() as i128)?);
    out.extend(normal);
    out.extend(world_containers_code(ctx)?);
    out.extend(pointer_locals_code(ctx, 1)?);
    out.extend(constant);
    out.extend(absolute_jump(base + ctx.rva(0x53E2C7B)?));
    Ok(out)
}
