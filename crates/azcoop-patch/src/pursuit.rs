//! `pursuit_code`: choose the nearer living player at the native enemy's interpolated pose.
//!
//! Only the enemy loop's borrowed target coordinates change; player state stays untouched.
//! XY distance matches the native pursuit calculation.

use crate::{absolute_jump, hx, pack_i32, pack_u32, pack_u64, Ctx, Result, Snip, P};

fn frame(ctx: &Ctx, snip: Snip) -> Result<Vec<u8>> {
    Ok(if ctx.is_47e4() { snip.fields(ctx, "enemy_frame", &["rbp"])? } else { snip.game_frame(ctx)? }.bytes)
}

struct Builder {
    code: Vec<u8>,
    branches: Vec<(usize, String)>,
}

impl Builder {
    fn branch(&mut self, opcode: &str, label: &str) {
        self.code.extend(hx(opcode));
        self.branches.push((self.code.len(), label.to_string()));
        self.code.extend([0u8; 4]);
    }
}

/// `cmp reg, rax`, `cmp reg, rdx` and `mov rdx, reg` for the 64 bit register number `reg` (0..15), as hex.
pub fn cursor_encodings(reg: u8) -> (String, String, String) {
    let (rex_b, rex_r, low) = (0x48 | (reg >> 3), 0x48 | ((reg >> 3) << 2), reg & 7);
    (
        format!("{rex_b:02x}39{:02x}", 0xC0 | low),
        format!("{rex_b:02x}39{:02x}", 0xC0 | (2 << 3) | low),
        format!("{rex_r:02x}89{:02x}", 0xC0 | (low << 3) | 2),
    )
}

/// `movaps xmm1, xmmN`, `movaps xmm0, xmmN` and `subps xmm1, xmmN` for the XMM register number `n` (8..15 with the REX.B prefix), as hex.
pub fn xy_encodings(n: u8) -> (String, String, String) {
    let (prefix, low) = (if n >= 8 { "41" } else { "" }, n & 7);
    (
        format!("{prefix}0f28{:02x}", 0xC0 | (1 << 3) | low),
        format!("{prefix}0f28{:02x}", 0xC0 | low),
        format!("{prefix}0f5c{:02x}", 0xC0 | (1 << 3) | low),
    )
}

/// `pursuit_code(base, guest, guests, game=..., guard=...)`.
pub fn pursuit_code(ctx: &Ctx, base: u64, guest: u64, guests: u32, game_and_guard: Option<(u64, u64)>) -> Result<Vec<u8>> {
    let mut b = Builder { code: hx("52 9c 50 4883ec30 0f110424 0f114c2410 0f11542420"), branches: Vec::new() };
    let v47 = ctx.is_47e4();
    let v7264 = ctx.is_7264();
    // The enemy cursor register and the XMM with the interpolated enemy xy differ per build (0.95.0: R12 / XMM15, 0.97.1: RDI / XMM13).
    let registers = ctx.variant.pursuit_registers();
    let (cursor_cmp_rax, cursor_cmp_rdx, cursor_to_rdx) = cursor_encodings(registers.cursor);
    let (xy_to_xmm1, xy_to_xmm0, xy_sub_xmm1) = xy_encodings(registers.xy);
    let stride = ctx.variant.enemy_layout().stride;
    if let Some((game, guard)) = game_and_guard {
        // Validate ownership before reading Game, then validate the native Enemy cursor without
        // dereferencing it. Failure preserves the native path and is reported on the next batch.
        b.code.extend(frame(ctx, Snip::new(&[P::Raw("488b85"), P::Mem(0x3E0, 4, "rbp")]))?);
        b.code.extend([0x48, 0xBA]);
        b.code.extend_from_slice(&pack_u64(game as i128)?);
        b.code.extend(hx("4839d0"));
        b.branch("0f85", "guard_failed");
        b.code.extend(hx(if v47 { "660f7ef2" } else { "660f7efa" }));
        b.code.extend([0x3B, 0x90]);
        b.code.extend_from_slice(&pack_u32(ctx.game_field(0x85C)? as i128)?);
        b.branch("0f85", "guard_failed");
        b.code.extend(hx("81e20000807f81fa0000807f"));
        b.branch("0f84", "guard_failed");
        b.code.extend(hx(if v47 {
            "66440f7ec285d2"
        } else if ctx.is_0843() {
            "66440f7eea85d2"
        } else {
            "66440f7ef285d2"
        })); // Native interpolation threshold is +0.0 in XMM14.
        b.branch("0f85", "guard_failed");
        let pointer = ctx.game_field(0x568)?;
        b.code.extend([0x48, 0x8B, 0x90]);
        b.code.extend_from_slice(&pack_u32(pointer as i128 + 8)?);
        b.code.extend(hx("4881fab80b0000"));
        b.branch("0f87", "guard_failed");
        b.code.extend(hx("4869d2"));
        b.code.extend_from_slice(&pack_u32(stride as i128)?);
        b.code.extend([0x48, 0x8B, 0x80]);
        b.code.extend_from_slice(&pack_u32(pointer as i128)?);
        b.code.extend(hx(&cursor_cmp_rax));
        b.branch("0f82", "guard_failed");
        b.code.extend(hx("4801c2"));
        b.branch("0f82", "guard_failed");
        b.code.extend(hx(&cursor_cmp_rdx));
        b.branch("0f83", "guard_failed");
        b.code.extend(hx(&format!("{cursor_to_rdx}4829c24889d031d251b9")));
        b.code.extend_from_slice(&pack_u32(stride as i128)?);
        b.code.extend(hx("48f7f1594885d2"));
        b.branch("0f85", "guard_failed");
        // Reject NaN/infinity in either native interpolated XY lane.
        b.code.extend([0x48, 0xB8]);
        b.code.extend_from_slice(&pack_u64(0x7F8000007F800000)?);
        b.code.extend(hx(&format!("66480f6ec0{xy_to_xmm1}0f54c8660f76c80f50d1f6c203")));
        b.branch("0f85", "guard_failed");
        b.code.extend([0x48, 0xB8]);
        b.code.extend_from_slice(&pack_u64(guard as i128)?);
        b.code.extend(hx("48ff4008"));
    }
    // Reset the loop's target to the host before selecting for this enemy.
    let reset = Snip::new(&[
        P::Raw("488b85"),
        P::Mem(0x3E0, 4, "rbp"),
        P::Raw("f20f1080"),
        P::Mem(0x498, 4, "rax"),
        P::Raw("0f2985"),
        P::Mem(0xD0, 4, "rbp"),
        P::Raw("f30f1080"),
        P::Mem(0x4A0, 4, "rax"),
        P::Raw("f30f1185"),
        P::Mem(0x2E4, 4, "rbp"),
    ])
    .fields(ctx, "game", &["rax"])?;
    b.code.extend(frame(ctx, reset)?);
    b.code.extend(frame(ctx, Snip::new(&[P::Raw("488b95"), P::Mem(0x3E0, 4, "rbp")]))?);
    b.code.extend(Snip::new(&[P::Raw("80ba"), P::Mem(0x8CF, 4, "rdx"), P::Raw("04")]).fields(ctx, "game", &["rdx"])?.bytes);
    // Dead host contributes infinite distance; all living guests are compared.
    b.code.extend(frame(ctx, Snip::new(&[P::Raw("7516 48b80000807f0000807f 66480f6ec0 0f2985"), P::Mem(0xD0, 4, "rbp")]))?);
    let mut labels = std::collections::BTreeMap::new();
    for index in 0..guests {
        let skip = format!("next_{index}");
        b.code.extend([0x48, 0xB8]);
        b.code.extend_from_slice(&pack_u64(guest as i128 + index as i128 * 16)?);
        b.code.extend(hx("80780c01"));
        b.branch("0f85", &skip);
        b.code.extend(frame(ctx, Snip::new(&[P::Raw(&format!("{xy_to_xmm0}0f5c85")), P::Mem(0xD0, 4, "rbp"), P::Raw("0f59c0 f30f16d0 f30f58c2")]))?);
        b.code.extend(hx(&format!("f20f1008{xy_sub_xmm1}0f59c9 f30f16d1 f30f58ca 0f2fc1")));
        b.branch("0f86", &skip);
        b.code.extend(frame(
            ctx,
            Snip::new(&[P::Raw("f20f1000 0f2985"), P::Mem(0xD0, 4, "rbp"), P::Raw("f30f104008 f30f1185"), P::Mem(0x2E4, 4, "rbp")]),
        )?);
        labels.insert(skip, b.code.len());
    }
    if let Some((_, guard)) = game_and_guard {
        b.branch("e9", "done");
        labels.insert("guard_failed".to_string(), b.code.len());
        b.code.extend([0x48, 0xB8]);
        b.code.extend_from_slice(&pack_u64(guard as i128)?);
        b.code.extend(hx("48c70001000000"));
    }
    labels.insert("done".to_string(), b.code.len());
    b.code.extend(hx("0f100424 0f104c2410 0f10542420 4883c430 58 9d 5a"));
    b.code.extend(ctx.expected_bytes(0x53E370A, &hx("450f28cf 440f5c8dd0000000 f3450f16e9"))?);
    b.code.extend(absolute_jump(base + ctx.rva(0x53E371B)?));
    for (offset, label) in &b.branches {
        let target = labels[label] as i128;
        let value = pack_i32(target - *offset as i128 - 4)?;
        b.code[*offset..*offset + 4].copy_from_slice(&value);
    }
    Ok(b.code)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The encodings that used to be written out by hand per build.
    #[test]
    fn the_register_encodings_equal_the_hand_written_ones() {
        let hand = [
            (6u8, ("4839c6", "4839d6", "4889f2")),   // 0.84.3: RSI
            (15, ("4939c7", "4939d7", "4c89fa")),    // 0.93.1: R15
            (12, ("4939c4", "4939d4", "4c89e2")),    // 0.95.0: R12
            (7, ("4839c7", "4839d7", "4889fa")),     // 0.97.1: RDI
        ];
        for (reg, (a, b, c)) in hand {
            assert_eq!(cursor_encodings(reg), (a.to_string(), b.to_string(), c.to_string()), "register {reg}");
        }
        let xy = [(15u8, ("410f28cf", "410f28c7", "410f5ccf")), (12, ("410f28cc", "410f28c4", "410f5ccc")), (13, ("410f28cd", "410f28c5", "410f5ccd")), (7, ("0f28cf", "0f28c7", "0f5ccf"))];
        for (n, (a, b, c)) in xy {
            assert_eq!(xy_encodings(n), (a.to_string(), b.to_string(), c.to_string()), "xmm{n}");
        }
    }
}
