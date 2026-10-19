//! `guest_damage_patches()`: apply guest damage without the host's conditional
//! bonuses, healing and procs. The patches exist only during the injected DAMAGE call.

use crate::{hx, pack_i32, Ctx, Result};

/// (rva, original bytes, replacement bytes)
pub type Patch = (u64, Vec<u8>, Vec<u8>);

fn padded(mut replacement: Vec<u8>, length: usize) -> Vec<u8> {
    if replacement.len() < length {
        replacement.resize(length, 0x90);
    }
    replacement
}

pub fn guest_damage_patches(ctx: &Ctx) -> Result<Vec<Patch>> {
    let jump = |source: u64, target: u64, size: usize| ctx.reviewed_branch(source, target, &[0xE9], size);
    let concat = |a: Vec<u8>, b: Vec<u8>| -> Vec<u8> { a.into_iter().chain(b).collect() };
    let rows: Vec<(u64, Vec<u8>, Vec<u8>)> = if ctx.is_47e4() {
        // 47e4 DAMAGE.
        vec![
            // Personal meter is the call 0x54c4900 with a borrowed label: skip only that call.
            (0x540B73A, hx("4c8ba6800600004889b578010000"), jump(0x540B741, 0x540B79D, 5)?),
            (0x540B15F, hx("f3440f59de"), hx("440f28c690")),
            // Class heal/leech factor and heal: XMM12 = 0, continue at its JBE target.
            (0x540BA5C, hx("0fb6824c03000004fe"), concat(hx("450f57e4"), jump(0x540BA60, 0x540BDD7, 5)?)),
            (0x540C2C7, hx("f30f108844050000"), hx("450f57e4")),
            (0x540CFAC, hx("488b8660030000488b8e68030000"), jump(0x540CFAC, 0x540E318, 5)?),
        ]
    } else {
        vec![
            (0x540B73A, hx("4c8ba6800600004889b578010000"), concat(hx("4889b578010000"), jump(0x540B741, 0x540B79D, 7)?)),
            (0x540B15F, hx("f3440f59de"), hx("440f28de90")),
            (0x540BA5C, hx("0fb6824c03000004fe"), concat(hx("450f57e4"), jump(0x540BA60, 0x540BDD7, 5)?)),
            (0x540C2C7, hx("f30f108844050000"), concat(hx("0f57c9"), vec![0x90; 5])),
            (0x540CFAC, hx("488b8660030000488b8e68030000"), jump(0x540CFAC, 0x540E318, 14)?),
        ]
    };
    let mut out = Vec::new();
    for (address, original, replacement) in rows {
        let actual = ctx.reviewed_bytes(address, &original)?;
        let length = actual.len();
        out.push((ctx.reviewed_rva(address)?, actual, padded(replacement, length)));
    }
    if ctx.is_47e4() {
        // The family added a second meter call before the boss meter: the run meter
        // (Game+0x5C8) counted injected guest hits on the host's meter as "Melee".
        let [start, resume, meter] = ctx.family()?.run_meter;
        // lea rcx,[rsi+<run meter field>]; mov rdx,r15; movaps xmm2,xmm7; call <meter>. The field moves with the Game layout
        // (0x5C8 up to 0.99.0, 0x5E0 in 0.100.1): every other byte is checked, the displacement is the build's own.
        let mut run_meter = hx("488d8ec80500004c89fa0f28d7e8");
        run_meter.extend_from_slice(&pack_i32(meter as i128 - resume as i128)?);
        if run_meter.len() as u64 != resume - start {
            return Err("Run meter call span changed".into());
        }
        let own = ctx.image.bytes(start, run_meter.len())?;
        let field = u32::from_le_bytes(own.get(3..7).ok_or("Run meter call span changed")?.try_into().unwrap());
        if own[..3] != run_meter[..3] || own[7..] != run_meter[7..] || !(0x400..0x900).contains(&field) {
            return Err("Run meter call span changed".into());
        }
        run_meter[3..7].copy_from_slice(&field.to_le_bytes());
        let skip = resume - start - 2;
        let mut replacement = vec![0xEB, u8::try_from(skip).map_err(|_| "byte must be in range(0, 256)".to_string())?];
        replacement.extend(vec![0x90; skip as usize]);
        out.push((start, run_meter, replacement));
    }
    Ok(out)
}
