//! Generated native entries: the team-defeat screen (`defeat_ui_code`, native_probe.py) and
//! the per-character boss gear roll (`reward_code`, boss_rewards.py).

use crate::{hx, pack_i32, pack_u32, pack_u64, Ctx, Result, Snip};

fn call(base: u64, rva: u64) -> Result<Vec<u8>> {
    let mut out = vec![0x48, 0xB8];
    out.extend_from_slice(&pack_u64(base as i128 + rva as i128)?);
    out.extend([0xFF, 0xD0]);
    Ok(out)
}

/// Use native result serialization and native Vec allocation/ownership.
pub fn defeat_ui_code(ctx: &Ctx, base: u64) -> Result<Vec<u8>> {
    let defeat_ui = ctx.profile.hooks.get("DEFEAT_UI").ok_or("profile has no DEFEAT_UI hook")?.rva;
    let mut code = hx("53 57 4883ec48 4889cb 488d4c2430 4889da");
    code.extend([0x49, 0xB8]);
    code.extend_from_slice(&pack_u64(base as i128 + ctx.rva(0x6622698)? as i128)?);
    code.extend(hx("41b906000000"));
    code.extend(call(base, defeat_ui)?);
    let (length, capacity, pointer) = (ctx.field("game", 0x610)?, ctx.field("game", 0x600)?, ctx.field("game", 0x608)?);
    code.extend([0x48, 0x8B, 0xBB]);
    code.extend_from_slice(&pack_u32(length as i128)?);
    code.extend([0x48, 0x3B, 0xBB]);
    code.extend_from_slice(&pack_u32(capacity as i128)?);
    let mut reserve = vec![0x48, 0x8D, 0x8B];
    reserve.extend_from_slice(&pack_u32(capacity as i128)?);
    reserve.extend(call(base, ctx.rva(0x566ED90)?)?);
    code.push(0x75);
    code.push(u8::try_from(reserve.len()).map_err(|_| "byte must be in range(0, 256)".to_string())?);
    code.extend(reserve);
    code.extend([0x48, 0x8B, 0x83]);
    code.extend_from_slice(&pack_u32(pointer as i128)?);
    code.extend(hx("488d0c7f 0f10442430 0f1104c8"));
    code.extend(hx("488b542440 488954c810 48ffc7 4889bb"));
    code.extend_from_slice(&pack_u32(length as i128)?);
    code.extend(hx("4883c448 5f 5b c3"));
    Ok(code)
}

const DIFFICULTY: u64 = 0x53B1DD0;
const LOOT_TABLE: u64 = 0x53D0380;
const RESERVE_REWARDS: u64 = 0x568DE90;
const FREE: u64 = 0x21D0;

/// Windows x64 `void(game*, (map_index << 8) | boss_index)`.
pub fn reward_code(ctx: &Ctx, base: u64) -> Result<Vec<u8>> {
    let mut a = Snip::default();
    let mut labels = std::collections::BTreeMap::new();
    let mut fixups: Vec<(usize, &'static str)> = Vec::new();
    macro_rules! call {
        ($rva:expr) => {{
            a.raw("48 b8");
            a.bytes.extend_from_slice(&pack_u64(base as i128 + ctx.reviewed_rva($rva)? as i128)?);
            a.raw("ff d0");
        }};
    }
    macro_rules! branch {
        ($op:expr, $label:expr) => {{
            a.raw($op);
            fixups.push((a.bytes.len(), $label));
            a.bytes.extend([0u8; 4]);
        }};
    }
    // Seven nonvolatile pushes align RSP; 60h includes shadow space and locals.
    a.raw("53 56 57 41 54 41 55 41 56 41 57 48 83 ec 60");
    a.raw("0f 29 74 24 40 48 89 ce 49 89 d7");
    a.raw("ff 86").mem(0x6DC, 4, "rsi").raw("80 be").mem(0x8C9, 4, "rsi").raw("00");
    branch!("0f 85", "done"); // Native run rule disables gear, but still counts kills.
    a.raw("48 8d 8e").mem(0x2F8, 4, "rsi");
    call!(DIFFICULTY);
    a.raw("0f 28 f0 4d 89 f8 49 c1 e8 08 45 0f b6 cf");
    a.raw("0f b6 96").mem(0x34C, 4, "rsi").raw("48 8d 4c 24 20");
    call!(LOOT_TABLE);
    a.raw("48 8b 7c 24 28 4c 8b 74 24 30 4e 8d 34 f7");
    a.raw("4c 8d a6").mem(0x648, 4, "rsi").raw("c7 44 24 50 00 00 80 33");
    labels.insert("loop", a.bytes.len());
    a.raw("4c 39 f7");
    branch!("0f 84", "free");
    a.raw("44 8b 2f f3 0f 10 47 04");
    // Exact xoshiro256++ state transition and high-24-bit f32 conversion from native
    // 540CBEE..540CC50, using RSI=game. Never seed/copy host RNG here.
    a.raw("48 8b 86").mem(0x830, 4, "rsi").raw("48 8b 8e").mem(0x818, 4, "rsi").raw("48 8b 96").mem(0x820, 4, "rsi");
    a.raw("4c 8d 04 08 49 c1 c0 17 49 01 c8 49 89 d1 49 c1 e1 11");
    a.raw("4c 8b 96").mem(0x828, 4, "rsi").raw("49 31 ca 48 31 d0 4c 31 d2");
    a.raw("48 89 96").mem(0x820, 4, "rsi").raw("48 31 c1 48 89 8e").mem(0x818, 4, "rsi");
    a.raw("4d 31 ca 48 c1 c0 2d 49 c1 e8 28 0f 57 c9 f3 41 0f 2a c8");
    a.raw("4c 89 96").mem(0x828, 4, "rsi").raw("48 89 86").mem(0x830, 4, "rsi");
    a.raw("f3 0f 58 86").mem(0x2D0, 4, "rsi").raw("f3 0f 59 4c 24 50 f3 0f 59 c6 0f 2e c1");
    branch!("0f 86", "next"); // Native strictly-greater chance test, including NaN.
    a.raw("48 8b 9e").mem(0x658, 4, "rsi").raw("48 3b 9e").mem(0x648, 4, "rsi");
    branch!("0f 85", "append");
    a.raw("4c 89 e1");
    call!(RESERVE_REWARDS);
    labels.insert("append", a.bytes.len());
    a.raw("48 8b 86").mem(0x650, 4, "rsi").raw("44 89 2c 98 48 ff c3 48 89 9e").mem(0x658, 4, "rsi");
    labels.insert("next", a.bytes.len());
    a.raw("48 83 c7 08");
    branch!("e9", "loop");
    labels.insert("free", a.bytes.len());
    a.raw("48 8b 54 24 20 48 85 d2");
    branch!("0f 84", "done");
    a.raw("48 c1 e2 03 48 8b 4c 24 28 41 b8 04 00 00 00");
    call!(FREE);
    labels.insert("done", a.bytes.len());
    a.raw("0f 28 74 24 40 48 83 c4 60 41 5f 41 5e 41 5d 41 5c 5f 5e 5b c3");
    for (offset, label) in fixups {
        let value = pack_i32(labels[label] as i128 - offset as i128 - 4)?;
        a.bytes[offset..offset + 4].copy_from_slice(&value);
    }
    Ok(a.fields(ctx, "game", &["rsi"])?.bytes)
}
