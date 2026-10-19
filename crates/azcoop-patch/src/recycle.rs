//! The recycle-distance filter replacement (`recycle_distance_*`) and `rbp_operand`.

use crate::{absolute_jump, hx, pack_i32, pack_u64, Result};

fn rr(dst: u8, src: u8) -> u8 {
    0xC0 | dst << 3 | src
}

/// `prefix + ModRM [rbp+disp]` (disp8 when it fits, else disp32) for register field `reg`.
pub fn rbp_operand(prefix: &[u8], reg: u8, disp: i64) -> Result<Vec<u8>> {
    let mut out = prefix.to_vec();
    if (-128..128).contains(&disp) {
        out.push(0x45 | reg << 3);
        out.push(disp as i8 as u8);
    } else {
        out.push(0x85 | reg << 3);
        out.extend_from_slice(&pack_i32(disp as i128)?);
    }
    Ok(out)
}

/// 0.92 recycle filter test without its JA.
pub fn recycle_distance_original(position: u8, scratch: u8) -> Vec<u8> {
    let mut out = hx("f2410f10");
    out.extend([0x45 | scratch << 3, 0x00, 0x0F, 0x5C, rr(position, scratch), 0x0F, 0x59, rr(position, position)]);
    out.extend([0xF3, 0x0F, 0x16, rr(scratch, position), 0xF3, 0x0F, 0x58, rr(scratch, position), 0x0F, 0x2E, rr(scratch, 7)]);
    out
}

/// Squared XY distance from the enemy to the nearest of host ([r13]) and living guests; JA select else resume.
pub fn recycle_distance_code(table: u64, guests: u32, position: u8, scratch: u8, temp: u8, select: u64, resume: u64) -> Result<Vec<u8>> {
    let distance_into = |dst: Option<u8>| -> Vec<u8> {
        let mut out = vec![0x0F, 0x5C, rr(temp, position), 0x0F, 0x59, rr(temp, temp), 0xF2, 0x0F, 0x7C, rr(temp, temp)];
        match dst {
            Some(d) if d == scratch => out.extend([0x0F, 0x28, rr(d, temp)]),
            _ => out.extend([0xF3, 0x0F, 0x5D, rr(scratch, temp)]),
        }
        out
    };
    let mut code = hx("f2410f10");
    code.extend([0x45 | temp << 3, 0x00]); // movsd T,[r13] (host XY)
    code.extend(distance_into(Some(scratch)));
    code.extend([0x50, 0x48, 0xB8]); // push rax; mov rax,table
    code.extend_from_slice(&pack_u64(table as i128)?);
    for index in 0..guests {
        let offset = index.checked_mul(16).filter(|o| *o < 256).ok_or("byte must be in range(0, 256)")? as u8;
        let mut step = vec![0xF2, 0x0F, 0x10, 0x40 | temp << 3, offset];
        step.extend(distance_into(None));
        let alive = offset.checked_add(12).ok_or("byte must be in range(0, 256)")?;
        let skip = u8::try_from(step.len()).map_err(|_| "byte must be in range(0, 256)".to_string())?;
        code.extend([0x80, 0x78, alive, 0x01, 0x75, skip]); // alive flag == 1
        code.extend(step);
    }
    code.extend([0x58, 0x0F, 0x2E, rr(scratch, 7)]); // pop rax; ucomiss S,xmm7
    code.extend([0x76, 0x0E]);
    code.extend(absolute_jump(select));
    code.extend(absolute_jump(resume));
    Ok(code)
}
