//! `dispatch_guard_code` and `install_dispatch_guards`: preserve a valid native table
//! dispatch, trap before an out-of-domain lookup.

use crate::{absolute_jump, hx, pack_i32, pack_u64, Ctx, Result};
use azcoop_game::profile::DispatchGuard;

pub fn dispatch_guard_code(ctx: &Ctx, base: u64, contract: &DispatchGuard) -> Result<Vec<u8>> {
    let expected = &contract.expected;
    let bad_cast = || "Unrecognized guarded native cast dispatch".to_string();
    let bad_loot = || "Unrecognized guarded native loot dispatch".to_string();
    let table = pack_u64(base as i128 + contract.table_rva as i128)?;
    let mut code;
    match (contract.kind.as_str(), ctx.is_47e4()) {
        ("cast_tag", true) | ("cast_tag", false) => {
            let (head, tail, mov) = if ctx.is_47e4() {
                ("89d24c8d05", "496314904c01c2", "89d2 49b8")
            } else if ctx.is_0843() {
                ("89d24c8d0d", "496314914c01ca", "89d2 49b9")
            } else {
                ("89d24c8d15", "496314924c01d2", "89d2 49ba")
            };
            let relative = i32::from_le_bytes(expected.get(5..9).ok_or_else(bad_cast)?.try_into().unwrap()) as i128;
            if contract.maximum != 4
                || expected.len() != 16
                || expected[..5] != hx(head)[..]
                || expected[9..] != hx(tail)[..]
                || contract.rva as i128 + 9 + relative != contract.table_rva as i128
                || contract.continuation_rva != contract.rva + 16
            {
                return Err(bad_cast());
            }
            let mut body = hx(mov);
            body.extend_from_slice(&table);
            body.extend_from_slice(&expected[9..]);
            body.extend(absolute_jump(base + contract.continuation_rva));
            code = hx("83fa04 0f87");
            code.extend_from_slice(&pack_i32(body.len() as i128)?);
            code.extend(body);
        }
        ("loot_tag", _) => {
            let (wanted, compare, cmp_index) = if ctx.is_47e4() {
                ("89d8 4963448500 4c01e8 ffe0", "4939c5", "83fb06 0f87")
            } else {
                ("89f8 49630484 4c01e0 ffe0", "4939c4", "83ff06 0f87")
            };
            if contract.maximum != 6 || expected[..] != hx(wanted)[..] {
                return Err(bad_loot());
            }
            let mut table_check = vec![0x48, 0xB8];
            table_check.extend_from_slice(&table);
            table_check.extend(hx(compare));
            code = hx(cmp_index);
            code.extend_from_slice(&pack_i32((table_check.len() + 6 + expected.len()) as i128)?);
            code.extend(table_check);
            code.extend(hx("0f85"));
            code.extend_from_slice(&pack_i32(expected.len() as i128)?);
            code.extend_from_slice(expected);
        }
        _ => return Err("Unknown native dispatch guard kind".into()),
    }
    code.extend([0x0F, 0x0B]); // A debugger-visible fatal invariant failure.
    Ok(code)
}

/// One guard to install: the caller checks the live bytes at `base + rva` against `expected`,
/// allocates the code (near the site when `near_site`) and writes `replacement(entry)`.
#[derive(Debug, Clone, PartialEq)]
pub struct GuardInstall {
    pub kind: String,
    pub rva: u64,
    pub expected: Vec<u8>,
    pub code: Vec<u8>,
    pub near_site: bool,
}

impl GuardInstall {
    pub fn replacement(&self, base: u64, entry: u64) -> Result<Vec<u8>> {
        let site = base + self.rva;
        let length = self.expected.len();
        if self.kind == "cast_tag" {
            let mut out = absolute_jump(entry);
            out.resize(out.len() + length.saturating_sub(14), 0x90);
            Ok(out)
        } else if length < 12 {
            let mut out = vec![0xE9];
            out.extend_from_slice(&pack_i32(entry as i128 - site as i128 - 5)?);
            out.resize(out.len() + length.saturating_sub(5), 0x90);
            Ok(out)
        } else {
            let mut out = vec![0x48, 0xB8];
            out.extend_from_slice(&pack_u64(entry as i128)?);
            out.extend([0xFF, 0xE0]);
            Ok(out)
        }
    }

    /// The `ud2` the guard falls into when the table index is out of domain.
    pub fn trap(&self, entry: u64) -> u64 {
        entry + self.code.len() as u64 - 2
    }
}

pub fn dispatch_guard_installs(ctx: &Ctx, base: u64) -> Result<Vec<GuardInstall>> {
    let mut out = Vec::new();
    for contract in &ctx.profile.dispatch_guards {
        if !contract.mandatory_runtime_guard {
            return Err("Native dispatch contract lacks mandatory guard".into());
        }
        out.push(GuardInstall {
            kind: contract.kind.clone(),
            rva: contract.rva,
            expected: contract.expected.clone(),
            code: dispatch_guard_code(ctx, base, contract)?,
            near_site: contract.expected.len() < 12,
        });
    }
    Ok(out)
}
