//! The register context of a hook event, addressed by the offsets of the Windows x64 CONTEXT
//! the Python debugger used (`q(context, 128)` is RCX, `q(context, 152)` RSP, ...), so ported
//! code reads like the original.

pub const RAX: usize = 120;
pub const RCX: usize = 128;
pub const RDX: usize = 136;
pub const RBX: usize = 144;
pub const RSP: usize = 152;
pub const RBP: usize = 160;
pub const RSI: usize = 168;
pub const RDI: usize = 176;
pub const R8: usize = 184;
pub const R9: usize = 192;
pub const R10: usize = 200;
pub const R11: usize = 208;
pub const R12: usize = 216;
pub const R13: usize = 224;
pub const R14: usize = 232;
pub const R15: usize = 240;
pub const RIP: usize = 248;
/// EFlags (a 32-bit field) sits at 68 of the CONTEXT.
pub const EFLAGS: usize = 68;
/// XMM0 sits at 416; each register is 16 bytes.
pub const XMM0: usize = 416;

#[derive(Debug, Clone, PartialEq)]
pub struct Regs {
    gp: [u64; 17],
    eflags: u32,
    pub xmm: [[u8; 16]; 16],
}

impl Default for Regs {
    fn default() -> Regs {
        Regs { gp: [0; 17], eflags: 0, xmm: [[0; 16]; 16] }
    }
}

impl Regs {
    fn index(offset: usize) -> usize {
        assert!((RAX..=RIP).contains(&offset) && (offset - RAX) % 8 == 0, "not a general register offset: {offset}");
        (offset - RAX) / 8
    }

    /// `q(context, offset)`
    pub fn q(&self, offset: usize) -> u64 {
        self.gp[Regs::index(offset)]
    }

    pub fn set_q(&mut self, offset: usize, value: u64) {
        self.gp[Regs::index(offset)] = value;
    }

    /// The low float of XMM `n` (`struct.unpack_from('<f', context, 416 + 16 * n)`).
    pub fn xmm_f32(&self, n: usize) -> f32 {
        f32::from_le_bytes(self.xmm[n][..4].try_into().unwrap())
    }

    pub fn set_xmm_f32(&mut self, n: usize, value: f32) {
        self.xmm[n][..4].copy_from_slice(&value.to_le_bytes());
    }

    /// `struct.pack_into('<Q', context, RIP, [rsp]); struct.pack_into('<Q', context, RSP, rsp + 8)` — return
    /// from the hooked function without running it. The caller supplies the return address read at `[rsp]`.
    pub fn skip_with(&mut self, return_address: u64) {
        let stack = self.q(RSP);
        self.set_q(RIP, return_address);
        self.set_q(RSP, stack + 8);
    }

    pub fn eflags(&self) -> u32 {
        self.eflags
    }

    pub fn set_eflags(&mut self, value: u32) {
        self.eflags = value;
    }

    pub fn general(&self) -> &[u64; 17] {
        &self.gp
    }
}

/// Size of a Windows x64 CONTEXT.
pub const CONTEXT_SIZE: usize = 1232;

impl Regs {
    /// Reads the registers out of a raw x64 CONTEXT (the layout the Python debugger exposed).
    pub fn from_context(context: &[u8]) -> Regs {
        assert!(context.len() >= CONTEXT_SIZE, "CONTEXT is {CONTEXT_SIZE} bytes");
        let mut regs = Regs::default();
        for (i, slot) in regs.gp.iter_mut().enumerate() {
            let at = RAX + 8 * i;
            *slot = u64::from_le_bytes(context[at..at + 8].try_into().unwrap());
        }
        regs.eflags = u32::from_le_bytes(context[EFLAGS..EFLAGS + 4].try_into().unwrap());
        for (i, lane) in regs.xmm.iter_mut().enumerate() {
            lane.copy_from_slice(&context[XMM0 + 16 * i..XMM0 + 16 * i + 16]);
        }
        regs
    }

    /// Writes the registers back into a raw x64 CONTEXT.
    pub fn write_context(&self, context: &mut [u8]) {
        assert!(context.len() >= CONTEXT_SIZE, "CONTEXT is {CONTEXT_SIZE} bytes");
        for (i, slot) in self.gp.iter().enumerate() {
            let at = RAX + 8 * i;
            context[at..at + 8].copy_from_slice(&slot.to_le_bytes());
        }
        context[EFLAGS..EFLAGS + 4].copy_from_slice(&self.eflags.to_le_bytes());
        for (i, lane) in self.xmm.iter().enumerate() {
            context[XMM0 + 16 * i..XMM0 + 16 * i + 16].copy_from_slice(lane);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_round_trip_keeps_every_register() {
        let mut context = vec![0u8; CONTEXT_SIZE];
        for (i, b) in context.iter_mut().enumerate() {
            *b = (i * 7 + 3) as u8;
        }
        let regs = Regs::from_context(&context);
        let mut again = vec![0xEEu8; CONTEXT_SIZE];
        regs.write_context(&mut again);
        // everything the Regs model covers survives; the rest of the CONTEXT is untouched
        for i in (RAX..RAX + 17 * 8).chain(EFLAGS..EFLAGS + 4).chain(XMM0..XMM0 + 256) {
            assert_eq!(again[i], context[i], "byte {i}");
        }
        assert_eq!(again[0], 0xEE);
        assert_eq!(regs.q(RCX), u64::from_le_bytes(context[RCX..RCX + 8].try_into().unwrap()));
    }
}
