//! The game process as seen from inside it: safe memory reads and writes (ReadProcessMemory /
//! WriteProcessMemory on the own process report a bad address instead of faulting), code
//! patching with protection and instruction-cache handling, and executable buffers for
//! trampolines. The Python reached all of this through the debugger handle; this is the same
//! surface for the in-process core.

use azcoop_game::readers::Mem;
use azcoop_patch::install::Process;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Diagnostics::Debug::{FlushInstructionCache, ReadProcessMemory, WriteProcessMemory};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Memory::{VirtualAlloc, VirtualProtect, MEM_COMMIT, MEM_RESERVE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READWRITE};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

type Result<T> = std::result::Result<T, String>;

/// Largest single read the adapter accepts (`MAX_NATIVE_READ` in native_probe.py).
pub const MAX_NATIVE_READ: usize = 64 * 1024 * 1024;

pub struct Local {
    pub base: usize,
    pub image_size: usize,
    process: HANDLE,
}

unsafe impl Send for Local {}
unsafe impl Sync for Local {}

impl Local {
    /// The game's own executable image.
    pub fn game() -> Result<Local> {
        let base = unsafe { GetModuleHandleW(std::ptr::null()) } as usize;
        if base == 0 {
            return Err("no module handle for the game executable".into());
        }
        let local = Local { base, image_size: 0, process: unsafe { GetCurrentProcess() } };
        let e_lfanew = u32::from_le_bytes(local.read(base + 0x3C, 4)?[..4].try_into().unwrap()) as usize;
        let size = u32::from_le_bytes(local.read(base + e_lfanew + 24 + 56, 4)?[..4].try_into().unwrap()) as usize;
        Ok(Local { image_size: size, ..local })
    }

    /// A stand-in image (tests): `base` and `image_size` are only used for the near-allocation search.
    pub fn with_image(base: usize, image_size: usize) -> Local {
        Local { base, image_size, process: unsafe { GetCurrentProcess() } }
    }

    pub fn read(&self, address: usize, len: usize) -> Result<Vec<u8>> {
        if len > MAX_NATIVE_READ {
            return Err("Unreasonable native read".into());
        }
        let mut out = vec![0u8; len];
        let mut done = 0usize;
        let ok = unsafe { ReadProcessMemory(self.process, address as *const _, out.as_mut_ptr() as *mut _, len, &mut done) };
        if ok == 0 || done != len {
            return Err(format!("native read of {len} bytes at {address:#x} failed"));
        }
        Ok(out)
    }

    pub fn write(&self, address: usize, bytes: &[u8]) -> Result<()> {
        let mut done = 0usize;
        let ok = unsafe { WriteProcessMemory(self.process, address as *const _, bytes.as_ptr() as *const _, bytes.len(), &mut done) };
        if ok == 0 || done != bytes.len() {
            return Err(format!("native write of {} bytes at {address:#x} failed", bytes.len()));
        }
        Ok(())
    }

    /// `client.patch(address, data)`: writable for the moment of the write, then back.
    pub fn patch_at(&self, address: usize, bytes: &[u8]) -> Result<()> {
        let mut old = 0u32;
        if unsafe { VirtualProtect(address as *const _, bytes.len(), PAGE_EXECUTE_READWRITE, &mut old) } == 0 {
            return Err(format!("cannot make {address:#x} writable"));
        }
        let written = self.write(address, bytes);
        let mut scratch = 0u32;
        let restored = unsafe { VirtualProtect(address as *const _, bytes.len(), old, &mut scratch) };
        unsafe { FlushInstructionCache(self.process, address as *const _, bytes.len()) };
        written?;
        if restored == 0 {
            return Err(format!("cannot restore the protection of {address:#x}"));
        }
        Ok(())
    }

    /// `allocate(handle, None, size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)`
    pub fn alloc(&self, size: usize) -> Result<usize> {
        let address = unsafe { VirtualAlloc(std::ptr::null(), size.max(1), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) } as usize;
        if address == 0 {
            return Err("native allocation failed".into());
        }
        crate::crash::note_buffer('d', address as u64, size);
        Ok(address)
    }

    /// `executable_buffer(data, near=...)`: code in memory the process can run, within rel32 reach
    /// of `near` (an absolute address) when given.
    pub fn exec_alloc(&self, code: &[u8], near: Option<usize>) -> Result<usize> {
        let address = match near {
            None => (unsafe { VirtualAlloc(std::ptr::null(), code.len().max(1), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) }) as usize,
            Some(site) => {
                let start = (self.base + self.image_size + 0xFFFF) & !0xFFFF;
                let end = (start + 0x1000_0000).min(site + 0x7FFF_0000);
                let mut found = 0usize;
                let mut candidate = start;
                while candidate < end {
                    found = unsafe { VirtualAlloc(candidate as *const _, code.len().max(1), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) } as usize;
                    if found != 0 {
                        break;
                    }
                    candidate += 0x10000;
                }
                if found == 0 {
                    return Err("No nearby memory for the native dispatch guard".into());
                }
                found
            }
        };
        if address == 0 {
            return Err("native allocation failed".into());
        }
        self.write(address, code)?;
        let mut old = 0u32;
        if unsafe { VirtualProtect(address as *const _, code.len().max(1), PAGE_EXECUTE_READ, &mut old) } == 0 {
            return Err("cannot make the trampoline executable".into());
        }
        unsafe { FlushInstructionCache(self.process, address as *const _, code.len()) };
        crate::crash::note_buffer('c', address as u64, code.len());
        Ok(address)
    }
}

impl Mem for Local {
    fn read(&self, address: u64, len: usize) -> Result<Vec<u8>> {
        Local::read(self, address as usize, len)
    }
}

impl Process for Local {
    fn base(&self) -> u64 {
        self.base as u64
    }
    fn memory(&mut self, rva: u64, len: usize) -> Result<Vec<u8>> {
        Local::read(self, self.base + rva as usize, len)
    }
    fn patch(&mut self, rva: u64, bytes: &[u8]) -> Result<()> {
        self.patch_at(self.base + rva as usize, bytes)
    }
    fn executable_buffer(&mut self, code: &[u8], near: Option<u64>) -> Result<u64> {
        self.exec_alloc(code, near.map(|rva| self.base + rva as usize)).map(|a| a as u64)
    }
    fn allocate(&mut self, size: usize) -> Result<u64> {
        self.alloc(size).map(|a| a as u64)
    }
    fn put(&mut self, address: u64, bytes: &[u8]) -> Result<()> {
        self.write(address as usize, bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn begin(name: &str) -> std::time::Instant {
        println!("[ .... ] {name}");
        std::time::Instant::now()
    }

    #[test]
    fn reads_and_writes_report_bad_addresses_instead_of_faulting() {
        let name = "proc: safe read/write on own memory, bad addresses are errors";
        let started = begin(name);
        let local = Local::with_image(0, 0);
        let buffer = local.alloc(4096).unwrap();
        local.write(buffer, b"azeroth").unwrap();
        assert_eq!(local.read(buffer, 7).unwrap(), b"azeroth");
        assert!(local.read(0x10, 8).is_err(), "unmapped low address");
        assert!(local.read(buffer + 4096, 8).is_err(), "just past the allocation (a guard region)");
        assert!(local.write(0x10, b"x").is_err());
        assert!(local.read(buffer, MAX_NATIVE_READ + 1).is_err(), "unreasonable length");
        println!("[  OK  ] {name} ({:.1} ms)", started.elapsed().as_secs_f64() * 1000.0);
    }

    #[test]
    fn patches_running_code_and_allocates_trampolines_near_the_image() {
        let name = "proc: patch executable code, allocate an executable buffer near a site";
        let started = begin(name);
        let region = Local::with_image(0, 0).alloc(1 << 16).unwrap();
        // `mov eax, 5; ret` in a page we make executable through the same path the installer uses.
        let local = Local::with_image(region, 1 << 16);
        let code = local.exec_alloc(&[0xB8, 5, 0, 0, 0, 0xC3], None).unwrap();
        let call = |address: usize| -> u32 { unsafe { std::mem::transmute::<usize, extern "system" fn() -> u32>(address)() } };
        assert_eq!(call(code), 5);
        local.patch_at(code + 1, &[9]).unwrap();
        assert_eq!(call(code), 9, "the patched immediate is executed");
        // near: a buffer within rel32 reach of the site, after the image
        let site = code;
        let near = local.exec_alloc(&[0xB8, 7, 0, 0, 0, 0xC3], Some(site)).unwrap();
        assert!(near >= region + (1 << 16), "after the image");
        assert!((near as i64 - site as i64).abs() < 0x7FFF_0000, "within rel32 of the site");
        assert_eq!(call(near), 7);
        println!("[  OK  ] {name} ({:.1} ms)", started.elapsed().as_secs_f64() * 1000.0);
    }

    #[test]
    fn game_image_of_the_test_process_is_found() {
        let local = Local::game().unwrap();
        assert!(local.base != 0 && local.image_size > 0x1000);
        assert_eq!(local.read(local.base, 2).unwrap(), b"MZ");
    }
}
