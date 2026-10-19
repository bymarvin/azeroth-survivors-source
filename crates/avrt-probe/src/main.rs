//! Test program for the avrt.dll proxy (not part of the mod).
//!
//! The game imports three avrt functions. This program imports the same ones
//! through the normal import table (`raw-dylib`), so the loader (Windows or Wine)
//! decides which `avrt.dll` serves them: a copy next to this exe wins on Windows;
//! under Wine the override `WINEDLLOVERRIDES="avrt=n,b"` is needed.
//!
//! It prints which file serves avrt, calls the functions and waits a moment so
//! the DLL's worker thread can write its log before the process exits.

use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::time::Duration;

use windows_sys::Win32::Foundation::HMODULE;
use windows_sys::Win32::System::LibraryLoader::{GetModuleFileNameW, GetModuleHandleW};

#[link(name = "avrt", kind = "raw-dylib")]
extern "system" {
    fn AvSetMmThreadCharacteristicsW(task: *const u16, index: *mut u32) -> isize;
    fn AvSetMmThreadPriority(handle: isize, priority: i32) -> i32;
    fn AvRevertMmThreadCharacteristics(handle: isize) -> i32;
}

fn module_path(module: HMODULE) -> String {
    let mut buffer = vec![0u16; 1024];
    let length = unsafe { GetModuleFileNameW(module, buffer.as_mut_ptr(), buffer.len() as u32) };
    OsString::from_wide(&buffer[..length as usize]).to_string_lossy().into_owned()
}

fn main() {
    let name: Vec<u16> = "avrt.dll\0".encode_utf16().collect();
    let module = unsafe { GetModuleHandleW(name.as_ptr()) };
    if module.is_null() {
        println!("avrt module: (not loaded)");
    } else {
        println!("avrt module: {}", module_path(module));
    }

    let task: Vec<u16> = "Games\0".encode_utf16().collect();
    let mut index = 0u32;
    let handle = unsafe { AvSetMmThreadCharacteristicsW(task.as_ptr(), &mut index) };
    println!("AvSetMmThreadCharacteristicsW -> handle {handle:#x}, task index {index}");
    let priority = unsafe { AvSetMmThreadPriority(handle, 0) };
    println!("AvSetMmThreadPriority -> {priority}");
    let revert = unsafe { AvRevertMmThreadCharacteristics(handle) };
    println!("AvRevertMmThreadCharacteristics -> {revert}");

    // Let the proxy's worker thread (if loaded) write its log lines.
    std::thread::sleep(Duration::from_millis(2500));
    println!("done");
}
