//! Command executor for calls into the game (M4 of the native co-op core).
//!
//! * [`command`]: the commands, with the argument validation of `call_before`.
//! * [`executor`]: ordered, bounded, idempotent, state-guarded, fail-stop queue.
//! * [`native`]: the real call shapes (Windows x64 ABI) for each command.

pub mod command;
pub mod executor;
pub mod native;

pub type Result<T> = std::result::Result<T, String>;

/// The prologue of the pause/resume functions that the UI-only entries re-run before jumping
/// into the body (`push rbp/rsi/rdi/rbx; sub rsp,0x88; lea rbp,[rsp+0x80]; mov qword [rbp],-2`).
pub const UI_PROLOGUE: [u8; 27] = [
    0x55, 0x56, 0x57, 0x53, 0x48, 0x81, 0xEC, 0x88, 0x00, 0x00, 0x00, 0x48, 0x8D, 0xAC, 0x24, 0x80, 0x00, 0x00, 0x00, 0x48,
    0xC7, 0x45, 0x00, 0xFE, 0xFF, 0xFF, 0xFF,
];
