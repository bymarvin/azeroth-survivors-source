//! The in-game bridge of the co-op core: the hook-event dispatcher (`Bridge.__call__`),
//! queue-write orchestration and TICK handling as a state machine over a game-process trait.
//! Verified against the real Python bridge classes driven by the same events.

pub mod before_batch;
#[cfg(feature = "test-hooks")]
pub mod stress;
pub mod bridge;
pub mod client;
pub mod control;
pub mod guest_filter;
pub mod io;
pub mod menu;
pub mod native_hooks;
pub mod online;
pub mod online_send;
pub mod ordmap;
pub mod process;
pub mod regs;
pub mod resume;
pub mod route;
pub mod serialize;
pub mod server_write;
pub mod sync_stats;
pub mod tick;
pub mod write;
pub mod wire;

pub use bridge::{Bridge, Build};
pub use client::{CallSpec, Client, Hook, Result};
pub use regs::Regs;
