//! Wire protocols shared by the DLL (avrt.dll) and the network helper
//! (azcoop-net.exe).
//!
//! * `transport` - PROTOCOL 5 frames, byte-compatible with coop_transport.py.
//!   Used only by the helper; the DLL carries no network code.
//! * `ipc` - the binary message format on the local named pipe between the
//!   DLL inside the game and the helper.

pub mod ipc;
pub mod transport;
