//! Azeroth Survivors Together co-op network helper, as a library so its parts
//! can be tested on their own. The binary (main.rs) only wires them together.
//!
//! * `endpoint` - the local channel to the DLL in the game, restricted to the
//!   current Windows user and refused from other machines.

pub mod endpoint;

pub mod session;

pub mod peer;

pub mod tls;

pub mod relay;

pub mod link;

pub mod hub;

pub mod watch;
