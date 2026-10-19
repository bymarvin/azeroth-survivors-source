//! The Python-compatible co-op `state` message (online_bridge.py, 0.0.14/0.0.15).
//!
//! A native peer and a Python peer exchange exactly this JSON message inside
//! PROTOCOL 5 frames. [`build`] writes it (a port of `send_state`), [`peer`]
//! validates it (a port of `receive_state`) and keeps the per-peer state the
//! Python keeps. Everything the native side does not implement yet is bounded
//! and either ignored harmlessly or rejected (fail closed), never trusted.

pub mod auras;
pub mod build;
pub mod enemies;
pub mod group;
pub mod peer;
pub mod producers;

use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use base64::{alphabet, Engine};
use serde_json::Value;

pub type Result<T> = std::result::Result<T, String>;

/// play_limits.py (decision 17.10.2026: far above real play, reject only broken data).
pub mod limits {
    pub const MAX_ENEMY_DAMAGE: f64 = 1e12;
    pub const MAX_HIT_DAMAGE: f64 = 1e12;
    pub const MAX_DAMAGE_TOTAL: f64 = 1e18;
    pub const MAX_CLOCK: f64 = 1e9;
    pub const MAX_MULTIPLIER: f64 = 1e6;
    pub const MAX_COUNTER: f64 = 4294967295.0;
    pub const MAX_ENEMIES: usize = 32768;
    pub const MAX_QUEUE: usize = 65536;
    pub const MAX_NATIVE_OBJECTS: usize = 1_000_000;
    /// The co-op renderer backlog in host-world bytes.
    pub const MAX_RENDER_BACKLOG: usize = 524_288;
}

// Python's b64decode(validate=True): canonical padding required, trailing bits tolerated.
const DECODER: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::RequireCanonical),
);

/// `binary`: base64 text of bytes.
pub fn binary(bytes: &[u8]) -> Value {
    Value::String(base64::engine::general_purpose::STANDARD.encode(bytes))
}

/// `unbinary(value, maximum)`.
pub fn unbinary(value: &Value, maximum: usize) -> Result<Vec<u8>> {
    let text = value.as_str().ok_or("Invalid binary co-op field")?;
    if text.len() > (maximum + 2) / 3 * 4 {
        return Err("Invalid binary co-op field".into());
    }
    let bytes = DECODER.decode(text).map_err(|_| "Invalid binary co-op field".to_string())?;
    if bytes.len() > maximum {
        return Err("Co-op field exceeds bound".into());
    }
    Ok(bytes)
}

/// `finite(value, low, high)`: a JSON int or float within the bounds (bool excluded).
pub fn finite(value: &Value, low: f64, high: f64) -> Result<f64> {
    let number = match value {
        Value::Number(n) => n.as_f64(),
        _ => None,
    };
    match number {
        Some(v) if v.is_finite() && low <= v && v <= high => Ok(v),
        _ => Err("Invalid numeric co-op field".into()),
    }
}

/// `type(value) is int` (JSON integers; floats such as 1.0 and booleans are not).
pub fn is_int(value: &Value) -> bool {
    matches!(value, Value::Number(n) if n.is_i64() || n.is_u64())
}

/// Any JSON integer (Python's unbounded `int`): GUIDs are u64 and do not fit an i64.
pub fn as_big(value: &Value) -> Option<i128> {
    match value {
        Value::Number(n) => n.as_i64().map(i128::from).or_else(|| n.as_u64().map(i128::from)),
        _ => None,
    }
}

pub fn as_int(value: &Value) -> Option<i64> {
    if is_int(value) {
        value.as_i64()
    } else {
        None
    }
}
