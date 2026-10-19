//! `OnlineBridge.send_state`: the state message a native peer sends.

use crate::binary;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

pub type Packet = (u16, Vec<u8>);

/// Keys both roles send.
#[derive(Debug, Clone, Default)]
pub struct Common {
    pub ready: bool,
    pub loaded: bool,
    /// Native player state: (phase, level, xp, talents due).
    pub state: Option<[u64; 4]>,
    /// Remote players already created for this peer.
    pub created: Vec<u32>,
    /// Pause requests (`controls`), oldest first.
    pub controls: Vec<bool>,
    pub restart: bool,
    pub xp_multiplier: f64,
    pub closing: bool,
    pub name_response: Option<Vec<u8>>,
    /// Sent exactly once per session.
    pub template: Option<Vec<u8>>,
    pub movement: Option<Packet>,
    /// Attack, hurt and notice packets for the peer.
    pub packets: Vec<Packet>,
    /// `Some(None)` publishes "no claim", `None` leaves the key out.
    pub claim: Option<Option<Value>>,
    /// Guests: world packets received so far; hosts send 0.
    pub world_received: u64,
}

#[derive(Debug, Clone, Default)]
pub struct HostPart {
    /// `(kind, clock)` with kind "hits" or "areas".
    pub hit_order: Vec<(String, f64)>,
    pub powerups: Vec<u8>,
    pub surrender: bool,
    pub raid_assignments: BTreeMap<u32, u8>,
    pub boss_rewards: Vec<Value>,
    pub clock: f64,
    pub boss: Value,
    pub xp: u64,
    pub gold: u64,
    pub hits: Vec<(i128, f64, f64)>,
    pub areas: Vec<(i128, f64)>,
    pub world: Vec<Packet>,
    pub damage_done: Vec<(i128, f64)>,
    pub chests: Vec<Value>,
    /// Party hosts send sequenced deltas instead of the full `enemies` / `chests` lists.
    pub deltas: bool,
    pub enemy_update: Option<Value>,
    pub chest_update: Option<Value>,
}

#[derive(Debug, Clone, Default)]
pub struct GuestPart {
    pub boss_reward_ack: u64,
    pub damage: Vec<(i128, f64)>,
    pub effects: Vec<(i128, Vec<u8>, i64)>,
    pub surrendered: bool,
    /// Group layer: the enemy sequence this guest applied last, and whether it needs a full snapshot.
    pub enemy_ack: Option<u64>,
    pub enemy_full: bool,
}

pub enum Role {
    Host(HostPart),
    Guest(GuestPart),
}

fn packets(list: &[Packet]) -> Value {
    Value::Array(list.iter().map(|(op, body)| json!([op, binary(body)])).collect())
}

/// A GUID as a JSON integer (the u64 range included).
pub fn guid(g: i128) -> Value {
    if let Ok(v) = u64::try_from(g) {
        json!(v)
    } else {
        json!(i64::try_from(g).unwrap_or(0))
    }
}

fn number(value: f64) -> Value {
    // Whole values travel as JSON integers like the Python's counters and clocks do.
    if value.fract() == 0.0 && value.abs() < 9.0e15 {
        json!(value as i64)
    } else {
        json!(value)
    }
}

pub fn state_message(common: &Common, role: &Role) -> Value {
    let mut m = Map::new();
    m.insert("kind".into(), json!("state"));
    m.insert("ready".into(), json!(common.ready));
    m.insert("loaded".into(), json!(common.loaded));
    m.insert("state".into(), common.state.map_or(Value::Null, |s| json!(s)));
    m.insert("created".into(), json!(common.created));
    m.insert("controls".into(), Value::Array(common.controls.iter().map(|p| json!({"paused": p})).collect()));
    m.insert("restart".into(), json!(common.restart));
    m.insert("xp_multiplier".into(), number(common.xp_multiplier));
    m.insert("closing".into(), json!(common.closing));
    if let Some(name) = &common.name_response {
        m.insert("name_response".into(), binary(name));
    }
    m.insert("world_received".into(), json!(common.world_received));
    if let Some(template) = &common.template {
        m.insert("template".into(), binary(template));
    }
    if let Some((op, body)) = &common.movement {
        m.insert("movement".into(), json!([op, binary(body)]));
    }
    m.insert("packets".into(), packets(&common.packets));
    if let Some(claim) = &common.claim {
        m.insert("claim".into(), claim.clone().unwrap_or(Value::Null));
    }
    match role {
        Role::Host(host) => {
            m.insert("hit_order".into(), json!(host.hit_order));
            m.insert("powerups".into(), json!(host.powerups));
            if host.surrender {
                m.insert("surrender".into(), json!(true));
            }
            m.insert(
                "raid_assignments".into(),
                Value::Object(host.raid_assignments.iter().map(|(n, icon)| (n.to_string(), json!(icon))).collect()),
            );
            m.insert("boss_rewards".into(), Value::Array(host.boss_rewards.clone()));
            m.insert("clock".into(), number(host.clock));
            m.insert("boss".into(), host.boss.clone());
            m.insert("xp".into(), json!(host.xp));
            m.insert("gold".into(), json!(host.gold));
            m.insert("hits".into(), Value::Array(host.hits.iter().map(|(g, d, c)| json!([guid(*g), number(*d), number(*c)])).collect()));
            m.insert("areas".into(), Value::Array(host.areas.iter().map(|(g, d)| json!([guid(*g), number(*d)])).collect()));
            m.insert("world".into(), packets(&host.world));
            m.insert("damage_done".into(), Value::Array(host.damage_done.iter().map(|(g, d)| json!([guid(*g), number(*d)])).collect()));
            if host.deltas {
                if let Some(update) = &host.enemy_update {
                    m.insert("enemy_update".into(), update.clone());
                }
                if let Some(update) = &host.chest_update {
                    m.insert("chest_update".into(), update.clone());
                }
            } else {
                m.insert("chests".into(), Value::Array(host.chests.clone()));
            }
        }
        Role::Guest(guest) => {
            m.insert("boss_reward_ack".into(), json!(guest.boss_reward_ack));
            m.insert("damage".into(), Value::Array(guest.damage.iter().map(|(g, d)| json!([guid(*g), number(*d)])).collect()));
            m.insert(
                "effects".into(),
                Value::Array(guest.effects.iter().map(|(g, e, s)| json!([guid(*g), binary(e), s])).collect()),
            );
            if let Some(ack) = guest.enemy_ack {
                m.insert("enemy_ack".into(), json!(ack));
            }
            if guest.enemy_full {
                m.insert("enemy_full".into(), json!(true));
            }
            if guest.surrendered {
                m.insert("surrendered".into(), json!(true));
            }
        }
    }
    Value::Object(m)
}
