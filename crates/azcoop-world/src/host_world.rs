//! Host-side world replication state: a port of the base `capture_world` of
//! `visibility_bridge.py` (0.0.14).
//!
//! The host sees every packet of its own native world. This decides which of
//! them guests receive: it tracks the set of active world objects, retires
//! them on DESTROY / OUT_OF_RANGE, rewrites combat packets for each guest, and
//! enforces the backlog bounds. Pure: the queues belong to the caller, who
//! passes how many bytes each guest already has queued and applies the returned
//! deliveries. The aura overlay (protocol 4) hooks in through `observe`.

use crate::{
    dynamic_object, object_packet, objects, remap_combat, ObjectBlock, Reader, Result, DESTROY, HOST, PROGRESSION,
    SELF, UPDATE,
};
use std::collections::{BTreeMap, HashSet};

/// play_limits.MAX_WORLD_OBJECTS.
pub const MAX_WORLD_OBJECTS: usize = 1_000_000;
/// play_limits.MAX_WORLD_BACKLOG = MAX_MESSAGE // 2.
pub const MAX_WORLD_BACKLOG: usize = 16 << 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery {
    pub recipient: u32,
    pub opcode: u16,
    pub body: Vec<u8>,
}

#[derive(Default)]
pub struct HostWorld {
    /// Active host world objects (GUIDs) guests are shown.
    pub world_guids: HashSet<u64>,
    /// Last seen values of the own-player progression fields.
    pub progress_fields: BTreeMap<u32, u32>,
    /// Bytes captured since the last send (`world_bytes`).
    pub world_bytes: usize,
    /// Host progression as `router.set_host_progress` stores it: (level, xp, next).
    pub host_progress: Option<[u32; 3]>,
}

impl HostWorld {
    /// `Bridge.capture_world(opcode, body)`.
    ///
    /// `queued_bytes(recipient)` is `sum(len(data) + 4)` over that guest's queue
    /// before this call. `observe(blocks, destroyed)` is the `world_observed`
    /// hook (host world blocks before replication, or a destroyed GUID).
    pub fn capture(
        &mut self,
        opcode: u16,
        body: &[u8],
        guests: &[u32],
        queued_bytes: &dyn Fn(u32) -> usize,
        observe: &mut dyn FnMut(&[ObjectBlock], Option<u64>),
    ) -> Result<Vec<Delivery>> {
        let mut body = body.to_vec();
        if opcode == DESTROY {
            let destroyed = Reader::configured(&body, false, HOST, None, None).guid(false, false)?;
            self.world_guids.remove(&destroyed);
            observe(&[], Some(destroyed));
        }
        if opcode == UPDATE {
            let blocks = objects(&body, true, None)?;
            observe(&blocks, None);
            let mut selected: Vec<ObjectBlock> = Vec::new();
            for block in &blocks {
                if block.guid == SELF {
                    for (k, v) in block.fields.iter().filter(|(k, _)| PROGRESSION.contains(k)) {
                        self.progress_fields.insert(*k, *v);
                    }
                    if PROGRESSION.iter().all(|k| self.progress_fields.contains_key(k)) {
                        let [level, xp, next] = PROGRESSION.map(|k| self.progress_fields[&k]);
                        if level == 0 {
                            return Err("Invalid host progression".into());
                        }
                        self.host_progress = Some([level, xp, next]);
                    }
                }
                // Host ground spells keep the native GUID; guest copies use reserved owner bits.
                let tracked_type = matches!(block.object_type, Some(3) | Some(5));
                if tracked_type || dynamic_object(block, true)? {
                    if !self.world_guids.contains(&block.guid) && self.world_guids.len() >= MAX_WORLD_OBJECTS {
                        return Err(format!("Host world active-object limit exceeded ({MAX_WORLD_OBJECTS} objects)"));
                    }
                    self.world_guids.insert(block.guid);
                }
                if self.world_guids.contains(&block.guid) || (block.guid == SELF && block.kind == 0) {
                    selected.push(block.clone());
                }
                if block.kind == 4 {
                    // OUT_OF_RANGE retires visibility; kind 5 is NEAR_OBJECTS.
                    self.world_guids.remove(&block.guid);
                }
            }
            if selected.is_empty() {
                return Ok(Vec::new());
            }
            body = object_packet(&selected);
        }
        if guests.is_empty() {
            // Solo hosts still track progression, but have no replication backlog.
            self.world_bytes = 0;
            return Ok(Vec::new());
        }
        self.world_bytes += body.len() + 4;
        if self.world_bytes > MAX_WORLD_BACKLOG {
            return Err(format!("Host-world queue backlog exceeded {MAX_WORLD_BACKLOG} bytes"));
        }
        let mut deliveries = Vec::with_capacity(guests.len());
        for recipient in guests {
            let delivered = if opcode == UPDATE {
                body.clone()
            } else {
                remap_combat(opcode, &body, HOST, Some(0xFF0100 + *recipient as u64), None)?
            };
            if queued_bytes(*recipient) + delivered.len() + 4 > MAX_WORLD_BACKLOG {
                return Err(format!("Guest {recipient} world-queue backlog exceeded {MAX_WORLD_BACKLOG} bytes"));
            }
            deliveries.push(Delivery { recipient: *recipient, opcode, body: delivered });
        }
        Ok(deliveries)
    }
}
