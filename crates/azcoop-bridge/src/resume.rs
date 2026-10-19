//! Step 3: a peer link that went down inside its grace window and may come back.
//!
//! The helper reports `down` (the slot stays open) and later `connected` again with a rising epoch; the mailbox turns them into
//! `NetEvent::Down` / `NetEvent::Up`. Here is what the bridge does with them:
//!
//! * host, a guest went down: the guest stays in the room (no `remove_guest`), its avatar stands still (damage is computed on the
//!   guest, so nobody hurts it), its claim and queued hits are dropped, nothing is built for it while it is away, the party gets a
//!   notice. The run goes on for everybody else.
//! * guest, the host went down: the guest pauses its simulation (its enemies are mirrors of the host's snapshots) until the host is back.
//! * the link is back: only the protocol state of that one link is reset, the gameplay state stays. The host sends the guest a full
//!   enemy snapshot and full loot again and its current pause state; the guest asks for the full snapshot and starts its enemy
//!   sequence over. Cumulative totals (damage, xp, gold, boss reward and end-action sequences) heal by themselves.
//!
//! What a gap loses: the host's world packets for the away guest (spell, aura and projectile objects) are dropped while it is away.

use crate::bridge::Bridge;
use crate::client::{Client, Result};
use crate::io::GameIo;
use crate::online::Online;
use crate::regs::Regs;
use azcoop_logic::Event;
use azcoop_world::builders::system_message;
use serde_json::json;
use std::collections::BTreeMap;

impl Bridge {
    /// `NetEvent::Down(peer)`.
    pub fn peer_down(&mut self, client: &mut dyn Client, peer: u32) -> Result<()> {
        let mut online = self.online.take().ok_or("the bridge is not online")?;
        let result = self.peer_down_with(client, &mut online, peer);
        self.online = Some(online);
        result
    }

    /// `NetEvent::Up(peer, epoch)`.
    pub fn peer_up(&mut self, client: &mut dyn Client, peer: u32, epoch: u64) -> Result<()> {
        let mut online = self.online.take().ok_or("the bridge is not online")?;
        let result = self.peer_up_with(client, &mut online, peer, epoch);
        self.online = Some(online);
        result
    }

    /// The host's queued packets for a guest that is away: nobody reads them, so they must not pile up.
    pub fn drop_queued_for(&mut self, peer: u32) {
        if let Some(feed) = self.wire.feeds.get_mut(&peer) {
            feed.world_pending.clear();
            feed.attack_packets.clear();
            feed.hurt_packets.clear();
            feed.notice_packets.clear();
        }
    }

    /// A system notice for every member that is not away.
    fn notify_all(&mut self, text: &str, away: &BTreeMap<u32, f64>) {
        if let Ok(notice) = system_message(text) {
            for member in self.room.members.clone() {
                if !away.contains_key(&member) {
                    self.room.notice.entry(member).or_default().push(notice.clone());
                }
            }
        }
    }

    fn peer_down_with(&mut self, client: &mut dyn Client, online: &mut Online, peer: u32) -> Result<()> {
        if online.group.departed.contains(&peer) || online.away.contains_key(&peer) {
            return Ok(());
        }
        if online.number == 1 && !self.room.guests.contains(&peer) {
            return Ok(());
        }
        online.away.insert(peer, self.now);
        client.record(Event::new("peer_down").num("player", peer as f64));
        if online.number == 1 {
            if self.economy.chest_claim.as_ref().is_some_and(|c| c.player() == peer) {
                self.economy.chest_claim = None;
            }
            {
                self.refresh();
                let mut regs = Regs::default();
                let mut io = GameIo::new(client, &mut regs, &self.build.fields, &mut self.results);
                self.hits.clear_incoming_hits(&mut io, peer, "link_down", self.now);
            }
            self.drop_queued_for(peer);
            // the others hear it (the away guest itself is skipped)
            self.notify_all(&format!("Player {peer} lost the connection and may come back."), &online.away);
        } else {
            // the host is away: stand still until it is back
            self.room.paused = true;
            self.room.pause_pending.insert(online.number, true);
            if let Ok(notice) = system_message("Connection to the host lost. Reconnecting...") {
                self.room.notice.entry(online.number).or_default().push(notice);
            }
        }
        Ok(())
    }

    fn peer_up_with(&mut self, client: &mut dyn Client, online: &mut Online, peer: u32, epoch: u64) -> Result<()> {
        if online.group.departed.contains(&peer) {
            return Ok(()); // the slot is final; the helper refuses such links, this is only a stale event
        }
        let was_away = online.away.remove(&peer).is_some();
        client.record(Event::new("peer_up").num("player", peer as f64).num("epoch", epoch as f64).num("was_down", was_away as u8 as f64));
        if online.number == 1 {
            // everything the guest was sent over the old link starts over: full enemies, full loot, the template, the acks
            online.outgoing.encoders.remove(&peer);
            online.outgoing.chest_sync.remove(&peer);
            online.outgoing.snapshot_due.remove(&peer);
            online.outgoing.template_sent.remove(&peer);
            online.outgoing.sync.forget(peer);
            online.group.enemy_sequences.remove(&peer);
            online.group.enemy_acked.remove(&peer);
            online.group.enemy_full_requested.insert(peer);
            online.group.resync.insert(peer);
            // the guest paused itself while the host was away from its point of view; tell it the real state
            online.controls.push(json!({"paused": self.room.paused}));
            self.notify_all(&format!("Player {peer} is back."), &online.away);
        } else {
            if let Some(p) = online.group.peers.get_mut(&peer) {
                p.enemy_mirror.seq = 0;
                p.enemy_mirror.full_needed = true;
            }
            online.outgoing.template_sent.remove(&peer);
            if let Ok(notice) = system_message("Reconnected to the host.") {
                self.room.notice.entry(online.number).or_default().push(notice);
            }
        }
        Ok(())
    }
}
