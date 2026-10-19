"""Host fan-out over the existing authenticated, bounded two-peer wire codec."""
import json
import re
import struct
import time
import queue

from online_bridge import OnlineBridge, binary, unbinary
from play_limits import MAX_COUNTER, MAX_QUEUE
from sessions import MOVEMENT_OPCODES, Pose, LOGIN
from visibility_bridge import clone_player, frame
from world_packets import validate_movement_packet, WORLD, DESTROY

def _seconds_from_environment(name, default):
    import os
    try:
        value = float(os.environ.get(name, default))
    except ValueError:
        return default
    return value if 0 <= value <= 3600 else default


FULL_SNAPSHOT_SECONDS = _seconds_from_environment('COOP_FULL_SNAPSHOT_S', 0)  # 0 = only on demand


class ReceiptBook(dict):
    """Cumulative damage receipts of one guest that remember which entries changed.

    Writes mark the target, so a send costs O(changes). Receipts of enemies that
    are gone are forgotten once sent (prune_receipts) and announced as [guid, 0],
    so the book stays as small as the living enemies over any session length.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.dirty = set(self)
        self.forgotten = set()

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        self.dirty.add(key)

    def forget(self, guid):
        del self[guid]
        self.forgotten.add(guid)

    def take_changes(self):
        # A forget precedes a later write of the same enemy (receipt restarted from zero).
        changed = [[guid, 0] for guid in self.forgotten]
        changed += [[guid, self[guid]] for guid in self.dirty if guid in self]
        self.forgotten.clear()
        self.dirty.clear()
        return changed


RECEIPT_PRUNE_SECONDS = 10.0


ENEMY_SNAPSHOT_INTERVAL =.1  # Seconds between enemy updates per guest (.1 = 10 Hz, ~2.5x less upload).


# Room id and invite of the directory (the EU directory is not ours: any URL-safe token, bounded).
NEXT_ROOM = re.compile(r'[A-Za-z0-9_-]{1,64}')
NEXT_INVITE = re.compile(r'[A-Za-z0-9_.~-]{1,128}')


class GroupOnlineBridge(OnlineBridge):
    def __init__(self, output, number, channels):
        self.channels = dict(channels)
        self.departed = set()
        # "Next run": the host's invitation to the following room travels over these pinned channels.
        self.next_run_offer = None      # host: {'room', 'invite'} published to every guest
        self.next_run_acks = set()      # host: guests that confirmed this offer
        self.next_run_received = None   # guest: the host's offer, accepted from peer 1 only
        self.host_closing = False
        self.quiesced_peers = set()
        self.world_sent = {n: 0 for n in channels}
        self.world_acked = {n: 0 for n in channels}
        self.template_sent = set()
        self.party_templates_sent = {n: set() for n in channels}
        self.chests_sent = {}
        self.congested = set()
        self.claims_sent = {}
        self.damage_receipts = {n: ReceiptBook() for n in channels}
        self.damage_owners = {}
        # Host upload shaping (per recipient): sequenced enemy deltas at 25 Hz,
        # a full enemy snapshot every 2 s or on request, changed receipts only.
        self.enemy_deltas = True
        self.enemy_views, self.enemy_sequences, self.enemy_acked = {}, {}, {}
        self.enemy_full_due, self.enemy_full_requested = {}, set()
        self.snapshot_due, self.damage_done_sent, self.size_report_due = {}, {}, {}
        self.poll_generation = 0
        self.enemy_view_cache = (None, {})
        self.enemy_wire_text, self.enemy_view_sent = {}, None
        # Diagnostics: per record byte, how often it changed between updates.
        self.enemy_churn, self.enemy_churn_compared, self.enemy_churn_patched = {}, 0, 0
        self.enemy_churn_due = 0

        self.connection_failure = None
        self.connection_after_run = False
        self.last_diagnostic = self.last_poll = time.monotonic()
        super().__init__(output, number, next(iter(channels.values())))

    def remove_guest(self, number, reason='left'):
        if number in self.departed:
            return
        if number not in self.guests or number == self.number:
            raise ValueError('Invalid departing guest')
        self.clear_incoming_hits(number, 'player_departed')
        pending_world = len(self.world_pending if number == 2 else self.world_queues.get(number, ()))
        self.departed.add(number)
        self.quiesced_peers.discard(number)
        self.name_responses.pop(number, None)
        for pending in self.name_queries.values():
            pending.discard(number)
        channel = self.channels.pop(number, None)
        link = self.link_state(channel)
        for mapping in (self.enemy_views, self.enemy_sequences, self.enemy_acked, self.enemy_full_due,
                        self.snapshot_due, self.damage_done_sent, self.size_report_due, self.chests_sent):
            mapping.pop(number, None)
        self.enemy_full_requested.discard(number)
        if channel is not None:
            channel.close()
        self.members = tuple(n for n in self.members if n != number)
        self.raid_assignments.pop(number, None)
        self.guests = tuple(n for n in self.guests if n != number)
        for recipient, created in self.created.items():
            if number in created and recipient in self.members:
                self.notice_packets[recipient].append((DESTROY, struct.pack('<Q', 0xFF0100 + number)))
            created.discard(number)
        for guid in self.summons.pop(number, set()):
            for recipient in self.members:
                self.notice_packets[recipient].append((DESTROY, struct.pack('<Q', guid)))
        self.summon_maps.pop(number, None)
        self.drop_guest_auras(number)
        self.router.disconnect(str(number))
        self.router.players.pop(0xFF0100 + number, None)
        for mapping in (self.templates, self.native_states, self.latest_movement, self.created,
                        self.revive_progress, self.revive_status, self.pause_pending, self.end_pending, self.hit_work_turn,
                        self.boss_reward_applied, self.gold_by_guest):
            mapping.pop(number, None)
        for group in (self.ready, self.loaded, self.downed, self.talent_paused,
                      self.team_defeat, self.menu_players):
            group.discard(number)
        for mapping in (self.world_queues, self.hit_queues, self.areas_by_guest,
                        self.attack_packets, self.hurt_packets, self.notice_packets):
            if number in mapping:
                mapping[number].clear()
        self.xp_queues[number] = 0
        if number == 2:
            self.world_pending.clear()
            self.guest_hits.clear()
            self.area_hits.clear()
            self.xp_pending = self.gold_pending = 0
        if self.number == 1:
            self.drop_loot_member(number)  # His claim ends; no chest waits for him any more.
        if self.number == 1:
            # Unacknowledged work for a departed recipient cannot be delivered.
            abandoned = self.world_sent[number] - self.world_acked[number] + pending_world
            self.counts['world_abandoned'] = self.counts.get('world_abandoned', 0) + abandoned
            acknowledged = min(self.boss_reward_applied.values(), default=self.boss_reward_sequence)
            self.boss_reward_events[:] = [e for e in self.boss_reward_events if e['sequence'] > acknowledged]
        self.router.paused = self.draining
        self.pause_pending.update({n: self.draining for n in self.members})
        self.controls = [] if self.draining else [dict(paused=False)]
        self.last_network = 0
        self.record(event='guest_departed', player=number, reason=reason, **link)

    @staticmethod
    def link_state(channel):
        """Transport backlog at departure; diagnoses an uplink that fell behind."""
        if channel is None or not hasattr(channel, 'outgoing'):
            return {}
        error = getattr(channel, 'error', None)
        return dict(queued_bytes=channel.queued_bytes, queued_messages=channel.outgoing.qsize(),
                    latency_ms=channel.latency_ms(), transport_error=repr(error) if error else None)

    def connection_ended(self, peer, reason):
        if isinstance(reason, BaseException):
            from coop_transport import failure_details
            self.record_network('transport_failure', peer=peer, errors=failure_details(reason),
                                **self.link_state(self.channels.get(peer)))
            # After giving up, the host closing is expected. Once this guest's run has ended as planned, a lost
            # link is still reported (that is how the relay cut after New hero was found), but the player sees an
            # orderly end, not an error (room_client: connection_after_run).
            if self.number != 1 and not self.self_surrendered:
                self.connection_failure = reason
                self.connection_after_run = self.run_finished_here()
            reason = type(reason).__name__
        if self.number == 1:
            self.remove_guest(peer, reason)
        else:
            self.peer_finished = self.stop_requested = True
            self.record(event='host_departed', reason=reason, after_run=self.run_finished_here(),
                        **self.link_state(self.channels.get(peer)))

    def run_finished_here(self):
        """This player's run is over: victory screen, New hero/Again after it, team defeat or the party's give-up."""
        number = self.number
        return (self.native_states.get(number, (0,))[0] == 5 or number in self.completed_players
                or number in self.team_defeat or bool(getattr(self, 'party_surrender', False)))

    def native_exited(self, client, code):
        # Each network process owns one game; RoomClient sends goodbye after
        # native cleanup and preserves this player's save in its finally block.
        self.stop_requested = True

    def record(self, **event):
        if (getattr(self, 'number', 0) == 1 and event.get('event') in
                ('native_guest_damage_applied', 'guest_damage_target_already_dead')):
            remaining = event['requested']
            owners = self.damage_owners.get(event['target'], {})
            for owner in list(owners):
                applied = min(remaining, owners[owner])
                receipts = self.damage_receipts[owner]
                receipts[event['target']] = receipts.get(event['target'], 0) + applied
                remaining -= applied
                owners[owner] -= applied
                if owners[owner] <= 0:
                    del owners[owner]
            if not owners:
                self.damage_owners.pop(event['target'], None)  # Nothing in flight for this enemy.
            if remaining > .001:
                raise ValueError('Damage acknowledgement has no authenticated owner')
            from native_guest_combat import NativeCombatBridge
            return NativeCombatBridge.record(self, **event)
        super().record(**event)

    def prune_receipts(self, now=None):
        """Forget sent receipts of gone enemies with nothing in flight (every 10 s, O(receipts))."""
        now = time.monotonic() if now is None else now
        if now < getattr(self, 'receipts_prune_due', 0):
            return
        self.receipts_prune_due = now + RECEIPT_PRUNE_SECONDS
        alive, pending, owners = self.enemy_snapshot, self.damage_pending, self.damage_owners
        for book in self.damage_receipts.values():
            for guid in [g for g in book if g not in alive and g not in pending and not owners.get(g)
                         and g not in book.dirty]:
                book.forget(guid)

    def _select_guest(self, number):
        # ponytail: reuse the tested two-peer codec; this compatibility seam is
        # bounded to three guests. Move wire fields into a DTO if it grows.
        if number == 2:
            return None
        saved = (self.world_pending, self.xp_pending, self.gold_pending, self.guest_hits, self.area_hits)
        self.selected_guest_saved = saved
        self.world_pending = self.world_queues[number]
        self.xp_pending = self.xp_queues[number]
        self.gold_pending = self.gold_by_guest[number]
        self.guest_hits = self.hit_queues[number]
        self.area_hits = self.areas_by_guest[number]
        return saved

    def _restore_guest(self, number, saved):
        if saved is not None:
            self.world_queues[number], self.xp_queues[number], self.gold_by_guest[number] = self.world_pending, self.xp_pending, self.gold_pending
            self.hit_queues[number], self.areas_by_guest[number] = self.guest_hits, self.area_hits
            self.world_pending, self.xp_pending, self.gold_pending, self.guest_hits, self.area_hits = saved
            self.selected_guest_saved = None

    def poll_network(self):
        now = time.monotonic()
        gap, self.last_poll = now - self.last_poll, now
        if now - self.last_diagnostic >= 5 or gap >= 1:
            self.record_network('network_health', poll_gap_seconds=round(gap, 3))
            self.last_diagnostic = now
        if self.peer_finished:
            return
        if self.host_closing:
            # Keep applying accepted work and publishing acknowledgments until
            # the host confirms that every recipient has drained.
            from native_guest_combat import NativeCombatBridge
            NativeCombatBridge.finish_ready(self)
        for peer, channel in list(self.channels.items()):
            self.other = peer
            try:
                for message in channel.drain():
                    self.receive_peer(peer, message)
                    if peer not in self.channels:
                        break
            except (ConnectionError, TimeoutError, queue.Full) as error:
                self.connection_ended(peer, error)
            if self.peer_finished:
                return
        now = time.monotonic()
        if now - self.last_network >= .04 or self.restart_requested:
            self.poll_generation += 1  # Enemy wire parts are encoded once per send round.
            controls = list(self.controls)
            for peer, channel in list(self.channels.items()):
                self.other = peer
                self.controls = list(controls)
                guest = peer if self.number == 1 else self.number
                saved = self._select_guest(guest)
                self.remote_template_sent = peer in self.template_sent
                self.claim_sent = self.claims_sent.get(peer)
                if self.number == 1:
                    self.damage_done = self.damage_receipts[peer]
                class DecoratedChannel:
                    def send(_, message):
                        self.decorate(peer, message)
                        if self.number == 1:
                            self.thin_snapshot(peer, channel, message)
                        channel.send(message)
                self.channel = DecoratedChannel()
                try:
                    self.send_state()
                    if self.remote_template_sent:
                        self.template_sent.add(peer)
                    self.claims_sent[peer] = self.claim_sent
                except (ConnectionError, TimeoutError, queue.Full) as error:
                    # Restore the selected queue before removing its member.
                    failed = error
                else:
                    failed = None
                finally:
                    self._restore_guest(guest, saved)
                if failed:
                    self.connection_ended(peer, failed)
            self.controls = []
            self.last_network = now

    def receive_next_run(self, peer, message):
        """The host's next-run invitation (guests, from peer 1 only) and the guests' confirmations (host)."""
        if self.number != 1 and 'next_run' in message:
            offer = message['next_run']
            if peer != 1:
                self.record(event='next_run_rejected', player=self.number, sender=peer)  # Only the host invites.
                return
            if (not isinstance(offer, dict) or set(offer) != {'room', 'invite'} or
                    not isinstance(offer['room'], str) or not NEXT_ROOM.fullmatch(offer['room']) or
                    not isinstance(offer['invite'], str) or not NEXT_INVITE.fullmatch(offer['invite'])):
                raise ValueError('Invalid next-run invitation')
            if offer != self.next_run_received:
                self.next_run_received = offer
                self.record(event='next_run_invited', player=self.number, room=offer['room'])
                self.next_run_offered(offer)
        elif self.number == 1 and 'next_run_seen' in message:
            if self.next_run_offer and message['next_run_seen'] == self.next_run_offer['room'] and peer not in self.next_run_acks:
                self.next_run_acks.add(peer)
                self.record(event='next_run_confirmed', player=peer, room=self.next_run_offer['room'])

    def next_run_offered(self, offer):
        """Guest hook: the launcher joins the offered room once this game has closed."""

    def offer_next_run(self, room, invite):
        """Host: invite every guest to the next room over the existing channels."""
        self.next_run_offer = dict(room=room, invite=invite)
        self.next_run_acks = set()
        self.record(event='next_run_offered', room=room, guests=sorted(n for n in self.members if n != 1))

    def run_over(self):
        """The host's run ended as planned (victory then New hero/Again, team defeat, give up)."""
        return 1 in self.completed_players or 1 in self.team_defeat or bool(getattr(self, 'party_surrender', False))

    def record_network(self, event, **details):
        self.record(event=event, elapsed=round(time.monotonic() - self.started, 3),
            channels={n: channel.diagnostics() for n, channel in self.channels.items()
                      if hasattr(channel, 'diagnostics')},
            states=dict(self.native_states), world_bytes=self.world_bytes,
            host_clock=self.host_clock,
            hit_queues=self.diagnostic_summary()['incoming_hits'],
            world_captured=self.counts['world_captured'], world_delivered=self.counts['world_delivered'],
            **details)

    def decorate(self, peer, message):
        if self.number == 1:
            message['departed'] = sorted(self.departed)
            if self.next_run_offer:
                message['next_run'] = dict(self.next_run_offer)
            message['host_action'] = self.end_action
            message['host_map'] = getattr(self, 'host_map', None)
            self.world_sent[peer] += len(message.get('world', []))
            message['party'] = {str(n): dict(
                name_response=binary(self.name_responses[n]) if n in self.name_responses else None,
                state=self.native_states.get(n), ready=n in self.ready, loaded=n in self.loaded,
                movement=([self.latest_movement[n][0], binary(self.latest_movement[n][1])]
                          if n in self.latest_movement else None))
                for n in self.members if n not in (1, peer) and n in self.templates}
            # Templates never change; the ordered channel delivers each once.
            sent = self.party_templates_sent.setdefault(peer, set())
            for raw_number, entry in message['party'].items():
                if int(raw_number) not in sent:
                    entry['template'] = binary(self.templates[int(raw_number)])
                    sent.add(int(raw_number))
        else:
            if self.next_run_received:
                message['next_run_seen'] = self.next_run_received['room']
            # Hits are applied only in phase 1 (apply_incoming_hit). The host's close pauses this game for good, so a
            # hit the host routed just before (in flight while the pause landed) could never apply and would keep
            # this guest from acknowledging the drain: the host then stalled 5 s and failed its shutdown (0.0.22
            # melee-run, guest 3 with one area hit). Release them, as after a host departure or the run's end.
            if (self.draining and self.native_states.get(self.number, (1,))[0] != 1
                    and not self.pause_pending.get(self.number)):
                self.clear_incoming_hits(self.number, 'drain_stopped')
            # This state follows final local damage capture. send_state includes
            # those damage/effect deltas in this same ordered TLS message.
            message['quiesced'] = bool(self.draining and
                (getattr(self, 'drain_capture_complete', False) or
                 self.native_states.get(self.number, (None,))[0] == 5 or
                 self.number in self.menu_players) and
                self.native_states.get(self.number, (1,))[0] != 1 and
                not self.pause_pending.get(self.number) and
                not self.guest_hits and not any(self.hit_queues.values()) and
                not self.area_hits and not any(self.areas_by_guest.values()) and
                not self.powerups_pending[self.number] and
                all(c.saved_context is None for c in self.clients.values()))
            forwarded = {}
            for recipient in self.guests:
                if recipient == self.number:
                    continue
                packets = self.attack_packets[recipient] + self.hurt_packets[recipient] + self.notice_packets[recipient]
                forwarded[str(recipient)] = [[op, binary(body)] for op, body in packets]
                self.attack_packets[recipient].clear()
                self.hurt_packets[recipient].clear()
                self.notice_packets[recipient].clear()
            message['forwarded'] = forwarded
            message['enemy_ack'] = self.enemy_seq
            if self.enemy_full_needed:
                message['enemy_full'] = True

    def thin_snapshot(self, peer, channel, message):
        """Keep accepted deltas flowing when the host uplink falls behind.

        Enemy and loot snapshots are replaced by the next one, so a congested
        channel skips them. Hits, world, rewards and acknowledgments are kept.
        """
        outgoing = getattr(channel, 'outgoing', None)
        congested = outgoing is not None and outgoing.qsize() >= 8
        if congested != (peer in self.congested):
            self.record(event='host_uplink_congested' if congested else 'host_uplink_recovered',
                        player=peer, **self.link_state(channel))
            (self.congested.add if congested else self.congested.discard)(peer)
        # Receipts are cumulative per enemy; the ordered channel needs only changes.
        self.prune_receipts()
        receipts = self.damage_receipts.get(peer)
        message['damage_done'] = receipts.take_changes() if isinstance(receipts, ReceiptBook) else []
        now = time.monotonic()
        # A small tolerance keeps a snapshot in every 40 ms send round despite timer jitter.
        snapshot = not congested and now >= self.snapshot_due.get(peer, 0) - .005
        if snapshot:
            # Enemy cadence (25 Hz = every send round; ~1 Mbit/s late game).
            self.snapshot_due[peer] = max(self.snapshot_due.get(peer, 0) + ENEMY_SNAPSHOT_INTERVAL, now)
            update = self.enemy_update(peer, now)
            if update is not None:
                message['enemy_update'] = update
        message.pop('enemies', None)
        if 'chests' in message:
            # Loot gates claims, so every change goes out at 25 Hz, but only
            # the changed objects. A congested link keeps the last baseline.
            current = dict(message.pop('chests'))
            if not congested:
                previous = self.chests_sent.get(peer)
                if previous is None:
                    message['chest_update'] = dict(full=True, set=[[guid, value] for guid, value in current.items()])
                else:
                    changed = [[guid, value] for guid, value in current.items() if previous.get(guid) != value]
                    removed = [guid for guid in previous if guid not in current]
                    if changed or removed:
                        message['chest_update'] = dict(full=False, set=changed, drop=removed)
                self.chests_sent[peer] = current
        if now >= self.size_report_due.get(peer, 0):
            self.size_report_due[peer] = now + 10
            sizes = {key: len(json.dumps(value, separators=(',', ':'))) for key, value in message.items()}
            self.record(event='host_message_bytes', player=peer, total=sum(sizes.values()),
                        fields={k: v for k, v in sorted(sizes.items(), key=lambda i: -i[1])[:6]},
                        payload_bytes=getattr(channel, 'payload_bytes', None),
                        wire_bytes=getattr(channel, 'wire_bytes', None))

    def enemy_wire_view(self):
        """Encode the host enemy snapshot once per send round for every recipient."""
        from online_bridge import enemy_parts, enemy_motion
        generation, view = self.enemy_view_cache
        if generation != self.poll_generation:
            view = {}
            for guid, (flat, hp, pose) in self.enemy_snapshot.items():
                stable, spans = enemy_parts(flat)
                view[guid] = (flat, stable, spans, enemy_motion(hp, pose), self.boss_definitions.get(guid))
            self.enemy_view_cache = (self.poll_generation, view)
            self.enemy_wire_text = {}
            self.enemy_view_sent = None
        return view

    def enemy_sent_view(self, view):
        """What a recipient holds after this round's update; shared, never mutated."""
        if self.enemy_view_sent is None:
            self.enemy_view_sent = {guid: (stable, spans, motion, boss)
                                    for guid, (_, stable, spans, motion, boss) in view.items()}
        return self.enemy_view_sent

    def enemy_full_entry(self, guid, flat, motion, boss):
        """A complete entry, encoded once per send round for all recipients."""
        from online_bridge import enemy_entry, ENEMY_FULL, ENEMY_BOSS, ENEMY_MOTION
        entry = self.enemy_wire_text.get(guid)
        if entry is None:
            flags = ENEMY_FULL | ENEMY_MOTION | (ENEMY_BOSS if boss is not None else 0)
            entry = self.enemy_wire_text[guid] = enemy_entry(guid, flags, flat, boss, motion=motion)
        return entry

    def enemy_update(self, peer, now):
        """Full snapshot (base None) or a delta against the last update sent.

        A known enemy carries only what changed: patched record bytes, its
        debuff spans, its motion. A changed GUID/definition/boss sends the full
        record again, which the guest revalidates.
        """
        from online_bridge import (enemy_entry, enemy_patch_runs, ENEMY_IDENTITY,
                                   ENEMY_PATCH, ENEMY_SPANS_SET, ENEMY_MOTION)
        view = self.enemy_wire_view()
        sent = self.enemy_views.get(peer)
        # Full snapshots only on demand (first update, a guest gap). A periodic
        # full is optional for diagnostics: COOP_FULL_SNAPSHOT_S=<seconds>.
        full = (sent is None or peer in self.enemy_full_requested or
                FULL_SNAPSHOT_SECONDS > 0 and now >= self.enemy_full_due.get(peer, 0))
        parts, patched = [], 0
        low, high = ENEMY_IDENTITY
        churn = self.enemy_churn
        for guid, (flat, stable, spans, motion, boss) in view.items():
            old = None if full else sent.get(guid)
            if old is None or old[3] != boss or old[0][low:high] != stable[low:high]:
                parts.append(self.enemy_full_entry(guid, flat, motion, boss))
                continue
            flags, runs = 0, ()
            if old[0] != stable:
                runs = enemy_patch_runs(old[0], stable)
                flags |= ENEMY_PATCH
                patched += 1
                for run in runs:
                    churn[run] = churn.get(run, 0) + 1
            if old[1] != spans:
                flags |= ENEMY_SPANS_SET
            if old[2] != motion:
                flags |= ENEMY_MOTION
            if flags:
                parts.append(enemy_entry(guid, flags, flat, runs=runs, spans=spans, motion=motion))
        self.enemy_churn_compared += 0 if full else len(view)
        self.enemy_churn_patched += patched
        drop = [] if full else [guid for guid in sent if guid not in view]
        if not full and not parts and not drop:
            return None
        sequence = self.enemy_sequences.get(peer, 0) + 1
        update = dict(seq=sequence, base=None if full else self.enemy_sequences[peer], blob=binary(b''.join(parts)))
        if drop:
            update['drop'] = drop
        self.enemy_sequences[peer] = sequence
        self.enemy_views[peer] = self.enemy_sent_view(view)
        if full:
            self.enemy_full_due[peer] = now + FULL_SNAPSHOT_SECONDS
            self.enemy_full_requested.discard(peer)
            self.record(event='enemy_full_snapshot', player=peer, enemies=len(view), bytes=len(update['blob']))
        if now >= self.enemy_churn_due:
            self.report_enemy_churn(now)
        return update

    def report_enemy_churn(self, now):
        """Which enemy record bytes change between updates (record offsets, +0x68 based)."""
        churn, compared = self.enemy_churn, self.enemy_churn_compared
        if compared:
            top = sorted(churn.items(), key=lambda item: -item[1])[:12]
            # [record offset, length, share of compared enemies whose run changed]
            self.record(event='enemy_record_churn', compared=compared, patched=self.enemy_churn_patched,
                        spans=[[hex(0x68 + start), end - start, round(count / compared, 3)]
                               for (start, end), count in top])
        self.enemy_churn = {}
        self.enemy_churn_compared = self.enemy_churn_patched = 0
        self.enemy_churn_due = now + 10

    def receive_peer(self, peer, message):
        if message.get('kind') == 'goodbye':
            self.connection_ended(peer, 'left')
            return
        self.receive_next_run(peer, message)
        if 'closing' in message and type(message['closing']) is not bool:
            raise ValueError('Invalid closing state')
        closing = message.get('closing') is True
        quiesced = message.get('quiesced', False)
        if type(quiesced) is not bool or quiesced and not closing:
            raise ValueError('Invalid drain quiescence acknowledgement')
        leaving = self.number == 1 and closing and not self.draining
        departed = []
        if closing:
            if self.number != 1:
                self.host_closing = True
                self.draining = True
            # A guest's drain acknowledgement is not a departure, and a host's
            # drain request must not start the guest's bounded exit timer.
            message = dict(message, closing=False)
        if self.number == 1 and isinstance(message.get('created'), list):
            message = dict(message, created=[n for n in message['created'] if n not in self.departed])
        guest = peer if self.number == 1 else self.number
        saved = self._select_guest(guest)
        self.other = peer
        # Incoming messages must use the same per-peer claim history as sends.
        # Otherwise another guest's empty state can replay a chest award.
        self.claim_sent = self.claims_sent.get(peer)
        total_delivered = self.counts['world_delivered']
        total_captured = self.counts['world_captured']
        try:
            if self.number == 1:
                if 'party' in message:
                    raise ValueError('Only the host can publish the party')
                ack, full = message.get('enemy_ack', 0), message.get('enemy_full', False)
                if type(ack) is not int or not 0 <= ack <= self.enemy_sequences.get(peer, 0) or type(full) is not bool:
                    raise ValueError('Invalid enemy snapshot acknowledgement')
                self.enemy_acked[peer] = ack
                if full:
                    self.enemy_full_requested.add(peer)
                self.counts['world_delivered'] = self.world_acked[peer]
                self.counts['world_captured'] = self.world_sent[peer]
                claim = message.get('claim')
                if claim is not None and claim.get('player', 2) != peer:
                    raise ValueError('Loot claim belongs to another player')
                # 0.0.19: every guest holds its own claim at the same time (no busy refusal any more).
                before = dict(self.damage_pending)
                self.receive_state(message)
                # The final deltas above are accepted before the FIFO barrier.
                if quiesced:
                    self.quiesced_peers.add(peer)
                else:
                    self.quiesced_peers.discard(peer)
                self.world_acked[peer] = self.counts['world_delivered']
                for guid, amount in self.damage_pending.items():
                    delta = amount - before.get(guid, 0)
                    if delta > 0:
                        owners = self.damage_owners.setdefault(guid, {})
                        owners[peer] = owners.get(peer, 0) + delta
                if not self.draining:
                    self.controls.extend(message.get('controls', []))
                for recipient, packets in message.get('forwarded', {}).items():
                    recipient = int(recipient)
                    if recipient in self.departed:
                        continue  # An already in-flight packet may name a departed peer.
                    if recipient not in self.guests or recipient == peer or len(packets) > MAX_QUEUE:
                        raise ValueError('Invalid peer packet recipient')
                    for opcode, encoded in packets:
                        if opcode not in WORLD | MOVEMENT_OPCODES | {0x96}:
                            raise ValueError('Unsupported peer packet')
                        payload = unbinary(encoded)
                        from party_markers import reject_remote_marker_packet
                        reject_remote_marker_packet(opcode, payload)
                        if opcode in MOVEMENT_OPCODES:
                            validate_movement_packet(payload, self.members, peer)
                        self.receive_summon_packet(opcode, payload, peer)
                        payload = self.sanitize_player_values(peer, opcode, payload)
                        if payload is not None:
                            self.notice_packets[recipient].append((opcode, payload))
            elif message.get('kind') == 'claim_refund':
                claim = message['claim']
                if not self.chest_claim or claim.get('guid') != self.chest_claim['guid']:
                    raise ValueError('Unexpected chest refund')
                self.chest_claim['status'] = 'refund'
                # This is a host response, not a new guest request to echo back.
                self.claim_sent = dict(self.chest_claim)
            else:
                self.receive_state(message)
                departed = message.get('departed', [])
                if (not isinstance(departed, list) or len(departed) > 3 or
                        any(type(n) is not int or n not in (*self.guests, *self.departed)
                            or n == self.number for n in departed)):
                    raise ValueError('Invalid departed party members')
                zone = message.get('host_map')
                if zone is not None:
                    from party_menu import ZONES
                    if zone not in ZONES or (getattr(self, 'host_map', None) not in (None, zone)):
                        raise ValueError('Invalid or changed host map')
                    self.host_map = zone
                action = message.get('host_action')
                if action is not None:
                    if type(action.get('sequence')) is not int or not 1 <= action['sequence'] <= 2 ** 53 or action.get('command') not in (8, 9):
                        raise ValueError('Invalid host victory action')
                    if self.end_action is None or action['sequence'] > self.end_action['sequence']:
                        self.end_action = action
                        self.end_pending[self.number] = action['command']
                for raw_number, entry in message.get('party', {}).items():
                    number = int(raw_number)
                    if number not in self.guests or number == self.number:
                        raise ValueError('Invalid party member')
                    if entry.get('name_response') is not None:
                        self.set_name_response(number, unbinary(entry['name_response'], 128))
                    if number not in self.templates:
                        if entry.get('template') is None:
                            raise ValueError('Party member template missing')
                        body = unbinary(entry['template'])
                        pose = Pose(*struct.unpack_from('<4f', body, 20))
                        guid = 0xFF0100 + number
                        clone_player(body, guid, pose)
                        self.templates[number], self.created[number] = body, set()
                        self.router.add_player(guid, str(number), pose)
                        self.router.attach_authenticated(str(number), str(number))
                        self.router.receive(str(number), frame(LOGIN, struct.pack('<Q', guid)))
                    state = entry.get('state')
                    if state is not None:
                        if len(state) != 4 or any(type(v) is not int or not 0 <= v <= MAX_COUNTER for v in state) or state[0] > 5:
                            raise ValueError('Invalid party state')
                        self.native_states[number] = tuple(state)
                    for key, target in (('ready', self.ready), ('loaded', self.loaded)):
                        if type(entry.get(key)) is not bool:
                            raise ValueError('Invalid party readiness')
                        if entry[key]:
                            target.add(number)
                    if entry.get('movement'):
                        opcode, encoded = entry['movement']
                        body = unbinary(encoded, 44)
                        self.router.receive(str(number), frame(opcode, body))
                        self.latest_movement[number] = (opcode, body)
                if message.get('restart'):
                    # Other guests' final states arrive in party, after the
                    # two-peer codec observes restart. Capture before exiting.
                    self.completed_transition(self.number, 6)
        finally:
            self.claims_sent[peer] = self.claim_sent
            if self.number == 1:
                self.counts['world_captured'] = total_captured
                self.counts['world_delivered'] = sum(self.world_acked.values())
            self._restore_guest(guest, saved)
        if leaving:
            self.remove_guest(peer)
        for number in departed:
            self.remove_guest(number)

    def finish_ready(self):
        from native_guest_combat import NativeCombatBridge
        self.draining = True  # Publish closing before waiting for guest barriers.
        if self.number != 1 and self.peer_finished:
            if self.chest_claim and self.chest_claim['status'] in ('reserved', 'removed'):
                self.record(event='disconnected_purchase_refund_pending', **self.chest_claim)
                # No guest award has happened in either state. Compensate its
                # debit on exit, even if the host already removed the chest.
                self.chest_claim['status'] = 'refund'
            abandoned = 0
            for queues in (self.attack_packets, self.hurt_packets, self.notice_packets):
                for recipient, packets in queues.items():
                    if recipient != self.number:
                        abandoned += len(packets)
                        packets.clear()
            if abandoned:
                self.record(event='outbound_packets_abandoned', count=abandoned)
            # The host can no longer acknowledge outbound attacks. Keep received
            # rewards, world updates and native callbacks subject to normal drain.
            if self.damage_pending or self.effects_pending:
                self.record(event='outbound_combat_abandoned',
                            damage=dict(self.damage_pending), effects=len(self.effects_pending))
                self.damage_pending.clear()
                self.effects_pending.clear()
            # Host hits are consumed only while the native game runs; after the
            # host left, a guest in a menu or pause would otherwise never drain.
            self.clear_incoming_hits(self.number, 'host_departed')
            # The departed host's last mirrored phase can no longer change;
            # a stale running phase would keep the drain from ever stopping.
            for n, state in list(self.native_states.items()):
                if n != self.number and state[0] == 1:
                    self.native_states[n] = (3, *state[1:])
        if self.number == 1 and not set(self.guests) <= self.quiesced_peers:
            return False
        ready = NativeCombatBridge.finish_ready(self) and (self.number != 1 or
            (not self.boss_reward_events and self.counts['world_captured'] ==
             self.counts['world_delivered'] + self.counts.get('world_abandoned', 0)))
        if ready and not self.peer_finished:
            self.last_network = 0
            self.poll_network()  # Publish final acknowledgments before goodbye.
        return ready and not (self.host_closing and not self.peer_finished)


def main():
    import argparse
    import hashlib
    import hmac
    import json
    import os
    from pathlib import Path
    import socket
    from coop_transport import accept, connect
    from native_probe import ROOT, ACTIVE_HASH, run, _candidate_home
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('host', 'join'))
    parser.add_argument('--slot', type=int, choices=(2, 3, 4))
    parser.add_argument('--players', type=int, choices=(2, 3, 4), default=4)
    parser.add_argument('--pairing', type=Path, default=(
        _candidate_home / 'pairing' if _candidate_home else ROOT / '.coop-pairing'))
    parser.add_argument('--address', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=47653)
    parser.add_argument('--seconds', type=int, default=180)
    parser.add_argument('--verify', action='store_true')
    parser.add_argument('--verify-boss', action='store_true')
    parser.add_argument('--verify-coop', action='store_true')
    parser.add_argument('--verify-economy', action='store_true')
    parser.add_argument('--verify-split', action='store_true')
    parser.add_argument('--verify-forms', action='store_true')
    parser.add_argument('--verify-surrender', action='store_true')
    parser.add_argument('--verify-melee-run', action='store_true')
    parser.add_argument('--verify-pressure', choices=('fix', '0.0.17'), help='enemy pressure diagnostic (two players)')
    parser.add_argument('--pressure-seconds', type=int, default=180)
    parser.add_argument('--pressure-pattern', choices=('circle', 'line', 'stand', 'apart', 'native'), default='circle')
    parser.add_argument('--pressure-label', default='duo')
    args = parser.parse_args()
    os.environ['COOP_PLAYERS'] = str(args.players)
    invite = json.loads((args.pairing / 'invite.json').read_text())
    def token(slot):
        return hmac.new(invite['token'].encode(), str(slot).encode(), hashlib.sha256).hexdigest()
    channels = {}
    try:
        if args.mode == 'host':
            members = {n: token(n) for n in range(2, args.players + 1)}
            with socket.create_server((args.address, args.port)) as listener:
                listener.settimeout(180)
                print('Waiting for room members', flush=True)
                while members:
                    number, channel = accept(listener, args.pairing, invite, ACTIVE_HASH, members)
                    channels[number] = channel
                    del members[number]
            for channel in channels.values():
                channel.send(dict(kind='start', players=args.players))
            number = 1
        else:
            if args.slot is None or args.slot > args.players:
                parser.error('Choose a guest slot in this room')
            number = args.slot
            channel = connect(args.address, args.port, dict(invite, token=token(number)), ACTIVE_HASH, number)
            channels[1] = channel
            deadline = time.monotonic() + 180
            while True:
                messages = channel.drain()
                if messages:
                    if messages != [dict(kind='start', players=args.players)]:
                        raise ValueError('Unexpected room launch handshake')
                    break
                if time.monotonic() > deadline:
                    raise TimeoutError('Room did not start')
                time.sleep(.02)
        adapter = GroupOnlineBridge
        if args.verify:
            from native_probe import CHOOSE, game_field
            class Verification(GroupOnlineBridge):
                def before_batch(self, client, context):
                    game = client.server + 0x10
                    if self.native_states[client.number][0] == 2:
                        count = struct.unpack('<Q', client.memory(game + game_field(0x618), 8))[0]
                        if not 1 <= count <= 16:
                            raise ValueError('Invalid native choices')
                        client.call_before(context, CHOOSE, game, (client.number - 1) % count)
                        return True
                    return super().before_batch(client, context)
            adapter = Verification
        if args.verify_boss:
            from verify_network_boss import NetworkBossVerification
            adapter = NetworkBossVerification
        if args.verify_coop:
            from verify_network_coop import NetworkCoopVerification
            adapter = NetworkCoopVerification
        if args.verify_economy:
            from verify_network_economy import NetworkEconomyVerification
            adapter = NetworkEconomyVerification
        if args.verify_melee_run:
            from verify_melee_run import MeleeRunVerification
            adapter = MeleeRunVerification
        if args.verify_pressure:
            from verify_enemy_pressure import adapter as pressure
            adapter = pressure(GroupOnlineBridge, args.verify_pressure, args.pressure_label, args.pressure_seconds,
                               args.pressure_pattern)
        if args.verify_split:
            from verify_split_spawns import SplitSpawnVerification
            adapter = SplitSpawnVerification
        if args.verify_surrender:
            from verify_surrender import adapter as surrender
            adapter = surrender(GroupOnlineBridge)
        if args.verify_forms:
            from verify_druid_forms import adapter as druid_forms
            adapter = druid_forms(GroupOnlineBridge)
        if os.environ.get('COOP_VERIFY_NATIVE_MOVEMENT') == '1':
            if not (args.verify or args.verify_split or (args.verify_pressure and args.pressure_pattern == 'native')):
                raise ValueError('Native movement input is restricted to the verification driver')
            from verify_native_input import NativeMovementDiagnostic
            class MovementVerification(NativeMovementDiagnostic, adapter):
                pass
            adapter = MovementVerification
        with (ROOT / f'analysis/group-online-{number}.jsonl').open('w') as output:
            bridge = adapter(output, number, channels)
            if (args.verify or args.verify_boss or args.verify_coop or args.verify_economy or args.verify_split or
                    args.verify_forms or args.verify_surrender or args.verify_melee_run or args.verify_pressure):
                bridge.autostart = True
            try:
                # The host owns timed diagnostics. Guests wait for its drained
                # goodbye instead of racing their own nearly-identical timers.
                run(args.seconds if number == 1 else args.seconds + 30, 1, bridge, player_numbers=[number])
            finally:
                bridge.record(event='summary', states=bridge.native_states, **bridge.counts)
            for channel in bridge.channels.values():
                try:
                    channel.finish()
                except ConnectionError:
                    # A guest that gave up was removed by the host, which closed its channel.
                    if not (getattr(bridge, 'self_surrendered', False) or bridge.peer_finished):
                        raise
    finally:
        for channel in channels.values():
            channel.close()


if __name__ == '__main__':
    main()
