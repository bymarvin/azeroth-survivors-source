//! The bridge: the hook-event dispatcher of `Bridge.__call__` (visibility_bridge.py,
//! native_guest_combat.py, boss_rewards.py) as a state machine over a [`Client`].
//!
//! One process owns one game (`client.number()`); `members` are the players of the room. All
//! decisions live in `azcoop-logic`; this module orders them exactly as the Python does.

use crate::client::{Client, Hook, Result};
use crate::io::GameIo;
use crate::menu::{host_zone, zones_of};
use crate::regs::{self, Regs};
use azcoop_game::builds::Variant;
use azcoop_game::readers::GameFields;
use azcoop_logic::economy::Economy;
use azcoop_logic::results::Results;
use azcoop_logic::revival::Room;
use azcoop_logic::Event;
use crate::guest_filter::GuestState;
use crate::ordmap::OrdMap;
use azcoop_logic::mirrors::Mirrors;
use azcoop_world::auras::{AuraOverlay, OwnAuras};
use azcoop_world::guest_input::GuestInput;
use azcoop_world::builders::system_message;
use azcoop_world::host_world::HostWorld;
use azcoop_world::rebuild::Bridge as WireBridge;
use std::collections::{BTreeMap, BTreeSet};

pub struct Build {
    pub variant: Variant,
    pub fields: GameFields,
    /// `server.connections` vector offset (`CONNECTIONS = field('server', 0x918)`).
    pub connections: u64,
    /// `field('game', 0x5C0)`: the native totem vector.
    pub totem_vector: u64,
    /// The Game fields that used to be family constants (impacts, guardian counters, surrender flag), resolved at start.
    pub raw: azcoop_game::profile::RawGameFields,
    /// The reviewed address profile of this build (hooks, fields, addresses, dispatch guards).
    pub profile: azcoop_game::profile::Profile,
}

/// `play_limits.MAX_ENEMIES`: the aura overlay's bound.
pub const MAX_ENEMIES: usize = 32_768;

pub struct Bridge {
    pub build: Build,
    pub shared_world: bool,
    pub room: Room,
    pub economy: Economy,
    pub results: Results,
    pub loaded: BTreeSet<u32>,
    pub menu_players: BTreeSet<u32>,
    /// The launcher asked this player to leave the run properly (`Command::LeaveRun`): done at the next opportunity in the game's batch.
    pub leave_requested: bool,
    /// `AZCOOP_GUEST_NEW_HERO=1`: a guest may start a new hero from the game menu after the run (the old behaviour).
    pub guest_new_hero_allowed: bool,
    /// The guest guard told the player once.
    pub guest_new_hero_held: bool,
    /// The in-game hint about the next run was shown (once per run).
    pub run_over_hint: bool,
    /// Players whose `team_defeat_delivered` line was written (the replacement itself repeats, the line does not).
    pub defeat_delivered_logged: BTreeSet<u32>,
    /// Players whose client has called in (`self.clients`); one in a game process.
    pub clients: BTreeSet<u32>,
    pub host_started: bool,
    pub restart_requested: bool,
    pub stop_requested: bool,
    /// Diagnostics only (off in the differential tests, on in the game): log a native defeat screen that nothing replaced.
    pub trace_defeat_ui: bool,
    pub hit_turn: u64,
    /// Wire-level state of the batch rebuild: templates, router poses, feeds, name registry.
    pub wire: WireBridge,
    /// Host world replication (`capture_world`).
    pub world: HostWorld,
    pub overlay: AuraOverlay,
    pub counts: BTreeMap<&'static str, u64>,
    /// Cipher position after our last batch, per player (`server_states`).
    pub server_states: BTreeMap<u32, (usize, u8)>,
    /// The bridge clock (`time.monotonic()`), set by the caller before each event.
    pub now: f64,
    pub mirrors: Mirrors,
    pub input: GuestInput,
    pub guest: GuestState,
    pub own_auras: BTreeMap<u32, OwnAuras>,
    pub aura_drops_seen: u64,
    pub native_combat_packets: u64,
    /// `ranged_targets[(attacker, spell)]` -> target player.
    pub ranged_targets: OrdMap<(u64, u32), u32>,
    /// Players whose first TICK (the one-shot installation hook) already ran.
    pub ticked: BTreeSet<u32>,
    pub dispatch_guards_installed: BTreeSet<u32>,
    /// `PartyMenu.host_map`: the zone the host chose (published to the guests).
    pub host_map: Option<String>,
    /// The guest's zone clamp has been replaced (once per process).
    pub party_map_patched: bool,
    /// Trials only (`AZCOOP_AUTO_TALENT=1`): a level-up choice is made by the core itself, like the Python acceptance drivers do
    /// (`CHOOSE` with slot `(player - 1) % count`), so an unattended round does not stop at the first level-up.
    pub auto_talent: bool,
    /// Code patches that must not be installed (`AZCOOP_SKIP_PATCHES`, for finding which one a crash comes from):
    /// `guards`, `host_world`, `guest_gate`, `spawn_balance`, `guest_tick`.
    pub skip_patches: BTreeSet<String>,
    pub world_enable: u64,
    pub guest_target: u64,
    pub pursuit_guard: u64,
    pub spawn_clone: u64,
    pub spawn_option: u64,
    pub spawn_scale: u64,
    /// The late-game stress test (test-hooks only): AZCOOP_TEST_STRESS.
    #[cfg(feature = "test-hooks")]
    pub stress: Option<crate::stress::Stress>,
    #[cfg(feature = "test-hooks")]
    pub stress_clock_done: bool,
    #[cfg(feature = "test-hooks")]
    pub stress_victory_since: Option<f64>,
    #[cfg(feature = "test-hooks")]
    pub stress_click_buffer: u64,
    #[cfg(feature = "test-hooks")]
    pub stress_clicked: bool,
    pub party_xp_buffer: u64,
    /// Client-direction frame parsers (the game's own input stream), per player.
    pub parsers: BTreeMap<u32, azcoop_world::session::ClientFrames>,
    pub latest_movement: BTreeMap<u32, (u32, Vec<u8>)>,
    /// Cipher keys of each mirrored player's server connection.
    pub connection_keys: BTreeMap<u32, Vec<u8>>,
    pub pursuit_guard_observed: bool,
    /// Keys of `self.created`: players whose login template was registered.
    pub registered: BTreeSet<u32>,
    /// Incoming-hit queues and the hit application chain.
    pub hits: azcoop_logic::hits::HitQueues,
    pub applier: azcoop_logic::apply_hit::HitApplier,
    pub hit_work_turn: BTreeMap<u32, bool>,
    pub perf: f64,
    pub powerups_pending: BTreeMap<u32, Vec<u64>>,
    pub bonus_spawns: Vec<u64>,
    pub spawning_bonus: bool,
    /// Front-loaded first wave (`AZCOOP_FRONT_LOAD=1`): at the first native spawn of a run every living player gets
    /// `ceil(4 (n-1) / n)` spawns of its own (`AZCOOP_FRONT_LOAD_COUNT` overrides), so each one meets about as many enemies as solo.
    pub front_load: bool,
    pub front_count: Option<u32>,
    pub front_loaded: bool,
    /// (enemy kind, owner) still to spawn, one per batch.
    pub front_spawns: std::collections::VecDeque<(u64, u32)>,
    /// The owner of the spawn being made (a front-loaded one); `None`: the native round robin.
    pub spawn_owner_override: Option<u32>,
    /// (attack kind, ability id, count) of the enemy attack events seen at ENEMY_TARGET, each logged once (`enemy_attack_kind`):
    /// which attacks a zone has (kind 1 with count > 0 is the radial volley that reaches ENEMY_AOE). Bounded.
    pub attack_kinds_seen: std::collections::HashSet<(u32, u32, u32)>,
    pub spawn_bonus_distance: f64,
    pub drain_capture_complete: bool,
    pub next_guest_attack: f64,
    pub guardian_count_seen: u64,
    pub boss_reward_events: Vec<crate::before_batch::RewardEvent>,
    pub boss_reward_sequence: u64,
    pub boss_reward_pending: BTreeMap<u32, Vec<crate::before_batch::RewardEvent>>,
    pub boss_reward_seen: BTreeMap<u32, u64>,
    pub boss_reward_applied: BTreeMap<u32, u64>,
    pub command_buffers: BTreeMap<u32, u64>,
    pub buffers: BTreeMap<u32, u64>,
    pub pursuit_guests: Vec<u32>,
    pub remote_display_seen: BTreeMap<(u32, u64), u32>,
    pub guest_stats: Option<(u8, f64, f64, f64)>,
    pub loading_check: f64,
    /// Seconds between two looks at the game's loading log (Python: 1 s; `AZCOOP_LOADING_POLL_MS`, default 100 ms: START up to ~0.9 s earlier).
    pub loading_poll: f64,
    pub raid_assignments: BTreeMap<u32, u8>,
    pub raid_sent: BTreeMap<u32, (u16, Vec<u8>)>,
    pub minimap_sent: BTreeMap<u32, f64>,
    /// The host's boss bar (`host_boss_hud`) and the guests' replacement buffers.
    pub host_boss_hud: Option<serde_json::Value>,
    pub hud_buffer: u64,
    pub hud_buffers: BTreeMap<u32, u64>,
    pub spawn_counts: BTreeMap<u32, u64>,
    pub spawn_turn: u64,
    pub spawn_rng: bool,
    pub spawn_kind: u64,
    pub spawn_debt: f64,
    /// The remote peer link (`OnlineBridge`), when this bridge is one end of a pair.
    pub online: Option<crate::online::Online>,
    /// Guests that left the room (`departed`).
    pub departed: BTreeSet<u32>,
    /// Guests whose surrender broadcast was already refused (`surrender_rejected`).
    pub surrender_rejected: BTreeSet<u32>,
    /// A restart received from the host is not echoed back (`remote_restart`).
    pub remote_restart: bool,
    /// `client.saved_context is not None` of the client that last called in (`self.clients`).
    pub client_saved: bool,
}

fn u32_at(v: &[u8]) -> u32 {
    u32::from_le_bytes(v[..4].try_into().unwrap())
}

impl Bridge {
    /// `Bridge(output, shared_world=True)` with `COOP_PLAYERS` players.
    pub fn new(build: Build, players: u32) -> Result<Bridge> {
        if !(1..=4).contains(&players) {
            return Err("Co-op rooms support one to four players".into());
        }
        let members: Vec<u32> = (1..=players).collect();
        let guests: Vec<u32> = members[1..].to_vec();
        let mut economy = Economy { members: members.clone(), guests: guests.clone(), guardian_offset: build.raw.guardian_choices, ..Default::default() };
        for g in &guests {
            economy.xp_queues.insert(*g, 0);
        }
        let mut room = Room {
            members: members.clone(),
            guests: guests.iter().copied().collect(),
            release_7264: build.variant.is_7264_family(),
            surrender_flag: build.raw.surrender_flag,
            ..Default::default()
        };
        for m in &members {
            room.notice.insert(*m, Vec::new());
            room.hurt.insert(*m, Vec::new());
            economy.notice.insert(*m, Vec::new());
        }
        Ok(Bridge {
            shared_world: true,
            room,
            economy,
            results: Results { layout: Some(build.variant.result_evaluation()), ..Default::default() },
            loaded: BTreeSet::new(),
            menu_players: BTreeSet::new(),
            leave_requested: false,
            guest_new_hero_allowed: std::env::var("AZCOOP_GUEST_NEW_HERO").is_ok_and(|v| v == "1"),
            guest_new_hero_held: false,
            run_over_hint: false,
            defeat_delivered_logged: BTreeSet::new(),
            clients: BTreeSet::new(),
            host_started: false,
            restart_requested: false,
            stop_requested: false,
            trace_defeat_ui: false,
            hit_turn: 0,
            wire: WireBridge { members: members.clone(), guests: guests.clone(), shared_world: true, ..Default::default() },
            world: HostWorld::default(),
            overlay: AuraOverlay::new(MAX_ENEMIES),
            counts: [
                ("created", 0u64), ("relayed", 0), ("native_moves", 0), ("unsupported_moves", 0), ("world_captured", 0), ("world_delivered", 0),
                ("guest_suppressed", 0), ("serializer_stops", 0), ("batch_reads", 0),
            ]
            .into_iter()
            .collect(),
            server_states: BTreeMap::new(),
            now: 0.0,
            mirrors: {
                let mut mirrors = Mirrors::new(build.variant, 126_312_448);
                mirrors.smoothing = std::env::var("COOP_MIRROR_SMOOTH").map_or(true, |v| v != "0");
                mirrors
            },
            input: GuestInput::new(&members),
            guest: GuestState::new(&members),
            own_auras: members.iter().map(|m| (*m, OwnAuras::new(MAX_ENEMIES))).collect(),
            aura_drops_seen: 0,
            native_combat_packets: 0,
            ranged_targets: OrdMap::default(),
            ticked: BTreeSet::new(),
            dispatch_guards_installed: BTreeSet::new(),
            host_map: None,
            party_map_patched: false,
            auto_talent: false,
            skip_patches: BTreeSet::new(),
            world_enable: 0,
            guest_target: 0,
            pursuit_guard: 0,
            spawn_clone: 0,
            spawn_option: 0,
            spawn_scale: 0,
            #[cfg(feature = "test-hooks")]
            stress: crate::stress::Stress::load(&build.profile.sha256)?,
            #[cfg(feature = "test-hooks")]
            stress_clock_done: false,
            #[cfg(feature = "test-hooks")]
            stress_victory_since: None,
            #[cfg(feature = "test-hooks")]
            stress_click_buffer: 0,
            #[cfg(feature = "test-hooks")]
            stress_clicked: false,
            party_xp_buffer: 0,
            parsers: BTreeMap::new(),
            latest_movement: BTreeMap::new(),
            connection_keys: BTreeMap::new(),
            pursuit_guard_observed: false,
            registered: BTreeSet::new(),
            hits: Default::default(),
            applier: Default::default(),
            hit_work_turn: BTreeMap::new(),
            perf: 0.0,
            powerups_pending: members.iter().map(|m| (*m, Vec::new())).collect(),
            bonus_spawns: Vec::new(),
            spawning_bonus: false,
            front_load: std::env::var("AZCOOP_FRONT_LOAD").is_ok_and(|v| v == "1"),
            front_count: std::env::var("AZCOOP_FRONT_LOAD_COUNT").ok().and_then(|v| v.parse().ok()).filter(|n| (1..=8).contains(n)),
            front_loaded: false,
            front_spawns: std::collections::VecDeque::new(),
            spawn_owner_override: None,
            attack_kinds_seen: std::collections::HashSet::new(),
            spawn_bonus_distance: 100.0,
            drain_capture_complete: false,
            next_guest_attack: 0.0,
            guardian_count_seen: 0,
            boss_reward_events: Vec::new(),
            boss_reward_sequence: 0,
            boss_reward_pending: guests.iter().map(|g| (*g, Vec::new())).collect(),
            boss_reward_seen: guests.iter().map(|g| (*g, 0)).collect(),
            boss_reward_applied: guests.iter().map(|g| (*g, 0)).collect(),
            command_buffers: BTreeMap::new(),
            buffers: BTreeMap::new(),
            pursuit_guests: guests.clone(),
            remote_display_seen: BTreeMap::new(),
            guest_stats: None,
            loading_check: 0.0,
            loading_poll: std::env::var("AZCOOP_LOADING_POLL_MS").ok().and_then(|v| v.parse::<f64>().ok()).filter(|ms| (10.0..=5000.0).contains(ms)).map_or(0.1, |ms| ms / 1000.0),
            raid_assignments: members.iter().map(|m| (*m, (*m - 1) as u8)).collect(),
            raid_sent: BTreeMap::new(),
            minimap_sent: BTreeMap::new(),
            host_boss_hud: None,
            hud_buffer: 0,
            hud_buffers: BTreeMap::new(),
            spawn_counts: members.iter().map(|m| (*m, 0)).collect(),
            spawn_turn: 0,
            spawn_rng: false,
            spawn_kind: 0,
            spawn_debt: 0.0,
            online: None,
            departed: BTreeSet::new(),
            surrender_rejected: BTreeSet::new(),
            remote_restart: false,
            client_saved: false,
            build,
        })
    }

    pub fn members(&self) -> &[u32] {
        &self.room.members
    }

    /// Return from the hooked function without running it: the caller's address is read at `[rsp]`.
    pub(crate) fn skip_function(client: &mut dyn Client, regs: &mut Regs) -> Result<()> {
        let stack = regs.q(regs::RSP);
        let return_address = u64::from_le_bytes(client.memory(stack, 8)?[..8].try_into().unwrap());
        regs.skip_with(return_address);
        Ok(())
    }

    /// `completed_transition(number, command, phase)`: a guest's pending combat hits are obsolete once its run ended.
    pub(crate) fn completed_transition(&mut self, client: &mut dyn Client, regs: &mut Regs, number: u32, command: u32, phase: Option<u64>) {
        self.refresh();
        let state_of = |room: &Room, n: u32| room.native_states.get(&n).map_or(0, |s| s[0]);
        let phase_now = phase.unwrap_or_else(|| state_of(&self.room, number));
        let ended = phase_now == 5 || (phase_now == 4 && self.room.members.iter().all(|n| state_of(&self.room, *n) == 4));
        let will = matches!(command, 6 | 9) && !self.room.completed_players.contains(&number) && ended;
        let mut io = GameIo::new(client, regs, &self.build.fields, &mut self.results);
        if will && self.room.guests.contains(&number) {
            self.hits.clear_incoming_hits(&mut io, number, "run_transition", self.now);
        }
        self.room.completed_transition(&mut io, number, command, phase);
    }

    /// `Bridge.__call__` for one hook event.
    pub fn on_hook(&mut self, client: &mut dyn Client, hook: Hook, regs: &mut Regs) -> Result<()> {
        azcoop_logic::skips::set_clock(self.now);
        if matches!(hook, Hook::MapSelect | Hook::MenuLogin) {
            // PartyMenu.__call__ comes before everything else and needs no server object: the map selection and the
            // login happen in the menu, before the first TICK, and never reach the base handler.
            let number = client.number();
            let result = if hook == Hook::MapSelect { self.map_select(client, regs, number) } else { self.menu_login(client, regs, number) };
            self.flush_outputs();
            return result;
        }
        if self.online.is_none() {
            let result = self.dispatch(client, hook, regs);
            self.flush_outputs();
            return result;
        }
        let (result, pauses) = {
            let mut tap = crate::online_send::Tap { inner: client, pauses: Vec::new() };
            let result = self.dispatch(&mut tap, hook, regs);
            (result, tap.pauses)
        };
        self.flush_outputs();
        let absorbed = self.absorb_events(pauses);
        result.and(absorbed)
    }

    fn dispatch(&mut self, client: &mut dyn Client, hook: Hook, regs: &mut Regs) -> Result<()> {
        let number = client.number();
        self.refresh();
        // BossRewards and NativeCombatBridge act before the base handler sees the event.
        if self.native_hook_branches(client, hook, regs, number)?.is_some() {
            return Ok(());
        }
        // NativeCombatBridge: a guest's own mirror XP awards are suppressed before anything else sees them.
        if hook == Hook::AwardXp && number != 1 && self.shared_world {
            let is_request = if client.saved_context() {
                let top = u64::from_le_bytes(client.memory(regs.q(regs::RSP), 8)?[..8].try_into().unwrap());
                top != client.call_return()
            } else {
                true
            };
            if is_request {
                Bridge::skip_function(client, regs)?;
                client.record(Event::new("mirror_xp_suppressed"));
                return Ok(());
            }
        }
        // The base handler.
        if hook == Hook::Write {
            return self.write(client, regs, number); // checks the menu itself, after the pursuit guard
        }
        self.clients.insert(number);
        self.client_saved = client.saved_context();
        if hook == Hook::Tick {
            return self.tick(client, regs, number); // its native-combat half also runs for a player back in the menu
        }
        if self.menu_players.contains(&number) {
            return Ok(()); // Native character-selection lifecycle owns this server again.
        }
        match hook {
            Hook::UiCommand => self.ui_command(client, regs, number),
            Hook::Hurt => self.hurt(client, regs, number),
            Hook::Move => {
                if regs.q(regs::RCX) != client.server() + 0x10 {
                    return Err("Unexpected native movement game object".into());
                }
                self.room.ready.insert(number);
                client.disable_hook(Hook::Move);
                client.record(Event::new("native_ready").num("player", number as f64));
                Ok(())
            }
            Hook::Start => {
                if self.shared_world && self.loaded.len() != self.room.members.len() {
                    return Bridge::skip_function(client, regs); // Defer native start until all clients finish loading.
                }
                if number == 1 {
                    self.host_started = true;
                }
                client.record(Event::new("native_start").num("player", number as f64));
                Ok(())
            }
            Hook::AwardXp => {
                let amount = (regs.q(regs::RDX) & 0xFFFF_FFFF) as i128;
                if number == 1 {
                    if self.economy.guests.contains(&2) {
                        self.economy.xp_pending += amount;
                    }
                    for guest in self.economy.guests.clone() {
                        if guest != 2 {
                            *self.economy.xp_queues.entry(guest).or_insert(0) += amount;
                        }
                    }
                    client.record(Event::new("native_xp_award").num("amount", amount as f64));
                }
                Ok(())
            }
            Hook::Choose => {
                client.record(Event::new("native_talent_choice").num("player", number as f64).num("slot", regs.q(regs::RDX) as f64));
                Ok(())
            }
            Hook::Pause | Hook::Resume => self.pause_event(client, regs, number, hook == Hook::Pause),
            Hook::Serialize => self.serialize(client, regs, number),
            _ => Ok(()), // hooks without a base-handler branch
        }
    }

    /// `PartyMenu.__call__` for MAP_SELECT, host side: only the explicit native Enter selection publishes the host map
    /// (the startup/default config must not release waiting guests). The guest side (enforcing the host's map with a
    /// code patch) is not part of this slice: a guest keeps the native menu.
    fn map_select(&mut self, client: &mut dyn Client, regs: &mut Regs, number: u32) -> Result<()> {
        let Some(menu) = self.build.profile.menu.clone() else { return Ok(()) };
        if number != 1 {
            return self.guest_map_clamp(client, &menu);
        }
        let caller = u64::from_le_bytes(client.memory(regs.q(regs::RSP), 8)?[..8].try_into().unwrap()).wrapping_sub(client.base());
        if caller != menu.host_map_return {
            return Ok(());
        }
        let zones = zones_of(Some(&menu));
        let selected = host_zone(client, regs.q(regs::RDX), regs.q(regs::R8), &zones)?;
        if self.host_map.as_deref().is_some_and(|m| m != selected) {
            return Err("Start a new room to change the party map".into());
        }
        client.record(Event::new("host_map_selected").text("zone", &selected));
        self.host_map = Some(selected);
        Ok(())
    }

    /// `PartyMenu.__call__` for MAP_SELECT on a guest: once the host's map is known, the native zone clamp is replaced
    /// (once) by `mov eax, <zone index>; jmp <allocation path>`, so the guest's own selection becomes the host's zone.
    /// Class and gear stay the player's own. Before the host chose, the startup / menu previews run unchanged.
    fn guest_map_clamp(&mut self, client: &mut dyn Client, menu: &azcoop_game::profile::Menu) -> Result<()> {
        if self.party_map_patched {
            return Ok(());
        }
        let Some(zone) = self.host_map.clone() else { return Ok(()) };
        let Some(index) = zones_of(Some(menu)).iter().position(|z| *z == zone) else { return Err("Guest cannot load before the host chooses a map".into()) };
        let Some(clamp) = &menu.clamp else { return Err("The build has no verified map clamp".into()) };
        let site = client.base() + clamp.site;
        if client.memory(site, clamp.expected.len())? != clamp.expected {
            return Err("Native zone clamp changed".into());
        }
        let mut patch = vec![0xB8];
        patch.extend_from_slice(&(index as u32).to_le_bytes());
        patch.extend(azcoop_patch::absolute_jump(client.base() + clamp.allocation_path));
        if patch.len() > clamp.expected.len() {
            return Err("Map patch does not fit the clamp".into());
        }
        client.patch(site, &patch)?;
        self.party_map_patched = true;
        client.record(Event::new("guest_map_enforced").num("player", client.number() as f64).text("zone", &zone));
        Ok(())
    }

    /// `PartyMenu.__call__` for the login branch: a guest's login must ask for the host's map, then the branch is taken
    /// unconditionally (the requested map is borrowed); a host that reaches it emulates the original `jnz`.
    fn menu_login(&mut self, client: &mut dyn Client, regs: &mut Regs, number: u32) -> Result<()> {
        let Some(login) = self.build.profile.menu.as_ref().and_then(|m| m.login.clone()) else { return Ok(()) };
        let destination = if number != 1 {
            let Some(zone) = self.host_map.clone() else { return Err("Guest login has no confirmed host map".into()) };
            let size = u64::from_le_bytes(client.memory(regs.q(regs::RBP) + login.requested_length_stack, 8)?[..8].try_into().unwrap());
            if !(1..=16).contains(&size) {
                return Err("Invalid borrowed login map length".into());
            }
            let name = client.memory(regs.q(regs::R15), size as usize)?;
            if name != zone.as_bytes() {
                return Err("Guest requested a different login map from the host".into());
            }
            client.record(Event::new("guest_login_map_verified").num("player", number as f64).text("zone", &zone));
            login.continuation
        } else {
            // defensive emulation of `jnz +2+disp`: taken unless ZF
            let zero = regs.eflags() & 0x40 != 0;
            if zero { regs.q(regs::RIP).wrapping_sub(client.base()) + 2 } else { login.continuation }
        };
        regs.set_q(regs::RIP, client.base() + destination);
        Ok(())
    }

    /// `PartyMenu.__call__` for UI_COMMAND: does this native Enter have to wait for the host's map? (A guest that has not been
    /// told the zone yet, and has not entered a world before.) The caller keeps the native command on the paused thread
    /// and polls the network until the map is known.
    pub fn enter_waits_for_map(&mut self, client: &mut dyn Client, regs: &Regs, number: u32) -> Result<bool> {
        let Some(menu) = self.build.profile.menu.clone() else { return Ok(false) };
        let command = u32::from_le_bytes(client.memory(regs.q(regs::RDX), 4)?[..4].try_into().unwrap());
        let finished = self.menu_players.contains(&number) || self.room.ready.contains(&number);
        let waiting = number != 1 && self.host_map.is_none();
        let wait = command == menu.enter_tag && waiting && !finished;
        if wait {
            client.record(Event::new("party_waiting_for_map").num("player", number as f64));
        }
        Ok(wait)
    }

    fn ui_command(&mut self, client: &mut dyn Client, regs: &mut Regs, number: u32) -> Result<()> {
        let command = u32_at(&client.memory(regs.q(regs::RDX), 4)?);
        let phase = if matches!(command, 6 | 8 | 9) {
            let address = regs.q(regs::RCX) + 0x10 + self.build.fields.get(0x8BF)?;
            client.memory(address, 1)?[0] as u64
        } else {
            self.room.native_states.get(&number).map_or(0, |s| s[0])
        };
        // Guest guard (player crash reports: 4 of 5 guest heap corruptions came 0.03-0.5 s after a guest's own New hero after a team
        // defeat): after the party's run ended, a guest's in-game New hero does not start a native world of its own; the next run
        // comes from the host (Next run) and the launcher restarts the game. Our own leave call (saved context) passes.
        // AZCOOP_GUEST_NEW_HERO=1 restores the old behaviour.
        let run_over = !self.room.team_defeat.is_empty() || !self.room.completed_players.is_empty() || self.room.party_surrender;
        if number != 1 && command == 9 && phase != 5 && run_over && !client.saved_context() && !self.guest_new_hero_allowed {
            if !self.guest_new_hero_held {
                self.guest_new_hero_held = true;
                if let Ok(notice) = system_message("The party's run is over. Wait for the host to start the next run, or close the game to leave.") {
                    self.room.notice.entry(number).or_default().push(notice);
                }
            }
            client.record(Event::new("guest_new_hero_held").num("player", number as f64).num("phase", phase as f64));
            return Bridge::skip_function(client, regs);
        }
        if command == 9 && phase != 5 {
            self.completed_transition(client, regs, number, command, Some(phase));
        }
        if matches!(command, 8 | 9) && (!client.saved_context() || client.call_is_request()) && phase == 5 {
            if number == 1 {
                let mut io = GameIo::new(client, regs, &self.build.fields, &mut self.results);
                self.room.request_victory_action(&mut io, command)?;
            } else {
                let notice = system_message("The host chooses whether the party keeps fighting or returns to character selection.")?;
                self.room.notice.entry(number).or_default().push(notice);
            }
            return Bridge::skip_function(client, regs);
        }
        if command == 6 {
            // Native Again command has no owned payload.
            self.completed_transition(client, regs, number, command, Some(phase));
            self.restart_requested = true;
            Bridge::skip_function(client, regs)?;
            client.record(Event::new("shared_restart_requested").num("player", number as f64));
        }
        Ok(())
    }

    fn pause_event(&mut self, client: &mut dyn Client, regs: &mut Regs, number: u32, pause: bool) -> Result<()> {
        if self.room.draining {
            // The native call still returns normally; repair a late Resume through the existing owned
            // Pause call at the next batch.
            self.room.paused = true;
            if !pause {
                self.room.pause_pending.insert(number, true);
            }
            return Ok(());
        }
        // Calls mirrored by us must not feed back as fresh player requests.
        let fresh = !client.saved_context() || client.call_is_request();
        if fresh && self.wire.poses.contains_key(&number) {
            let address = regs.q(regs::RCX) + self.build.fields.get(0x8BF)?;
            let phase = client.memory(address, 1)?[0];
            if phase == if pause { 1 } else { 3 } || phase == 4 {
                self.room.paused = pause;
                let state = self.room.paused;
                for n in self.clients.clone() {
                    self.room.pause_pending.insert(n, state);
                }
                client.record(Event::new("shared_pause_requested").num("player", number as f64).num("paused", state as u8 as f64));
            }
        }
        Ok(())
    }
}
