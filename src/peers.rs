//! The DLL's end of the peer network: the pipe to the helper carries the Python mod's `state` messages
//! (`Kind::State {peer, message}`) in both directions, so the bridge inside the game talks to its peers like
//! the Python bridge did through `coop_transport.Channel`.
//!
//! * [`PeerPipe`]: two threads (one reads the pipe, one writes it; overlapped handles, so neither holds up
//!   the other) and bounded queues. The game never waits on the network: the hook drains what arrived and
//!   queues what to send.
//! * [`OnlineHandler`]: the engine's handler once the helper is there. At the start of every hook it drains
//!   the pipe (the Python's `poll_network` drained its channels before each event), hands the messages to
//!   the bridge, and sends what the bridge produced. Until every expected peer has connected the bridge
//!   runs offline and the messages wait in the queue.

use crate::engine::{HookHandler, Result};
use crate::ipc_client::{self, Pipe, Reader};
use azcoop_bridge::bridge::Bridge;
use azcoop_bridge::client::{Client, Hook};
use azcoop_bridge::online_send::NetEvent;
use azcoop_bridge::regs::Regs;
use azcoop_proto::ipc::{self, Command, Kind, Message};
use serde_json::Value;
use std::collections::BTreeSet;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Messages the reader thread may hold before it waits for the game (the pipe then backs up, and so do the peers).
pub const INBOX_LIMIT: usize = 1024;
/// Messages waiting for the writer thread; a full queue is the Python's "outgoing backlog": the peer is dropped.
pub const OUTBOX_LIMIT: usize = 1024;
/// How many events one hook takes at most.
pub const DRAIN_LIMIT: usize = 4096;

/// What came over the pipe.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    /// The helper linked player `.0`.
    Connected(u32),
    /// A message of player `.0`.
    State(u32, Value),
    /// The link to player `.0` ended.
    Lost(u32, String),
    /// The helper or the pipe is gone: every link is.
    Closed(String),
    /// A decision of the launcher (relay mode): the victory choice or the next-run offer.
    Command(Command),
    /// The link to player `.0` went down but its slot stays open (Step 3); `.1` is the link generation.
    Down(u32, u64),
    /// The link to player `.0` is back, generation `.1` (> 0).
    Back(u32, u64),
}

/// The grace window the DLL asks the helper for (seconds): `AZCOOP_RESUME_GRACE`, default 90, `0` = off.
pub fn resume_grace() -> Option<u64> {
    grace_from(std::env::var("AZCOOP_RESUME_GRACE").ok().as_deref())
}

/// [`resume_grace`] for a given value of the variable (an unreadable value means the default).
pub fn grace_from(value: Option<&str>) -> Option<u64> {
    let seconds = value.and_then(|v| v.trim().parse::<u64>().ok()).unwrap_or(90);
    (seconds > 0).then_some(seconds.min(ipc::MAX_GRACE_SECONDS))
}

pub struct PeerPipe {
    events: Mutex<Receiver<Event>>,
    outgoing: SyncSender<Message>,
    pub role: String,
    pipe: Arc<Pipe>,
}

impl PeerPipe {
    /// Connects to the helper (retrying while it starts), shakes hands and starts the two threads.
    pub fn connect(session: &str, build: &str, sha256: &str, pid: u32, wait: Duration) -> std::result::Result<PeerPipe, String> {
        let deadline = Instant::now() + wait;
        let pipe = loop {
            match Pipe::connect(session) {
                Ok(p) => break p,
                Err(e) if Instant::now() < deadline => {
                    let _ = e;
                    std::thread::sleep(Duration::from_millis(250));
                }
                Err(e) => return Err(format!("helper pipe not available: {e}")),
            }
        };
        let pipe = Arc::new(pipe);
        let (event_tx, event_rx) = sync_channel::<Event>(INBOX_LIMIT);
        let (role_tx, role_rx) = sync_channel::<std::result::Result<String, String>>(1);
        let (build, sha256) = (build.to_string(), sha256.to_string());
        let reading = pipe.clone();
        // the reader thread shakes hands itself, so bytes that follow the ack stay in its reader
        std::thread::Builder::new()
            .name("azcoop-peers-in".into())
            .spawn(move || {
                let mut reader = Reader::new(&reading);
                let role = ipc_client::handshake_resume(&mut reader, azcoop_proto::transport::PROTOCOL, &build, &sha256, pid, resume_grace());
                let failed = role.is_err();
                let _ = role_tx.send(role);
                if !failed {
                    read_loop(reader, event_tx);
                }
            })
            .map_err(|e| e.to_string())?;
        let role = role_rx.recv_timeout(Duration::from_secs(10)).map_err(|_| "helper handshake timed out".to_string())??;
        Self::start(pipe, role, event_rx)
    }

    /// Starts the writer thread on a pipe whose handshake is done; `events` is fed by the reader thread.
    fn start(pipe: Arc<Pipe>, role: String, events: Receiver<Event>) -> std::result::Result<PeerPipe, String> {
        let (out_tx, out_rx) = sync_channel::<Message>(OUTBOX_LIMIT);
        let writing = pipe.clone();
        std::thread::Builder::new()
            .name("azcoop-peers-out".into())
            .spawn(move || {
                while let Ok(message) = out_rx.recv() {
                    let goodbye = message.kind == Kind::Goodbye;
                    let Ok(bytes) = message.encode() else { continue };
                    if writing.write_all(&bytes).is_err() || goodbye {
                        return;
                    }
                }
            })
            .map_err(|e| e.to_string())?;
        Ok(PeerPipe { events: Mutex::new(events), outgoing: out_tx, role, pipe })
    }

    /// Everything that arrived so far (at most `limit` events).
    pub fn drain(&self, limit: usize) -> Vec<Event> {
        let rx = self.events.lock().unwrap();
        let mut out = Vec::new();
        while out.len() < limit {
            match rx.try_recv() {
                Ok(event) => out.push(event),
                Err(_) => break,
            }
        }
        out
    }

    /// Queues `message` for player `peer`. An error means the writer is behind or gone (a lost link).
    pub fn send(&self, peer: u32, message: Value) -> std::result::Result<(), String> {
        let frame = Message::new(Kind::State, ipc::state_payload(peer, message));
        match self.outgoing.try_send(frame) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err("Co-op outgoing backlog exceeded".into()),
            Err(TrySendError::Disconnected(_)) => Err("Co-op connection closed".into()),
        }
    }

    /// Queues one core event for the launcher (best effort: a full queue drops it, the next change is sent anyway).
    pub fn send_event(&self, name: &str, fields: Vec<(String, Value)>) -> bool {
        self.outgoing.try_send(Message::new(Kind::Event, ipc::event_payload(name, fields))).is_ok()
    }

    /// Tells the helper to close the links (best effort).
    pub fn goodbye(&self) {
        let _ = self.outgoing.try_send(Message::new(Kind::Goodbye, serde_json::json!({"reason": "dll"})));
    }

    pub fn pipe(&self) -> &Arc<Pipe> {
        &self.pipe
    }
}

fn read_loop(mut reader: Reader<'_>, events: SyncSender<Event>) {
    let closed = |reason: String| {
        let _ = events.send(Event::Closed(reason));
    };
    loop {
        match reader.next() {
            Ok(Some(message)) => {
                let event = match message.kind {
                    Kind::State => match ipc::parse_state(&message.payload) {
                        Ok((peer, body)) => Some(Event::State(peer, body)),
                        Err(_) => None,
                    },
                    Kind::Status => {
                        let peer = message.payload["peer"].as_u64().filter(|p| (1..=4).contains(p)).map(|p| p as u32);
                        let epoch = message.payload["epoch"].as_u64().unwrap_or(0);
                        match (peer, message.payload["event"].as_str()) {
                            (Some(p), Some("connected")) if epoch > 0 => Some(Event::Back(p, epoch)),
                            (Some(p), Some("down")) => Some(Event::Down(p, epoch)),
                            (Some(p), Some("connected")) => Some(Event::Connected(p)),
                            (Some(p), Some("lost")) => Some(Event::Lost(p, message.payload["reason"].as_str().unwrap_or("").to_string())),
                            _ => None,
                        }
                    }
                    Kind::Command => ipc::parse_command(&message.payload).ok().map(Event::Command),
                    Kind::Goodbye => return closed("the helper said goodbye".into()),
                    _ => None,
                };
                if let Some(event) = event {
                    if events.send(event).is_err() {
                        return; // nobody reads any more
                    }
                }
            }
            Ok(None) => return closed("the helper closed the pipe".into()),
            Err(e) => return closed(e),
        }
    }
}

// ---- the engine's handler ------------------------------------------------------------------------------

static NET: OnceLock<PeerPipe> = OnceLock::new();

/// Publishes the pipe to the handler (set once by the starter thread).
pub fn publish(pipe: PeerPipe) -> bool {
    NET.set(pipe).is_ok()
}

pub fn get() -> Option<&'static PeerPipe> {
    NET.get()
}

/// The Python's `ConnectionError` / `TimeoutError` names for a link failure, as `connection_ended` records them.
pub fn reason_name(text: &str) -> &'static str {
    let lower = text.to_ascii_lowercase();
    if lower.contains("stopped responding") || lower.contains("timeout") || lower.contains("timed out") {
        "TimeoutError"
    } else if lower.contains("backlog exceeded") {
        "TimeoutError"
    } else {
        "ConnectionError"
    }
}

/// What the handler keeps between hooks: who is linked, and the events the bridge has not seen yet.
pub struct Mailbox {
    /// The peers that must be linked before the network starts.
    expected: BTreeSet<u32>,
    connected: BTreeSet<u32>,
    pending: Vec<NetEvent>,
    /// Peers whose link broke on a send; reported to the bridge with the next events.
    broken: Vec<(u32, String)>,
    closed: bool,
    pub received: u64,
    /// The launcher's decisions, applied by the handler after the hook.
    commands: Vec<Command>,
}

impl Mailbox {
    pub fn new(number: u32, players: u32) -> Mailbox {
        let expected: BTreeSet<u32> = if number == 1 { (2..=players).collect() } else { [1].into_iter().collect() };
        Mailbox { expected, connected: BTreeSet::new(), pending: Vec::new(), broken: Vec::new(), closed: false, received: 0, commands: Vec::new() }
    }

    /// The expected peers are all linked, so the room is complete.
    pub fn ready(&self) -> bool {
        self.expected.is_subset(&self.connected)
    }

    /// Takes what the pipe brought.
    pub fn absorb(&mut self, events: Vec<Event>) {
        for event in events {
            match event {
                Event::Connected(peer) => {
                    self.connected.insert(peer);
                }
                Event::State(peer, message) => {
                    self.received += 1;
                    self.pending.push(NetEvent::Message(peer, message));
                }
                Event::Lost(peer, reason) => self.pending.push(NetEvent::Lost(peer, reason_name(&reason).to_string())),
                Event::Command(command) => self.commands.push(command),
                Event::Down(peer, _) => self.pending.push(NetEvent::Down(peer)),
                Event::Back(peer, epoch) => {
                    self.connected.insert(peer);
                    self.pending.push(NetEvent::Up(peer, epoch));
                }
                Event::Closed(reason) => {
                    if !self.closed {
                        self.closed = true;
                        // the whole network is gone: every expected link ended
                        for peer in self.expected.clone() {
                            self.pending.push(NetEvent::Lost(peer, reason_name(&reason).to_string()));
                        }
                    }
                }
            }
        }
        for (peer, reason) in std::mem::take(&mut self.broken) {
            self.pending.push(NetEvent::Lost(peer, reason));
        }
    }

    /// A send to `peer` failed: the link counts as broken.
    pub fn send_failed(&mut self, peer: u32, error: &str) {
        self.broken.push((peer, reason_name(error).to_string()));
    }

    /// The events for the bridge, in arrival order.
    pub fn take(&mut self) -> Vec<NetEvent> {
        std::mem::take(&mut self.pending)
    }

    /// The launcher's decisions since the last call, in arrival order.
    pub fn take_commands(&mut self) -> Vec<Command> {
        std::mem::take(&mut self.commands)
    }
}

/// The bridge plus its network: what `NativeCombatBridge` became in `OnlineBridge`/`GroupOnlineBridge`.
pub struct OnlineHandler {
    bridge: Bridge,
    number: u32,
    image_size: u64,
    mail: Mailbox,
    online: bool,
    pub sent: u64,
    watch: azcoop_bridge::control::Watch,
    /// Failures of the read-only enemy figure so far (a line for the first and then for every 64th: the figure fails every second after a run).
    sync_failures: u64,
}

/// How long a guest holds the native Enter for the host's map (`PartyMenu`: five minutes).
const MAP_WAIT: Duration = Duration::from_secs(300);

impl OnlineHandler {
    /// `PartyMenu.__call__` for the guest's native Enter: the command and its owned strings stay on the paused thread
    /// while the network is served, until the host has chosen the map.
    fn menu_gate(&mut self, client: &mut dyn Client, hook: Hook, regs: &mut Regs) -> Result<()> {
        if hook != Hook::UiCommand || self.number == 1 {
            return Ok(());
        }
        let Some(net) = get() else { return Ok(()) };
        if !self.bridge.enter_waits_for_map(client, regs, self.number)? {
            return Ok(());
        }
        let started = Instant::now();
        let base = self.bridge.now;
        loop {
            self.mail.absorb(net.drain(DRAIN_LIMIT));
            if !self.online && self.mail.ready() {
                self.bridge.go_online(self.number, self.image_size);
                self.online = true;
            }
            let now = base + started.elapsed().as_secs_f64();
            self.bridge.now = now;
            self.bridge.perf = now;
            if self.online {
                let events = self.mail.take();
                for (peer, message) in self.bridge.poll_events(client, &events)? {
                    match net.send(peer, message) {
                        Ok(()) => self.sent += 1,
                        Err(e) => self.mail.send_failed(peer, &e),
                    }
                }
            }
            if let Some(zone) = self.bridge.host_map.clone() {
                client.record(azcoop_logic::Event::new("party_enter_resumed").num("player", self.number as f64).text("zone", &zone));
                return Ok(());
            }
            if self.bridge.stop_requested || self.bridge.restart_requested || self.bridge.peer_finished() {
                return Err("Party closed while waiting for the host map".into());
            }
            if started.elapsed() >= MAP_WAIT {
                return Err("The host did not select a map within five minutes".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// The launcher's side: its decisions are carried out, then what changed for it goes out as events.
    fn control(&mut self, client: &mut dyn Client, net: &PeerPipe) {
        for command in self.mail.take_commands() {
            if let Err(e) = self.bridge.host_command(client, command.clone()) {
                client.record(azcoop_logic::Event::new("command_failed").text("reason", &e));
            }
        }
        let mut events = self.bridge.control_events(&mut self.watch);
        events.extend(crate::control::take());
        for (name, fields) in events {
            net.send_event(&name, fields);
        }
    }

    pub fn new(bridge: Bridge, number: u32, players: u32, image_size: u64) -> OnlineHandler {
        OnlineHandler { bridge, number, image_size, mail: Mailbox::new(number, players), online: false, sent: 0, watch: Default::default(), sync_failures: 0 }
    }
}

impl HookHandler for OnlineHandler {
    fn set_clock(&mut self, now: f64) {
        self.bridge.now = now;
        self.bridge.perf = now;
    }

    fn menu(&mut self, client: &mut dyn Client, hook: Hook, regs: &mut Regs) -> Result<()> {
        self.menu_gate(client, hook, regs)
    }

    fn handle(&mut self, client: &mut dyn Client, hook: Hook, regs: &mut Regs) -> Result<()> {
        self.menu_gate(client, hook, regs)?;
        // the menu's map selection and login come before the game server exists: no network round around them
        let Some(net) = get().filter(|_| !matches!(hook, Hook::MapSelect | Hook::MenuLogin)) else { return self.bridge.on_hook(client, hook, regs) };
        self.mail.absorb(net.drain(DRAIN_LIMIT));
        if !self.online && self.mail.ready() {
            self.bridge.go_online(self.number, self.image_size);
            self.online = true;
        }
        if !self.online {
            self.mail.take_commands(); // a decision made before the party is complete has nothing to act on
            return self.bridge.on_hook(client, hook, regs);
        }
        let events = self.mail.take();
        let out = self.bridge.on_hook_events(client, hook, regs, &events)?;
        for (peer, message) in out {
            match net.send(peer, message) {
                Ok(()) => self.sent += 1,
                Err(e) => self.mail.send_failed(peer, &e),
            }
        }
        self.bridge.claim_notes(client);
        self.control(client, net);
        if hook == Hook::Tick {
            // the figure only reads; a failure of it never stops the game
            if let Err(e) = self.bridge.sync_stats(client) {
                if self.sync_failures % 64 == 0 {
                    client.record(azcoop_logic::Event::new("enemy_sync_failed").text("reason", &e).num("failures", (self.sync_failures + 1) as f64));
                }
                self.sync_failures += 1;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn the_network_starts_when_every_expected_peer_is_linked() {
        let mut host = Mailbox::new(1, 3);
        assert!(!host.ready());
        host.absorb(vec![Event::Connected(2)]);
        assert!(!host.ready());
        host.absorb(vec![Event::Connected(3)]);
        assert!(host.ready());
        let mut guest = Mailbox::new(3, 3);
        assert!(!guest.ready());
        guest.absorb(vec![Event::Connected(1)]);
        assert!(guest.ready());
        let solo = Mailbox::new(1, 1);
        assert!(solo.ready(), "a solo host has nobody to wait for");
    }

    #[test]
    fn a_link_that_went_down_and_came_back_is_reported_to_the_bridge_in_order() {
        let mut host = Mailbox::new(1, 2);
        host.absorb(vec![
            Event::Connected(2),
            Event::State(2, json!({"i": 1})),
            Event::Down(2, 0),
            Event::Back(2, 1),
            Event::State(2, json!({"i": 2})),
        ]);
        assert!(host.ready());
        assert_eq!(
            host.take(),
            vec![NetEvent::Message(2, json!({"i": 1})), NetEvent::Down(2), NetEvent::Up(2, 1), NetEvent::Message(2, json!({"i": 2}))]
        );
        // a helper that only reports `Back` (it missed the down) still brings the slot up
        let mut guest = Mailbox::new(2, 2);
        guest.absorb(vec![Event::Back(1, 3)]);
        assert!(guest.ready());
        assert_eq!(guest.take(), vec![NetEvent::Up(1, 3)]);
    }

    #[test]
    fn the_grace_window_comes_from_the_environment_with_a_default() {
        assert_eq!(grace_from(None), Some(90));
        assert_eq!(grace_from(Some("30")), Some(30));
        assert_eq!(grace_from(Some(" 45 ")), Some(45));
        assert_eq!(grace_from(Some("0")), None, "0 switches the feature off");
        assert_eq!(grace_from(Some("99999")), Some(ipc::MAX_GRACE_SECONDS));
        assert_eq!(grace_from(Some("soon")), Some(90));
    }

    #[test]
    fn events_keep_their_order_and_a_lost_link_follows_its_messages() {
        let mut mail = Mailbox::new(1, 3);
        mail.absorb(vec![
            Event::State(2, json!({"i": 1})),
            Event::State(3, json!({"i": 2})),
            Event::State(2, json!({"kind": "goodbye"})),
            Event::Lost(2, "Co-op connection failed: Co-op peer stopped responding".into()),
            Event::Lost(3, "Co-op peer disconnected".into()),
        ]);
        let events = mail.take();
        assert_eq!(events.len(), 5);
        assert_eq!(events[0], NetEvent::Message(2, json!({"i": 1})));
        assert_eq!(events[3], NetEvent::Lost(2, "TimeoutError".into()));
        assert_eq!(events[4], NetEvent::Lost(3, "ConnectionError".into()));
        assert!(mail.take().is_empty());
        assert_eq!(mail.received, 3);
    }

    #[test]
    fn a_closed_pipe_ends_every_link_once_and_a_failed_send_ends_one() {
        let mut mail = Mailbox::new(1, 4);
        mail.absorb(vec![Event::Closed("the helper closed the pipe".into()), Event::Closed("again".into())]);
        let lost: Vec<u32> = mail.take().iter().map(|e| if let NetEvent::Lost(p, _) = e { *p } else { 0 }).collect();
        assert_eq!(lost, vec![2, 3, 4]);
        mail.send_failed(3, "Co-op outgoing backlog exceeded");
        mail.absorb(vec![]);
        assert_eq!(mail.take(), vec![NetEvent::Lost(3, "TimeoutError".into())]);
        let mut guest = Mailbox::new(2, 2);
        guest.absorb(vec![Event::Closed("x".into())]);
        assert_eq!(guest.take(), vec![NetEvent::Lost(1, "ConnectionError".into())]);
    }
}
