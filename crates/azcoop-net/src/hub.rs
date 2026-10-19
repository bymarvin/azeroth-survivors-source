//! The helper's relay between the DLL's pipe and the peer links (`state` mode).
//!
//! The DLL sends `Kind::State {peer, message}`; the hub puts the message on that peer's link. What the
//! links receive goes to the DLL the same way, in arrival order, followed by a `Status lost` when a link
//! ends (so the bridge sees every message a peer sent before it vanished, like the Python's `drain`).
//! The messages are not interpreted here: the Python mod's `state` dicts pass through unchanged, and the
//! validation stays in the bridge, as in the Python.
//!
//! Reconnect (Step 3): when the DLL asked for a grace window in its HELLO (`resume`), a lost link is first reported as
//! `Status down` and its slot stays open for that long. A new authenticated link for the slot replaces the lost (or even
//! a still-open) one and is announced as `Status connected` with a rising `epoch`; when the window ends the slot is final
//! (`Status lost`, later links refused) exactly as without the window. A DLL that did not ask sees today's behaviour.
//!
//! One thread reads the pipe (overlapped I/O, so it never holds up the writes); this thread polls the
//! links and writes to the pipe.

use crate::endpoint::Endpoint;
use crate::link::PeerIo;
use crate::session::Reader;
use crate::tls::TlsChannel;
use azcoop_proto::ipc::{self, Kind, Message};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

/// A peer link that finished its handshake, with the player number it plays.
pub struct Join {
    pub peer: u32,
    pub channel: TlsChannel,
}

/// What the hub did, for the boot log and the tests.
#[derive(Clone, Debug, Default)]
pub struct HubStats {
    pub to_peers: u64,
    pub from_peers: u64,
    pub joined: u64,
    pub lost: u64,
    /// Links that went down inside their grace window, and slots that came back.
    pub down: u64,
    pub rejoined: u64,
}

/// How a hub treats a lost link.
#[derive(Clone, Copy, Default)]
pub struct Resume<'a> {
    /// The grace window the DLL asked for; `None` = a lost link is final at once.
    pub grace: Option<Duration>,
    /// Called (on the hub thread, so it must not block) when a link goes down inside its window: the guest helper starts re-dialling.
    pub on_down: Option<&'a (dyn Fn(u32) + Sync)>,
}

enum Inbound {
    Message(Message),
    Closed,
    Failed(String),
}

/// Runs until the DLL says goodbye or closes the pipe. `log` receives boot-log lines (`[ INFO ]` etc. are added by the caller).
pub fn run(pipe: &Endpoint, reader: Reader<'_>, joins: Receiver<Join>, log: &(dyn Fn(&str) + Sync)) -> Result<HubStats, String> {
    run_with(pipe, reader, joins, Resume::default(), log)
}

/// [`run`] with the reconnect behaviour.
pub fn run_with(pipe: &Endpoint, reader: Reader<'_>, joins: Receiver<Join>, resume: Resume<'_>, log: &(dyn Fn(&str) + Sync)) -> Result<HubStats, String> {
    let mut stats = HubStats::default();
    std::thread::scope(|scope| {
        let (tx, rx) = channel::<Inbound>();
        let mut reader = reader;
        scope.spawn(move || loop {
            match reader.next() {
                Ok(Some(message)) => {
                    if tx.send(Inbound::Message(message)).is_err() {
                        return;
                    }
                }
                Ok(None) => {
                    let _ = tx.send(Inbound::Closed);
                    return;
                }
                Err(e) => {
                    let _ = tx.send(Inbound::Failed(e));
                    return;
                }
            }
        });
        let result = pump(pipe, &rx, &joins, &mut stats, resume, log);
        pipe.cancel_io(); // the reader thread may still be blocked in its read
        result
    })?;
    Ok(stats)
}

fn write(pipe: &Endpoint, kind: Kind, payload: Value) -> Result<(), String> {
    pipe.write_all(&Message::new(kind, payload).encode()?)
}

/// The links of one hub and what became of the slots.
struct Links {
    peers: BTreeMap<u32, PeerIo>,
    /// Slots whose link is gone but may still come back, with the time they went down.
    down: BTreeMap<u32, Instant>,
    /// Slots that are final: later links are refused.
    gone: Vec<u32>,
    /// How often each slot came back.
    epochs: BTreeMap<u32, u64>,
}

fn pump(pipe: &Endpoint, rx: &Receiver<Inbound>, joins: &Receiver<Join>, stats: &mut HubStats, resume: Resume<'_>, log: &(dyn Fn(&str) + Sync)) -> Result<(), String> {
    let mut links = Links { peers: BTreeMap::new(), down: BTreeMap::new(), gone: Vec::new(), epochs: BTreeMap::new() };
    let finish_all = |links: &mut Links| {
        for (_, io) in links.peers.iter() {
            let _ = io.finish();
        }
        links.peers.clear();
    };
    loop {
        // ---- from the DLL
        let mut busy = false;
        loop {
            match rx.recv_timeout(if busy { Duration::ZERO } else { Duration::from_millis(1) }) {
                Ok(Inbound::Message(message)) => {
                    busy = true;
                    match message.kind {
                        Kind::State => match ipc::parse_state(&message.payload) {
                            Ok((peer, body)) => {
                                if let Some(io) = links.peers.get(&peer) {
                                    match io.send(&body) {
                                        Ok(()) => stats.to_peers += 1,
                                        Err(e) => lose(pipe, &mut links, stats, resume, peer, &e, log)?,
                                    }
                                }
                            }
                            Err(e) => log(&format!("dropped a bad state message from the DLL: {e}")),
                        },
                        Kind::Goodbye => {
                            log("DLL said goodbye; closing the peer links");
                            finish_all(&mut links);
                            return Ok(());
                        }
                        _ => {}
                    }
                }
                Ok(Inbound::Closed) => {
                    log("DLL pipe closed; the game exited");
                    finish_all(&mut links);
                    return Ok(());
                }
                Ok(Inbound::Failed(e)) => {
                    finish_all(&mut links);
                    return Err(format!("DLL pipe failed: {e}"));
                }
                Err(RecvTimeoutError::Timeout) => break,
                Err(RecvTimeoutError::Disconnected) => {
                    finish_all(&mut links);
                    return Ok(());
                }
            }
        }

        // ---- new links
        while let Ok(join) = joins.try_recv() {
            if links.gone.contains(&join.peer) {
                log(&format!("refused a link for player {}: the slot is final", join.peer));
                continue;
            }
            let known = links.peers.contains_key(&join.peer) || links.down.contains_key(&join.peer);
            if known && resume.grace.is_none() {
                log(&format!("refused a second link for player {}", join.peer));
                continue;
            }
            if let Some(old) = links.peers.remove(&join.peer) {
                // a link the peer already replaced: what it still holds goes first, then it is closed
                if let Ok(messages) = old.drain() {
                    for message in messages {
                        stats.from_peers += 1;
                        write(pipe, Kind::State, ipc::state_payload(join.peer, message))?;
                    }
                }
                old.close();
            }
            links.down.remove(&join.peer);
            let epoch = if known {
                stats.rejoined += 1;
                let e = links.epochs.entry(join.peer).or_insert(0);
                *e += 1;
                *e
            } else {
                stats.joined += 1;
                links.epochs.insert(join.peer, 0);
                0
            };
            links.peers.insert(join.peer, PeerIo::spawn(join.channel, &format!("p{}", join.peer)));
            log(&if known { format!("player {} is back (epoch {epoch})", join.peer) } else { format!("player {} connected", join.peer) });
            write(pipe, Kind::Status, ipc::peer_connected(join.peer, epoch))?;
        }

        // ---- from the links
        let numbers: Vec<u32> = links.peers.keys().copied().collect();
        for number in numbers {
            let Some(io) = links.peers.get(&number) else { continue };
            match io.drain() {
                Ok(messages) => {
                    for message in messages {
                        stats.from_peers += 1;
                        write(pipe, Kind::State, ipc::state_payload(number, message))?;
                    }
                }
                Err(e) => lose(pipe, &mut links, stats, resume, number, &e, log)?,
            }
        }

        // ---- grace windows that ended
        if let Some(grace) = resume.grace {
            let now = Instant::now();
            let expired: Vec<u32> = links.down.iter().filter(|(_, since)| now.duration_since(**since) >= grace).map(|(peer, _)| *peer).collect();
            for peer in expired {
                links.down.remove(&peer);
                links.gone.push(peer);
                stats.lost += 1;
                log(&format!("player {peer} did not come back within {} s", grace.as_secs()));
                write(pipe, Kind::Status, ipc::peer_status(peer, "lost", "grace window ended"))?;
            }
        }
    }
}

fn lose(pipe: &Endpoint, links: &mut Links, stats: &mut HubStats, resume: Resume<'_>, peer: u32, reason: &str, log: &(dyn Fn(&str) + Sync)) -> Result<(), String> {
    let Some(io) = links.peers.remove(&peer) else { return Ok(()) };
    if resume.grace.is_some() {
        io.close();
        links.down.insert(peer, Instant::now());
        stats.down += 1;
        log(&format!("player {peer} link down: {reason}; the slot stays open for {} s", resume.grace.map_or(0, |g| g.as_secs())));
        let mut payload = ipc::peer_status(peer, "down", reason);
        payload["epoch"] = links.epochs.get(&peer).copied().unwrap_or(0).into(); // the link generation that went down
        write(pipe, Kind::Status, payload)?;
        if let Some(on_down) = resume.on_down {
            on_down(peer);
        }
    } else {
        links.gone.push(peer);
        stats.lost += 1;
        log(&format!("player {peer} lost: {reason}"));
        write(pipe, Kind::Status, ipc::peer_status(peer, "lost", reason))?;
    }
    Ok(())
}

// ---- relay mode: the peer links live in another process (the Python launcher) ---------------------------------

/// Bridges the DLL's pipe and a local TCP connection to the launcher, frame for frame (`ipc::Message` on both
/// sides): `State {peer, message}` and `Status {peer, event}` go through unchanged in both directions, a goodbye
/// ends the relay. `Event` passes DLL -> launcher only and `Command` launcher -> DLL only (the core validates every
/// command); anything else is dropped, so the launcher cannot talk to the helper's handshake. Used when the launcher owns the lobby, the relay servers and the peer links.
pub fn run_relay(pipe: &Endpoint, reader: Reader<'_>, mut tcp: std::net::TcpStream, log: &(dyn Fn(&str) + Sync)) -> Result<HubStats, String> {
    use std::io::{Read, Write};
    let mut stats = HubStats::default();
    let stop = std::sync::atomic::AtomicBool::new(false);
    let counts = (std::sync::atomic::AtomicU64::new(0), std::sync::atomic::AtomicU64::new(0));
    let mut tcp_writer = tcp.try_clone().map_err(|e| e.to_string())?;
    let mut reader = reader;
    std::thread::scope(|scope| {
        // DLL -> launcher
        scope.spawn(|| {
            loop {
                match reader.next() {
                    Ok(Some(message)) => match message.kind {
                        Kind::State | Kind::Status | Kind::Goodbye | Kind::Event => {
                            let goodbye = message.kind == Kind::Goodbye;
                            let Ok(bytes) = message.encode() else { continue };
                            if tcp_writer.write_all(&bytes).is_err() || goodbye {
                                break;
                            }
                            counts.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        _ => {}
                    },
                    Ok(None) | Err(_) => break,
                }
            }
            stop.store(true, std::sync::atomic::Ordering::SeqCst);
            let _ = tcp_writer.shutdown(std::net::Shutdown::Both);
        });
        // launcher -> DLL
        let mut buffer: Vec<u8> = Vec::new();
        let mut chunk = vec![0u8; 64 * 1024];
        'outer: loop {
            match tcp.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            }
            if buffer.len() > 2 * ipc::MAX_IPC {
                log("launcher backlog exceeded");
                break;
            }
            let Ok((messages, used)) = ipc::split_messages(&buffer) else { break };
            buffer.drain(..used);
            for message in messages {
                match message.kind {
                    Kind::State | Kind::Status | Kind::Goodbye | Kind::Command => {
                        let goodbye = message.kind == Kind::Goodbye;
                        let Ok(bytes) = message.encode() else { continue };
                        if pipe.write_all(&bytes).is_err() {
                            break 'outer;
                        }
                        counts.1.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        if goodbye {
                            break 'outer;
                        }
                    }
                    _ => {}
                }
            }
        }
        pipe.cancel_io();
        let _ = tcp.shutdown(std::net::Shutdown::Both);
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
    });
    stats.from_peers = counts.0.load(std::sync::atomic::Ordering::Relaxed);
    stats.to_peers = counts.1.load(std::sync::atomic::Ordering::Relaxed);
    log(&format!("relay ended: {} frames to the launcher, {} to the DLL", stats.from_peers, stats.to_peers));
    Ok(stats)
}
