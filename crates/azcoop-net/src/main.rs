//! Azeroth Survivors Together co-op network helper.
//!
//! Runs beside the game, never inside it. It owns the peer link (TLS,
//! PROTOCOL 5) and the per-user local pipe to the DLL, and relays the host's
//! WORLD stream to the guest. This is the one-way vertical slice
//! (host WORLD -> guest apply); guest->host input is the next milestone.
//!
//! Usage (the launcher supplies these; nothing is read from the network):
//!   azcoop-net --role host  --session <hex> --game-pid <n> --build <id>
//!              --game-sha <hex> --listen <addr>
//!   azcoop-net --role guest --session <hex> --game-pid <n> --build <id>
//!              --game-sha <hex> --connect <addr>
//!              --fingerprint <hex> --token <hex>
//!
//! The host prints its invite (fingerprint + token) to stdout for the launcher
//! to hand to the guest out of band; secrets never go in the log.

use std::collections::HashMap;
use std::net::{TcpListener, TcpStream};

use azcoop_net::peer::{Invite, Pairing};
use azcoop_net::session::Reader;
use azcoop_net::{endpoint, hub, relay, session, tls};
use azcoop_proto::ipc::{Kind, Message};
use azcoop_proto::transport::PROTOCOL;

mod bootlog;

fn main() {
    let args = parse_args();
    let role = args.get("role").cloned().unwrap_or_default();
    bootlog::init("azcoop-net.log");
    bootlog::info(&format!("azcoop-net {} starting, role {role}", env!("CARGO_PKG_VERSION")));

    let result = match role.as_str() {
        "host" | "guest" if args.get("mode").map(String::as_str) == Some("relay") => run_relay_mode(&args, &role),
        "host" if args.get("mode").map(String::as_str) == Some("state") => run_host_state(&args),
        "guest" if args.get("mode").map(String::as_str) == Some("state") => run_guest_state(&args),
        "host" => run_host(&args),
        "guest" => run_guest(&args),
        other => Err(format!("unknown --role {other:?} (expected host or guest)")),
    };
    if let Err(e) = result {
        bootlog::error(&format!("co-op helper stopped: {e}"));
        std::process::exit(1);
    }
}

fn require<'a>(args: &'a HashMap<String, String>, key: &str) -> Result<&'a String, String> {
    args.get(key).ok_or_else(|| format!("missing --{key}"))
}

/// `--members 2:<token>,3:<token>`: the token each guest slot must present (default: the session token for slot 2).
fn parse_members(args: &HashMap<String, String>, fallback: &str) -> Result<std::collections::BTreeMap<u32, String>, String> {
    let mut members = std::collections::BTreeMap::new();
    match args.get("members").filter(|m| !m.is_empty()) {
        None => {
            members.insert(2, fallback.to_string());
        }
        Some(list) => {
            for entry in list.split(',') {
                let (slot, token) = entry.split_once(':').ok_or("bad --members entry")?;
                let slot: u32 = slot.parse().map_err(|_| "bad --members slot")?;
                if !(2..=4).contains(&slot) || token.is_empty() {
                    return Err("bad --members entry".into());
                }
                members.insert(slot, token.to_string());
            }
        }
    }
    Ok(members)
}

/// Host in `state` mode: every guest of the room links to this helper; the DLL's bridge exchanges the Python mod's
/// `state` messages with them through the hub.
fn run_host_state(args: &HashMap<String, String>) -> Result<(), String> {
    let session_id = require(args, "session")?;
    let game_pid: u32 = require(args, "game-pid")?.parse().map_err(|_| "bad --game-pid")?;
    let build = require(args, "build")?.clone();
    let game_sha = require(args, "game-sha")?;
    let listen = require(args, "listen")?;

    let pairing = std::sync::Arc::new(Pairing::generate()?);
    let members = parse_members(args, &pairing.invite.token)?;
    println!("invite fingerprint {}", pairing.invite.fingerprint);
    println!("invite token {}", pairing.invite.token);
    bootlog::info("generated per-session certificate; invite printed to stdout");

    bootlog::info(&format!("serving pipe for session {session_id}"));
    let pipe = endpoint::serve(session_id)?;
    let mut reader = Reader::new(&pipe);
    let (role, grace) = session::helper_accept_resume(&mut reader, game_pid, PROTOCOL, &build, game_sha, "host")?;
    bootlog::info(&format!("DLL connected and accepted as {role}"));
    if let Some(seconds) = grace {
        bootlog::info(&format!("reconnect enabled: a lost guest link keeps its slot for {seconds} s"));
    }
    let exit_logged = azcoop_net::watch::watch_exit(game_pid, |line| bootlog::info(line));

    let listener = TcpListener::bind(listen).map_err(|e| e.to_string())?;
    bootlog::info(&format!("listening for the co-op guests on {listen}"));
    let (joins_tx, joins_rx) = std::sync::mpsc::channel::<hub::Join>();
    let handshakes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let Ok(tcp) = incoming else { continue };
            if handshakes.load(std::sync::atomic::Ordering::SeqCst) >= 8 {
                continue; // too many half-open links: drop this one
            }
            handshakes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let (pairing, members, build, joins_tx, handshakes) = (pairing.clone(), members.clone(), build.clone(), joins_tx.clone(), handshakes.clone());
            std::thread::spawn(move || {
                let from = tcp.peer_addr().map(|a| a.to_string()).unwrap_or_default();
                match tls::host_accept_member(tcp, &pairing, &build, &|slot| members.get(&slot).cloned()) {
                    Ok((peer, channel)) => {
                        bootlog::info(&format!("guest for slot {peer} connected from {from}"));
                        let _ = joins_tx.send(hub::Join { peer, channel });
                    }
                    Err(e) => bootlog::warn(&format!("refused a co-op link from {from}: {e}")),
                }
                handshakes.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            });
        }
    });
    let resume = hub::Resume { grace: grace.map(std::time::Duration::from_secs), on_down: None };
    let stats = hub::run_with(&pipe, reader, joins_rx, resume, &|line| bootlog::info(line))?;
    azcoop_net::watch::wait_logged(&exit_logged, 3.0);
    bootlog::info(&format!(
        "hub ended: {} to peers, {} from peers, {} joined, {} lost, {} went down, {} came back",
        stats.to_peers, stats.from_peers, stats.joined, stats.lost, stats.down, stats.rejoined
    ));
    Ok(())
}

/// `relay` mode: the launcher (Python) owns the lobby, the relay servers and the peer links; this helper only
/// serves the DLL's pipe and passes `State`/`Status` frames to and from the launcher over a local TCP connection
/// (127.0.0.1, one connection, the first frame must carry `--relay-token`). It prints `relay port <n>` first.
fn run_relay_mode(args: &HashMap<String, String>, role: &str) -> Result<(), String> {
    let session_id = require(args, "session")?;
    let game_pid: u32 = require(args, "game-pid")?.parse().map_err(|_| "bad --game-pid")?;
    let build = require(args, "build")?;
    let game_sha = require(args, "game-sha")?;
    let token = require(args, "relay-token")?;
    if token.len() < 32 {
        return Err("--relay-token is too short".into());
    }
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    println!("relay port {}", listener.local_addr().map_err(|e| e.to_string())?.port());
    use std::io::Write as _;
    let _ = std::io::stdout().flush();
    bootlog::info("waiting for the launcher");
    let mut tcp = loop {
        let (mut tcp, from) = listener.accept().map_err(|e| e.to_string())?;
        let _ = tcp.set_read_timeout(Some(std::time::Duration::from_secs(10)));
        let mut buffer: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 4096];
        let first = loop {
            match std::io::Read::read(&mut tcp, &mut chunk) {
                Ok(0) | Err(_) => break None,
                Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            }
            if let Ok((messages, _)) = azcoop_proto::ipc::split_messages(&buffer) {
                if let Some(m) = messages.into_iter().next() {
                    break Some(m);
                }
            }
            if buffer.len() > 4096 {
                break None;
            }
        };
        if first.is_some_and(|m| m.kind == Kind::Hello && m.payload["token"].as_str() == Some(token.as_str())) {
            let _ = tcp.set_read_timeout(None);
            bootlog::info(&format!("launcher connected from {from}"));
            break tcp;
        }
        bootlog::warn(&format!("refused a relay connection from {from}"));
    };
    let _ = tcp.write_all(&Message::new(Kind::HelloAck, serde_json::json!({"accepted": true})).encode()?);

    bootlog::info(&format!("serving pipe for session {session_id}"));
    let pipe = endpoint::serve(session_id)?;
    let mut reader = Reader::new(&pipe);
    let accepted = session::helper_accept_with(&mut reader, game_pid, PROTOCOL, build, game_sha, role)?;
    bootlog::info(&format!("DLL connected and accepted as {accepted}"));
    let exit_logged = azcoop_net::watch::watch_exit(game_pid, |line| bootlog::info(line));
    let stats = hub::run_relay(&pipe, reader, tcp, &|line| bootlog::info(line))?;
    azcoop_net::watch::wait_logged(&exit_logged, 3.0);
    bootlog::info(&format!("relay done: {} frames from the DLL, {} to it", stats.from_peers, stats.to_peers));
    Ok(())
}

/// Guest in `state` mode: one link to the host (player 1).
fn run_guest_state(args: &HashMap<String, String>) -> Result<(), String> {
    let session_id = require(args, "session")?;
    let game_pid: u32 = require(args, "game-pid")?.parse().map_err(|_| "bad --game-pid")?;
    let build = require(args, "build")?;
    let game_sha = require(args, "game-sha")?;
    let connect = require(args, "connect")?;
    let slot: u32 = require(args, "slot")?.parse().map_err(|_| "bad --slot")?;
    if !(2..=4).contains(&slot) {
        return Err("--slot must be 2..4".into());
    }
    let invite = Invite { protocol: PROTOCOL, fingerprint: require(args, "fingerprint")?.clone(), token: require(args, "token")?.clone() };

    bootlog::info(&format!("serving pipe for session {session_id}"));
    let pipe = endpoint::serve(session_id)?;
    let mut reader = Reader::new(&pipe);
    let (role, grace) = session::helper_accept_resume(&mut reader, game_pid, PROTOCOL, build, game_sha, "guest")?;
    bootlog::info(&format!("DLL connected and accepted as {role}"));

    bootlog::info(&format!("connecting to the host at {connect} as player {slot}"));
    let tcp = TcpStream::connect(connect).map_err(|e| e.to_string())?;
    let channel = tls::guest_connect_slot(tcp, &invite, build, Some(slot))?;
    bootlog::info("peer link established");
    let (joins_tx, joins_rx) = std::sync::mpsc::channel::<hub::Join>();
    joins_tx.send(hub::Join { peer: 1, channel }).map_err(|e| e.to_string())?;
    // a lost link: the hub reports it as down and this thread dials again (backoff) until the grace window is over
    let (down_tx, down_rx) = std::sync::mpsc::channel::<()>();
    let down_tx = std::sync::Mutex::new(down_tx);
    let on_down = move |_peer: u32| {
        let _ = down_tx.lock().map(|tx| tx.send(()));
    };
    let window = grace.map(std::time::Duration::from_secs);
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let redial = {
        let (invite, connect, build, joins_tx, stop) = (invite.clone(), connect.clone(), build.clone(), joins_tx.clone(), stop.clone());
        std::thread::spawn(move || {
            for () in down_rx {
                let Some(window) = window else { continue };
                redial(&connect, &invite, &build, slot, window, &joins_tx, &stop);
            }
        })
    };
    let resume = hub::Resume { grace: window, on_down: window.map(|_| &on_down as &(dyn Fn(u32) + Sync)) };
    let stats = hub::run_with(&pipe, reader, joins_rx, resume, &|line| bootlog::info(line))?;
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    drop(on_down);
    let _ = redial.join();
    bootlog::info(&format!("hub ended: {} to the host, {} from the host, {} went down, {} came back", stats.to_peers, stats.from_peers, stats.down, stats.rejoined));
    Ok(())
}

/// Dials the host again after a lost link: 1, 2, 4, 8 s, then every 8 s, until `window` is over or a link is up.
fn redial(connect: &str, invite: &Invite, build: &str, slot: u32, window: std::time::Duration, joins: &std::sync::mpsc::Sender<hub::Join>, stop: &std::sync::atomic::AtomicBool) {
    use std::sync::atomic::Ordering::SeqCst;
    use std::net::ToSocketAddrs;
    let started = std::time::Instant::now();
    let mut pause = 1u64;
    let mut attempt = 0u32;
    while started.elapsed() < window && !stop.load(SeqCst) {
        attempt += 1;
        let tried: Result<hub::Join, String> = (|| {
            let address = connect.to_socket_addrs().map_err(|e| e.to_string())?.next().ok_or("no address")?;
            let tcp = TcpStream::connect_timeout(&address, std::time::Duration::from_secs(5)).map_err(|e| e.to_string())?;
            let channel = tls::guest_connect_slot(tcp, invite, build, Some(slot))?;
            Ok(hub::Join { peer: 1, channel })
        })();
        match tried {
            Ok(join) => {
                bootlog::info(&format!("peer link re-established (attempt {attempt}, {:.1} s after the loss)", started.elapsed().as_secs_f64()));
                let _ = joins.send(join);
                return;
            }
            Err(e) => bootlog::info(&format!("re-dial {attempt} failed: {e}")),
        }
        let until = std::time::Instant::now() + std::time::Duration::from_secs(pause).min(window.saturating_sub(started.elapsed()));
        while std::time::Instant::now() < until && !stop.load(SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        pause = (pause * 2).min(8);
    }
    bootlog::info("re-dial gave up: the grace window is over");
}

fn run_host(args: &HashMap<String, String>) -> Result<(), String> {
    let session_id = require(args, "session")?;
    let game_pid: u32 = require(args, "game-pid")?.parse().map_err(|_| "bad --game-pid")?;
    let build = require(args, "build")?;
    let game_sha = require(args, "game-sha")?;
    let listen = require(args, "listen")?;

    // Per-session credentials; print the invite for the launcher (not the log).
    let pairing = Pairing::generate()?;
    println!("invite fingerprint {}", pairing.invite.fingerprint);
    println!("invite token {}", pairing.invite.token);
    bootlog::info("generated per-session certificate; invite printed to stdout");

    // Pipe to the DLL, then the HELLO handshake.
    bootlog::info(&format!("serving pipe for session {session_id}"));
    let pipe = endpoint::serve(session_id)?;
    let mut reader = Reader::new(&pipe);
    let role = session::helper_accept_with(&mut reader, game_pid, PROTOCOL, build, game_sha, "host")?;
    bootlog::info(&format!("DLL connected and accepted as {role}"));

    // Wait for the guest peer, pinned to this session's cert via the invite.
    bootlog::info(&format!("listening for the co-op peer on {listen}"));
    let listener = TcpListener::bind(listen).map_err(|e| e.to_string())?;
    let (tcp, from) = listener.accept().map_err(|e| e.to_string())?;
    bootlog::info(&format!("peer connected from {from}; starting TLS"));
    let mut peer = tls::host_accept(tcp, &pairing, build)?;
    bootlog::info("peer link established; relaying WORLD to the guest");

    // One-way relay: WORLD from the DLL -> the guest over TLS (same Reader).
    let mut forwarded: u64 = 0;
    loop {
        match reader.next()? {
            Some(msg) => {
                if let Some(payload) = relay::host_forward(&msg) {
                    peer.send_payload(&payload)?;
                    forwarded += 1;
                    if forwarded % 100 == 0 {
                        bootlog::info(&format!("forwarded {forwarded} WORLD updates to the guest"));
                    }
                } else if msg.kind == Kind::Goodbye {
                    bootlog::info("DLL said goodbye; closing");
                    return Ok(());
                }
            }
            None => {
                bootlog::info("DLL pipe closed; the game exited");
                return Ok(());
            }
        }
    }
}

fn run_guest(args: &HashMap<String, String>) -> Result<(), String> {
    let session_id = require(args, "session")?;
    let game_pid: u32 = require(args, "game-pid")?.parse().map_err(|_| "bad --game-pid")?;
    let build = require(args, "build")?;
    let game_sha = require(args, "game-sha")?;
    let connect = require(args, "connect")?;
    let invite = Invite {
        protocol: PROTOCOL,
        fingerprint: require(args, "fingerprint")?.clone(),
        token: require(args, "token")?.clone(),
    };

    bootlog::info(&format!("serving pipe for session {session_id}"));
    let pipe = endpoint::serve(session_id)?;
    let role = session::helper_accept(&pipe, game_pid, PROTOCOL, build, game_sha, "guest")?;
    bootlog::info(&format!("DLL connected and accepted as {role}"));

    bootlog::info(&format!("connecting to the host at {connect}"));
    let tcp = TcpStream::connect(connect).map_err(|e| e.to_string())?;
    let mut peer = tls::guest_connect(tcp, &invite, build)?;
    bootlog::info("peer link established; applying WORLD from the host");

    // One-way relay: WORLD from the host over TLS -> the DLL, validated first.
    let mut applied: u64 = 0;
    loop {
        let payload = match peer.recv_payload() {
            Ok(p) => p,
            Err(e) => {
                bootlog::info(&format!("peer link closed: {e}"));
                let _ = pipe.write_all(&Message::new(Kind::Goodbye, serde_json::json!({"reason": "peer"})).encode()?);
                return Ok(());
            }
        };
        match relay::guest_wrap(&payload) {
            Ok(msg) => {
                pipe.write_all(&msg.encode()?)?;
                applied += 1;
                if applied % 100 == 0 {
                    bootlog::info(&format!("delivered {applied} WORLD updates to the DLL"));
                }
            }
            Err(e) => bootlog::warn(&format!("dropped an invalid WORLD update from the peer: {e}")),
        }
    }
}

/// Minimal `--key value` parser. Unknown keys are ignored; flags without a
/// value are stored as empty strings.
fn parse_args() -> HashMap<String, String> {
    let mut map = HashMap::new();
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        if let Some(key) = arg.strip_prefix("--") {
            let value = it.next().unwrap_or_default();
            map.insert(key.to_string(), value);
        }
    }
    map
}
