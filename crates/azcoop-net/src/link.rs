//! The duplex peer link: `coop_transport.Channel` for the helper.
//!
//! One I/O thread owns the TLS stream (concurrent reads and writes of one TLS object are unsafe), so
//! the callers never wait for the network: `send` puts a serialized message into a bounded queue,
//! `drain` takes what the thread received. A peer that stops answering becomes an error, not memory
//! growth. The wire behaviour is the Python's: a frame at least once a second (`payload: null` when
//! idle, or the peer ends the link after ten silent seconds), `ping`/`pong` control fields for the
//! latency sample, the in-order sequence check, and the receiving side stops reading while its
//! incoming queue is full.

use crate::tls::TlsChannel;
use azcoop_proto::transport::{self, MAX_MESSAGE};
use serde_json::Value;
use std::io::ErrorKind;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering::*};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TryRecvError, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// `Channel.incoming = queue.Queue(16)`.
pub const INCOMING_LIMIT: usize = 16;
/// `Channel.outgoing = queue.Queue(256)`.
pub const OUTGOING_LIMIT: usize = 256;
/// Bytes waiting to be written: 16 messages of the largest size.
pub const BACKLOG_LIMIT: usize = 16 * MAX_MESSAGE;
/// A peer that sends nothing for this long is gone.
pub const SILENCE: Duration = Duration::from_secs(10);
const KEEPALIVE: Duration = Duration::from_secs(1);
const PROBE_EVERY: Duration = Duration::from_secs(2);
const PONG_EVERY: Duration = Duration::from_millis(100);
/// How long one turn of the I/O loop waits for incoming bytes.
const TURN: Duration = Duration::from_millis(5);

enum Job {
    Send(Vec<u8>),
    Flush(SyncSender<()>),
    Stop,
}

/// What the I/O thread and the callers share.
#[derive(Default)]
struct Shared {
    error: Mutex<Option<String>>,
    closed: AtomicBool,
    goodbye: AtomicBool,
    queued: AtomicUsize,
    received: AtomicU64,
    sent: AtomicU64,
    sent_bytes: AtomicU64,
    received_bytes: AtomicU64,
    /// Smoothed round trip in microseconds, -1 without a sample.
    latency: AtomicI64,
    last_sample: Mutex<Option<Instant>>,
}

pub struct PeerIo {
    incoming: Receiver<Value>,
    outgoing: SyncSender<Job>,
    shared: Arc<Shared>,
    worker: Mutex<Option<JoinHandle<()>>>,
}

/// Counters for the `network_health` style diagnostics.
#[derive(Clone, Debug, Default)]
pub struct Stats {
    pub received_messages: u64,
    pub sent_messages: u64,
    pub received_bytes: u64,
    pub sent_bytes: u64,
    pub queued_bytes: usize,
    pub latency_ms: Option<u64>,
}

impl PeerIo {
    /// Takes over a handshaken channel and starts its I/O thread.
    pub fn spawn(channel: TlsChannel, name: &str) -> PeerIo {
        let (incoming_tx, incoming) = sync_channel(INCOMING_LIMIT);
        let (outgoing, outgoing_rx) = sync_channel(OUTGOING_LIMIT);
        let shared = Arc::new(Shared { latency: AtomicI64::new(-1), ..Default::default() });
        let worker_shared = shared.clone();
        let worker = std::thread::Builder::new()
            .name(format!("peer-io-{name}"))
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    io_loop(channel, &worker_shared, incoming_tx, outgoing_rx)
                }));
                let failure = match result {
                    Ok(Ok(())) => None,
                    Ok(Err(e)) => Some(e),
                    Err(_) => Some("panic in the peer link".to_string()),
                };
                if let Some(e) = failure {
                    if !worker_shared.closed.load(SeqCst) {
                        let mut slot = worker_shared.error.lock().unwrap();
                        if slot.is_none() {
                            *slot = Some(e);
                        }
                    }
                }
            })
            .expect("spawn the peer I/O thread");
        PeerIo { incoming, outgoing, shared, worker: Mutex::new(Some(worker)) }
    }

    /// `Channel.check`: an error if the link failed or was closed.
    pub fn check(&self) -> Result<(), String> {
        if let Some(e) = self.shared.error.lock().unwrap().as_ref() {
            return Err(format!("Co-op connection failed: {e}"));
        }
        if self.shared.closed.load(SeqCst) {
            return Err("Co-op connection closed".into());
        }
        Ok(())
    }

    /// `Channel.send`: serialize here, frame and write on the I/O thread.
    pub fn send(&self, message: &Value) -> Result<(), String> {
        self.check()?;
        let body = transport::compact(message)?;
        if body.len() + 64 > MAX_MESSAGE {
            return Err("Co-op envelope exceeds size limit".into());
        }
        if self.shared.queued.load(SeqCst) + body.len() > BACKLOG_LIMIT {
            return Err("Co-op outgoing backlog exceeded 16 MiB".into());
        }
        let size = body.len();
        match self.outgoing.try_send(Job::Send(body)) {
            Ok(()) => {
                self.shared.queued.fetch_add(size, SeqCst);
                Ok(())
            }
            Err(TrySendError::Full(_)) => Err("Co-op outgoing backlog exceeded 256 messages".into()),
            Err(TrySendError::Disconnected(_)) => self.check().and(Err("Co-op connection closed".into())),
        }
    }

    /// `Channel.drain`: everything received so far. Once the queue is empty a failed link is reported.
    pub fn drain(&self) -> Result<Vec<Value>, String> {
        let mut messages = Vec::new();
        loop {
            match self.incoming.try_recv() {
                Ok(message) => messages.push(message),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => break,
            }
        }
        if messages.is_empty() {
            self.check()?;
        }
        Ok(messages)
    }

    /// `Channel.flush`: waits (two seconds at most) until everything queued so far is written.
    pub fn flush(&self) -> Result<(), String> {
        let (tx, rx) = sync_channel(1);
        self.outgoing.send_timeout_compat(Job::Flush(tx))?;
        rx.recv_timeout(Duration::from_secs(2)).map_err(|_| "Co-op writer did not drain".to_string())
    }

    /// `Channel.finish`: a goodbye, unless the peer already said one.
    pub fn finish(&self) -> Result<(), String> {
        if self.shared.goodbye.load(SeqCst) {
            return Ok(());
        }
        let result = self.send(&serde_json::json!({"kind": "goodbye"})).and_then(|()| self.flush());
        if result.is_err() && self.shared.goodbye.load(SeqCst) {
            return Ok(());
        }
        result
    }

    /// The peer sent its goodbye.
    pub fn peer_said_goodbye(&self) -> bool {
        self.shared.goodbye.load(SeqCst)
    }

    pub fn stats(&self) -> Stats {
        let latency = self.latency_ms();
        Stats {
            received_messages: self.shared.received.load(Relaxed),
            sent_messages: self.shared.sent.load(Relaxed),
            received_bytes: self.shared.received_bytes.load(Relaxed),
            sent_bytes: self.shared.sent_bytes.load(Relaxed),
            queued_bytes: self.shared.queued.load(Relaxed),
            latency_ms: latency,
        }
    }

    /// `Channel.latency_ms`: the smoothed sample, if fresh.
    pub fn latency_ms(&self) -> Option<u64> {
        let micros = self.shared.latency.load(Relaxed);
        let fresh = self.shared.last_sample.lock().unwrap().is_some_and(|t| t.elapsed() < Duration::from_secs(10));
        (micros >= 0 && fresh && self.check().is_ok()).then(|| (micros as f64 / 1000.0).round() as u64)
    }

    /// `Channel.close`.
    pub fn close(&self) {
        self.shared.closed.store(true, SeqCst);
        let _ = self.outgoing.try_send(Job::Stop);
        if let Some(worker) = self.worker.lock().unwrap().take() {
            let _ = worker.join();
        }
    }
}

impl Drop for PeerIo {
    fn drop(&mut self) {
        self.close();
    }
}

/// `SyncSender::send` with the Python's two-second bound.
trait SendTimeout {
    fn send_timeout_compat(&self, job: Job) -> Result<(), String>;
}

impl SendTimeout for SyncSender<Job> {
    fn send_timeout_compat(&self, mut job: Job) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match self.try_send(job) {
                Ok(()) => return Ok(()),
                Err(TrySendError::Full(back)) => {
                    if Instant::now() >= deadline {
                        return Err("Co-op writer did not drain".into());
                    }
                    job = back;
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(TrySendError::Disconnected(_)) => return Err("Co-op connection closed".into()),
            }
        }
    }
}

fn timed_out(kind: ErrorKind) -> bool {
    matches!(kind, ErrorKind::WouldBlock | ErrorKind::TimedOut)
}

/// The body of the I/O thread (`Channel._io`).
fn io_loop(mut channel: TlsChannel, shared: &Shared, incoming: SyncSender<Value>, outgoing: Receiver<Job>) -> Result<(), String> {
    let _ = channel.tcp().set_nodelay(true);
    channel.tcp().set_read_timeout(Some(TURN)).map_err(|e| e.to_string())?;
    channel.tcp().set_write_timeout(Some(SILENCE)).map_err(|e| e.to_string())?;
    let mut buffer: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; 64 * 1024];
    let mut expected: u64 = 0;
    let mut sent: u64 = 0;
    let started = Instant::now();
    let (mut last_sent, mut last_received) = (started, started);
    let (mut probe_id, mut probe_started, mut next_probe) = (0u64, None::<Instant>, started);
    let mut pong: Option<u64> = None;
    let mut last_pong = started.checked_sub(Duration::from_secs(1)).unwrap_or(started);
    // a parsed payload the incoming queue had no room for
    let mut pending: Option<Value> = None;
    // after the peer's goodbye nothing is read any more, but the socket stays open (the Python returns from
    // its I/O loop without closing) so that our own goodbye and flush still go through
    let mut after_goodbye = false;

    while !shared.closed.load(SeqCst) {
        // ---- write: what the callers queued, else a keepalive
        let job = match outgoing.try_recv() {
            Ok(job) => Some(job),
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => return Ok(()),
        };
        let now = Instant::now();
        let mut item: Option<Vec<u8>> = None;
        match job {
            Some(Job::Stop) => return Ok(()),
            Some(Job::Flush(done)) => {
                let _ = done.try_send(());
            }
            Some(Job::Send(body)) => {
                shared.queued.fetch_sub(body.len(), SeqCst);
                item = Some(body);
            }
            None => {
                if now.duration_since(last_sent) >= KEEPALIVE || (pong.is_some() && now.duration_since(last_pong) >= PONG_EVERY) {
                    item = Some(b"null".to_vec());
                }
            }
        }
        if let Some(body) = item {
            // older peers ignore optional metadata
            let mut control = String::new();
            if body.len() + 128 <= MAX_MESSAGE && now >= next_probe && probe_started.map_or(true, |t| now.duration_since(t) > Duration::from_secs(10)) {
                probe_id += 1;
                probe_started = Some(now);
                next_probe = now + PROBE_EVERY;
                control = format!("\"ping\":{probe_id}");
            }
            if body.len() + 128 <= MAX_MESSAGE && pong.is_some() && now.duration_since(last_pong) >= PONG_EVERY {
                if !control.is_empty() {
                    control.push(',');
                }
                control.push_str(&format!("\"pong\":{}", pong.take().unwrap()));
                last_pong = now;
            }
            let frame = transport::frame_body(sent, &body, if control.is_empty() { None } else { Some(control.as_bytes()) })?;
            sent += 1;
            channel.stream().write_all(&frame).map_err(|e| format!("Co-op peer write failed: {e}"))?;
            channel.stream().flush().map_err(|e| format!("Co-op peer write failed: {e}"))?;
            last_sent = Instant::now();
            shared.sent.store(sent, Relaxed);
            shared.sent_bytes.fetch_add(frame.len() as u64, Relaxed);
        }

        if after_goodbye {
            std::thread::sleep(TURN);
            continue;
        }

        // ---- read (not while the incoming queue is full: the peer's backlog then ends its link, like the Python's)
        if let Some(payload) = pending.take() {
            match incoming.try_send(payload) {
                Ok(()) => {}
                Err(TrySendError::Full(payload)) => pending = Some(payload),
                Err(TrySendError::Disconnected(_)) => return Ok(()),
            }
        }
        if pending.is_none() {
            match channel.stream().read(&mut chunk) {
                Ok(0) => return Err("Co-op peer disconnected".into()),
                Ok(n) => {
                    if buffer.len() + n > 2 * MAX_MESSAGE + 8 {
                        return Err("Co-op receive backlog exceeded".into());
                    }
                    buffer.extend_from_slice(&chunk[..n]);
                    last_received = Instant::now();
                    shared.received_bytes.fetch_add(n as u64, Relaxed);
                }
                Err(e) if timed_out(e.kind()) => {}
                Err(e) => return Err(format!("Co-op peer read failed: {e}")),
            }
        } else {
            std::thread::sleep(TURN);
        }
        while pending.is_none() && buffer.len() >= 4 {
            let size = u32::from_be_bytes(buffer[..4].try_into().unwrap()) as usize;
            if !(1..=MAX_MESSAGE).contains(&size) {
                return Err("Co-op message exceeds size limit".into());
            }
            if buffer.len() < size + 4 {
                break;
            }
            let item = transport::frame_payload(&buffer[4..size + 4])?;
            buffer.drain(..size + 4);
            let Some(object) = item.as_object() else { return Err("Out-of-order co-op message".into()) };
            if object.get("seq").and_then(Value::as_u64) != Some(expected) {
                return Err("Out-of-order co-op message".into());
            }
            expected += 1;
            shared.received.store(expected, Relaxed);
            let now = Instant::now();
            if let Some(ping) = object.get("ping").and_then(Value::as_u64) {
                if 0 < ping && ping <= 9_007_199_254_740_991 {
                    pong = Some(ping);
                }
            }
            if let (Some(answer), Some(began)) = (object.get("pong").and_then(Value::as_u64), probe_started) {
                if answer == probe_id {
                    let elapsed = now.duration_since(began).as_micros() as i64;
                    let previous = shared.latency.load(Relaxed);
                    let value = if previous < 0 { elapsed } else { (previous as f64 * 0.75 + elapsed as f64 * 0.25) as i64 };
                    shared.latency.store(value, Relaxed);
                    *shared.last_sample.lock().unwrap() = Some(now);
                    probe_started = None;
                }
            }
            match object.get("payload") {
                None | Some(Value::Null) => {}
                Some(payload @ Value::Object(_)) => {
                    let goodbye = payload.get("kind").and_then(Value::as_str) == Some("goodbye");
                    let mut message = payload.clone();
                    // the goodbye ends this thread, so it may not be left behind in `pending`
                    let deadline = Instant::now() + Duration::from_secs(2);
                    loop {
                        match incoming.try_send(message) {
                            Ok(()) => break,
                            Err(TrySendError::Full(back)) if goodbye && Instant::now() < deadline => {
                                message = back;
                                std::thread::sleep(Duration::from_millis(2));
                            }
                            Err(TrySendError::Full(back)) => {
                                pending = Some(back);
                                break;
                            }
                            Err(TrySendError::Disconnected(_)) => return Ok(()),
                        }
                    }
                    if goodbye {
                        shared.goodbye.store(true, SeqCst);
                        after_goodbye = true;
                        break;
                    }
                }
                Some(_) => return Err("Invalid co-op payload".into()),
            }
        }
        if last_received.elapsed() > SILENCE {
            return Err(if pending.is_some() {
                "Co-op receive timeout with local incoming queue full".into()
            } else {
                "Co-op peer stopped responding".into()
            });
        }
    }
    Ok(())
}
