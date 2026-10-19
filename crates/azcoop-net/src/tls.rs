//! TLS peer link, matching coop_transport.py connect/accept.
//!
//! The host serves its per-session self-signed cert. The guest does NOT trust
//! a CA; instead it pins the host cert's SHA-256 against the invite fingerprint
//! (an EXACT-certificate check, stricter than a CA chain), then sends the token
//! only over that verified channel. After the TLS handshake both sides run the
//! PROTOCOL 5 application handshake ({protocol, build, token}) and then exchange
//! gameplay frames via the shared transport codec.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use azcoop_proto::transport::{self, PROTOCOL};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, ServerConfig, ServerConnection, SignatureScheme,
    StreamOwned,
};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::peer::{Invite, Pairing};

/// Verifier that accepts exactly one certificate, by its SHA-256 fingerprint.
/// Signatures are still verified via the ring provider, so this pins the peer's
/// identity rather than weakening the handshake.
#[derive(Debug)]
struct PinnedCert {
    fingerprint: String,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for PinnedCert {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let got: String = Sha256::digest(end_entity.as_ref()).iter().map(|b| format!("{b:02x}")).collect();
        if got.eq_ignore_ascii_case(&self.fingerprint) {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General("host certificate does not match the invitation".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// A connected, authenticated peer link that exchanges PROTOCOL 5 gameplay
/// frames. `sent`/`expected` track the frame sequence numbers.
pub enum TlsChannel {
    Server { stream: StreamOwned<ServerConnection, TcpStream>, sent: u64, expected: u64 },
    Client { stream: StreamOwned<ClientConnection, TcpStream>, sent: u64, expected: u64 },
}

pub trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

impl TlsChannel {
    /// The socket under the TLS stream (timeouts, shutdown).
    pub fn tcp(&self) -> &TcpStream {
        match self {
            TlsChannel::Server { stream, .. } => &stream.sock,
            TlsChannel::Client { stream, .. } => &stream.sock,
        }
    }

    /// The raw reader/writer for the pump (`link::PeerIo`).
    pub fn stream(&mut self) -> &mut dyn ReadWrite {
        self.io()
    }

    fn io(&mut self) -> &mut dyn ReadWrite {
        match self {
            TlsChannel::Server { stream, .. } => stream,
            TlsChannel::Client { stream, .. } => stream,
        }
    }

    fn send_control(&mut self, value: &serde_json::Value) -> Result<(), String> {
        let bytes = transport::encode(value)?;
        self.io().write_all(&bytes).map_err(|e| e.to_string())
    }

    fn recv_control(&mut self) -> Result<serde_json::Value, String> {
        let mut len = [0u8; 4];
        self.io().read_exact(&mut len).map_err(|e| e.to_string())?;
        let size = u32::from_be_bytes(len) as usize;
        if !(1..=transport::MAX_MESSAGE).contains(&size) {
            return Err("control message size out of range".into());
        }
        let mut body = vec![0u8; size];
        self.io().read_exact(&mut body).map_err(|e| e.to_string())?;
        transport::decode_control(&body)
    }

    /// Send one gameplay payload as the next sequenced frame.
    pub fn send_payload(&mut self, payload: &serde_json::Value) -> Result<(), String> {
        let seq = match self {
            TlsChannel::Server { sent, .. } | TlsChannel::Client { sent, .. } => sent,
        };
        let frame = transport::frame(*seq, payload, None)?;
        *seq += 1;
        self.io().write_all(&frame).map_err(|e| e.to_string())
    }

    /// Receive the next gameplay frame's `payload`, checking the sequence.
    pub fn recv_payload(&mut self) -> Result<serde_json::Value, String> {
        let mut len = [0u8; 4];
        self.io().read_exact(&mut len).map_err(|e| e.to_string())?;
        let size = u32::from_be_bytes(len) as usize;
        if !(1..=transport::MAX_MESSAGE).contains(&size) {
            return Err("frame size out of range".into());
        }
        let mut body = vec![0u8; size];
        self.io().read_exact(&mut body).map_err(|e| e.to_string())?;
        let item = transport::frame_payload(&body)?;
        let expected = match self {
            TlsChannel::Server { expected, .. } | TlsChannel::Client { expected, .. } => expected,
        };
        if item["seq"].as_u64() != Some(*expected) {
            return Err("out-of-order co-op frame".into());
        }
        *expected += 1;
        Ok(item["payload"].clone())
    }
}

fn server_config(pairing: &Pairing) -> Result<Arc<ServerConfig>, String> {
    let cert = CertificateDer::from(pairing.cert_der.clone());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pairing.key_der.clone()));
    let config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|e| e.to_string())?;
    Ok(Arc::new(config))
}

fn client_config(fingerprint: &str) -> Result<Arc<ClientConfig>, String> {
    let provider = Arc::new(default_provider());
    let verifier = Arc::new(PinnedCert { fingerprint: fingerprint.to_string(), provider: provider.clone() });
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Constant-time string compare (like hmac.compare_digest), for the token.
fn constant_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Host side: wrap an accepted TCP stream in TLS and run the PROTOCOL 5
/// handshake. Rejects a wrong protocol with a named reason, a wrong build or
/// token by closing. Returns the ready channel.
pub fn host_accept(tcp: TcpStream, pairing: &Pairing, build_id: &str) -> Result<TlsChannel, String> {
    accept_with(tcp, pairing, build_id, None).map(|(_, channel)| channel)
}

/// Host side of a group: each guest names its slot (2..=4) and brings that slot's own token;
/// `token_of` returns the token a slot must present. The reply carries the slot back, like
/// `coop_transport.accept(members=...)`.
pub fn host_accept_member(
    tcp: TcpStream,
    pairing: &Pairing,
    build_id: &str,
    token_of: &dyn Fn(u32) -> Option<String>,
) -> Result<(u32, TlsChannel), String> {
    accept_with(tcp, pairing, build_id, Some(token_of))
}

fn accept_with(
    tcp: TcpStream,
    pairing: &Pairing,
    build_id: &str,
    token_of: Option<&dyn Fn(u32) -> Option<String>>,
) -> Result<(u32, TlsChannel), String> {
    // the handshake has the Python's ten seconds; the pump sets its own timeouts afterwards
    let _ = tcp.set_read_timeout(Some(std::time::Duration::from_secs(10)));
    let _ = tcp.set_write_timeout(Some(std::time::Duration::from_secs(10)));
    let conn = ServerConnection::new(server_config(pairing)?).map_err(|e| e.to_string())?;
    let mut channel = TlsChannel::Server { stream: StreamOwned::new(conn, tcp), sent: 0, expected: 0 };
    let hello = channel.recv_control()?;
    if hello["protocol"].as_u64() != Some(PROTOCOL) {
        let _ = channel.send_control(&json!({"accepted": false, "reason": "protocol", "protocol": PROTOCOL}));
        return Err("co-op version mismatch".into());
    }
    let presented = hello["token"].as_str();
    let (slot, expected) = match token_of {
        None => (0, Some(pairing.invite.token.clone())),
        Some(token_of) => {
            let slot = hello["slot"].as_u64().filter(|s| (2..=4).contains(s) && hello["slot"].is_u64());
            let Some(slot) = slot.filter(|_| presented.is_some()) else {
                return Err("Invalid co-op invitation or player slot".into());
            };
            (slot as u32, token_of(slot as u32))
        }
    };
    let ok = hello["build"].as_str() == Some(build_id)
        && matches!((presented, &expected), (Some(t), Some(e)) if constant_eq(t, e));
    if !ok {
        return Err("invalid co-op invitation or game build".into());
    }
    let mut reply = json!({"accepted": true, "protocol": PROTOCOL, "build": build_id});
    if token_of.is_some() {
        reply["slot"] = json!(slot);
    }
    channel.send_control(&reply)?;
    Ok((slot, channel))
}

/// Guest side: connect over TLS pinning the host cert against the invite, then
/// run the PROTOCOL 5 handshake. Returns the ready channel.
pub fn guest_connect(tcp: TcpStream, invite: &Invite, build_id: &str) -> Result<TlsChannel, String> {
    guest_connect_slot(tcp, invite, build_id, None)
}

/// [`guest_connect`] for a group member: the hello names the slot and the reply must echo it.
pub fn guest_connect_slot(tcp: TcpStream, invite: &Invite, build_id: &str, slot: Option<u32>) -> Result<TlsChannel, String> {
    let _ = tcp.set_read_timeout(Some(std::time::Duration::from_secs(10)));
    let _ = tcp.set_write_timeout(Some(std::time::Duration::from_secs(10)));
    let conn = ClientConnection::new(
        client_config(&invite.fingerprint)?,
        ServerName::try_from("azeroth-coop").map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let mut channel = TlsChannel::Client { stream: StreamOwned::new(conn, tcp), sent: 0, expected: 0 };
    let mut hello = json!({"protocol": PROTOCOL, "build": build_id, "token": invite.token});
    if let Some(slot) = slot {
        hello["slot"] = json!(slot);
    }
    channel.send_control(&hello)?;
    let reply = channel.recv_control()?;
    if reply["reason"].as_str() == Some("protocol") {
        return Err("co-op version mismatch".into());
    }
    let mut expected = json!({"accepted": true, "protocol": PROTOCOL, "build": build_id});
    if let Some(slot) = slot {
        expected["slot"] = json!(slot);
    }
    if reply != expected {
        return Err("host rejected the co-op handshake".into());
    }
    Ok(channel)
}
