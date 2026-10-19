//! The peer link: a per-session self-signed certificate and the invite the
//! guest uses to pin it. TLS transport is built on top of this (next step).
//!
//! Matches coop_transport.py: an ECDSA P-256 self-signed cert, and an invite
//! carrying {protocol, fingerprint = sha256(cert DER) hex, token = 32 random
//! bytes hex}. The guest pins `fingerprint` before sending the token, so a
//! man-in-the-middle with a different cert is rejected.

use azcoop_proto::transport::PROTOCOL;
use sha2::{Digest, Sha256};

/// Host credentials for one co-op session. Never written to disk here.
pub struct Pairing {
    /// Certificate in DER form (what rustls serves).
    pub cert_der: Vec<u8>,
    /// Private key in DER (PKCS#8).
    pub key_der: Vec<u8>,
    /// The invite the guest needs: protocol, cert fingerprint, token.
    pub invite: Invite,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invite {
    pub protocol: u64,
    pub fingerprint: String,
    pub token: String,
}

fn hex(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(H[(b >> 4) as usize] as char);
        s.push(H[(b & 15) as usize] as char);
    }
    s
}

/// 32 random bytes as hex, from the OS RNG (ring, via rustls' provider).
fn random_token() -> Result<String, String> {
    use rustls::crypto::ring::default_provider;
    let mut buf = [0u8; 32];
    default_provider()
        .secure_random
        .fill(&mut buf)
        .map_err(|_| "secure random failed".to_string())?;
    Ok(hex(&buf))
}

impl Pairing {
    /// Generate a fresh per-session cert + invite.
    pub fn generate() -> Result<Pairing, String> {
        let mut params = rcgen::CertificateParams::new(vec!["Azeroth co-op".to_string()])
            .map_err(|e| format!("cert params: {e}"))?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Azeroth co-op");
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(|e| format!("key: {e}"))?;
        let cert = params.self_signed(&key).map_err(|e| format!("self-sign: {e}"))?;
        let cert_der = cert.der().to_vec();
        let fingerprint = hex(&Sha256::digest(&cert_der));
        Ok(Pairing {
            cert_der,
            key_der: key.serialize_der(),
            invite: Invite { protocol: PROTOCOL, fingerprint, token: random_token()? },
        })
    }
}
