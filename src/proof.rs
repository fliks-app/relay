//! Request signatures and tickets (PROTOCOL.md, "Identity" and "Ticket").

use axum::http::HeaderMap;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::error::ApiError;

pub const SKEW_SECS: i64 = 300;
pub const TICKET_MAX_AHEAD_SECS: i64 = 600;

pub fn b64(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

pub fn unb64(s: &str) -> Option<Vec<u8>> {
    B64.decode(s).ok()
}

pub fn id16(s: &str) -> Option<[u8; 16]> {
    unb64(s)?.try_into().ok()
}

pub fn key_hash(key: &[u8; 32]) -> String {
    hex::encode(Sha256::digest(key))
}

pub fn request_message(method: &str, host: &str, path: &str, time: i64, body: &[u8]) -> String {
    format!(
        "fliks-relay-v1\n{method}\n{host}\n{path}\n{time}\n{}",
        hex::encode(Sha256::digest(body))
    )
}

fn verifying_key(bytes: &[u8]) -> Option<VerifyingKey> {
    VerifyingKey::from_bytes(bytes.try_into().ok()?).ok()
}

fn verify(key: &VerifyingKey, msg: &[u8], sig: &str) -> bool {
    let Some(sig) = unb64(sig).and_then(|b| Signature::from_slice(&b).ok()) else {
        return false;
    };
    key.verify_strict(msg, &sig).is_ok()
}

/// Returns the signing key's 32 bytes.
pub fn verify_request(
    host: &str,
    now: i64,
    method: &str,
    path: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<[u8; 32], ApiError> {
    let h = |n: &str| headers.get(n).and_then(|v| v.to_str().ok());
    let (Some(key), Some(time), Some(sig)) =
        (h("fliks-key"), h("fliks-time"), h("fliks-signature"))
    else {
        return Err(ApiError::bad_signature());
    };
    let key_bytes: [u8; 32] = unb64(key)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(ApiError::bad_signature)?;
    let vk = verifying_key(&key_bytes).ok_or_else(ApiError::bad_signature)?;
    let parsed: i64 = time.parse().map_err(|_| ApiError::bad_signature())?;
    if parsed.to_string() != time {
        return Err(ApiError::bad_signature());
    }
    let time = parsed;
    if (now - time).abs() > SKEW_SECS {
        return Err(ApiError::new(401, "clock_skew"));
    }
    let msg = request_message(method, host, path, time, body);
    if !verify(&vk, msg.as_bytes(), sig) {
        return Err(ApiError::bad_signature());
    }
    Ok(key_bytes)
}

#[derive(Deserialize)]
struct TicketBody {
    key: String,
    sub: String,
    aud: String,
    exp: i64,
}

pub struct Ticket {
    pub key: [u8; 32],
    pub sub: [u8; 16],
}

pub fn verify_ticket(host: &str, now: i64, ticket: &str) -> Result<Ticket, ApiError> {
    let bad = || ApiError::new(401, "bad_ticket");
    let (first, sig) = ticket.split_once('.').ok_or_else(bad)?;
    let body: TicketBody =
        serde_json::from_slice(&unb64(first).ok_or_else(bad)?).map_err(|_| bad())?;
    let key: [u8; 32] = unb64(&body.key)
        .and_then(|b| b.try_into().ok())
        .ok_or_else(bad)?;
    let vk = verifying_key(&key).ok_or_else(bad)?;
    let msg = format!("fliks-relay-ticket-v1\n{first}");
    if !verify(&vk, msg.as_bytes(), sig)
        || body.aud != host
        || body.exp <= now
        || body.exp > now + TICKET_MAX_AHEAD_SECS
    {
        return Err(bad());
    }
    Ok(Ticket {
        key,
        sub: id16(&body.sub).ok_or_else(bad)?,
    })
}
