//! The seam between the relay and APNs / FCM. The real senders implement [`Platform`];
//! [`Fake`] records pushes for tests and `RELAY_FAKE_PLATFORMS=1`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde::Deserialize;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Apns,
    Fcm,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Apns => "apns",
            Kind::Fcm => "fcm",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "apns" => Some(Kind::Apns),
            "fcm" => Some(Kind::Fcm),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Env {
    Sandbox,
    Production,
}

impl Env {
    pub fn as_str(self) -> &'static str {
        match self {
            Env::Sandbox => "sandbox",
            Env::Production => "production",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "sandbox" => Some(Env::Sandbox),
            "production" => Some(Env::Production),
            _ => None,
        }
    }
}

/// What one push carries to the platform; the sender builds the `{k, s, p}` envelope from it.
pub struct Push<'a> {
    pub token: &'a str,
    /// Set for APNs, `None` for FCM.
    pub env: Option<Env>,
    pub key: &'a str,
    pub sub: &'a str,
    pub payload: &'a str,
    pub ttl: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PushError {
    /// The platform says the token is gone (APNs `Unregistered`, `ExpiredToken`,
    /// `DeviceTokenNotForTopic`; FCM `UNREGISTERED`, `SENDER_ID_MISMATCH`).
    DeadToken,
    /// APNs `BadDeviceToken`: dead, or valid for the other environment. The APNs sender may try
    /// the other environment before returning it; the relay treats what it receives as dead.
    BadDeviceToken,
    TooLarge,
    /// Anything else, including FCM `INVALID_ARGUMENT`, which deletes nothing.
    Failed(String),
}

#[async_trait]
pub trait Platform: Send + Sync {
    async fn send(&self, push: &Push<'_>) -> Result<(), PushError>;
    /// Whether a token registered for `env` (APNs only) can be delivered.
    fn serves(&self, _env: Option<Env>) -> bool {
        true
    }
}

#[derive(Default)]
pub struct Platforms(HashMap<Kind, Arc<dyn Platform>>);

impl Platforms {
    pub fn with(mut self, kind: Kind, p: Arc<dyn Platform>) -> Self {
        self.0.insert(kind, p);
        self
    }
    pub fn get(&self, kind: Kind) -> Option<&Arc<dyn Platform>> {
        self.0.get(&kind)
    }
    pub fn names(&self) -> Vec<&'static str> {
        let mut v: Vec<_> = self.0.keys().map(|k| k.as_str()).collect();
        v.sort();
        v
    }
    pub fn fake() -> (Self, Arc<Fake>) {
        let f = Arc::new(Fake::default());
        (
            Self::default()
                .with(Kind::Apns, f.clone())
                .with(Kind::Fcm, f.clone()),
            f,
        )
    }
}

#[derive(Clone, Debug)]
pub struct Sent {
    pub token: String,
    pub key: String,
    pub sub: String,
    pub payload: String,
    pub ttl: u32,
}

#[derive(Default)]
pub struct Fake {
    pub sent: Mutex<Vec<Sent>>,
    outcome: Mutex<Option<PushError>>,
}

impl Fake {
    /// Every following push fails with `e` until reset with `None`.
    pub fn set_outcome(&self, e: Option<PushError>) {
        *self.outcome.lock().unwrap() = e;
    }
}

#[async_trait]
impl Platform for Fake {
    async fn send(&self, p: &Push<'_>) -> Result<(), PushError> {
        if let Some(e) = self.outcome.lock().unwrap().clone() {
            return Err(e);
        }
        self.sent.lock().unwrap().push(Sent {
            token: p.token.into(),
            key: p.key.into(),
            sub: p.sub.into(),
            payload: p.payload.into(),
            ttl: p.ttl,
        });
        Ok(())
    }
}
