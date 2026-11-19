//! APNs sender: HTTP/2, ES256 provider token, one team key per environment.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Deserialize;

use crate::platform::{Env, Platform, Push, PushError};

/// Apple accepts a provider token between 20 and 60 minutes old.
const TOKEN_LIFETIME: Duration = Duration::from_secs(45 * 60);

pub struct EnvKey {
    pub key_id: String,
    pub pem: Vec<u8>,
    pub base_url: String,
}

struct Signer {
    key_id: String,
    key: EncodingKey,
    base_url: String,
    cached: Mutex<Option<(String, Instant)>>,
}

impl Signer {
    fn token(&self, team_id: &str) -> Result<String, PushError> {
        let mut cached = self.cached.lock().unwrap();
        if let Some((t, at)) = cached.as_ref()
            && at.elapsed() < TOKEN_LIFETIME
        {
            return Ok(t.clone());
        }
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.key_id.clone());
        let iat = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let t = jsonwebtoken::encode(
            &header,
            &serde_json::json!({ "iss": team_id, "iat": iat }),
            &self.key,
        )
        .map_err(|e| PushError::Failed(format!("apns provider token: {e}")))?;
        *cached = Some((t.clone(), Instant::now()));
        Ok(t)
    }
}

pub struct Apns {
    client: reqwest::Client,
    topic: String,
    team_id: String,
    signers: HashMap<Env, Signer>,
}

#[derive(Deserialize)]
struct Reason {
    reason: Option<String>,
}

impl Apns {
    pub fn new(
        client: reqwest::Client,
        topic: String,
        team_id: String,
        keys: Vec<(Env, EnvKey)>,
    ) -> anyhow::Result<Self> {
        let mut signers = HashMap::new();
        for (env, k) in keys {
            let key = EncodingKey::from_ec_pem(&k.pem)
                .map_err(|e| anyhow::anyhow!("APNs {} key: {e}", env.as_str()))?;
            signers.insert(
                env,
                Signer {
                    key_id: k.key_id,
                    key,
                    base_url: k.base_url,
                    cached: Mutex::new(None),
                },
            );
        }
        anyhow::ensure!(!signers.is_empty(), "no APNs key is configured");
        Ok(Self {
            client,
            topic,
            team_id,
            signers,
        })
    }

    async fn send_to(&self, env: Env, p: &Push<'_>) -> Result<(), PushError> {
        let signer = self
            .signers
            .get(&env)
            .ok_or_else(|| PushError::Failed(format!("no APNs key for {}", env.as_str())))?;
        let expiration = if p.ttl == 0 {
            0
        } else {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + u64::from(p.ttl)
        };
        let body = serde_json::json!({
            "aps": {
                "alert": { "title-loc-key": "push_fallback_title", "loc-key": "push_fallback_body" },
                "mutable-content": 1,
                "sound": "default",
            },
            "k": p.key, "s": p.sub, "p": p.payload,
        });
        let res = self
            .client
            .post(format!("{}/3/device/{}", signer.base_url, p.token))
            .bearer_auth(signer.token(&self.team_id)?)
            .header("apns-push-type", "alert")
            .header("apns-topic", &self.topic)
            .header("apns-priority", "10")
            .header("apns-expiration", expiration.to_string())
            .json(&body)
            .send()
            .await
            .map_err(|e| PushError::Failed(format!("apns: {e}")))?;
        let status = res.status();
        if status.is_success() {
            return Ok(());
        }
        let reason = res
            .json::<Reason>()
            .await
            .ok()
            .and_then(|r| r.reason)
            .unwrap_or_default();
        Err(match reason.as_str() {
            "BadDeviceToken" => PushError::BadDeviceToken,
            "Unregistered" | "ExpiredToken" | "DeviceTokenNotForTopic" => PushError::DeadToken,
            "PayloadTooLarge" => PushError::TooLarge,
            "ExpiredProviderToken" | "InvalidProviderToken" => {
                *signer.cached.lock().unwrap() = None;
                PushError::Failed(format!("apns {status}: {reason}"))
            }
            _ => PushError::Failed(format!("apns {status}: {reason}")),
        })
    }
}

#[async_trait]
impl Platform for Apns {
    async fn send(&self, p: &Push<'_>) -> Result<(), PushError> {
        let env = p.env.unwrap_or(Env::Production);
        match self.send_to(env, p).await {
            // A sandbox token sent to production (or the reverse) reads as bad: try the other side.
            Err(PushError::BadDeviceToken) => {
                let other = match env {
                    Env::Sandbox => Env::Production,
                    Env::Production => Env::Sandbox,
                };
                if self.signers.contains_key(&other) {
                    self.send_to(other, p).await
                } else {
                    Err(PushError::BadDeviceToken)
                }
            }
            r => r,
        }
    }
}
