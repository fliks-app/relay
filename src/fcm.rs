//! FCM sender: HTTP v1, OAuth access token from a service account (RS256 grant).

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Deserialize;
use tokio::sync::Mutex;

use crate::platform::{Platform, Push, PushError};

const SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";

#[derive(Deserialize)]
pub struct ServiceAccount {
    pub client_email: String,
    pub private_key: String,
    pub project_id: String,
    pub token_uri: String,
}

pub struct Fcm {
    client: reqwest::Client,
    account: ServiceAccount,
    key: EncodingKey,
    send_url: String,
    token: Mutex<Option<(Arc<str>, Instant)>>,
}

#[derive(Deserialize)]
struct Grant {
    access_token: String,
    expires_in: u64,
}

#[derive(Deserialize)]
struct ErrBody {
    error: Option<ErrInner>,
}
#[derive(Deserialize)]
struct ErrInner {
    status: Option<String>,
    #[serde(default)]
    details: Vec<serde_json::Value>,
}

impl Fcm {
    /// `api_base` is `https://fcm.googleapis.com` outside tests.
    pub fn new(
        client: reqwest::Client,
        account: ServiceAccount,
        api_base: &str,
    ) -> anyhow::Result<Self> {
        let key = EncodingKey::from_rsa_pem(account.private_key.as_bytes())
            .map_err(|e| anyhow::anyhow!("FCM service account private key: {e}"))?;
        let send_url = format!(
            "{api_base}/v1/projects/{}/messages:send",
            account.project_id
        );
        Ok(Self {
            client,
            account,
            key,
            send_url,
            token: Mutex::new(None),
        })
    }

    async fn access_token(&self) -> Result<Arc<str>, PushError> {
        let mut cached = self.token.lock().await;
        if let Some((t, until)) = cached.as_ref()
            && Instant::now() < *until
        {
            return Ok(t.clone());
        }
        let fail = |e: String| PushError::Failed(format!("fcm oauth: {e}"));
        let net = |e: reqwest::Error| fail(e.without_url().to_string());
        let iat = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let assertion = jsonwebtoken::encode(
            &Header::new(Algorithm::RS256),
            &serde_json::json!({
                "iss": self.account.client_email,
                "scope": SCOPE,
                "aud": self.account.token_uri,
                "iat": iat,
                "exp": iat + 3600,
            }),
            &self.key,
        )
        .map_err(|e| fail(e.to_string()))?;
        let res = self
            .client
            .post(&self.account.token_uri)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", assertion.as_str()),
            ])
            .send()
            .await
            .map_err(net)?;
        if !res.status().is_success() {
            return Err(fail(format!("status {}", res.status())));
        }
        let g: Grant = res.json().await.map_err(net)?;
        let t: Arc<str> = g.access_token.into();
        let until = Instant::now() + Duration::from_secs(g.expires_in.saturating_sub(60));
        *cached = Some((t.clone(), until));
        Ok(t)
    }
}

#[async_trait]
impl Platform for Fcm {
    async fn send(&self, p: &Push<'_>) -> Result<(), PushError> {
        let body = serde_json::json!({ "message": {
            "token": p.token,
            "data": { "k": p.key, "s": p.sub, "p": p.payload },
            "android": { "priority": "HIGH", "ttl": format!("{}s", p.ttl) },
        }});
        let res = self
            .client
            .post(&self.send_url)
            .bearer_auth(self.access_token().await?)
            .json(&body)
            .send()
            .await
            .map_err(|e| PushError::Failed(format!("fcm: {}", e.without_url())))?;
        let status = res.status();
        if status.is_success() {
            return Ok(());
        }
        if status == reqwest::StatusCode::UNAUTHORIZED {
            *self.token.lock().await = None;
        }
        let err = res.json::<ErrBody>().await.ok().and_then(|b| b.error);
        let not_found = status == reqwest::StatusCode::NOT_FOUND;
        let code = err
            .as_ref()
            .and_then(|e| {
                e.details
                    .iter()
                    .find_map(|d| d.get("errorCode")?.as_str().map(String::from))
            })
            .or_else(|| err.as_ref().and_then(|e| e.status.clone()))
            .unwrap_or_else(|| {
                if not_found {
                    "NOT_FOUND".into()
                } else {
                    String::new()
                }
            });
        Err(match code.as_str() {
            "UNREGISTERED" | "SENDER_ID_MISMATCH" | "NOT_FOUND" => PushError::DeadToken,
            _ => PushError::Failed(format!("fcm {status}: {code}")),
        })
    }
}
