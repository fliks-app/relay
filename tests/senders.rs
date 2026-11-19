//! The APNs and FCM senders against a local mock HTTP server.

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Uri};
use fliks_relay::apns::{Apns, EnvKey};
use fliks_relay::fcm::{Fcm, ServiceAccount};
use fliks_relay::platform::{Env, Platform, Push, PushError};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde_json::{Value, json};

type Reply = Arc<dyn Fn(&str) -> (u16, String) + Send + Sync>;
type Seen = Arc<Mutex<Vec<(String, HeaderMap, String)>>>;

#[derive(Clone)]
struct Mock {
    reply: Reply,
    seen: Seen,
}

async fn handle(
    State(m): State<Mock>,
    uri: Uri,
    h: HeaderMap,
    body: Bytes,
) -> (axum::http::StatusCode, String) {
    let path = uri.path().to_string();
    m.seen
        .lock()
        .unwrap()
        .push((path.clone(), h, String::from_utf8_lossy(&body).into()));
    let (status, text) = (m.reply)(&path);
    (axum::http::StatusCode::from_u16(status).unwrap(), text)
}

async fn mock(reply: impl Fn(&str) -> (u16, String) + Send + Sync + 'static) -> (String, Seen) {
    let seen = Seen::default();
    let app = Router::new().fallback(handle).with_state(Mock {
        reply: Arc::new(reply),
        seen: seen.clone(),
    });
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (url, seen)
}

fn push<'a>(env: Option<Env>) -> Push<'a> {
    Push {
        token: "devtoken",
        env,
        key: "KEY",
        sub: "SUB",
        payload: "PAYLOAD",
        ttl: 600,
    }
}

fn claims(token: &str, alg: Algorithm, pem: &str) -> (jsonwebtoken::Header, Value) {
    let key = match alg {
        Algorithm::ES256 => DecodingKey::from_ec_pem(pem.as_bytes()),
        _ => DecodingKey::from_rsa_pem(pem.as_bytes()),
    }
    .unwrap();
    let mut v = Validation::new(alg);
    v.validate_exp = false;
    v.validate_aud = false;
    v.required_spec_claims.clear();
    let d = jsonwebtoken::decode::<Value>(token, &key, &v).unwrap();
    (d.header, d.claims)
}

fn apns(urls: &[(Env, &str)]) -> Apns {
    let keys = urls
        .iter()
        .map(|(e, u)| {
            (
                *e,
                EnvKey {
                    key_id: format!("KID{}", e.as_str()),
                    pem: include_bytes!("fixtures/apns-test.p8").to_vec(),
                    base_url: u.to_string(),
                },
            )
        })
        .collect();
    Apns::new(
        reqwest::Client::new(),
        "media.test".into(),
        "TEAM".into(),
        keys,
    )
    .unwrap()
}

fn bad_token(_: &str) -> (u16, String) {
    (400, json!({"reason": "BadDeviceToken"}).to_string())
}

#[tokio::test]
async fn apns_request_shape_and_token_reuse() {
    let (url, seen) = mock(|_| (200, String::new())).await;
    let a = apns(&[(Env::Production, &url)]);
    a.send(&push(Some(Env::Production))).await.unwrap();
    a.send(&push(Some(Env::Production))).await.unwrap();
    let seen = seen.lock().unwrap();
    let (path, h, body) = &seen[0];
    assert_eq!(path, "/3/device/devtoken");
    assert_eq!(h["apns-topic"], "media.test");
    assert_eq!(h["apns-push-type"], "alert");
    assert_eq!(h["apns-priority"], "10");
    let exp: u64 = h["apns-expiration"].to_str().unwrap().parse().unwrap();
    assert!(exp > 1_700_000_000);
    let bearer = h["authorization"]
        .to_str()
        .unwrap()
        .strip_prefix("bearer ")
        .or_else(|| h["authorization"].to_str().unwrap().strip_prefix("Bearer "))
        .unwrap()
        .to_string();
    let (head, c) = claims(
        &bearer,
        Algorithm::ES256,
        include_str!("fixtures/apns-test.pub"),
    );
    assert_eq!(head.kid.as_deref(), Some("KIDproduction"));
    assert_eq!(c["iss"], "TEAM");
    assert_eq!(h["authorization"], seen[1].1["authorization"]);
    let b: Value = serde_json::from_str(body).unwrap();
    assert_eq!(b["aps"]["mutable-content"], 1);
    assert_eq!(b["aps"]["alert"]["loc-key"], "push_fallback_body");
    assert_eq!(
        (&b["k"], &b["s"], &b["p"]),
        (&json!("KEY"), &json!("SUB"), &json!("PAYLOAD"))
    );
}

#[tokio::test]
async fn apns_bad_device_token_tries_the_other_environment() {
    let (sb, sb_seen) = mock(bad_token).await;
    let (prod, prod_seen) = mock(|_| (200, String::new())).await;
    let a = apns(&[(Env::Sandbox, &sb), (Env::Production, &prod)]);
    a.send(&push(Some(Env::Sandbox))).await.unwrap();
    assert_eq!(sb_seen.lock().unwrap().len(), 1);
    assert_eq!(prod_seen.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn apns_bad_device_token_everywhere_is_returned() {
    let (sb, _) = mock(bad_token).await;
    let (prod, _) = mock(bad_token).await;
    let both = apns(&[(Env::Sandbox, &sb), (Env::Production, &prod)]);
    assert_eq!(
        both.send(&push(Some(Env::Production))).await,
        Err(PushError::BadDeviceToken)
    );
    let one = apns(&[(Env::Production, &prod)]);
    assert_eq!(
        one.send(&push(Some(Env::Production))).await,
        Err(PushError::BadDeviceToken)
    );
}

#[tokio::test]
async fn apns_error_mapping() {
    for (status, reason, want) in [
        (410, "Unregistered", PushError::DeadToken),
        (410, "ExpiredToken", PushError::DeadToken),
        (400, "DeviceTokenNotForTopic", PushError::DeadToken),
        (413, "PayloadTooLarge", PushError::TooLarge),
        (
            500,
            "InternalServerError",
            PushError::Failed("apns 500 Internal Server Error: InternalServerError".into()),
        ),
    ] {
        let (url, _) = mock(move |_| (status, json!({"reason": reason}).to_string())).await;
        let got = apns(&[(Env::Production, &url)])
            .send(&push(Some(Env::Production)))
            .await;
        assert_eq!(got, Err(want), "{reason}");
    }
}

fn account(token_uri: String) -> ServiceAccount {
    ServiceAccount {
        client_email: "relay@proj.iam.test".into(),
        private_key: include_str!("fixtures/fcm-test.pem").into(),
        project_id: "proj".into(),
        token_uri,
    }
}

fn fcm_reply(send: (u16, Value)) -> impl Fn(&str) -> (u16, String) + Send + Sync {
    move |path| match path {
        "/token" => (
            200,
            json!({"access_token": "AT", "expires_in": 3600}).to_string(),
        ),
        _ => (send.0, send.1.to_string()),
    }
}

#[tokio::test]
async fn fcm_grant_and_request_shape() {
    let (url, seen) = mock(fcm_reply((200, json!({"name": "m"})))).await;
    let f = Fcm::new(
        reqwest::Client::new(),
        account(format!("{url}/token")),
        &url,
    )
    .unwrap();
    f.send(&push(None)).await.unwrap();
    f.send(&push(None)).await.unwrap();
    let seen = seen.lock().unwrap();
    assert_eq!(
        seen.iter().filter(|s| s.0 == "/token").count(),
        1,
        "access token is cached"
    );
    let grant = &seen[0].2;
    assert!(grant.contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer"));
    let assertion = grant.split("assertion=").nth(1).unwrap();
    let (_, c) = claims(
        assertion,
        Algorithm::RS256,
        include_str!("fixtures/fcm-test.pub"),
    );
    assert_eq!(c["iss"], "relay@proj.iam.test");
    assert_eq!(
        c["scope"],
        "https://www.googleapis.com/auth/firebase.messaging"
    );
    let (path, h, body) = &seen[1];
    assert_eq!(path, "/v1/projects/proj/messages:send");
    assert_eq!(h["authorization"], "Bearer AT");
    let b: Value = serde_json::from_str(body).unwrap();
    assert_eq!(
        b,
        json!({"message": {
            "token": "devtoken",
            "data": {"k": "KEY", "s": "SUB", "p": "PAYLOAD"},
            "android": {"priority": "HIGH", "ttl": "600s"},
        }})
    );
}

#[tokio::test]
async fn fcm_error_mapping() {
    let err = |status: &str, code: &str| json!({"error": {"status": status, "details": [{"@type": "type.googleapis.com/google.firebase.fcm.v1.FcmError", "errorCode": code}]}});
    for (http, body, want) in [
        (404, err("NOT_FOUND", "UNREGISTERED"), PushError::DeadToken),
        (
            403,
            err("PERMISSION_DENIED", "SENDER_ID_MISMATCH"),
            PushError::DeadToken,
        ),
        (
            400,
            err("INVALID_ARGUMENT", "INVALID_ARGUMENT"),
            PushError::Failed("fcm 400 Bad Request: INVALID_ARGUMENT".into()),
        ),
        (
            503,
            json!({"error": {"status": "UNAVAILABLE"}}),
            PushError::Failed("fcm 503 Service Unavailable: UNAVAILABLE".into()),
        ),
    ] {
        let (url, _) = mock(fcm_reply((http, body))).await;
        let f = Fcm::new(
            reqwest::Client::new(),
            account(format!("{url}/token")),
            &url,
        )
        .unwrap();
        assert_eq!(f.send(&push(None)).await, Err(want));
    }
}
