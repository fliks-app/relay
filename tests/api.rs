use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use fliks_relay::api::{self, AppState};
use fliks_relay::config::Config;
use fliks_relay::gate::{Gate, Reject, Rule};
use fliks_relay::platform::{Fake, Platforms, PushError};
use fliks_relay::proof::{b64, request_message, unb64};
use fliks_relay::{proof, stats, store};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

const HOST: &str = "relay.example.test";
const NOW: u64 = 1_800_000_000;

struct Rig {
    app: Router,
    fake: Arc<Fake>,
    state: Arc<AppState>,
    clock: Arc<AtomicU64>,
}

async fn rig(tweak: impl FnOnce(&mut Config)) -> Rig {
    let mut cfg = Config::from_env().unwrap();
    cfg.host = HOST.into();
    tweak(&mut cfg);
    let (platforms, fake) = Platforms::fake();
    let mut st = AppState::new(
        store::open_memory().await.unwrap(),
        cfg,
        platforms,
        vec![7; 32],
    );
    let clock = Arc::new(AtomicU64::new(NOW));
    let c = clock.clone();
    st.clock = Box::new(move || c.load(Ordering::SeqCst));
    let state = Arc::new(st);
    Rig {
        app: api::router(state.clone()),
        fake,
        state,
        clock,
    }
}

fn key(n: u8) -> SigningKey {
    SigningKey::from_bytes(&[n; 32])
}

fn signed(k: &SigningKey, method: &str, path: &str, body: &str, now: u64) -> Request<Body> {
    let msg = request_message(method, HOST, path, now as i64, body.as_bytes());
    Request::builder()
        .method(method)
        .uri(path)
        .header("fliks-key", b64(k.verifying_key().as_bytes()))
        .header("fliks-time", now.to_string())
        .header("fliks-signature", b64(&k.sign(msg.as_bytes()).to_bytes()))
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn ticket(k: &SigningKey, sub: [u8; 16], exp: u64) -> String {
    let first = b64(json!({"key": b64(k.verifying_key().as_bytes()), "sub": b64(&sub), "aud": HOST, "exp": exp}).to_string().as_bytes());
    let sig = k.sign(format!("fliks-relay-ticket-v1\n{first}").as_bytes());
    format!("{first}.{}", b64(&sig.to_bytes()))
}

impl Rig {
    async fn call(&self, req: Request<Body>) -> (StatusCode, Value) {
        let res = self.app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }
    async fn s(&self, k: &SigningKey, method: &str, path: &str, body: &str) -> (StatusCode, Value) {
        self.call(signed(
            k,
            method,
            path,
            body,
            self.clock.load(Ordering::SeqCst),
        ))
        .await
    }
    async fn register(&self, k: &SigningKey) -> StatusCode {
        self.s(k, "POST", "/v1/servers", "{}").await.0
    }
    async fn subscribe(&self, k: &SigningKey, sub: u8, token: &str) -> StatusCode {
        let t = ticket(k, [sub; 16], self.clock.load(Ordering::SeqCst) + 300);
        let body = json!({"ticket": t, "platform": "fcm", "token": token}).to_string();
        let req = Request::builder()
            .method("PUT")
            .uri("/v1/subscriptions")
            .body(Body::from(body))
            .unwrap();
        self.call(req).await.0
    }
    async fn push(&self, k: &SigningKey, nid: u8, sub: u8) -> (StatusCode, Value) {
        let body = json!({"nid": b64(&[nid; 16]), "sub": b64(&[sub; 16]), "payload": b64(b"x"), "ttl": 60});
        self.s(k, "POST", "/v1/push", &body.to_string()).await
    }
}

#[test]
fn published_vectors_verify() {
    let v: Value = serde_json::from_str(include_str!("../vectors.json")).unwrap();
    let host = v["host"].as_str().unwrap();
    let now = v["tickets"]["now"].as_i64().unwrap();
    for r in v["requests"].as_array().unwrap() {
        let (path, body) = (r["path"].as_str().unwrap(), r["body"].as_str().unwrap());
        let time = r["time"].as_i64().unwrap();
        assert_eq!(
            request_message(
                r["method"].as_str().unwrap(),
                host,
                path,
                time,
                body.as_bytes()
            ),
            r["signed_string"]
        );
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            "fliks-key",
            v["server"]["public_key"].as_str().unwrap().parse().unwrap(),
        );
        h.insert("fliks-time", time.to_string().parse().unwrap());
        h.insert(
            "fliks-signature",
            r["signature"].as_str().unwrap().parse().unwrap(),
        );
        proof::verify_request(
            host,
            time,
            r["method"].as_str().unwrap(),
            path,
            &h,
            body.as_bytes(),
        )
        .unwrap();
        assert!(
            proof::verify_request(
                "relay.other.test",
                time,
                r["method"].as_str().unwrap(),
                path,
                &h,
                body.as_bytes()
            )
            .is_err()
        );
    }
    let t = &v["tickets"];
    proof::verify_ticket(host, now, t["valid"]["ticket"].as_str().unwrap()).unwrap();
    for bad in ["wrong_audience", "expired", "too_far_ahead"] {
        assert!(
            proof::verify_ticket(host, now, t[bad].as_str().unwrap()).is_err(),
            "{bad}"
        );
    }
    let id = &v["stats_id"];
    let key: [u8; 32] = unb64(id["key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let secret = hex::decode(id["stats_secret_hex"].as_str().unwrap()).unwrap();
    assert_eq!(stats::server_id(&secret, &key), id["server_id"]);
}

#[test]
fn window_limits_refuse_without_consuming() {
    let mut g = Gate::default();
    let rule = |k, limit| Rule {
        scope: "s",
        key: k,
        limit,
        window: 100,
    };
    g.hit(&[rule("a", 1), rule("b", 5)], 0).unwrap();
    assert_eq!(
        g.hit(&[rule("b", 5), rule("a", 1)], 10),
        Err(Reject::Limited {
            scope: "s",
            retry_after: 90
        })
    );
    for _ in 0..4 {
        g.hit(&[rule("b", 5)], 10).unwrap();
    }
    assert!(g.hit(&[rule("b", 5)], 10).is_err());
    g.hit(&[rule("a", 1)], 100).unwrap();
}

#[tokio::test]
async fn nid_counts_once_per_server_and_never_twice_per_subscription() {
    let r = rig(|c| c.limits.notifs_per_server = 1).await;
    let k = key(1);
    assert_eq!(r.register(&k).await, StatusCode::CREATED);
    assert_eq!(r.register(&k).await, StatusCode::OK);
    assert_eq!(r.subscribe(&k, 1, "t1").await, StatusCode::NO_CONTENT);
    assert_eq!(r.subscribe(&k, 2, "t2").await, StatusCode::NO_CONTENT);
    assert_eq!(r.push(&k, 9, 1).await.0, StatusCode::OK);
    assert_eq!(r.push(&k, 9, 1).await.0, StatusCode::CONFLICT);
    assert_eq!(r.push(&k, 9, 2).await.0, StatusCode::OK);
    let (s, body) = r.push(&k, 8, 1).await;
    assert_eq!(
        (s, body["scope"].as_str()),
        (StatusCode::TOO_MANY_REQUESTS, Some("server"))
    );
    assert_eq!(r.fake.sent.lock().unwrap().len(), 2);
    let g = stats::global_since(&r.state.pool, "2000-01-01")
        .await
        .unwrap();
    assert_eq!(
        (
            g[0].notifications,
            g[0].pushes_accepted,
            g[0].pushes_limited
        ),
        (1, 2, 1)
    );
}

#[tokio::test]
async fn dead_tokens_block_the_server_and_unknown_keys_are_refused() {
    let r = rig(|_| {}).await;
    let k = key(2);
    assert_eq!(r.push(&k, 1, 1).await.1["error"], "unknown_server");
    r.register(&k).await;
    r.fake.set_outcome(Some(PushError::DeadToken));
    for i in 0..51u8 {
        assert_eq!(
            r.subscribe(&k, i, &format!("t{i}")).await,
            StatusCode::NO_CONTENT
        );
        assert_eq!(r.push(&k, i, i).await.1["error"], "unknown_subscription");
    }
    assert_eq!(r.push(&k, 99, 0).await.1["error"], "blocked");
    assert_eq!(r.subscribe(&k, 60, "t60").await, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn deleting_a_server_cascades_and_a_blocked_key_stays_blocked() {
    let r = rig(|_| {}).await;
    let k = key(3);
    r.register(&k).await;
    r.subscribe(&k, 1, "t1").await;
    store::block(&r.state.pool, k.verifying_key().as_bytes(), NOW)
        .await
        .unwrap();
    assert_eq!(r.register(&k).await, StatusCode::FORBIDDEN);
    assert_eq!(
        r.s(&k, "DELETE", "/v1/servers/self", "").await.0,
        StatusCode::NO_CONTENT
    );
    let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM subscriptions")
        .fetch_one(&r.state.pool)
        .await
        .unwrap();
    assert_eq!(left, 0);
    assert_eq!(r.register(&k).await, StatusCode::FORBIDDEN);
}
