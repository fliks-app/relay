use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use fliks_relay::api::{self, AppState};
use fliks_relay::config::Config;
use fliks_relay::gate::{Gate, Reject, Rule};
use fliks_relay::platform::{Env, Fake, Kind, Platform, Platforms, Push, PushError};
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
    let sk = &v["clock_skew"];
    let r = &v["requests"][sk["request"].as_u64().unwrap() as usize];
    let (m, path, body) = (
        r["method"].as_str().unwrap(),
        r["path"].as_str().unwrap(),
        r["body"].as_str().unwrap(),
    );
    let mut h = axum::http::HeaderMap::new();
    h.insert(
        "fliks-key",
        v["server"]["public_key"].as_str().unwrap().parse().unwrap(),
    );
    h.insert("fliks-time", r["time"].to_string().parse().unwrap());
    h.insert(
        "fliks-signature",
        r["signature"].as_str().unwrap().parse().unwrap(),
    );
    for n in sk["accepted_at"].as_array().unwrap() {
        proof::verify_request(host, n.as_i64().unwrap(), m, path, &h, body.as_bytes()).unwrap();
    }
    for n in sk["refused_at"].as_array().unwrap() {
        let e = proof::verify_request(host, n.as_i64().unwrap(), m, path, &h, body.as_bytes())
            .unwrap_err();
        assert_eq!(e.code, "clock_skew");
    }
    let t = &v["tickets"];
    proof::verify_ticket(host, now, t["valid"]["ticket"].as_str().unwrap()).unwrap();
    for bad in [
        "wrong_audience",
        "expired",
        "too_far_ahead",
        "malformed_sub",
        "malformed_key",
    ] {
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

async fn raw(r: &Rig, method: &str, path: &str, body: String) -> (StatusCode, Value) {
    r.call(
        Request::builder()
            .method(method)
            .uri(path)
            .body(Body::from(body))
            .unwrap(),
    )
    .await
}

#[tokio::test]
async fn bad_requests_are_refused_with_their_codes() {
    let r = rig(|_| {}).await;
    let k = key(4);
    r.register(&k).await;
    let late = signed(&k, "POST", "/v1/servers", "{}", NOW - 301);
    assert_eq!(r.call(late).await.1["error"], "clock_skew");
    let mut padded = signed(&k, "POST", "/v1/servers", "{}", NOW);
    padded
        .headers_mut()
        .insert("fliks-time", format!("+{NOW}").parse().unwrap());
    assert_eq!(r.call(padded).await.1["error"], "bad_signature");
    let (s, _) = raw(&r, "PUT", "/v1/subscriptions", "x".repeat(9000)).await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);
    let bad = json!({"ticket": "nope", "platform": "fcm", "token": "t"}).to_string();
    assert_eq!(
        raw(&r, "PUT", "/v1/subscriptions", bad).await.1["error"],
        "bad_ticket"
    );
    let (s, body) = r.s(&k, "DELETE", "/v1/servers/self", "").await;
    assert_eq!((s, body), (StatusCode::NO_CONTENT, Value::Null));
}

#[tokio::test]
async fn token_and_put_limits_apply() {
    let r = rig(|c| {
        c.limits.push_per_token = 1;
        c.limits.put_per_sub = 1;
    })
    .await;
    let k = key(5);
    r.register(&k).await;
    assert_eq!(r.subscribe(&k, 1, "shared").await, StatusCode::NO_CONTENT);
    assert_eq!(
        r.subscribe(&k, 1, "shared").await,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(r.subscribe(&k, 2, "shared").await, StatusCode::NO_CONTENT);
    assert_eq!(r.push(&k, 1, 1).await.0, StatusCode::OK);
    let (s, body) = r.push(&k, 2, 2).await;
    assert_eq!(
        (s, body["scope"].as_str()),
        (StatusCode::TOO_MANY_REQUESTS, Some("token"))
    );
}

#[tokio::test]
async fn token_delete_needs_no_proof_but_is_limited() {
    let r = rig(|c| c.limits.delete_per_token = 1).await;
    let k = key(6);
    r.register(&k).await;
    r.subscribe(&k, 1, "t1").await;
    let del =
        |sub: Option<String>| json!({"platform": "fcm", "token": "t1", "sub": sub}).to_string();
    assert_eq!(
        raw(&r, "DELETE", "/v1/subscriptions", del(None)).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        raw(&r, "DELETE", "/v1/subscriptions", del(None)).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(r.push(&k, 1, 1).await.1["error"], "unknown_subscription");
    let bad = json!({"platform": "fcm", "token": "t2", "sub": "short"}).to_string();
    assert_eq!(
        raw(&r, "DELETE", "/v1/subscriptions", bad).await.1["error"],
        "bad_request"
    );
}

#[tokio::test]
async fn subscription_cap_is_enforced_without_counters_for_refused_puts() {
    let r = rig(|c| c.limits.subs_per_server = 1).await;
    let k = key(7);
    r.register(&k).await;
    assert_eq!(r.subscribe(&k, 1, "t1").await, StatusCode::NO_CONTENT);
    assert_eq!(r.subscribe(&k, 1, "t1b").await, StatusCode::NO_CONTENT);
    assert_eq!(r.subscribe(&k, 2, "t2").await, StatusCode::FORBIDDEN);
}

#[test]
fn counters_are_bounded_and_expire_at_their_own_length() {
    let mut g = Gate::default();
    g.max_windows = 2;
    let rule = |k, window| Rule {
        scope: "s",
        key: k,
        limit: 5,
        window,
    };
    g.hit(&[rule("a", 10)], 0).unwrap();
    g.hit(&[rule("b", 1000)], 0).unwrap();
    assert_eq!(
        g.hit(&[rule("c", 10)], 5),
        Err(Reject::Limited {
            scope: "relay",
            retry_after: 60
        })
    );
    g.hit(&[rule("c", 10)], 20).unwrap();
}

struct SandboxLess;

#[async_trait::async_trait]
impl Platform for SandboxLess {
    async fn send(&self, _: &Push<'_>) -> Result<(), PushError> {
        Ok(())
    }
    fn serves(&self, env: Option<Env>) -> bool {
        env != Some(Env::Sandbox)
    }
}

#[tokio::test]
async fn registration_for_an_unserved_apns_environment_is_refused() {
    let mut r = rig(|_| {}).await;
    let mut st = AppState::new(
        store::open_memory().await.unwrap(),
        Config::from_env().unwrap(),
        Platforms::default().with(Kind::Apns, Arc::new(SandboxLess)),
        vec![7; 32],
    );
    st.cfg.host = HOST.into();
    let c = r.clock.clone();
    st.clock = Box::new(move || c.load(Ordering::SeqCst));
    r.app = api::router(Arc::new(st));
    let k = key(9);
    r.register(&k).await;
    let t = ticket(&k, [1; 16], NOW + 300);
    for (env, status) in [("sandbox", 400), ("production", 204)] {
        let body = json!({"ticket": t, "platform": "apns", "token": "tok", "env": env});
        let (s, b) = raw(&r, "PUT", "/v1/subscriptions", body.to_string()).await;
        assert_eq!(s.as_u16(), status, "{env}");
        if status == 400 {
            assert_eq!(b["error"], "unsupported_environment");
        }
    }
}
