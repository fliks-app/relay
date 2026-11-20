use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use axum::Json;
use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::StatusCode;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sqlx::SqlitePool;

use crate::config::Config;
use crate::error::ApiError;
use crate::gate::{DAY, Gate, HOUR, Reject, Rule};
use crate::platform::{Env, Kind, Platforms, Push, PushError};
use crate::proof::{self, b64, id16};
use crate::stats::{self, Field};
use crate::store::{self, Sub};

const MAX_BODY: usize = 8 * 1024;
const MAX_PAYLOAD: usize = 2700;
const MAX_TTL: u32 = 259_200;
const MAX_TOKEN: usize = 4096;
const AUTO_BLOCK_DEAD: i64 = 50;
const BODY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

pub struct AppState {
    pub pool: SqlitePool,
    pub cfg: Config,
    pub platforms: Platforms,
    pub secret: Vec<u8>,
    pub gate: Mutex<Gate>,
    pub clock: Box<dyn Fn() -> u64 + Send + Sync>,
}

pub type Shared = Arc<AppState>;

impl AppState {
    pub fn new(pool: SqlitePool, cfg: Config, platforms: Platforms, secret: Vec<u8>) -> Self {
        let clock = || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        };
        Self {
            pool,
            cfg,
            platforms,
            secret,
            gate: Mutex::default(),
            clock: Box::new(clock),
        }
    }
    fn now(&self) -> u64 {
        (self.clock)()
    }
    fn hit(&self, rules: &[Rule]) -> Result<(), ApiError> {
        let now = self.now();
        self.gate
            .lock()
            .unwrap()
            .hit(rules, now)
            .map_err(|r| match r {
                Reject::Limited { scope, retry_after } => ApiError::limited(scope, retry_after),
                Reject::Duplicate => ApiError::new(409, "duplicate"),
            })
    }
}

pub fn router(state: Shared) -> Router {
    Router::new()
        .route("/v1/info", get(info))
        .route("/v1/servers", post(register))
        .route("/v1/servers/self", axum::routing::delete(unregister))
        .route("/v1/servers/self/stats", get(own_stats))
        .route(
            "/v1/subscriptions",
            axum::routing::put(subscribe).delete(unsubscribe_token),
        )
        .route(
            "/v1/subscriptions/{sub}",
            axum::routing::delete(unsubscribe),
        )
        .route("/v1/push", post(push))
        .with_state(state)
}

type Reply = Result<Response, ApiError>;

/// A 204 has no body.
fn ok(status: u16) -> Reply {
    match status {
        204 => Ok(StatusCode::NO_CONTENT.into_response()),
        _ => Ok((StatusCode::from_u16(status).unwrap(), Json(json!({}))).into_response()),
    }
}

async fn body_of(req: Request) -> Result<(Parts, Bytes), ApiError> {
    let (parts, body) = req.into_parts();
    let read = axum::body::to_bytes(Body::new(body), MAX_BODY);
    let bytes = tokio::time::timeout(BODY_TIMEOUT, read)
        .await
        .map_err(|_| ApiError::new(408, "request_timeout"))?
        .map_err(|_| ApiError::too_large())?;
    Ok((parts, bytes))
}

fn json_of<T: DeserializeOwned>(b: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(b).map_err(|_| ApiError::bad_request())
}

struct Signed {
    key: [u8; 32],
    b64: String,
    body: Bytes,
    parts: Parts,
}

async fn signed(st: &AppState, req: Request) -> Result<Signed, ApiError> {
    let (parts, body) = body_of(req).await?;
    let key = proof::verify_request(
        &st.cfg.host,
        st.now() as i64,
        parts.method.as_str(),
        parts.uri.path(),
        &parts.headers,
        &body,
    )?;
    Ok(Signed {
        key,
        b64: b64(&key),
        body,
        parts,
    })
}

/// A registered, not blocked server; counts it as active today.
async fn member(st: &AppState, a: &Signed) -> Result<(), ApiError> {
    if store::is_blocked(&st.pool, &a.key).await? {
        return Err(ApiError::blocked());
    }
    if !store::server_exists(&st.pool, &a.b64).await? {
        return Err(ApiError::new(401, "unknown_server"));
    }
    let now = st.now();
    if store::server_touch(&st.pool, &a.b64, now).await? {
        stats::bump_global(&st.pool, &stats::day(now), Field::ServersActive).await?;
    }
    Ok(())
}

/// Budget key of the caller. Behind `proxy_hops` trusted proxies the address is the one they appended
/// to `X-Forwarded-For`; a request that lacks it did not come through them and is refused.
fn client_key(st: &AppState, parts: &Parts) -> Result<String, ApiError> {
    let hops = st.cfg.proxy_hops;
    let ip = if hops > 0 {
        let ips: Vec<IpAddr> = parts
            .headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .filter_map(|v| v.trim().parse().ok())
            .collect();
        match ips.len().checked_sub(hops) {
            Some(i) => Some(ips[i]),
            None => {
                tracing::error!(
                    "X-Forwarded-For has fewer than {hops} addresses: is the proxy in front?"
                );
                return Err(ApiError::bad_request());
            }
        }
    } else {
        parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0.ip())
    };
    Ok(match ip {
        Some(IpAddr::V4(a)) => format!("ip:{a}"),
        Some(IpAddr::V6(a)) => format!("ip6:{}", hex::encode(&a.octets()[..6])),
        None => "ip:unknown".into(),
    })
}

/// Protocol versions served; `/v1` routes stay for as long as 1 is listed.
const SERVED_VERSIONS: [u32; 1] = [1];

async fn info(State(st): State<Shared>) -> Json<Value> {
    let l = &st.cfg.limits;
    Json(json!({
        "api": SERVED_VERSIONS,
        "platforms": st.platforms.names(),
        "limits": {
            "push_per_subscription_hour": l.push_per_sub,
            "notifications_per_server_hour": l.notifs_per_server,
            "subscriptions_per_server": l.subs_per_server,
        },
    }))
}

async fn register(State(st): State<Shared>, req: Request) -> Reply {
    let a = signed(&st, req).await?;
    if store::is_blocked(&st.pool, &a.key).await? {
        return Err(ApiError::blocked());
    }
    if store::server_exists(&st.pool, &a.b64).await? {
        member(&st, &a).await?;
        return ok(200);
    }
    let (ip, l) = (client_key(&st, &a.parts)?, &st.cfg.limits);
    st.hit(&[
        Rule {
            scope: "new_servers_ip",
            key: &ip,
            limit: l.new_servers_per_ip,
            window: DAY,
        },
        Rule {
            scope: "new_servers",
            key: "new_servers",
            limit: l.new_servers_total,
            window: DAY,
        },
    ])?;
    let now = st.now();
    if !store::server_insert(&st.pool, &a.b64, now).await? {
        return ok(200);
    }
    let day = stats::day(now);
    stats::bump_global(&st.pool, &day, Field::ServersNew).await?;
    stats::bump_global(&st.pool, &day, Field::ServersActive).await?;
    stats::refresh_gauges(&st.pool, &day).await?;
    ok(201)
}

async fn unregister(State(st): State<Shared>, req: Request) -> Reply {
    let a = signed(&st, req).await?;
    store::server_delete(&st.pool, &a.b64).await?;
    stats::delete_server(&st.pool, &stats::server_id(&st.secret, &a.key)).await?;
    stats::refresh_gauges(&st.pool, &stats::day(st.now())).await?;
    ok(204)
}

async fn own_stats(State(st): State<Shared>, req: Request) -> Reply {
    let a = signed(&st, req).await?;
    member(&st, &a).await?;
    let since = stats::day(st.now().saturating_sub(29 * DAY));
    let rows =
        stats::one_server_since(&st.pool, &stats::server_id(&st.secret, &a.key), &since).await?;
    let days: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({"day": r.day, "platform": r.platform, "notifications": r.notifications,
                   "accepted": r.accepted, "limited": r.limited, "failed": r.failed, "dead": r.dead})
        })
        .collect();
    Ok((StatusCode::OK, Json(json!({ "days": days }))).into_response())
}

#[derive(Deserialize)]
struct SubscribeBody {
    ticket: String,
    platform: Kind,
    token: String,
    env: Option<Env>,
}

async fn subscribe(State(st): State<Shared>, req: Request) -> Reply {
    let (_, body) = body_of(req).await?;
    let b: SubscribeBody = json_of(&body)?;
    if b.token.is_empty() || b.token.len() > MAX_TOKEN {
        return Err(ApiError::bad_request());
    }
    let t = proof::verify_ticket(&st.cfg.host, st.now() as i64, &b.ticket)?;
    if store::is_blocked(&st.pool, &t.key).await? {
        return Err(ApiError::blocked());
    }
    let key = b64(&t.key);
    if !store::server_exists(&st.pool, &key).await? {
        return Err(ApiError::new(403, "unknown_server"));
    }
    let env = match b.platform {
        Kind::Apns => Some(b.env.unwrap_or(Env::Production)),
        Kind::Fcm => None,
    };
    let Some(platform) = st.platforms.get(b.platform) else {
        return Err(ApiError::new(400, "unsupported_platform"));
    };
    if !platform.serves(env) {
        return Err(ApiError::new(400, "unsupported_environment"));
    }
    let sub = b64(&t.sub);
    let cap = st.cfg.limits.subs_per_server;
    if !store::sub_has_room(&st.pool, &key, &sub, cap).await? {
        return Err(ApiError::new(403, "subscription_cap"));
    }
    st.hit(&[Rule {
        scope: "subscription_put",
        key: &format!("put:{key}:{sub}"),
        limit: st.cfg.limits.put_per_sub,
        window: HOUR,
    }])?;
    let row = Sub {
        platform: b.platform.as_str().into(),
        env: env.map(|e| e.as_str().to_string()),
        token: b.token,
    };
    let stored = store::sub_upsert(&st.pool, &key, &sub, &row, cap, st.now())
        .await
        .map_err(|e| match e {
            sqlx::Error::Database(d) if d.is_foreign_key_violation() => {
                ApiError::new(403, "unknown_server")
            }
            e => e.into(),
        })?;
    if !stored {
        return Err(ApiError::new(403, "subscription_cap"));
    }
    stats::refresh_gauges(&st.pool, &stats::day(st.now())).await?;
    ok(204)
}

async fn unsubscribe(State(st): State<Shared>, Path(sub): Path<String>, req: Request) -> Reply {
    let a = signed(&st, req).await?;
    let sub = id16(&sub)
        .map(|s| b64(&s))
        .ok_or_else(ApiError::bad_request)?;
    if store::sub_delete(&st.pool, &a.b64, &sub).await? > 0 {
        stats::refresh_gauges(&st.pool, &stats::day(st.now())).await?;
    }
    ok(204)
}

#[derive(Deserialize)]
struct UnsubscribeBody {
    platform: Kind,
    token: String,
    sub: Option<String>,
}

async fn unsubscribe_token(State(st): State<Shared>, req: Request) -> Reply {
    let (_, body) = body_of(req).await?;
    let b: UnsubscribeBody = json_of(&body)?;
    let sub = match &b.sub {
        Some(s) => Some(id16(s).map(|s| b64(&s)).ok_or_else(ApiError::bad_request)?),
        None => None,
    };
    st.hit(&[Rule {
        scope: "token_delete",
        key: &format!("del:{}:{}", b.platform.as_str(), b.token),
        limit: st.cfg.limits.delete_per_token,
        window: HOUR,
    }])?;
    if store::subs_delete_by_token(&st.pool, b.platform.as_str(), &b.token, sub.as_deref()).await?
        > 0
    {
        stats::refresh_gauges(&st.pool, &stats::day(st.now())).await?;
    }
    ok(204)
}

#[derive(Deserialize)]
struct PushBody {
    nid: String,
    sub: String,
    payload: String,
    ttl: u32,
}

async fn push(State(st): State<Shared>, req: Request) -> Reply {
    let a = signed(&st, req).await?;
    let b: PushBody = json_of(&a.body)?;
    let (nid, sub_id) = (id16(&b.nid), id16(&b.sub));
    let (Some(nid), Some(sub_id), true) = (nid, sub_id, b.ttl <= MAX_TTL) else {
        return Err(ApiError::bad_request());
    };
    if proof::unb64(&b.payload)
        .ok_or_else(ApiError::bad_request)?
        .len()
        > MAX_PAYLOAD
    {
        return Err(ApiError::too_large());
    }
    member(&st, &a).await?;
    let sub = b64(&sub_id);
    let row = store::sub_get(&st.pool, &a.b64, &sub)
        .await?
        .ok_or_else(|| ApiError::new(404, "unknown_subscription"))?;
    let kind = Kind::parse(&row.platform).ok_or_else(|| ApiError::new(500, "internal"))?;
    let (now, sid) = (st.now(), stats::server_id(&st.secret, &a.key));
    let day = stats::day(now);
    let admitted = st.gate.lock().unwrap().admit_push(
        &st.cfg.limits,
        &a.b64,
        nid,
        &sub,
        sub_id,
        &row.token,
        kind,
        now,
    );
    let count = |f| stats::count(&st.pool, &day, &a.b64, &sid, kind.as_str(), f);
    let admitted = match admitted {
        Ok(x) => x,
        Err(Reject::Duplicate) => return Err(ApiError::new(409, "duplicate")),
        Err(Reject::Limited { scope, retry_after }) => {
            count(Field::Limited).await?;
            return Err(ApiError::limited(scope, retry_after));
        }
    };
    if admitted.new_platform {
        stats::bump_server(
            &st.pool,
            &day,
            &a.b64,
            &sid,
            kind.as_str(),
            Field::Notifications,
        )
        .await?;
    }
    if admitted.new_nid {
        stats::bump_global(&st.pool, &day, Field::Notifications).await?;
    }
    let env = row.env.as_deref().and_then(Env::parse);
    let push = Push {
        token: &row.token,
        env,
        key: &a.b64,
        sub: &sub,
        payload: &b.payload,
        ttl: b.ttl,
    };
    let sent = match st.platforms.get(kind) {
        Some(p) => p.send(&push).await,
        None => Err(PushError::Failed("platform not configured".into())),
    };
    match sent {
        Ok(()) => {
            store::sub_used(&st.pool, &a.b64, &sub, now).await?;
            count(Field::Accepted).await?;
            ok(200)
        }
        Err(PushError::DeadToken | PushError::BadDeviceToken) => {
            store::sub_delete(&st.pool, &a.b64, &sub).await?;
            count(Field::Dead).await?;
            stats::refresh_gauges(&st.pool, &day).await?;
            auto_block(&st, &a, &sid, &day).await?;
            Err(ApiError::new(404, "unknown_subscription"))
        }
        Err(PushError::TooLarge) => {
            count(Field::Failed).await?;
            Err(ApiError::too_large())
        }
        Err(PushError::Failed(why)) => {
            tracing::warn!(
                server = &a.b64[..8],
                platform = kind.as_str(),
                "push failed: {why}"
            );
            count(Field::Failed).await?;
            Err(ApiError::new(502, "platform_error"))
        }
    }
}

/// More than 50 dead tokens today and more than half of the day's pushes that reached a platform.
async fn auto_block(st: &AppState, a: &Signed, sid: &str, day: &str) -> Result<(), ApiError> {
    let (dead, reached) = store::dead_and_reached(&st.pool, day, sid).await?;
    if dead > AUTO_BLOCK_DEAD && dead * 2 > reached {
        tracing::warn!(
            server = &a.b64[..8],
            dead,
            reached,
            "blocking a server: dead tokens"
        );
        store::block(&st.pool, &a.key, st.now()).await?;
    }
    Ok(())
}
