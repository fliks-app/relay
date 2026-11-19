use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha256;
use sqlx::SqlitePool;
use time::OffsetDateTime;

pub fn day(unix: u64) -> String {
    OffsetDateTime::from_unix_timestamp(unix as i64)
        .unwrap()
        .date()
        .to_string()
}

/// `HMAC-SHA256(stats_secret, key)` cut to 16 hex characters.
pub fn server_id(secret: &[u8], key: &[u8; 32]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
    mac.update(key);
    hex::encode(&mac.finalize().into_bytes()[..8])
}

#[derive(Clone, Copy)]
pub enum Field {
    Notifications,
    Accepted,
    Limited,
    Failed,
    Dead,
    ServersNew,
    ServersActive,
}

impl Field {
    fn server_col(self) -> Option<&'static str> {
        Some(match self {
            Field::Notifications => "notifications",
            Field::Accepted => "accepted",
            Field::Limited => "limited",
            Field::Failed => "failed",
            Field::Dead => "dead",
            _ => return None,
        })
    }
    fn global_col(self) -> &'static str {
        match self {
            Field::Notifications => "notifications",
            Field::Accepted => "pushes_accepted",
            Field::Limited => "pushes_limited",
            Field::Failed => "pushes_failed",
            Field::Dead => "pushes_dead",
            Field::ServersNew => "servers_new",
            Field::ServersActive => "servers_active",
        }
    }
}

pub async fn bump_global(pool: &SqlitePool, day: &str, f: Field) -> sqlx::Result<()> {
    let c = f.global_col();
    sqlx::query(&format!("INSERT INTO stats_daily (day, {c}) VALUES (?, 1) ON CONFLICT (day) DO UPDATE SET {c} = {c} + 1"))
        .bind(day)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn bump_server(
    pool: &SqlitePool,
    day: &str,
    server_id: &str,
    platform: &str,
    f: Field,
) -> sqlx::Result<()> {
    let Some(c) = f.server_col() else {
        return Ok(());
    };
    sqlx::query(&format!(
        "INSERT INTO stats_server_daily (day, server_id, platform, {c}) VALUES (?, ?, ?, 1) \
         ON CONFLICT (day, server_id, platform) DO UPDATE SET {c} = {c} + 1"
    ))
    .bind(day)
    .bind(server_id)
    .bind(platform)
    .execute(pool)
    .await?;
    Ok(())
}

/// Counts the push in the server's and in the global counters.
pub async fn count(
    pool: &SqlitePool,
    day: &str,
    server_id: &str,
    platform: &str,
    f: Field,
) -> sqlx::Result<()> {
    bump_server(pool, day, server_id, platform, f).await?;
    bump_global(pool, day, f).await
}

/// Servers and subscriptions standing now, written into today's row.
pub async fn refresh_gauges(pool: &SqlitePool, day: &str) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO stats_daily (day, servers_total, subscriptions_total, subscriptions_apns, subscriptions_fcm) \
         VALUES (?, (SELECT COUNT(*) FROM servers), (SELECT COUNT(*) FROM subscriptions), \
         (SELECT COUNT(*) FROM subscriptions WHERE platform = 'apns'), \
         (SELECT COUNT(*) FROM subscriptions WHERE platform = 'fcm')) \
         ON CONFLICT (day) DO UPDATE SET servers_total = excluded.servers_total, \
         subscriptions_total = excluded.subscriptions_total, subscriptions_apns = excluded.subscriptions_apns, \
         subscriptions_fcm = excluded.subscriptions_fcm",
    )
    .bind(day)
    .execute(pool)
    .await?;
    Ok(())
}

#[derive(Serialize, sqlx::FromRow)]
pub struct Global {
    pub day: String,
    pub servers_total: i64,
    pub servers_new: i64,
    pub servers_active: i64,
    pub subscriptions_total: i64,
    pub subscriptions_apns: i64,
    pub subscriptions_fcm: i64,
    pub notifications: i64,
    pub pushes_accepted: i64,
    pub pushes_limited: i64,
    pub pushes_failed: i64,
    pub pushes_dead: i64,
}

#[derive(Serialize, sqlx::FromRow)]
pub struct PerServer {
    pub day: String,
    pub server_id: String,
    pub platform: String,
    pub notifications: i64,
    pub accepted: i64,
    pub limited: i64,
    pub failed: i64,
    pub dead: i64,
}

pub async fn global_since(pool: &SqlitePool, since: &str) -> sqlx::Result<Vec<Global>> {
    sqlx::query_as("SELECT * FROM stats_daily WHERE day >= ? ORDER BY day")
        .bind(since)
        .fetch_all(pool)
        .await
}

pub async fn servers_since(pool: &SqlitePool, since: &str) -> sqlx::Result<Vec<PerServer>> {
    sqlx::query_as(
        "SELECT * FROM stats_server_daily WHERE day >= ? ORDER BY day, server_id, platform",
    )
    .bind(since)
    .fetch_all(pool)
    .await
}

pub async fn one_server_since(
    pool: &SqlitePool,
    id: &str,
    since: &str,
) -> sqlx::Result<Vec<PerServer>> {
    sqlx::query_as(
        "SELECT * FROM stats_server_daily WHERE server_id = ? AND day >= ? ORDER BY day, platform",
    )
    .bind(id)
    .bind(since)
    .fetch_all(pool)
    .await
}

pub async fn delete_server(pool: &SqlitePool, id: &str) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM stats_server_daily WHERE server_id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(())
}
