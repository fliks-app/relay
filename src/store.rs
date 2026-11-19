use std::path::Path;
use std::str::FromStr;

use anyhow::{Result, bail};
use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};

use crate::config::Config;
use crate::proof::key_hash;
use crate::stats;

pub async fn open(path: &Path) -> Result<SqlitePool> {
    let opts = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .busy_timeout(std::time::Duration::from_secs(5))
        .foreign_keys(true);
    connect(opts, 8).await
}

pub async fn open_memory() -> Result<SqlitePool> {
    connect(
        SqliteConnectOptions::from_str("sqlite::memory:")?.foreign_keys(true),
        1,
    )
    .await
}

async fn connect(opts: SqliteConnectOptions, conns: u32) -> Result<SqlitePool> {
    let pool = SqlitePoolOptions::new()
        .max_connections(conns)
        .connect_with(opts)
        .await?;
    sqlx::migrate!().run(&pool).await?;
    let fk: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
        .fetch_one(&pool)
        .await?;
    if fk != 1 {
        bail!("SQLite foreign keys are off: refusing to start");
    }
    Ok(pool)
}

pub async fn is_blocked(pool: &SqlitePool, key: &[u8; 32]) -> sqlx::Result<bool> {
    Ok(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM blocked WHERE key_hash = ?")
            .bind(key_hash(key))
            .fetch_one(pool)
            .await?
            > 0,
    )
}

pub async fn block(pool: &SqlitePool, key: &[u8; 32], now: u64) -> sqlx::Result<()> {
    sqlx::query("INSERT OR IGNORE INTO blocked (key_hash, blocked_at) VALUES (?, ?)")
        .bind(key_hash(key))
        .bind(now as i64)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn unblock(pool: &SqlitePool, key: &[u8; 32]) -> sqlx::Result<bool> {
    let r = sqlx::query("DELETE FROM blocked WHERE key_hash = ?")
        .bind(key_hash(key))
        .execute(pool)
        .await?;
    Ok(r.rows_affected() > 0)
}

/// Previous `last_seen_at`, when the server exists.
pub async fn server_last_seen(pool: &SqlitePool, key: &str) -> sqlx::Result<Option<i64>> {
    sqlx::query_scalar("SELECT last_seen_at FROM servers WHERE key = ?")
        .bind(key)
        .fetch_optional(pool)
        .await
}

/// False when the key was registered meanwhile.
pub async fn server_insert(pool: &SqlitePool, key: &str, now: u64) -> sqlx::Result<bool> {
    let r = sqlx::query("INSERT INTO servers (key, created_at, last_seen_at) VALUES (?, ?, ?) ON CONFLICT DO NOTHING")
        .bind(key)
        .bind(now as i64)
        .bind(now as i64)
        .execute(pool)
        .await?;
    Ok(r.rows_affected() > 0)
}

pub async fn server_touch(pool: &SqlitePool, key: &str, now: u64) -> sqlx::Result<()> {
    sqlx::query("UPDATE servers SET last_seen_at = ? WHERE key = ?")
        .bind(now as i64)
        .bind(key)
        .execute(pool)
        .await?;
    Ok(())
}

/// The subscriptions go with the foreign key cascade.
pub async fn server_delete(pool: &SqlitePool, key: &str) -> sqlx::Result<()> {
    sqlx::query("DELETE FROM servers WHERE key = ?")
        .bind(key)
        .execute(pool)
        .await?;
    Ok(())
}

#[derive(sqlx::FromRow)]
pub struct Sub {
    pub platform: String,
    pub env: Option<String>,
    pub token: String,
}

pub async fn sub_get(pool: &SqlitePool, key: &str, sub: &str) -> sqlx::Result<Option<Sub>> {
    sqlx::query_as(
        "SELECT platform, env, token FROM subscriptions WHERE server_key = ? AND sub = ?",
    )
    .bind(key)
    .bind(sub)
    .fetch_optional(pool)
    .await
}

pub async fn sub_count(pool: &SqlitePool, key: &str) -> sqlx::Result<i64> {
    sqlx::query_scalar("SELECT COUNT(*) FROM subscriptions WHERE server_key = ?")
        .bind(key)
        .fetch_one(pool)
        .await
}

pub async fn sub_upsert(
    pool: &SqlitePool,
    key: &str,
    sub: &str,
    s: &Sub,
    now: u64,
) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO subscriptions (server_key, sub, platform, env, token, created_at, last_used_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (server_key, sub) DO UPDATE SET \
         platform = excluded.platform, env = excluded.env, token = excluded.token, last_used_at = excluded.last_used_at",
    )
    .bind(key)
    .bind(sub)
    .bind(&s.platform)
    .bind(&s.env)
    .bind(&s.token)
    .bind(now as i64)
    .bind(now as i64)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn sub_used(pool: &SqlitePool, key: &str, sub: &str, now: u64) -> sqlx::Result<()> {
    sqlx::query("UPDATE subscriptions SET last_used_at = ? WHERE server_key = ? AND sub = ?")
        .bind(now as i64)
        .bind(key)
        .bind(sub)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn sub_delete(pool: &SqlitePool, key: &str, sub: &str) -> sqlx::Result<u64> {
    Ok(
        sqlx::query("DELETE FROM subscriptions WHERE server_key = ? AND sub = ?")
            .bind(key)
            .bind(sub)
            .execute(pool)
            .await?
            .rows_affected(),
    )
}

pub async fn subs_delete_by_token(
    pool: &SqlitePool,
    platform: &str,
    token: &str,
    sub: Option<&str>,
) -> sqlx::Result<u64> {
    Ok(sqlx::query(
        "DELETE FROM subscriptions WHERE platform = ? AND token = ? AND (? IS NULL OR sub = ?)",
    )
    .bind(platform)
    .bind(token)
    .bind(sub)
    .bind(sub)
    .execute(pool)
    .await?
    .rows_affected())
}

/// Dead tokens and pushes that reached a platform today, for the automatic block.
pub async fn dead_and_reached(
    pool: &SqlitePool,
    day: &str,
    server_id: &str,
) -> sqlx::Result<(i64, i64)> {
    sqlx::query_as(
        "SELECT COALESCE(SUM(dead), 0), COALESCE(SUM(accepted + failed + dead), 0) \
         FROM stats_server_daily WHERE day = ? AND server_id = ?",
    )
    .bind(day)
    .bind(server_id)
    .fetch_one(pool)
    .await
}

pub async fn sweep(pool: &SqlitePool, cfg: &Config, secret: &[u8], now: u64) -> Result<()> {
    const D: u64 = 86400;
    let n = now as i64;
    sqlx::query("DELETE FROM subscriptions WHERE last_used_at < ?")
        .bind(n - 60 * D as i64)
        .execute(pool)
        .await?;
    let idle: Vec<String> = sqlx::query_scalar("SELECT key FROM servers WHERE last_seen_at < ?")
        .bind(n - 180 * D as i64)
        .fetch_all(pool)
        .await?;
    for key in idle {
        if let Some(k) = crate::proof::unb64(&key).and_then(|b| <[u8; 32]>::try_from(b).ok()) {
            stats::delete_server(pool, &stats::server_id(secret, &k)).await?;
        }
        server_delete(pool, &key).await?;
    }
    let cut = |days: i64| stats::day(now.saturating_sub(days as u64 * D));
    sqlx::query("DELETE FROM stats_server_daily WHERE day < ?")
        .bind(cut(cfg.stats_server_days))
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM stats_daily WHERE day < ?")
        .bind(cut(cfg.stats_global_days))
        .execute(pool)
        .await?;
    stats::refresh_gauges(pool, &stats::day(now)).await?;
    Ok(())
}
