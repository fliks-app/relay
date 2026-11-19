use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use fliks_relay::api::{self, AppState};
use fliks_relay::config::Config;
use fliks_relay::platform::Platforms;
use fliks_relay::proof::unb64;
use fliks_relay::{stats, store};
use rand::RngCore;
use sqlx::SqlitePool;

#[derive(Parser)]
#[command(version, about = "Push relay for self-hosted Fliks servers")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the relay.
    Serve,
    /// Print the daily counters, read from the database.
    Stats {
        #[arg(long, default_value_t = 30)]
        days: u64,
        #[arg(long)]
        per_server: bool,
        #[arg(long)]
        json: bool,
    },
    /// Refuse a server key (base64url).
    Block { key: String },
    /// Lift the block of a server key.
    Unblock { key: String },
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn parse_key(s: &str) -> Result<[u8; 32]> {
    unb64(s)
        .and_then(|b| b.try_into().ok())
        .context("the key must be 32 bytes, base64url without padding")
}

async fn open(cfg: &Config) -> Result<SqlitePool> {
    std::fs::create_dir_all(&cfg.data_dir)?;
    store::open(&cfg.data_dir.join("relay.db")).await
}

fn stats_secret(cfg: &Config) -> Result<Vec<u8>> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let path = cfg.data_dir.join("stats_secret");
    let mut secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
    {
        Ok(mut f) => f.write_all(hex::encode(secret).as_bytes())?,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    let stored =
        hex::decode(std::fs::read_to_string(&path)?.trim()).context("stats_secret is not hex")?;
    if stored.len() != 32 {
        bail!(
            "{} is truncated: delete it only if the statistics may lose their ids",
            path.display()
        );
    }
    Ok(stored)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let cfg = Config::from_env()?;
    match Cli::parse().cmd {
        Cmd::Serve => serve(cfg).await,
        Cmd::Stats {
            days,
            per_server,
            json,
        } => {
            let pool = open(&cfg).await?;
            let since = stats::day(now().saturating_sub(days.saturating_sub(1) * 86400));
            let global = stats::global_since(&pool, &since).await?;
            let servers = if per_server {
                stats::servers_since(&pool, &since).await?
            } else {
                vec![]
            };
            if json {
                println!(
                    "{}",
                    serde_json::json!({ "global": global, "servers": servers })
                );
            } else {
                for g in &global {
                    println!("{}", serde_json::to_string(g)?);
                }
                for s in &servers {
                    println!("{}", serde_json::to_string(s)?);
                }
            }
            Ok(())
        }
        Cmd::Block { key } => {
            let pool = open(&cfg).await?;
            store::block(&pool, &parse_key(&key)?, now()).await?;
            println!("blocked");
            Ok(())
        }
        Cmd::Unblock { key } => {
            let pool = open(&cfg).await?;
            if !store::unblock(&pool, &parse_key(&key)?).await? {
                bail!("that key is not blocked");
            }
            println!("unblocked");
            Ok(())
        }
    }
}

async fn serve(cfg: Config) -> Result<()> {
    cfg.require_host()?;
    if !cfg.fake_platforms {
        bail!(
            "no platform is configured: set RELAY_FAKE_PLATFORMS=1 (the APNs and FCM senders are not built in yet)"
        );
    }
    if cfg.proxy_hops == 0 {
        tracing::warn!(
            "RELAY_TRUSTED_PROXY_HOPS=0: behind a reverse proxy every new server shares the proxy's IP budget"
        );
    }
    let pool = open(&cfg).await?;
    let secret = stats_secret(&cfg)?;
    let (platforms, _) = Platforms::fake();
    let state = Arc::new(AppState::new(
        pool.clone(),
        cfg.clone(),
        platforms,
        secret.clone(),
    ));

    let (sweep_state, sweep_cfg) = (state.clone(), cfg.clone());
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(600));
        let mut last_sweep = 0;
        loop {
            tick.tick().await;
            let t = now();
            sweep_state.gate.lock().unwrap().prune(t);
            if t >= last_sweep + 86400 {
                match store::sweep(&sweep_state.pool, &sweep_cfg, &secret, t).await {
                    Ok(()) => last_sweep = t,
                    Err(e) => tracing::error!("daily sweep: {e}"),
                }
            }
        }
    });

    let listener = tokio::net::TcpListener::bind(cfg.bind).await?;
    tracing::info!("listening on {}", cfg.bind);
    axum::serve(
        listener,
        api::router(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown())
    .await?;
    Ok(())
}

async fn shutdown() {
    let mut term =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
    tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
}
