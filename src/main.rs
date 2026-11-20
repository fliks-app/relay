use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use fliks_relay::api::{self, AppState};
use fliks_relay::apns::{Apns, EnvKey};
use fliks_relay::config::Config;
use fliks_relay::fcm::Fcm;
use fliks_relay::platform::{Env, Kind, Platforms};
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
        .with_env_filter(
            tracing_subscriber::EnvFilter::builder()
                .with_default_directive(tracing::level_filters::LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .with_writer(std::io::stderr)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
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
    if cfg.proxy_hops == 0 {
        tracing::warn!(
            "RELAY_TRUSTED_PROXY_HOPS=0: behind a reverse proxy every new server shares the proxy's IP budget"
        );
    }
    let pool = open(&cfg).await?;
    let secret = stats_secret(&cfg)?;
    let platforms = if cfg.fake_platforms {
        let real = std::env::vars().any(|(k, v)| {
            !v.is_empty() && (k.starts_with("APNS_") || k == "FCM_SERVICE_ACCOUNT_FILE")
        });
        if real {
            bail!("RELAY_FAKE_PLATFORMS=1 is set next to real APNS_* / FCM_* credentials");
        }
        Platforms::fake().0
    } else {
        real_platforms()?
    };
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

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn required(name: &str) -> Result<String> {
    env(name).with_context(|| format!("{name} is not set"))
}

fn read_secret(file: &str) -> Result<Vec<u8>> {
    use std::os::unix::fs::PermissionsExt;
    let bytes = std::fs::read(file).with_context(|| format!("reading {file}"))?;
    if std::fs::metadata(file)?.permissions().mode() & 0o077 != 0 {
        tracing::warn!("{file} is readable by group or others: chmod 600 it");
    }
    Ok(bytes)
}

/// APNs from `APNS_*`, FCM from `FCM_SERVICE_ACCOUNT_FILE`; each is optional, one is required.
fn real_platforms() -> Result<Platforms> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    let mut platforms = Platforms::default();
    let mut keys = vec![];
    for (e, suffix, url) in [
        (Env::Production, "PRODUCTION", "https://api.push.apple.com"),
        (
            Env::Sandbox,
            "SANDBOX",
            "https://api.sandbox.push.apple.com",
        ),
    ] {
        let (id, file) = (
            env(&format!("APNS_KEY_ID_{suffix}")),
            env(&format!("APNS_KEY_FILE_{suffix}")),
        );
        match (id, file) {
            (Some(key_id), Some(file)) => keys.push((
                e,
                EnvKey {
                    key_id,
                    pem: read_secret(&file)?,
                    base_url: url.into(),
                },
            )),
            (None, None) => {}
            _ => bail!("APNS_KEY_ID_{suffix} and APNS_KEY_FILE_{suffix} must be set together"),
        }
    }
    if keys.is_empty() && (env("APNS_TOPIC").is_some() || env("APNS_TEAM_ID").is_some()) {
        bail!("APNS_TOPIC / APNS_TEAM_ID are set but no APNS key is");
    }
    if !keys.is_empty() {
        let apns = Apns::new(
            client.clone(),
            required("APNS_TOPIC")?,
            required("APNS_TEAM_ID")?,
            keys,
        )?;
        platforms = platforms.with(Kind::Apns, Arc::new(apns));
    }
    if let Some(file) = env("FCM_SERVICE_ACCOUNT_FILE") {
        let account = serde_json::from_slice(&read_secret(&file)?)
            .with_context(|| format!("{file} is not a service account file"))?;
        let fcm = Fcm::new(client, account, "https://fcm.googleapis.com")?;
        platforms = platforms.with(Kind::Fcm, Arc::new(fcm));
    }
    if platforms.names().is_empty() {
        bail!(
            "no platform is configured: set the APNS_* or FCM_SERVICE_ACCOUNT_FILE variables, or RELAY_FAKE_PLATFORMS=1 for development"
        );
    }
    tracing::info!("platforms: {}", platforms.names().join(", "));
    Ok(platforms)
}

async fn shutdown() {
    let mut term =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
    tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
}
