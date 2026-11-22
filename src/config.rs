use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Context, Result};

#[derive(Clone, Debug)]
pub struct Limits {
    pub push_per_sub: u32,
    pub push_per_token: u32,
    pub notifs_per_server: u32,
    pub subs_per_server: u32,
    pub put_per_sub: u32,
    pub delete_per_token: u32,
    pub delete_per_ip: u32,
    pub new_servers_per_ip: u32,
    pub new_servers_total: u32,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub data_dir: PathBuf,
    pub bind: SocketAddr,
    pub host: String,
    pub proxy_hops: usize,
    pub limits: Limits,
    pub stats_server_days: i64,
    pub stats_global_days: i64,
    pub fake_platforms: bool,
}

fn var<T: FromStr>(name: &str, default: T) -> Result<T> {
    match std::env::var(name) {
        Ok(v) => v
            .parse()
            .map_err(|_| anyhow::anyhow!("{name}: invalid value {v:?}")),
        Err(_) => Ok(default),
    }
}

impl Config {
    pub fn from_env() -> Result<Self> {
        Ok(Self {
            data_dir: var("RELAY_DATA_DIR", PathBuf::from("./data"))?,
            bind: var("RELAY_BIND", "0.0.0.0:8080".parse().unwrap())?,
            host: var("RELAY_HOST", String::new())?,
            proxy_hops: var("RELAY_TRUSTED_PROXY_HOPS", 0)?,
            limits: Limits {
                push_per_sub: var("RELAY_LIMIT_PUSH_PER_SUBSCRIPTION_HOUR", 30)?,
                push_per_token: var("RELAY_LIMIT_PUSH_PER_TOKEN_HOUR", 60)?,
                notifs_per_server: var("RELAY_LIMIT_NOTIFICATIONS_PER_SERVER_HOUR", 1000)?,
                subs_per_server: var("RELAY_LIMIT_SUBSCRIPTIONS_PER_SERVER", 1000)?,
                put_per_sub: var("RELAY_LIMIT_PUT_PER_SUBSCRIPTION_HOUR", 10)?,
                delete_per_token: var("RELAY_LIMIT_DELETE_PER_TOKEN_HOUR", 10)?,
                delete_per_ip: var("RELAY_LIMIT_DELETE_PER_IP_HOUR", 60)?,
                new_servers_per_ip: var("RELAY_LIMIT_NEW_SERVERS_PER_IP_DAY", 10)?,
                new_servers_total: var("RELAY_LIMIT_NEW_SERVERS_DAY", 500)?,
            },
            stats_server_days: var("RELAY_STATS_SERVER_DAYS", 90)?,
            stats_global_days: var("RELAY_STATS_GLOBAL_DAYS", 730)?,
            fake_platforms: var("RELAY_FAKE_PLATFORMS", 0u8)? != 0,
        })
    }

    pub fn require_host(&self) -> Result<()> {
        if self.host.is_empty() {
            return Err(anyhow::anyhow!("RELAY_HOST is not set"))
                .context("the canonical host is required");
        }
        Ok(())
    }
}
