//! Anti-spam counters: fixed windows in memory, reset on restart, one relay instance.

use std::collections::{HashMap, HashSet};

use crate::config::Limits;
use crate::platform::Kind;

pub const HOUR: u64 = 3600;
pub const DAY: u64 = 86400;

#[derive(Debug, PartialEq, Eq)]
pub enum Reject {
    Duplicate,
    Limited {
        scope: &'static str,
        retry_after: u64,
    },
}

pub struct Rule<'a> {
    pub scope: &'static str,
    pub key: &'a str,
    pub limit: u32,
    pub window: u64,
}

#[derive(Default)]
struct Nid {
    at: u64,
    subs: HashSet<[u8; 16]>,
    platforms: HashSet<Kind>,
}

/// What a push admitted for the first time contributes to the statistics.
pub struct Admitted {
    pub new_nid: bool,
    pub new_platform: bool,
}

#[derive(Default)]
pub struct Gate {
    windows: HashMap<String, (u64, u32)>,
    nids: HashMap<(String, [u8; 16]), Nid>,
}

impl Gate {
    fn check(&self, r: &Rule, now: u64) -> Result<(), Reject> {
        match self.windows.get(r.key) {
            Some(&(start, count)) if now < start + r.window && count >= r.limit => {
                Err(Reject::Limited {
                    scope: r.scope,
                    retry_after: start + r.window - now,
                })
            }
            _ => Ok(()),
        }
    }

    fn bump(&mut self, r: &Rule, now: u64) {
        let e = self.windows.entry(r.key.to_string()).or_insert((now, 0));
        if now >= e.0 + r.window {
            *e = (now, 0);
        }
        e.1 += 1;
    }

    /// Checks every rule, then counts them all: a refused request consumes nothing.
    pub fn hit(&mut self, rules: &[Rule], now: u64) -> Result<(), Reject> {
        rules.iter().try_for_each(|r| self.check(r, now))?;
        rules.iter().for_each(|r| self.bump(r, now));
        Ok(())
    }

    /// One push of `nid` to `sub`: a second push of the same pair is a duplicate, the server counter
    /// counts distinct `nid`, the per-subscription and per-token counters count pushes.
    #[allow(clippy::too_many_arguments)]
    pub fn admit_push(
        &mut self,
        limits: &Limits,
        server: &str,
        nid: [u8; 16],
        sub: &str,
        sub_id: [u8; 16],
        token: &str,
        kind: Kind,
        now: u64,
    ) -> Result<Admitted, Reject> {
        let nk = (server.to_string(), nid);
        let known = self.nids.get(&nk).filter(|n| now < n.at + HOUR);
        if known.is_some_and(|n| n.subs.contains(&sub_id)) {
            return Err(Reject::Duplicate);
        }
        let new_nid = known.is_none();
        let (server_key, sub_key, token_key) = (
            format!("nid:{server}"),
            format!("sub:{server}:{sub}"),
            format!("token:{}:{token}", kind.as_str()),
        );
        let mut rules = vec![
            Rule {
                scope: "subscription",
                key: &sub_key,
                limit: limits.push_per_sub,
                window: HOUR,
            },
            Rule {
                scope: "token",
                key: &token_key,
                limit: limits.push_per_token,
                window: HOUR,
            },
        ];
        if new_nid {
            rules.insert(
                0,
                Rule {
                    scope: "server",
                    key: &server_key,
                    limit: limits.notifs_per_server,
                    window: HOUR,
                },
            );
        }
        self.hit(&rules, now)?;
        let n = self.nids.entry(nk).or_default();
        if new_nid {
            *n = Nid {
                at: now,
                ..Nid::default()
            };
        }
        n.subs.insert(sub_id);
        let new_platform = n.platforms.insert(kind);
        Ok(Admitted {
            new_nid,
            new_platform,
        })
    }

    pub fn prune(&mut self, now: u64) {
        self.windows.retain(|_, (start, _)| now < *start + DAY);
        self.nids.retain(|_, n| now < n.at + HOUR);
    }
}
