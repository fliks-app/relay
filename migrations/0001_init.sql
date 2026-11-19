CREATE TABLE servers (
    key TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL
) STRICT;

CREATE TABLE subscriptions (
    server_key TEXT NOT NULL REFERENCES servers (key) ON DELETE CASCADE,
    sub TEXT NOT NULL,
    platform TEXT NOT NULL,
    env TEXT,
    token TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL,
    PRIMARY KEY (server_key, sub)
) STRICT;
CREATE INDEX subscriptions_token ON subscriptions (platform, token);

CREATE TABLE blocked (
    key_hash TEXT PRIMARY KEY,
    blocked_at INTEGER NOT NULL
) STRICT;

CREATE TABLE stats_server_daily (
    day TEXT NOT NULL,
    server_id TEXT NOT NULL,
    platform TEXT NOT NULL,
    notifications INTEGER NOT NULL DEFAULT 0,
    accepted INTEGER NOT NULL DEFAULT 0,
    limited INTEGER NOT NULL DEFAULT 0,
    failed INTEGER NOT NULL DEFAULT 0,
    dead INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (day, server_id, platform)
) STRICT;

CREATE TABLE stats_daily (
    day TEXT PRIMARY KEY,
    servers_total INTEGER NOT NULL DEFAULT 0,
    servers_new INTEGER NOT NULL DEFAULT 0,
    servers_active INTEGER NOT NULL DEFAULT 0,
    subscriptions_total INTEGER NOT NULL DEFAULT 0,
    subscriptions_apns INTEGER NOT NULL DEFAULT 0,
    subscriptions_fcm INTEGER NOT NULL DEFAULT 0,
    notifications INTEGER NOT NULL DEFAULT 0,
    pushes_accepted INTEGER NOT NULL DEFAULT 0,
    pushes_limited INTEGER NOT NULL DEFAULT 0,
    pushes_failed INTEGER NOT NULL DEFAULT 0,
    pushes_dead INTEGER NOT NULL DEFAULT 0
) STRICT;
