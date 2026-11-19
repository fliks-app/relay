# fliks-relay

The push relay of [Fliks](https://github.com/fliks-app): a small public service that hands an
encrypted notification from a self-hosted Fliks server to APNs or FCM, for a phone that has the
server's app installed. The wire protocol is [PROTOCOL.md](PROTOCOL.md).

The relay sees metadata only. The notification text is encrypted for the phone by the server; the relay
cannot read it.

## What is stored

| Data | Why | Kept |
|---|---|---|
| Server public keys | check the signature of each request | until the server unregisters, or 180 days without a request |
| Subscriptions: server key, subscription id, platform, environment, platform token | deliver a push | until the app or the server deletes it, or 60 days unused |
| Blocked key hashes (SHA-256) | a blocked key cannot register again | until `unblock` |
| `stats_secret` (a random file in the data directory) | makes the statistics ids unlinkable to keys | for the life of the database |

Never stored: notification content, payloads, push history, IP addresses, server versions. Logs carry
a key prefix, never a token or a payload.

## What is counted

Daily counters, kept in the database and read only by the operator with `fliks-relay stats`. No HTTP
route serves them, except that a server reads its own counters, signed.

- Global, 2 years (`RELAY_STATS_GLOBAL_DAYS`): servers (total, new, active), subscriptions per platform,
  notifications (distinct `nid`), pushes accepted, refused by a limit, failed at the platform, dead tokens.
- Per server, 90 days (`RELAY_STATS_SERVER_DAYS`): the same push counters per platform, under an opaque
  id, `HMAC-SHA256(stats_secret, key)` cut to 16 hex characters. Deleting the server at the relay
  deletes these rows; the global totals keep no identity.

## Run one

```bash
docker run -p 8080:8080 -v relay-data:/data \
  -e RELAY_HOST=relay.example.org -e RELAY_TRUSTED_PROXY_HOPS=1 \
  -e APNS_TOPIC=media.fliks.app -e APNS_TEAM_ID=ABCDE12345 \
  -e APNS_KEY_ID_PRODUCTION=AAAAAAAAAA -e APNS_KEY_FILE_PRODUCTION=/run/secrets/apns_production.p8 \
  -e APNS_KEY_ID_SANDBOX=BBBBBBBBBB -e APNS_KEY_FILE_SANDBOX=/run/secrets/apns_sandbox.p8 \
  -e FCM_SERVICE_ACCOUNT_FILE=/run/secrets/fcm.json \
  -v ./secrets:/run/secrets:ro ghcr.io/fliks-app/relay:latest
```

The image is `ghcr.io/fliks-app/relay`; release binaries (linux x86_64 and aarch64) are attached to each
GitHub release. They are built on Ubuntu 24.04 runners and link glibc 2.39 or newer, so they will not
start on Debian 12; use the image there. To build it yourself: `docker build -t fliks-relay .`.

GHCR creates the package private on the first publish: make `fliks-app/relay` public in the package
settings once, or pulls fail without a login.

Put a TLS reverse proxy in front: the relay has no TLS and no header read timeout of its own, so the
proxy sets both. Set `RELAY_TRUSTED_PROXY_HOPS` to the number of proxies (normally `1`): the client IP is
then read from `X-Forwarded-For`, and a request that arrives without it is refused. With the default `0`
the peer address is used, so behind a proxy every new server would share one IP budget; the relay logs a
warning at start.

Another relay only delivers to an app built by its operator (APNs and FCM tokens belong to the
publisher's app), and the store apps compile in the official relay host. A fork points its own build
at its own relay.

### Platforms

`serve` refuses to start with no platform configured. APNs and FCM are independent: set either or both.
The files hold secrets: mount them read-only, never bake them into an image.

| Variable | Meaning |
|---|---|
| `APNS_TOPIC` | the app's bundle id (required with APNs) |
| `APNS_TEAM_ID` | the Apple Developer team id (required with APNs) |
| `APNS_KEY_ID_PRODUCTION`, `APNS_KEY_FILE_PRODUCTION` | key id and `.p8` file of the production key |
| `APNS_KEY_ID_SANDBOX`, `APNS_KEY_FILE_SANDBOX` | the same for the sandbox key |
| `FCM_SERVICE_ACCOUNT_FILE` | the Firebase service account JSON |
| `RELAY_FAKE_PLATFORMS=1` | no real platform: pushes are recorded and nothing is sent (development) |

Apple scopes a team key to sandbox or production, so set one key per environment you serve. A push that
APNs rejects as `BadDeviceToken` is retried once on the other environment when its key is set; only then is
the subscription deleted.

**APNs keys.** In the Apple Developer account, Certificates, Identifiers & Profiles: enable Push
Notifications on the app's App ID, then Keys, create a key with the Apple Push Notifications service
enabled, once with the Sandbox environment and once with Production, and download each `.p8` (Apple
offers it once). The key id is shown on the key page; the team id is under Membership details.

**FCM service account.** In the Firebase console, create a project (Analytics not needed) and add
the Android app. In Google Cloud, IAM, Service accounts, create an account with the single role
"Firebase Cloud Messaging API Admin", then Keys, Add key, JSON: that file is `FCM_SERVICE_ACCOUNT_FILE`.
Don't use the `firebase-adminsdk` account Firebase creates: it can administer the whole project.

### Configuration

All by environment. Limits are fixed windows in memory, reset on restart, for one instance.

| Variable | Default |
|---|---|
| `RELAY_HOST` (canonical host, signed into requests and tickets; required) | none |
| `RELAY_DATA_DIR` (`relay.db` and `stats_secret`) | `./data` |
| `RELAY_BIND` | `0.0.0.0:8080` |
| `RELAY_TRUSTED_PROXY_HOPS` (set to `1` behind one proxy) | `0` |
| `RELAY_LIMIT_PUSH_PER_SUBSCRIPTION_HOUR` | `30` |
| `RELAY_LIMIT_PUSH_PER_TOKEN_HOUR` (across all servers) | `60` |
| `RELAY_LIMIT_NOTIFICATIONS_PER_SERVER_HOUR` (distinct `nid`) | `1000` |
| `RELAY_LIMIT_SUBSCRIPTIONS_PER_SERVER` | `1000` |
| `RELAY_LIMIT_PUT_PER_SUBSCRIPTION_HOUR` | `10` |
| `RELAY_LIMIT_DELETE_PER_TOKEN_HOUR` | `10` |
| `RELAY_LIMIT_NEW_SERVERS_PER_IP_DAY` (IPv4 or IPv6 /48) | `10` |
| `RELAY_LIMIT_NEW_SERVERS_DAY` | `500` |
| `RELAY_STATS_SERVER_DAYS` | `90` |
| `RELAY_STATS_GLOBAL_DAYS` | `730` |
| `RELAY_FAKE_PLATFORMS` | `0` |

A key whose pushes end in more than 50 dead tokens in a day, and in more than half of its pushes that
day, is blocked: APNs drops a connection that sends too many bad tokens.

### Commands

```bash
fliks-relay serve
fliks-relay stats [--days N] [--per-server] [--json]
fliks-relay block <key>
fliks-relay unblock <key>
```

They run on the relay host against the database in `RELAY_DATA_DIR`.

## Development

```bash
cargo test
```

The tests replay `vectors.json`, the protocol's test vectors.

## License

AGPL-3.0-only.
