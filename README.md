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
docker build -t fliks-relay .
docker run -p 8080:8080 -v relay-data:/data -e RELAY_HOST=relay.example.org \
  -e RELAY_FAKE_PLATFORMS=1 fliks-relay
```

`RELAY_FAKE_PLATFORMS=1` records pushes and sends nothing: development without credentials. The APNs
and FCM senders are not in this version yet. Put a TLS reverse proxy in front, and set
`RELAY_TRUSTED_PROXY_HOPS` to the number of proxies so the client IP is read from `X-Forwarded-For`.

Another relay only delivers to an app built by its operator (APNs and FCM tokens belong to the
publisher's app), and the store apps compile in the official relay host. A fork points its own build
at its own relay.

### Configuration

All by environment. Limits are fixed windows in memory, reset on restart, for one instance.

| Variable | Default |
|---|---|
| `RELAY_HOST` (canonical host, signed into requests and tickets; required) | none |
| `RELAY_DATA_DIR` (`relay.db` and `stats_secret`) | `./data` |
| `RELAY_BIND` | `0.0.0.0:8080` |
| `RELAY_TRUSTED_PROXY_HOPS` | `0` |
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
