# Fliks relay protocol, version 1

Wire spec between a Fliks server (S), the relay (R) and the Fliks apps (D). The reference
implementation is this repository; `vectors.json` holds test vectors, produced with an
independent Ed25519 implementation. Every implementation (S, apps, R) must reproduce them.

Unknown body fields are ignored, so fields can be added without a version bump. Bodies are JSON,
at most 8 KiB (`413` above). Binary values are base64url without padding.

## Versions

`GET /v1/info` lists in `api` every protocol version R serves. S registers only when its own version is
in that list. R keeps the `/v1` routes for as long as `api` lists 1, so a relay serving versions 1 and 2
answers `"api": [1, 2]` and both generations of S keep working.

The plaintext's `v` (see Encryption) is versioned separately, by S for D: D shows the generic text for a
`v` higher than the one it knows (see Device rules).

## Identity and request signature

- S holds an Ed25519 key pair. Its id on the wire, "the key", is the 32-byte public key, base64url.
- Signed requests carry three headers: `Fliks-Key` (the key), `Fliks-Time` (unix seconds) and
  `Fliks-Signature` (64-byte Ed25519 signature, base64url).
- Signed bytes, UTF-8 (`\n` is a line feed):

  ```
  "fliks-relay-v1" \n METHOD \n HOST \n PATH \n TIME \n lowercase-hex(sha256(body))
  ```

  `METHOD` is uppercase. `PATH` is the raw request path as sent, without query and without percent-decoding or normalisation. `TIME` is the decimal text of
  `Fliks-Time`, which must be canonical (no sign, no leading zero): `+123` and `0123` are refused. `body` is the raw request body (empty for `GET` and `DELETE`: the digest of nothing).
- `HOST` is the relay's canonical host as R is configured (`RELAY_HOST`, for example
  `relay.example.test`), never the received `Host` header. A request signed for another relay does not
  verify. S signs the host of the relay URL it was configured with.
- R refuses a time more than 300 s from its own with `401 clock_skew`. S reads the `Date` header of
  the reply (set by the relay's HTTP server on every reply, never by the application), keeps the offset, retries once, and uses the same offset for every time it puts on the
  wire, tickets included.
- There is no nonce: a signed request can be replayed during its 300 s window. A replayed push is a
  `409 duplicate` (`nid`, below). A replayed `DELETE /v1/servers/self` or `DELETE /v1/subscriptions/{sub}`
  deletes again what S registered since; S heals as for any lost row (`401 unknown_server`, then register
  again). TLS is what keeps the request from being captured.

## Ticket (S to D to R)

`base64url(JSON) "." base64url(signature)`, where the JSON is `{"key", "sub", "aud", "exp"}` and
the signed bytes are `"fliks-relay-ticket-v1" \n` followed by the first part exactly as written.

- `key`: the signing server's key. `sub`: 16 random bytes minted by S (base64url), the subscription id.
  `aud`: the relay's canonical host. `exp`: unix seconds, S's relay-adjusted time plus 300.
- R refuses (`401 bad_ticket`) a bad signature, an `aud` other than its host, an `exp` in the past or
  more than 600 s ahead.
- D refuses a ticket whose `aud` is not the relay compiled into the app, and stores `key` with the
  subscription.

## Errors

A failure is `{"error": code}` with the HTTP status below. `429` adds a `Retry-After` header (seconds)
and `"scope"`.

| Status | `error` | Cause |
|---|---|---|
| 400 | `bad_request`, `unsupported_platform`, `unsupported_environment` | malformed body or field; platform the relay does not serve; APNs `env` the relay has no key for |
| 401 | `bad_signature`, `clock_skew`, `bad_ticket`, `unknown_server` | see above; `unknown_server`: key not registered |
| 403 | `blocked`, `unknown_server`, `subscription_cap` | `unknown_server` is a 403 on `PUT /v1/subscriptions` (the caller is a device, not a signed server) and a 401 on the signed routes |
| 404 | `unknown_subscription` | no such `(key, sub)`, or the platform says the token is dead |
| 409 | `duplicate` | this `nid` was already pushed to this `sub` |
| 413 | `payload_too_large` | body over 8 KiB, payload over 2700 bytes decoded |
| 408 | `request_timeout` | the body took more than 10 s |
| 429 | `rate_limited` | `scope`: `server`, `subscription`, `token`, `subscription_put`, `token_delete`, `new_servers_ip`, `new_servers`, `relay` (the relay's counters are full: retry later) |
| 502 | `platform_error` | the platform refused or failed |

## Routes

| Route | Caller, proof | Body | Result |
|---|---|---|---|
| `GET /v1/info` | anyone | none | `{"api": [1], "platforms": [...], "limits": {...}}` |
| `POST /v1/servers` | S, signed | `{}` | 201, or 200 when known; `403 blocked` |
| `DELETE /v1/servers/self` | S, signed | none | 204; deletes the server, its subscriptions and its counters; allowed for a blocked key, and for an unknown one (204) |
| `GET /v1/servers/self/stats` | S, signed | none | `{"days": [{day, platform, notifications, accepted, limited, failed, dead}]}`, last 30 days |
| `PUT /v1/subscriptions` | D, ticket | `{ticket, platform, token, env?}` | 204; upsert on `(key, sub)` |
| `DELETE /v1/subscriptions/{sub}` | S, signed | none | 204; scoped to the signing key |
| `DELETE /v1/subscriptions` | D, knows the token | `{platform, token, sub?}` | 204 (also when no row matched); deletes the rows of that token, of that `sub` only when given; `400 bad_request` for a malformed body or `sub`; `429` past 10 per hour per token |
| `POST /v1/push` | S, signed | `{nid, sub, payload, ttl}` | see below |

- `platform`: `"apns"` or `"fcm"`. `env`: `"sandbox"` or `"production"`, read for APNs only
  (default `production`). `token`: the platform token, 1 to 4096 bytes.
- `PUT` errors: `401 bad_ticket`, `403 unknown_server` (key not registered), `403 blocked`,
  `403 subscription_cap`, `429`.
- `limits` in `GET /v1/info`: `push_per_subscription_hour`, `notifications_per_server_hour`,
  `subscriptions_per_server`.
- A relay that lost its data heals alone: S registers again on `401 unknown_server`, drops rows on
  `404`, the app subscribes again.

### `POST /v1/push`

Body `{nid, sub, payload, ttl}`:

- `nid`: 16 random bytes, one per notification, the same for every push of a notification sent to
  several users or devices, unrelated to the plaintext `id`.
- `sub`: the subscription id (16 bytes).
- `payload`: base64url, 2700 bytes at most once decoded. R never reads it.
- `ttl`: 0 to 259200 seconds.

| Reply | Meaning | S does |
|---|---|---|
| 200 | handed to the platform | nothing |
| `404 unknown_subscription` | no such `(key, sub)`, or the token is dead (R deleted the row) | deletes its row |
| `401 unknown_server` | R does not know the key | registers again, retries once |
| `429` | a window is full | drops the notification, logs |
| `409 duplicate` | this `nid` was already pushed to this `sub` | nothing |
| `403 blocked`, `413`, `502` | blocked key, payload too large, platform failure | drops, logs |

R remembers each `nid` for an hour, so a `nid` reaches each of a server's subscriptions at most once.
The slot is taken before the platform is called: a push that ends in `502` or `413` from the platform
cannot be retried with the same `nid` for an hour (S sends a new notification, with a new `nid`).
`429` and `403 blocked` take no slot.

R blocks a key automatically when, in one UTC day, `dead > 50` and `dead * 2 > accepted + failed + dead`,
counting the pushes that reached a platform (`accepted`, `failed`, `dead`). An operator can block and
unblock a key by hand.

### What R sends to the platform

The device gets `k` (the sending server's key, stamped by R), `s` (`sub`) and `p` (`payload`).

- APNs: `apns-push-type: alert`, `apns-priority: 10`, `apns-expiration` from `ttl`, body
  `{"aps": {"alert": {"title-loc-key": "push_fallback_title", "loc-key": "push_fallback_body"},
  "mutable-content": 1, "sound": "default"}, "k": key, "s": sub, "p": payload}`.
- FCM HTTP v1: data-only `{"k": key, "s": sub, "p": payload}`, `android.priority: HIGH`, `android.ttl`.

## Device rules

D checks every push before showing it:

- `k` differs from the key stored with `s`: dropped.
- Unknown `s`: dropped, and `DELETE /v1/subscriptions {token, sub}`.
- Known `s` that fails to decrypt: the generic text, nothing deleted.
- Decrypts, but `v` is higher than the plaintext version D knows: the same generic text, nothing deleted.
- `ts + ttl` in the past, or an `id` among the last 200 shown: dropped.

## Encryption

The payload is an RFC 8291 `aes128gcm` message, one record, 103 bytes of overhead, encrypted by S for
one subscription (D's P-256 public key and 16-byte auth secret). R never decrypts or checks it, so this
repository has no vector for it: the RFC's own Appendix A is the reference. The plaintext is JSON of 2500 bytes at most:
`{v: 1, id, ts, ttl, cat, title, body, url, image?, actions?, badge?, user}`.

## Statistics id

`server_id = hex(HMAC-SHA256(stats_secret, key bytes))[0..16]`. Only R computes it; it is listed
so the vector pins the construction.

## Test vectors

`vectors.json`, all at `host = relay.example.test`:

- server seed `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`, key `A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg`;
- three signed requests (`requests`), with the exact signed string and signature, and one signed for
  another host that must not verify (`request_wrong_host`);
- `clock_skew`: `requests[0]` verifies when the relay's time is 300 s before or after its own `time`, and
  is refused with `401 clock_skew` at 301 s;
- tickets at `now = 1800000000`: one valid, and one each with a wrong audience, expired,
  more than 600 s ahead, a `sub` of 15 bytes, and a `key` of 31 bytes;
- the statistics id for a secret and a key.

The first request:

```
POST /v1/push
Fliks-Key: A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg
Fliks-Time: 1800000000
Fliks-Signature: mfV3FJv38L4POWIc9LbnVhASryz3CrjPSi0dS3GoGanb0j-e6Ah7xgokuuyTcR99qV7nVKKd3CRt8irelBbPCw

{"nid":"ICEiIyQlJicoKSorLC0uLw","sub":"EBESExQVFhcYGRobHB0eHw","payload":"b3BhcXVlIGNpcGhlcnRleHQ","ttl":86400}
```

A valid ticket:

```
eyJrZXkiOiJBNkVIdl9QT0VMNGRjTjBZNTB2QW1XZmsxakNicFExZkhkeUdaQkpWTWJnIiwic3ViIjoiRUJFU0V4UVZGaGNZR1JvYkhCMGVIdyIsImF1ZCI6InJlbGF5LmV4YW1wbGUudGVzdCIsImV4cCI6MTgwMDAwMDMwMH0.gN3cmHED9avZeXUGJHU3TqX0OuHQoAvnoseWXWcshE2HNstMu0BIAvNZ8EZmAMvwa77zS2WtER7hy1tfN_jGDQ
```

Statistics id of that key under secret `6465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80818283`: `78eec61c88006896`.
