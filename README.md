# Xailon Relay

Durable WebSocket relay used by [XailonOrbit](https://github.com/infinialabs-ai/xailon-orbit) to connect the mobile app with `xailon-orbitd`. The public instance runs on Cloudflare at `wss://xailon-relay.infinialabs.ai/ws` (see [Cloudflare (hosted)](#cloudflare-hosted)); the Rust server below is the self-hosted alternative. Both speak the same wire protocol.

## Overview

A protocol-agnostic WebSocket relay that pairs two endpoints and durably
forwards opaque JSON payloads between them. The server does not inspect or
depend on the application protocol carried in `payload`.

## Run

```sh
cargo run --release -- \
  --bind 0.0.0.0:39371 \
  --database /var/lib/relay/relay.sqlite3
```

The default bind address is `0.0.0.0:39371` and the default database is
`relay.sqlite3` in the current directory. Every option also has an environment
variable:

| Option | Environment variable | Default |
| --- | --- | --- |
| `--debug` | `RELAY_DEBUG` | enabled automatically in debug builds |
| `--bind` | `RELAY_BIND` | `0.0.0.0:39371` |
| `--database` | `RELAY_DATABASE` | `relay.sqlite3` |
| `--max-pending-messages` | `RELAY_MAX_PENDING_MESSAGES` | `100000` per id and direction |
| `--max-pending-bytes` | `RELAY_MAX_PENDING_BYTES` | `1073741824` per id and direction |
| `--pending-retention-secs` | `RELAY_PENDING_RETENTION_SECS` | `3600` (1 hour) |
| `--receipt-retention-secs` | `RELAY_RECEIPT_RETENTION_SECS` | `3600` (1 hour) |
| `--device-retention-secs` | `RELAY_DEVICE_RETENTION_SECS` | `604800` (7 days) |
| `--cleanup-interval-secs` | `RELAY_CLEANUP_INTERVAL_SECS` | `600` (10 minutes) |
| `--require-auth` | `RELAY_REQUIRE_AUTH` | off: unclaimed channels accept unauthenticated clients |
| `--max-connections-per-minute` | `RELAY_MAX_CONNECTIONS_PER_MINUTE` | `120` per client IP (`0` disables) |
| `--client-ip-header` | `RELAY_CLIENT_IP_HEADER` | unset: the TCP peer address (set e.g. `X-Forwarded-For` behind a trusted proxy) |

Debug logging records connections, endpoints, message ids, acknowledgements,
and replay/forwarding outcomes. Channel and device ids appear only as short
SHA-256 labels, and payloads are never logged. Release builds can enable it
with `--debug` or `RELAY_DEBUG=true`; `RUST_LOG` can be used to override the
log filter.

For an internet-facing deployment, terminate TLS in a reverse proxy and expose
the WebSocket endpoint over `wss://`.

## Cloudflare (hosted)

`cloudflare/` is a port of the server to a Cloudflare Worker, and is what
runs at `xailon-relay.infinialabs.ai`. It is wire-compatible with the Rust
server: same `/ws` query parameters, frames, binary layout, delivery
contract and error strings, so `client-ts` and `client-rs` work unchanged.

**Architecture**

- The Worker validates `/ws` connections and routes each one to a Durable
  Object named by the pairing id (`idFromName(id)`). One object per pairing
  id plays the role of the Rust relay's per-id lock: its handlers run one at
  a time, so sequence assignment and acknowledgements need no locking.
- Each object keeps that channel's counters, receipts, pending messages and
  device cursors in its own SQLite storage. Payloads are stored in chunks,
  because one Durable Object row holds at most 2 MB and messages can be up
  to 10 MiB.
- Sockets use the WebSocket Hibernation API, so idle connections cost
  nothing. Expiry runs from a Durable Object alarm set for the next due
  pending message, receipt or device, instead of a fixed cleanup interval.
- `POST /push` forwards xailon-orbitd completion notifications to Firebase
  Cloud Messaging (HTTP v1). The body must name the caller's channel (`id`)
  and carry its auth token (`auth`, see [Channel auth](#channel-auth)); the
  channel's Durable Object checks the token and a per-channel hourly budget
  (`PUSH_PER_HOUR`, default 120). At most 10 device tokens per request. Only
  the device tokens and agent/session ids are taken from the request; the
  notification is built from a fixed template. Without the
  `FCM_SERVICE_ACCOUNT` secret it answers `503`. `ALLOW_UNAUTHENTICATED_PUSH`
  set to `"true"` restores the old unauthenticated behavior for daemons that
  predate channel auth.
- New connections (120 per minute) and pushes (30 per minute) are rate-limited
  per client IP with Workers Rate Limiting bindings (`ratelimits` in
  `wrangler.jsonc`).
- `GET /health` returns `200 OK`.

**Deploy to your own Cloudflare account** (the Free plan is enough: SQLite
Durable Objects are included):

```sh
cd cloudflare
npm install
# Either log in interactively…
npx wrangler login
# …or use an API token with "Workers Scripts: Edit" and, for a custom domain,
# "Zone: DNS: Edit" + "Workers Routes: Edit" on the zone.
export CLOUDFLARE_API_TOKEN=...
export CLOUDFLARE_ACCOUNT_ID=...
```

Edit `cloudflare/wrangler.jsonc`: set `routes[0].pattern` to your hostname (its
zone must be in the same Cloudflare account; DNS and the certificate are
created on deploy), or delete `routes` to use the `*.workers.dev` address.
Then:

```sh
npx wrangler deploy
curl https://relay.example.com/health   # OK
```

Clients connect to `wss://relay.example.com/ws`.

Push notifications (optional): create a Firebase project with your app
registered, create a service account with the *Firebase Cloud Messaging API
Admin* role, download its JSON key, and store it as a secret:

```sh
npx wrangler secret put FCM_SERVICE_ACCOUNT < service-account.json
```

Limits are Worker variables in `wrangler.jsonc`: `MAX_PENDING_MESSAGES`,
`MAX_PENDING_BYTES` (64 MiB per channel and direction on the hosted
instance, 1 GiB in the Rust server), `PENDING_RETENTION_SECS`,
`RECEIPT_RETENTION_SECS`, `DEVICE_RETENTION_SECS`, `PUSH_PER_HOUR`, and
`REQUIRE_AUTH` (see [Channel auth](#channel-auth)).

**Tests** start `wrangler dev` and drive the real `client-ts` end to end:

```sh
cd cloudflare
npm test                                                  # local workerd
RELAY_URL=wss://xailon-relay.infinialabs.ai/ws npm test   # a deployed relay
```

**Differences from the Rust server**

- The relay does not send WebSocket pings (Workers cannot), and there is no
  90-second idle timeout. Clients' pings are answered by Cloudflare, and idle
  sockets stay open; a dead client is detected when its TCP connection drops.
- There is no 16 MiB per-connection ephemeral queue budget: Workers do not
  expose a socket's buffered amount, so an ephemeral message counts as
  delivered once it is handed to the socket.
- A preempted connection receives `connection_replaced` and is then ignored
  until its client closes it, as in the Rust server.
- Storage-backed limits are per pairing id, as in the Rust server; there is
  no cross-channel database to shard.

## Docker

The release workflow builds the `linux/amd64` image
`ghcr.io/infinialabs-ai/xailon-relay` and publishes it to GitHub Container
Registry when a GitHub Release is published. It can also be started manually
from the Actions tab; it authenticates with the built-in `GITHUB_TOKEN`.

```sh
docker run --rm \
  -p 39371:39371 \
  -v relay-data:/data \
  ghcr.io/infinialabs-ai/xailon-relay:main
```

## Connect

Each channel has two numbered endpoints (1 and 2). Connect clients as endpoint 1 or endpoint 2,
specifying the URL-encoded pairing id and a unique `device_id`:

```text
wss://relay.example/ws?id=<pair-id>&endpoint=1&device_id=desktop
wss://relay.example/ws?id=<pair-id>&endpoint=2&device_id=phone_a
wss://relay.example/ws?id=<pair-id>&endpoint=2&device_id=phone_b
```

Query parameters for `/ws`:
- `id`: Channel/user pairing identifier (non-empty string, max 256 bytes).
- `endpoint`: `1` or `2`. Messages sent from 1 are forwarded to 2, and vice versa.
- `device_id`: Unique stable identifier for this device (non-empty string, max 256 bytes).
- `ack_head`: Optional boolean (`true` / `1`). When set on connect, resets this endpoint's receive cursor to the latest head sequence, immediately acknowledging and purging unread server backlog so the device only receives subsequent live messages.
- `auth`: Optional boolean (`1`). The first frame is a channel auth token; see [Channel auth](#channel-auth).

Messages are isolated by pairing id and forwarded to the opposite endpoint with
the same id:

- **Multi-Device Support & Targeted Routing**: Multiple devices with distinct `device_id`s can connect
  to the same endpoint simultaneously without conflicts. Inbound messages destined
  for that endpoint are broadcast in real-time to all currently active devices by default.
  Alternatively, messages can specify an optional `target_device_id` to route exclusively to
  a single designated device. Each device maintains its own durable acknowledgment cursor;
  broadcast messages are purged only after all registered devices have acknowledged them,
  while targeted messages are purged as soon as their designated target device acknowledges them.
- **Device Lifecycle & Inactivity Cutoff**: Inactive devices that have not connected
  within `--device-retention-secs` (default: 7 days) are automatically excluded from
  acknowledgment cursor calculations, preventing abandoned devices from permanently
  blocking pending message pruning.
- **Preemption (Takeover)**: If a connection opens with an already-active
  `(id, endpoint, device_id)`, the relay preempts (replaces) the older socket with
  a `connection_replaced` error frame, allowing mobile clients switching networks
  (e.g. WiFi to 5G) to resume immediately without waiting for half-open idle timeouts.

## Channel auth

A channel id travels in the connect URL, where proxies and access logs can see
it, so on its own it is a weak credential: anyone who learns it could preempt
a device or purge its backlog with `ack_head`. Clients should therefore
authenticate with a 32-byte **channel auth token** derived from a secret both
endpoints share (for example the pairing secret, through HKDF with a distinct
label). The token is never put in the URL:

1. Connect with `auth=1` in the query.
2. Send `{"type":"auth","token":"<base64url, no padding>"}` as the first frame.
3. The relay answers `ready` on success. Otherwise it sends
   `relay_auth_failed: …` or `relay_auth_required: …` and closes, before the
   connection can register, preempt another socket, or acknowledge anything.

How the relay checks a token depends on the id:

- **Self-certifying ids** (recommended): `xrc1_` +
  base64url(SHA-256("xailon-relay/channel/v1" ‖ 0x00 ‖ token)). The id is a hash
  of the token, so the relay verifies it without storing anything, and nobody
  can claim the channel without the token. `relay_client::auth::channel_id` and
  `channelId` in `client-ts` compute it.
- **Other ids** are claimed by their first authenticated connection. The relay
  stores only a SHA-256 verifier of the token bound to the id, and refuses
  every later connection without that token. A claim lapses after
  `--device-retention-secs` without an authenticated connection.
- **Unclaimed ids** keep accepting unauthenticated clients, so existing
  deployments keep working. Start the relay with `--require-auth` (Worker:
  `REQUIRE_AUTH="true"`) to refuse them once all clients authenticate.

Rust: `Client::new(url, store, handler).with_auth_token(token)`.
TypeScript: `new RelayClient({ ..., relayId: await channelId(token), authToken: token })`.

## Health Check

For container orchestrators (Kubernetes, Docker Swarm) and reverse proxies:

```text
GET /health
```
Returns `200 OK` when the service is healthy and ready to accept connections.

## Single instance

One channel's database must be served by exactly one relay process. Connection
state (which `(id, endpoint)` slots are occupied) lives in process memory, so
two relay processes sharing one SQLite file would each accept a connection for
the same `(id, endpoint)`, break duplicate detection, and deliver messages to
whichever process the client happened to reach. Run one process per SQLite
file and scale by sharding pairing ids across files, behind a load balancer
that routes all WebSockets for a pairing id to the same instance (for example
by consistent hashing on the `id` query parameter). After a failover, wait for
the old process to exit before starting the replacement on the same file.

## Wire protocol

Client to server:

```json
{"type":"message","message_id":"stable-client-generated-id","payload":{"any":"json"}}
{"type":"message","message_id":"stable-client-generated-id","payload":{"any":"json"},"target_device_id":"phone_a"}
{"type":"message","message_id":"client-generated-id","payload":{"any":"json"},"ephemeral":true}
{"type":"ack","sequence":42}
{"type":"auth","token":"base64url-32-byte-token"}
```

Server to client:

```json
{"type":"ready","endpoint":"1"}
{"type":"stored","message_id":"stable-client-generated-id"}
{"type":"rejected","message_id":"stable-client-generated-id","reason":"description"}
{"type":"message","message_id":"peer-message-id","sequence":42,"payload":{"any":"json"}}
{"type":"ephemeral","message_id":"peer-message-id","payload":{"any":"json"}}
{"type":"undeliverable","message_id":"client-generated-id","reason":"description"}
{"type":"error","message":"description"}
```

`payload` may be any JSON value. `message_id` must be non-empty, stable across
retries, and no longer than 256 bytes. `target_device_id` is an optional string
specifying a target device on the opposite endpoint; if omitted, the message
is broadcast to all active devices on that endpoint. WebSocket messages are limited to 10 MiB.

Binary WebSocket messages, in both directions, are laid out as
`[u16 big-endian header length][header JSON][body]`, where the header is
`{"message_id":"...","target_device_id":"..."}` (`target_device_id` optional).
They are always ephemeral, and the relay forwards them unchanged.

## Ephemeral delivery

Messages sent with `"ephemeral": true`, and all binary messages, skip the
reliable-delivery contract below. They suit request/response traffic and media
that is only useful while both sides are online:

- The relay forwards them only to devices connected at that moment. Nothing is
  written to SQLite, and no `stored`, sequence, `ack`, or replay is involved.
- Ephemeral text arrives as `{"type":"ephemeral",...}`; binary arrives in the
  same binary layout it was sent in.
- If no device accepts the message, the sender receives `undeliverable`. That
  happens when no matching device is connected, or when every match already
  has 16 MiB of ephemeral data queued, so that a slow receiver cannot grow
  relay memory. A broadcast that reaches only some devices is not reported.
- Within one connection, ephemeral and durable messages keep their relative
  order.

## Reliable delivery

Delivery is at-least-once across endpoint disconnects and relay restarts:

1. A sender writes a message to its own durable outbox, then sends it with a
   stable `message_id`.
2. The sender retains the message and retries it until the relay returns
   `stored`.
3. `stored` means both the pending delivery and its idempotency receipt (storing
   a compact SHA-256 payload hash to detect conflicting payloads) were committed to SQLite.
4. The receiver processes messages in `sequence` order, durably records its
   cumulative receive cursor, and only then sends `ack`.
5. The relay deletes acknowledged pending deliveries. Broadcast messages are purged
   once acknowledged by all active devices on that endpoint (or when expired). Targeted
   messages are purged as soon as the designated target device acknowledges them.
   Unacknowledged messages matching the connecting device (broadcast or targeted to it)
   are replayed in sequence order after reconnect or process restart.
6. If a sender retries a previously stored `message_id`, the relay returns
   `stored` without assigning a second sequence. Receivers must still tolerate
   repeated delivery of the same sequence when an acknowledgement was lost.

If either pending limit is reached, the relay rejects new messages with a
`queue_full` error; it does not evict messages that are still within their
retention period. A duplicate retry of an already stored `message_id` remains
accepted even while the queue is full.

Pending messages older than the configured retention period are removed along
with their receipts. A later retry of the same `message_id` is therefore treated
as a new delivery with a new sequence. Acknowledged receipts expire separately
after the receipt-retention period (default: 1 hour).

The relay detects dead connections itself: it pings every 30 seconds and closes
a connection that has sent nothing (no frames, pongs, or pings) for 90 seconds.
This releases the `(id, endpoint)` slot of a half-open peer — one whose network
path died without a TCP close, for example after a network switch or sleep — so
the real client can reconnect. Clients should also send their own protocol-level
pings if they need to detect a dead relay faster than their TCP stack does.

The relay deliberately provides at-least-once transport, not exactly-once
application execution. An application should make side effects idempotent when
processing a delivered payload.

Cleanup runs once at startup and periodically afterwards. It removes expired
rows; SQLite runs in WAL mode with full auto-vacuum so freed pages can be
returned to the filesystem.

## Client SDKs

The repository includes official clients for Rust and TypeScript/JavaScript implementing the full delivery contract (persistent outbox, automatic retries until `stored`, cumulative acknowledgments, exponential backoff, and preemption handling).

Both clients also send ephemeral messages (`send_ephemeral` / `send_binary` in Rust, `sendEphemeral` / `sendBinary` in TypeScript). These skip the outbox and fail immediately while the relay is not connected. Both take an optional message id (`message_id: Option<String>` in Rust, a third `messageId` argument in TypeScript), so an application can match `on_undeliverable` / `onUndeliverable` against its own ids. Ephemeral text is delivered through the regular payload callback, binary through `on_binary` / `onBinary`, and failed deliveries through `on_undeliverable` / `onUndeliverable`.

### Rust Client (`client-rs`)

Add to `Cargo.toml`:
```toml
[dependencies]
relay-client = { path = "client-rs" } # or git reference
```

Example usage:
```rust
use std::sync::Arc;
use relay_client::{Client, ClientHandler, memory::MemoryStore, transport::endpoint_url, Endpoint};
use serde_json::json;

struct MyHandler;

impl ClientHandler for MyHandler {
    fn on_payload(&self, payload: serde_json::Value) {
        println!("Received payload: {payload}");
    }
    fn on_connected(&self) {
        println!("Connected to relay");
    }
    fn on_disconnected(&self, error: Option<String>) {
        println!("Disconnected: {error:?}");
    }
    fn on_preempted(&self) {
        println!("Session preempted by a new connection from the same device");
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let url = endpoint_url("ws://127.0.0.1:39371/ws", "user_123", Endpoint::One, "desktop");
    let store = Arc::new(MemoryStore::new()); // Use a persistent OutboxStore in production
    let handler = Arc::new(MyHandler);

    let client = Client::new(url, store, handler);

    // Spawn client connection loop
    let client_task = client.clone();
    tokio::spawn(async move {
        if let Err(err) = client_task.run().await {
            eprintln!("Client exited: {err}");
        }
    });

    // Broadcast a message (queued to outbox and sent to all devices on opposite endpoint)
    let message_id = client.send(json!({ "hello": "world" })).await?;

    // Or send a targeted message to a specific device on opposite endpoint
    let targeted_id = client
        .send_targeted(json!({ "hello": "phone" }), Some("phone_a".to_string()))
        .await?;

    // Ephemeral JSON and bytes: live connection only, no outbox
    client.send_ephemeral(json!({ "typing": true }), None, None).await?;
    client.send_binary(&[0x89, 0x50, 0x4e, 0x47], Some("phone_a".to_string()), None).await?;
    // Optional own message id, reported back by on_undeliverable
    client.send_ephemeral(json!({ "request": 1 }), None, Some("request-1".to_string())).await?;

    // Close client when done (disconnects and exits run loop)
    // client.close();

    Ok(())
}
```

### TypeScript Client (`client-ts`)

Import from `client-ts/src/relay-client.ts` or install `relay-client-ts`:

```typescript
import { RelayClient } from './client-ts/src/relay-client';

const client = new RelayClient({
  relayUrl: 'wss://relay.example/ws',
  relayId: 'user_12345',       // User or pairing identifier (1-256 chars)
  endpoint: '2',               // Endpoint 1 or 2
  deviceId: 'phone_a',         // Unique device identifier
  ackHead: false,              // Set true on initial connect to drop stale backlog
  onPayload: (payload) => {
    console.log('Received payload from peer:', payload);
  },
  onBinary: (data, messageId) => {
    console.log('Received bytes from peer:', messageId, data.byteLength);
  },
  onUndeliverable: (messageId, reason) => {
    console.warn('Ephemeral message not delivered:', messageId, reason);
  },
  onStateChange: (state, error) => {
    console.log('Connection state:', state, error);
  },
  onDisconnect: (error) => {
    console.warn('Disconnected:', error.message);
  },
});

// Connect to the relay
await client.connect();

// Broadcast payload to all devices on opposite endpoint
await client.send({ text: 'Hello from phone' });

// Or send payload to a specific target device
await client.send({ text: 'Hello specifically to desktop' }, 'desktop');

// Ephemeral JSON and bytes: live connection only; throws while disconnected
client.sendEphemeral({ typing: true });
client.sendBinary(new Uint8Array([0x89, 0x50, 0x4e, 0x47]), 'desktop');
// Optional own message id, reported back by onUndeliverable
client.sendEphemeral({ request: 1 }, undefined, 'request-1');

// Close connection (stops reconnect loop)
// client.close();
```
