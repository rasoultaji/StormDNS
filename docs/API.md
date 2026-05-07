# StormDNS Client — Local HTTP API Reference

The StormDNS client exposes a local JSON HTTP API that external tools
(monitoring dashboards, mobile companion apps, etc.) can use to inspect the
client's runtime state and send basic control commands.

Base URL: `http://127.0.0.1:9157/api/v1`

The port is configurable via `API_LISTEN_PORT` in `client_config.toml`.

---

## Quick start

```bash
# Check if the API is alive
curl http://127.0.0.1:9157/api/v1/status

# See all resolvers with health stats
curl http://127.0.0.1:9157/api/v1/resolvers

# Stop the client
curl -X POST http://127.0.0.1:9157/api/v1/stop
```

---

## Read endpoints

### `GET /api/v1/status`

Current session state, uptime, and protocol configuration.

```json
{
  "session": {
    "ready": true,
    "id": 12,
    "uptime_seconds": 463.72
  },
  "version": "v2026.01.01.abc1234",
  "protocol": "SOCKS5",
  "encryption": {
    "method_id": 2,
    "method_name": "ChaCha20"
  },
  "compression": {
    "upload": "LZ4",
    "download": "LZ4"
  },
  "base_encoding": false,
  "mtu": {
    "upload_bytes": 196,
    "download_bytes": 3820
  }
}
```

| Field | Description |
|-------|-------------|
| `session.ready` | Whether the tunnel session is established |
| `session.id` | Current session identifier |
| `session.uptime_seconds` | Seconds since the client started |
| `version` | Build version string (from linker flags) |
| `protocol` | `SOCKS5` or `TCP` |
| `encryption.method_name` | NONE, XOR, ChaCha20, AES-128-GCM, AES-192-GCM, AES-256-GCM |
| `compression.upload/download` | OFF, ZSTD, LZ4, ZLIB |
| `base_encoding` | Whether base32/base64 DNS-safe encoding is active |
| `mtu.upload_bytes` | Negotiated upload MTU in bytes |
| `mtu.download_bytes` | Negotiated download MTU in bytes |

---

### `GET /api/v1/traffic`

Session byte counters and estimated current bandwidth.

```json
{
  "tx_bytes": 12345678,
  "rx_bytes": 87654321,
  "tx_speed_bytes_per_sec": 1500.5,
  "rx_speed_bytes_per_sec": 3000.2,
  "tx_total": "11.77 MB",
  "rx_total": "83.59 MB",
  "tx_speed": "1.47 KB/s",
  "rx_speed": "2.93 KB/s"
}
```

- Speeds are computed from the difference between consecutive calls.
- The first call after startup will report zero speed (no prior sample).
- Speed accuracy improves with polling intervals of 1 second or more.

---

### `GET /api/v1/resolvers`

Full list of all domain-resolver pairs with health, performance, and MTU data.

```json
{
  "total": 240,
  "valid": 187,
  "disabled": 5,
  "resolvers": [
    {
      "label": "8.8.8.8:53",
      "domain": "example.com",
      "ip": "8.8.8.8",
      "port": 53,
      "valid": true,
      "disabled": false,
      "rtt_micros": 12345,
      "packets_sent": 2890,
      "packets_acked": 2872,
      "loss_rate": 0.0062,
      "upload_mtu_bytes": 196,
      "download_mtu_bytes": 3820,
      "last_success_at": "2026-05-07T12:30:45Z",
      "timeout_count": 1
    }
  ]
}
```

| Field | Description |
|-------|-------------|
| `total` | Total domain-resolver pairs |
| `valid` | Number of currently valid (MTU-passed) connections |
| `disabled` | Number of auto-disabled resolvers |
| `label` | `IP:Port` label |
| `domain` | Tunnel domain |
| `valid` | Whether MTU check passed |
| `disabled` | Whether the resolver is currently auto-disabled |
| `disabled_cause` | Reason for disable (only when disabled) |
| `disabled_at` | When it was disabled (RFC3339) |
| `next_retry_at` | When it will be re-probed (RFC3339) |
| `rtt_micros` | Average round-trip time in microseconds |
| `packets_sent` / `packets_acked` | Packet tracking counters |
| `loss_rate` | (sent − acked) / sent (only when sent > 0) |
| `timeout_count` | Number of timeout events in the current window |
| `timeout_only_since` | Start of consecutive-timeout window (RFC3339) |

---

### `GET /api/v1/streams`

All active (and recently closed) tunnel streams.

```json
{
  "count": 3,
  "streams": [
    {
      "id": 1,
      "status": "ACTIVE",
      "created_at": "2026-05-07T12:30:40Z",
      "last_activity": "2026-05-07T12:30:50Z",
      "preferred_resolver": "8.8.8.8|53|example.com",
      "resend_streak": 0
    }
  ]
}
```

| Status | Meaning |
|--------|---------|
| `PENDING` | Created but not yet connecting |
| `CONNECTING` | TCP stream connection initiating |
| `SOCKS_CONNECTING` | SOCKS5 handshake in progress |
| `ACTIVE` | Data flowing |
| `DRAINING` | Local side is done sending, waiting for peer |
| `CLOSING` | Teardown in progress |
| `TIME_WAIT` | Terminal — waiting for lingering packets before cleanup |
| `SOCKS_FAILED` | SOCKS5 handshake failed |
| `CANCELLED` | Force-closed |
| `CLOSED` | Cleanly closed and removed |

---

### `GET /api/v1/balancer`

Current balancer state and best connection.

```json
{
  "strategy": "least_loss",
  "valid_connections": 187,
  "best_connection": "8.8.8.8|53|example.com"
}
```

| Strategy | Meaning |
|----------|---------|
| `round_robin` | Simple round-robin distribution |
| `random` | Uniform random selection |
| `least_loss` | Prefer connections with fewest losses |
| `lowest_latency` | Prefer connections with lowest RTT |

---

### `GET /api/v1/mtu`

Detailed MTU parameters (current negotiated values + config bounds).

```json
{
  "upload_bytes": 196,
  "download_bytes": 3820,
  "upload_chars": 48,
  "max_packed_blocks": 1,
  "min_upload": 100,
  "max_upload": 200,
  "min_download": 1000,
  "max_download": 4000,
  "crypto_overhead": 12
}
```

---

### `GET /api/v1/ping`

Timestamps for the most recent ping/pong activity and the current ping
interval mode.

```json
{
  "last_ping_sent_at": "2026-05-07T12:30:50Z",
  "last_pong_received_at": "2026-05-07T12:30:51Z",
  "last_non_ping_sent_at": "2026-05-07T12:30:49Z",
  "last_non_pong_received_at": "2026-05-07T12:30:50Z",
  "ping_interval_mode": "aggressive"
}
```

| Mode | Meaning |
|------|---------|
| `aggressive` | High activity — frequent pings |
| `lazy` | Moderate activity — less frequent pings |
| `cold` | Idle — infrequent keepalives |
| `disabled` | Ping manager not running |

---

### `GET /api/v1/socks`

SOCKS5 proxy connection counters.

```json
{
  "active_connections": 5,
  "blocked_ips": 2
}
```

- `active_connections`: Number of streams with `ACTIVE` status.
- `blocked_ips`: Number of IPs temporarily banned due to repeated SOCKS5
  authentication failures (brute-force protection).

---

### `GET /api/v1/version`

Build version string.

```json
{
  "version": "v2026.01.01.abc1234"
}
```

---

## Write endpoints

### `POST /api/v1/stop`

Gracefully stops the client. Returns `202 Accepted` immediately, then the
client initiates its normal shutdown sequence (session close burst → async
runtime teardown → exit).

```bash
curl -X POST http://127.0.0.1:9157/api/v1/stop
```

```json
{ "status": "accepted", "message": "shutting down" }
```

---

### `POST /api/v1/restart-session`

Restarts the DNS tunnel session without restarting the process.
The client tears down the current session (stopping all active streams),
re-runs MTU tests, and re-initializes a fresh session with the server.

```bash
curl -X POST http://127.0.0.1:9157/api/v1/restart-session
```

```json
{ "status": "accepted", "message": "restarting session" }
```

---

### `POST /api/v1/restart`

Restarts the entire client process. The current process spawns a new
instance with the same command-line arguments and then exits.

```bash
curl -X POST http://127.0.0.1:9157/api/v1/restart
```

```json
{ "status": "accepted", "message": "restarting process" }
```

> **Note:** The HTTP API port will briefly go down during the restart.
> The new process reads the same config file and will start a new listener.

---

## Error responses

All errors follow the same JSON structure:

```json
{
  "error": "description of the problem"
}
```

| HTTP status | Typical cause |
|-------------|---------------|
| `400 Bad Request` | Malformed request body on write endpoints |
| `405 Method Not Allowed` | Wrong HTTP method for the endpoint |
| `429 Too Many Requests` | API command channel full (write endpoints only) |

---

## Configuration

The API is controlled by three settings in `client_config.toml`:

```toml
API_ENABLED        = true          # Enable/disable the API
API_LISTEN_ADDRESS = "127.0.0.1"   # Bind address
API_LISTEN_PORT    = 9157          # TCP port
```

- `API_LISTEN_PORT` must not conflict with `LISTEN_PORT` or `LOCAL_DNS_PORT`.
- The API server binds to the configured address and starts concurrently with
  the tunnel runtime. It shuts down automatically when the client exits.
- No authentication is required — the default bind address (`127.0.0.1`)
  ensures only local processes can reach it.
