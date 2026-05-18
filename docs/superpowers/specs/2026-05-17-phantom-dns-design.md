# Phantom DNS — Design Spec

- **Date:** 2026-05-17
- **Status:** Approved (brainstorm), pending implementation plan
- **Scope:** Evolution of StormDNS in place — rename the deployed binaries to `phantom-client` / `phantom-server`, keep the Go module path `stormdns-go`, ship a backward-compatible v2 wire protocol alongside the existing v1
- **Authors:** brainstormed via `/superpowers:brainstorming` session

## 1. Goals & non-goals

### 1.1 Goals

Phantom DNS is StormDNS made meaningfully faster and meaningfully harder to detect/block by DPI, while preserving StormDNS's defining property: **the client never needs a direct route to the Phantom DNS server**. All client→server communication goes through public DNS resolvers (1.1.1.1, 8.8.8.8, 9.9.9.9, …), and the server is reachable only via standard recursive UDP/53 from those resolvers. An ISP can fully sinkhole the server's IP and the tunnel still works.

Concrete targets:

- **Throughput:** 2–3× StormDNS's effective throughput on a hostile network profile (~5% loss, ~200 ms RTT to resolver, 4 KB EDNS0 bufsize).
- **DPI resistance:** survive "hardest-tier" DPI within the existing "encoded but plausible" wire style — i.e., the queries are still DNS tunnel traffic, but they don't carry the obvious fingerprints (long single base32 label, TXT-only RR type, constant inter-query timing, fixed payload sizes) that today's StormDNS exposes.
- **ISP-level domain sinkhole resilience:** survive an ISP sinkholing one or more of the operator's auth domains.
- **Operator-side breakage:** zero forced migration. Existing v1 clients and v1 servers keep working indefinitely.

### 1.2 Non-goals (this release)

See §11 for the full YAGNI list. Highlights: not multi-tenant, not clustered HA, no 0-RTT resumption, no server-side DoH/DoT/DoQ listeners, no signed-manifest resolver discovery, no extraction of shared libraries with the sibling `phantom` proxy project.

## 2. Threat model & hard constraints

### 2.1 Threat model

The adversary is assumed to be capable of:

- **Passive observation** of all client↔resolver traffic, all resolver↔auth-NS traffic, and all server↔internet traffic.
- **Active DPI** middleboxes that fingerprint DNS queries by label shape, RR type distribution, message length, inter-query timing, and aggregate query volume.
- **Resolver sinkholing** at the ISP recursive resolver, for any auth domain the operator owns.
- **Response injection** — the ISP can inject DNS responses that look like they came from the auth domain.
- **PSK theft** — out of scope for cryptographic defense beyond what's already provided: a stolen PSK lets an active attacker impersonate the server in *new* sessions but does not decrypt past sessions (forward secrecy via per-session ephemeral DH).

The adversary is **not** assumed to:

- Break ChaCha20-Poly1305.
- Break X25519.
- Hijack TLS sessions to public DoH/DoT/DoQ providers (trust `crypto/tls` + `quic-go`).

### 2.2 Hard constraints

These are non-negotiable for v1:

1. **No direct route required.** The client never connects to the Phantom DNS server's IP. Every transport (UDP/53, DoH, DoT, DoQ) goes via a *public* resolver. The DoH/DoT/DoQ adapters validate at startup that their configured endpoints are not the auth domain (§3.2).
2. **v1 stays alive.** v1 clients with v1 servers must keep working unchanged after operators upgrade.
3. **PSK is the auth root.** The pre-shared key file the operator already manages (`encrypt_key.txt`) remains the deployment-identity secret. No new shared-secret material introduced.

## 3. Architecture overview

### 3.1 Module layout

```
internal/transport/         NEW — client-side transport adapter layer
   channel.go               QueryChannel interface
   udp53.go                 wraps current resolver-pool UDP/53 path
   doh.go                   DoH (RFC 8484) over HTTP/2 to public resolvers
   dot.go                   DoT (RFC 7858) TLS to public resolvers
   doq.go                   DoQ (RFC 9250) QUIC to public resolvers
   probe.go                 per-resolver capability probe + scoring
   scanner.go               two-phase resolver scanner (capability + authenticity)
   known_resolvers.go       bundled candidate list (Cloudflare, Google, Quad9, ...)

internal/handshake/         NEW — ephemeral KEX + session-key derivation
   handshake.go             X25519 ephemeral over PSK-authenticated channel
   session_keys.go          HKDF-derived per-direction AEAD keys, rekey state

internal/antidpi/           NEW — encoded-but-plausible toolkit
   labelshape.go            short/varied label generation, dict-backed
   rrtype.go                A/AAAA/HTTPS/SVCB/TXT rotation policy
   padding.go               EDNS0 padding to fixed buckets
   jitter.go                inter-query timing jitter

internal/vpnproto/          CHANGED — v2 framing alongside v1
   framing_v2.go            elastic frame sizes per channel capability
   negotiation.go           v1↔v2 detection via high Type bit
   builder.go, parser.go, packing.go  (v1 paths unchanged)

internal/security/          CHANGED — add AEAD over per-session keys
   codec.go                 unchanged for v1 path
   aead_session.go          v2 AEAD path

internal/client/            CHANGED — wire transport adapters in
   dispatcher.go            picks (resolver, channel, domain) per query
   balancer.go              per-(resolver, channel) health-weighted scoring
   resolver_health.go       per-(resolver, channel) tracking
   stream_resolver.go       async pump per channel with per-channel inflight cap
   domain_health.go         NEW — per-domain success-rate tracking

internal/udpserver/         CHANGED — accept v2 frames
   server_ingress.go        decode anti-DPI-shaped labels, dispatch v1/v2
   server_session.go        per-session AEAD state for v2 sessions

internal/config/            CHANGED — additive v2 keys
   client.go                [domains], [transports], [scanner], [antidpi],
                            [arq], [compression], [crypto], [protocol]
   server.go                [auth].domains, [protocol].accept, [v2].*

cmd/phantom-client/         RENAMED from cmd/client
cmd/phantom-server/         RENAMED from cmd/server
```

`go.mod` module path remains `stormdns-go` — no import-path churn for internal packages.

### 3.2 Data flow (v2 client ↔ v2 server, hostile network)

```
SOCKS5 app ──► phantom-client SOCKS5 listener
            ──► internal/client/dispatcher
            ──► internal/handshake (one-time per session)
            ──► internal/vpnproto v2 framing (elastic per channel)
            ──► internal/antidpi (label / RR-type / padding / jitter)
            ──► internal/transport.QueryChannel (UDP/53 | DoH | DoT | DoQ)
            ──► PUBLIC RESOLVER (1.1.1.1, 8.8.8.8, ...)
            ──► ISP path
            ──► auth domain (one of N rotating domains, NS = phantom-server)
            ──► phantom-server UDP/53 auth-NS
            ──► internal/udpserver v2 decode
            ──► internal/handshake server side
            ──► internal/socks5_upstream ──► real internet
```

The only hop that touches the server's IP is **public resolver → phantom-server** over standard auth-NS UDP/53. The client transport (any of UDP/53 / DoH / DoT / DoQ) terminates at the public resolver. Constraint preserved across all four transports.

### 3.3 What is unchanged

- `internal/arq` — ARQ logic operates on opaque payload bytes; only the in-flight window sizes are tuned per-channel via config.
- `internal/compression`, `internal/dnscache`, `internal/inflight`, `internal/mlq`, `internal/fragmentstore`, `internal/streamutil`, `internal/socksproto`.
- v1 wire format (`vpnproto/builder.go`, `vpnproto/parser.go`, `vpnproto/packing.go`) is frozen for v1 paths.
- The HTTP API (`internal/client/api.go`, `api_handlers.go`).

## 4. Transport adapter layer

### 4.1 Interface

```go
package transport

type QueryChannel interface {
    // Query sends one DNS query (wire format) and awaits one DNS response.
    Query(ctx context.Context, q []byte) ([]byte, error)

    // MaxResponseBytes is a best-effort capacity hint for choosing
    // v2 frame size. UDP/53 returns EDNS0 bufsize (1232..4096).
    // DoH/DoT/DoQ return ~16384.
    MaxResponseBytes() int

    // Health is the channel's current cost signal for the balancer.
    Health() Health

    // Kind identifies the channel for logging / metrics / per-kind budgets.
    Kind() Kind   // Kind53UDP | KindDoH | KindDoT | KindDoQ

    Close() error
}

type Health struct {
    RTTEMA       time.Duration
    SuccessRate  float64
    BudgetTokens int
    LastError    time.Time
    Parked       bool
    UnparkAt     time.Time
}
```

### 4.2 Implementations

| File | Underlying transport | Endpoint pattern | Notes |
|------|----------------------|------------------|-------|
| `udp53.go` | `net.UDPConn` | public resolver IP:53 | Wraps the existing `client/stream_resolver.go` UDP path. No behavior change for v1 paths. |
| `doh.go` | `net/http` with HTTP/2, keep-alive | `https://cloudflare-dns.com/dns-query` etc. | POST `application/dns-message` per RFC 8484. HTTP/2 stream multiplexing carries pipelined queries. 0-RTT not used. |
| `dot.go` | `crypto/tls` over TCP/853 | public DoT resolver | RFC 7858 framing (2-byte length prefix). Persistent connection, query pipelining. |
| `doq.go` | `quic-go` | UDP/853 | RFC 9250. One bidirectional QUIC stream per query in v1 (multi-stream pipelining handled by the per-channel inflight cap). |

`quic-go` is already declared in the StormDNS dependency graph indirectly via REALITY-style code in the sibling project; if not present in StormDNS's `go.sum` today, it is added as a direct dependency.

### 4.3 "No direct route" enforcement

The DoH/DoT/DoQ implementations refuse to accept the operator's auth domain as their endpoint hostname. At startup, the constructor for each channel cross-checks the configured endpoint against the auth-domain list and aborts with a clear error if there's a match. The check is also re-run on every config reload.

### 4.4 Probe + scoring

`internal/transport/probe.go` runs a capability probe per `(resolver, channel)` pair on client startup and on network-change signals:

1. Resolve the resolver's hostname (if any) via the system resolver (one-time, cached).
2. Open the channel and send a benign query (`A example.com`).
3. Measure RTT; classify response as success / DNS-error / network-error.
4. Tag the pair with: working flag, EDNS0 bufsize advertised, RR-type passthrough (probe with HTTPS / SVCB and observe whether the resolver returns them), measured RTT.

The probe results feed the balancer scoring (§7) and the dispatcher's choice of `(resolver, channel, domain)` per query.

## 5. Wire protocol v2

### 5.1 Background — v1 frame

Per `internal/vpnproto/builder.go`:

```
[0]  SessionID        (1B)
[1]  PacketType       (1B)
[2..n] optional extensions:
       StreamID       (2B) if packet flagged with Stream
       SequenceNum    (2B) if packet flagged with Sequence
       FragmentID     (1B) + TotalFragments (1B) if flagged Fragment
       CompressionType(1B) if flagged Compression
[+1] SessionCookie    (1B)
[+1] HeaderCheck      (1B)
[+0..n] Payload
```

Header is 4–9 bytes. Integrity is a 1-byte XOR-style header check. Encryption is applied to the payload by `internal/security/codec.go` using one of XOR / ChaCha20 / AES-GCM keyed by the PSK directly.

### 5.2 v2 frame layout

```
+--------+--------+--------+--------+--------+--------+--------+--------+
|  Type  |  ChCls |    SessionID    |    StreamID     |   SeqNum (lo)   |
+--------+--------+--------+--------+--------+--------+--------+--------+
|  SeqNum (hi)    |               Encrypted Payload (variable)        ...
+--------+--------+--------+--------+--------+--------+--------+--------+
                                                     |   AEAD tag (16) |
                                                     +--------+--------+
```

Fields:

| Field | Bytes | Notes |
|-------|-------|-------|
| `Type` | 1 | High bit (`0x80`) = v2 marker. Low 7 bits = packet type. v2 packet types occupy the `0x80..0xFE` range (avoiding `0xFF`, which v1 reserves for `PACKET_ERROR_DROP`). New v2-only constants live in `internal/enums/dns.go` alongside the existing v1 codes. v1 only uses values in `0x00..0x37` plus `0xFF`, so there is no collision with the v2 range. |
| `ChCls` | 1 | `0` = narrow (UDP/53), `1` = wide (DoH/DoT/DoQ). Tells the peer what frame size budget the sender is using so its ACK/NACK sizing matches. |
| `SessionID` | 2 | Wider than v1's 1B; assigned by server at INIT_ACK. |
| `StreamID` | 2 | Same width as v1. |
| `SeqNum` | 4 | 32-bit, little-endian. 32-bit space prevents wrap at v2 throughput. |
| Payload | variable | AEAD-encrypted. |
| AEAD tag | 16 | ChaCha20-Poly1305 trailer. |

Total overhead: 10 B header + 16 B tag = **26 B per frame**. On UDP/53 with ~1200 B effective payload, overhead ≈ 2.2%. On DoH/DoT/DoQ with 4–16 KB payloads, overhead < 1%.

### 5.3 AEAD construction

- Cipher: ChaCha20-Poly1305.
- Key: `K_c2s` (client→server) or `K_s2c` (server→client), derived in §6.
- Nonce: 12 B = `direction_byte || SessionID(2B) || SeqNum(4B) || 0x00 0x00 0x00 0x00 0x00`. Implicit; not transmitted.
- AAD: the 10-byte v2 header (Type … SeqNum hi).
- Tag: 16-byte trailer on the frame.

### 5.4 Multi-frame packing on wide channels

`internal/vpnproto/framing_v2.go` adds:

```go
func PackV2(frames []Frame) []byte    // multi-frame block
func UnpackV2(blob []byte) ([]Frame, error)
```

Layout: each frame prefixed by a 2-byte big-endian length, concatenated. The outer DNS encoding wraps the whole block as a single carrier message. On wide channels the carrier DNS message can be up to ~64 KB; in practice we cap at 16 KB (configurable) to fit comfortably under most resolver limits and to avoid pathological behavior with edge cases.

On UDP/53, packing is bounded by EDNS0 bufsize and stays close to v1 behavior (2–3 frames per message average).

### 5.5 Wire-DNS encoding

- **Query side:** v2 frame bytes → base32hex (DNS-label-safe, case-insensitive) → split into labels of `antidpi.LabelShape()`-chosen lengths → prepended to one of the currently active auth domains. v1 query encoding (single-label) is preserved unchanged on the v1 code path.
- **Response side:** the server picks an RR type per `antidpi.RRTypePolicy()`:
  - **A** records: 4-byte chunks of frame bytes across multiple RRs.
  - **AAAA** records: 16-byte chunks.
  - **HTTPS (65) / SVCB (64)** records: frame bytes in `SvcParams` blob.
  - **TXT** records: frame bytes split across character-strings (≤255 B each).

  The client decoder reassembles in the order the resolver returned the records and feeds bytes to `UnpackV2`.

### 5.6 Capability negotiation

There is no separate negotiation packet. v2 is signalled by the *client* sending a v2 INIT (Type high bit set) as the first packet of a new session. A **v1 server** sees a `Type` value in the unused `0x80..0xFE` range and rejects the frame via `ErrInvalidPacketType` in the existing v1 parser (`internal/vpnproto/parser.go`); no v1 packet-flags entry matches, so the v1 server silently drops the frame. The client times out the v2 INIT and retries in v1 mode. A **v2 server** recognises the high bit, runs the v2 handshake (§6), and replies in v2.

Result: zero-RTT negotiation in the v2↔v2 case. One wasted handshake RTT when probing a v1 server, sticky for the rest of the session.

A client configured `protocol.version = "v2"` (strict) refuses to fall back to v1. A client configured `"auto"` falls back. A client configured `"v1"` skips v2 entirely.

## 6. Handshake & crypto

### 6.1 1-RTT handshake

```
Client                                       Server
  |                                            |
  |--- INIT ---------------------------------->|
  |    PSK-AEAD-seal {                          |
  |      eph_pub_c (32B)                       |
  |      client_random (16B)                   |
  |      proposed_session_id (2B)              |
  |      capability_bits (2B)                  |
  |      timestamp (8B)                        |
  |    }                                        |
  |                                            |
  |<--- INIT_ACK ------------------------------|
  |    PSK-AEAD-seal {                          |
  |      eph_pub_s (32B)                       |
  |      server_random (16B)                   |
  |      accepted_session_id (2B)              |
  |      capability_bits (2B)                  |
  |    }                                        |
  |                                            |
  |=== data frames (per-session AEAD) ========>|
  |<== data frames (per-session AEAD) ========|
```

INIT and INIT_ACK are carried inside v2-framed packets with packet type `PACKET_V2_INIT` / `PACKET_V2_INIT_ACK`. Their AEAD is keyed by the PSK (via HKDF), not by the session keys (which don't exist yet).

### 6.2 PSK-AEAD seal/open

- Key: `HKDF-Expand(PSK, "phantom-dns-init-v1", 32)`
- Cipher: ChaCha20-Poly1305
- Nonce: 12 B = `direction_byte || client_random[0..10]` for INIT, `direction_byte || server_random[0..10]` for INIT_ACK
- AAD: the outer v2 header bytes
- Replay defense: server rejects any INIT with `timestamp` outside ±5 minutes of server's clock, and de-duplicates `client_random` for 10 minutes (small LRU keyed by random)

### 6.3 Session key derivation

After INIT_ACK is verified:

```
dh   = ECDH(eph_priv_c, eph_pub_s)   // 32B X25519 shared secret
prk  = HKDF-Extract(salt = client_random || server_random,
                    ikm  = PSK || dh)
K_c2s = HKDF-Expand(prk, "phantom-dns-c2s-v1", 32)
K_s2c = HKDF-Expand(prk, "phantom-dns-s2c-v1", 32)
```

The PSK is mixed into the key schedule so a network attacker who can run ECDH but doesn't know PSK still can't derive session keys. Compromise of PSK lets an active attacker impersonate either side in *new* sessions but does not decrypt past sessions (fresh ephemeral DH each session).

### 6.4 Data-frame AEAD

Every non-handshake v2 frame uses the AEAD construction in §5.3 with `K_c2s` (client→server) or `K_s2c` (server→client). Nonces are counter-based (constructed from `SessionID` + `SeqNum`); there is no per-frame nonce on the wire.

### 6.5 Rekey

Triggers (whichever fires first):

- 256 MB transferred per direction since last rekey, OR
- 1 hour wall-clock since last rekey

Both are configurable via `[crypto].rekey_bytes` / `[crypto].rekey_interval`. Defaults are conservative so rekey rarely fires in typical sessions.

Procedure:

1. Either side may initiate. Sender emits `PACKET_V2_REKEY` containing a fresh `eph_pub_*`, AEAD-sealed under the current session key.
2. Peer responds with its fresh ephemeral, AEAD-sealed under the current session key.
3. Both derive new `K_c2s'`, `K_s2c'` using the same HKDF construction in §6.3 with `client_random'` / `server_random'` drawn from the rekey messages.
4. Old keys retained for 2× Maximum Segment Lifetime (~120 s) to decrypt in-flight frames.

Per-packet cost: zero. The 32-bit `SeqNum` has enough headroom that rekey is bounded by bytes-transferred and wall-clock, not by nonce exhaustion.

**Collision tiebreaker:** if both sides initiate REKEY simultaneously (each sends a REKEY without having yet seen the other's), the **client's REKEY wins**. The server, upon receiving a client REKEY while having an outstanding server REKEY, discards its own ephemeral and adopts the client's; the client's REKEY reply path proceeds normally. This avoids a key-derivation desync. Mid-rekey data frames continue under the old session keys until both sides have exchanged ephemerals.

### 6.6 Throughput cost

The v1 path uses PSK directly with ChaCha20 or AES-GCM. The v2 path uses per-session-derived keys with ChaCha20-Poly1305. **The per-packet cipher cost is identical.** Only added cost is the 1-RTT handshake at session start, amortized to ~0 over a session.

### 6.7 Dependencies

All from Go stdlib + `golang.org/x/crypto`:

- `crypto/ecdh` — X25519
- `golang.org/x/crypto/chacha20poly1305`
- `golang.org/x/crypto/hkdf`

No new third-party crypto.

## 7. Anti-DPI layer

The bar is "hardest-tier DPI" within the "encoded but plausible" wire style. The layer is a **policy module** — given a frame to send, it shapes the carrier DNS message; given a frame to return, the server shapes the DNS response. The decoder is permissive: any well-formed shape that decodes to a valid v2 frame is accepted.

### 7.1 Label shape (`labelshape.go`)

- Encode frame bytes as base32hex (DNS-label-safe).
- **Split** encoded bytes into 2–5 labels with lengths drawn from a per-session distribution that approximates real-world DNS label-length histograms (mode ~6 chars, tail to 20).
- **Dictionary blending**: optional vocabulary of innocuous fragments (`api`, `cdn`, `img`, `s3`, `ws`, `eu-west`, `static`, `assets`, `web`, …) interleaved between encoded labels. Per-session entropy seeds which positions get dictionary fragments. Result reads partly like a real subdomain — e.g., `xyz9.cdn.h7q3pk.eu-west.example.com`.
- Default dictionary is embedded (`internal/antidpi/dict_default.go`). Operator can override via `[antidpi].label_dict_path`.
- Mixed case (DNS labels are case-insensitive on the wire but case is preserved through resolvers — aligns with browser 0x20-encoding).

### 7.2 RR-type rotation (`rrtype.go`)

A session that only queries TXT is a fingerprint. v2 rotates per query:

| RR type | Carrier capacity per RR | Use case |
|---------|-------------------------|----------|
| A | 4 bytes | small ACK/control packets, most common query type in normal traffic |
| AAAA | 16 bytes | medium control / small data |
| HTTPS (65) | ~250 B per record via SvcParams | modern, growing in browser traffic, high carrier capacity |
| SVCB (64) | similar to HTTPS | additional rotation slot |
| TXT | up to ~255 B per char-string, many strings | fallback for largest payloads on UDP/53 |

Per-session RR-type mix (default ~50/20/15/10/5) is chosen at INIT, biased by which RR types the chosen `(resolver, channel)` passes reliably (some resolvers strip or normalize HTTPS/SVCB — flagged during `transport/probe.go` capability probe).

### 7.3 EDNS0 padding (`padding.go`)

RFC 7830 EDNS(0) Padding option. Outgoing DNS messages padded to fixed bucket sizes:

- UDP/53: 128, 256, 512, 1024, 1232 bytes
- DoH/DoT/DoQ: 512, 1024, 2048, 4096, 8192, 16384 bytes

The decoder ignores the padding option.

### 7.4 Timing jitter (`jitter.go`)

Inter-query spacing drawn from a log-normal distribution centered on the current target rate. Bursty within a window (matches real browser behavior at page load), idle between bursts. On wide channels with pipelining, jitter applies to flush boundaries rather than per-query so it doesn't kill throughput.

Defaults: `jitter_mean_ms = 80`, `jitter_sigma = 0.4`. Tunable.

### 7.5 Query coalescing

When N frames are ready, pack them via existing `vpnproto/packing.go` (v1) or new multi-frame packing (§5.4, v2). Fewer queries → less suspicious volume → less budget consumed per resolver.

### 7.6 Server-side decoder

`internal/udpserver/server_ingress.go` is permissive — accepts any combination of label shape / RR type / padding that decodes to a valid v2 frame. New helpers extend support to the wider RR-type set. Existing `internal/dnsparser` already handles most RR types we need.

## 8. Multi-domain rotation + resolver pool

### 8.1 Multi-domain

The operator delegates **N domains** (e.g., `a.example.com`, `b.example.net`, `c.example.org`), each with NS records pointing to the same Phantom DNS server IP. The client config lists all N.

**Client config:**

```toml
[domains]
list = [
  { fqdn = "a.example.com", weight = 1 },
  { fqdn = "b.example.net", weight = 1 },
  { fqdn = "c.example.org", weight = 1 },
]
rotation = "per-session"   # default sticky-per-session
                           # also: "per-query", "weighted-random"
```

**Domain health (`internal/client/domain_health.go`):**

- Per-domain rolling success rate over last 100 queries.
- Healthy if success ≥ 70% across at least 3 different resolvers.
- Below threshold → parked for back-off, periodic re-probe at low rate.
- Hard signals (consistent NXDOMAIN / SERVFAIL / REFUSED dominating) park faster.

**Failover semantics:**

- Within a single in-flight query: try `(resolver, domain)` → on hard failure, retry same resolver + next domain → on second failure, try next resolver + first domain. Cap at 3 retries before signaling ARQ-level failure.
- Across the session: domain rotation is sticky within a stream by default to avoid invalidating per-domain encoding state, but free to switch on failure.

**Server config:**

```toml
[auth]
domains = ["a.example.com", "b.example.net", "c.example.org"]
```

**Server logic:** strip the auth domain from the FQDN — accept *any* of the configured domains. Reject (with REFUSED) FQDNs not matching the allowlist. The decoded v2 frame is identical regardless of which domain carried it; the v2 frame does **not** include the auth domain in its AAD (would break decoding when the client rotates domains within a stream).

### 8.2 Resolver pool

Extending `internal/client/resolver_health.go`, `balancer.go`, `stream_resolver.go`.

**Health key change:** today tracks per-resolver health. v2 tracks **per-(resolver, channel) health**, since the same resolver may work on UDP/53 but fail on DoT (or vice versa) on a given network.

```go
type resolverChannelKey struct {
    ResolverID string         // e.g., "cloudflare-1.1.1.1"
    Channel    transport.Kind
}
type resolverChannelHealth struct {
    RTTEMA       time.Duration
    SuccessRate  float64
    BudgetTokens int           // token-bucket for per-resolver QPS
    LastError    time.Time
    Parked       bool
    UnparkAt     time.Time
}
```

**Balancer picks `(resolver, channel, domain)`** per outgoing query, scoring on:

1. `(resolver, channel)` health & RTT.
2. `(resolver, channel)` budget remaining (token-bucket per resolver).
3. Domain health.
4. RR-type capability of `(resolver, channel)` for the chosen frame size — if the antidpi layer wants HTTPS RRs and this resolver strips them, balancer skips.

**Per-resolver budgets:** token-bucket sized per provider's published QPS limit; conservative default of 200 QPS.

**Known-resolver registry (`internal/transport/known_resolvers.go`):**

```go
var KnownResolvers = []ResolverSpec{
    {ID: "cloudflare", IP: "1.1.1.1",
     DoH: "https://cloudflare-dns.com/dns-query",
     DoT: "1.1.1.1:853",
     DoQ: "1.1.1.1:853"},
    {ID: "google", IP: "8.8.8.8",
     DoH: "https://dns.google/dns-query",
     DoT: "8.8.8.8:853",
     DoQ: ""},   // Google does not run DoQ as of writing
    {ID: "quad9", IP: "9.9.9.9",
     DoH: "https://dns.quad9.net/dns-query",
     DoT: "9.9.9.9:853",
     DoQ: ""},
    {ID: "adguard", IP: "94.140.14.14",
     DoH: "https://dns.adguard-dns.com/dns-query",
     DoT: "94.140.14.14:853",
     DoQ: "94.140.14.14:853"},
    // Mullvad, NextDNS, ControlD, dnsforge, and others
}
```

Operators can extend via config. Channel endpoint hostnames are validated at startup not to match any configured auth domain (preserves §2.2 constraint).

### 8.3 Resolver scanner (`internal/transport/scanner.go`)

Two-phase startup; optional background re-scan.

**Phase 1 — Capability probe.** For each *configured* resolver (known list + operator additions), probe which of the 4 channels respond and what their RTT looks like. Tag the working set and observed RR-type passthrough.

**Phase 2 — Authenticity probe.** For each working `(resolver, channel)` pair, send a probe query for our auth domain. The probe is shaped like a real Phantom DNS query but carries a special `PACKET_V2_PROBE` payload sealed with `PSK-AEAD-seal` (same key schedule as INIT, different HKDF info string `"phantom-dns-probe-v1"`). The server responds with `PACKET_V2_PROBE_ACK` containing a fresh server nonce, also PSK-sealed.

The client validates:

- AEAD tag verifies → **proven**: this resolver actually delivers to our server, the response isn't ISP-injected. Add to active pool.
- AEAD fails / NXDOMAIN / timeout → **rejected**: park.

This rules out: ISP DNS poisoning, captive resolvers, attacker-controlled clones of our auth domain, resolvers that strip the RR types we depend on.

**Optional active scan (`[scanner].active = true`):** sweep a bundled "candidate public resolver" list (~40 IPs) through the same two-phase probe. Disabled by default.

**Re-scan triggers:** network interface change, default route change, sustained health collapse across the active pool, low-rate periodic re-probe of parked resolvers every 10 minutes.

### 8.4 Response authentication summary

| Stage | Authenticator | What it defends |
|-------|---------------|-----------------|
| INIT_ACK | `PSK-AEAD-seal` with HKDF(PSK, "init") | ISP-injected fake INIT_ACK can't forge tag without PSK |
| PROBE_ACK | `PSK-AEAD-seal` with HKDF(PSK, "probe") | Proves resolver actually delivers to our server |
| Every data frame | Per-session AEAD with `K_s2c` | Forgery requires breaking ChaCha20-Poly1305 or knowing post-DH session key |
| REKEY | Per-session AEAD with current `K_s2c` | Rotation under existing session is authenticated |

The client / server **drop silently** on AEAD failure — no error response goes back, no information leak that we exist on this name.

## 9. Throughput tuning

### 9.1 Levers

1. Multi-frame packing per DNS message (§5.4).
2. Adaptive ARQ window per channel.
3. Compression policy.
4. Pipelining on wide channels.
5. Multi-path / multi-resolver parallelism.

### 9.2 Multi-frame packing (quantified)

| Channel | DNS message budget | Frames per message (1200 B avg payload) | Multiplier vs. v1 |
|---------|--------------------|------------------------------------------|-------------------|
| UDP/53 (EDNS0 4096) | ~3800 B usable | 2–3 | 2–3× |
| DoH (HTTP/2 body) | 16384 B per msg | 12–13 | ~12× per round trip |
| DoT (TCP) | 16384 B per msg | 12–13 | ~12× per round trip |
| DoQ (QUIC) | 16384 B per msg | 12–13 | ~12× per round trip |

### 9.3 Adaptive ARQ window

Configured per channel kind (`[arq]` config section):

| Channel | Default in-flight cap | Rationale |
|---------|----------------------|-----------|
| UDP/53 | 16 | bounded by per-resolver QPS budget, UDP loss tolerance |
| DoH | 64 | HTTP/2 multiplex, in-flight is cheap |
| DoT | 32 | TCP single-stream, head-of-line blocking risk |
| DoQ | 128 | QUIC stream-per-query is cheap, loss doesn't head-of-line block |

ARQ logic itself is unchanged; only the configured per-channel target window changes.

### 9.4 Compression

- **LZ4** is the default for v2 sessions: ~3–5× faster encode/decode than zlib, ~10–15% worse ratio. On modern hardware it saturates at multi-GB/s — effectively free.
- Per-stream LZ4 dictionary trained on the stream prefix for streams long enough to benefit; pure stateless mode for short bursts.
- Heuristic skip on incompressible payloads (TLS records, encrypted blobs) — sniff first 256 bytes.
- The existing `PACKET_FLAG_COMPRESSION` carrier byte stays unchanged; new algorithm codes added to its enumeration.

### 9.5 Pipelining on wide channels

`internal/client/stream_resolver.go`:

- UDP/53 — keep current pacing (resolver budget is the limit).
- DoH — async pump, up to `arq.inflight_doh` concurrent POSTs over the HTTP/2 connection.
- DoT — pipelined queries on the single TLS connection with per-query 2-byte length prefix.
- DoQ — one bidi QUIC stream per query, up to `arq.inflight_doq` concurrent streams.

### 9.6 Multi-path / multi-resolver parallelism

`internal/client/balancer.go`:

- Maintain an active pool of `(resolver, channel)` pairs.
- For each outgoing frame, pick one of the top-K healthy pairs (default `K=3`) weighted by health score.
- A single Phantom DNS session may simultaneously have queries on Cloudflare-DoH + Google-UDP53 + Quad9-DoT.

Safe under the "no direct route" rule: each `(resolver, channel)` is still a public-resolver hop. The server only sees recursive UDP/53 traffic.

### 9.7 Target check (back-of-envelope)

Hostile-network profile (5% loss, 200 ms RTT):

- **v1 StormDNS**: 1 resolver, UDP/53, 1 frame/query, ~200 B payload, ARQ window 8 → ~40 KB/s.
- **v2 Phantom DNS** (modest setup): 3 active resolvers, mix UDP/53 + DoH, ~4 frames/query packed, 1200 B effective payload:
  - Per-resolver UDP/53 at 200 QPS budget, window 16, 200 ms RTT → ~96 KB/s
  - Per-resolver DoH with HTTP/2 keep-alive, ~400 ms effective RTT, window 64, 12 frames packed/response → ~230 KB/s
  - Weighted blend across 3 active pairs → ~150 KB/s aggregate, **~3.75× v1**. Clears 2–3× with margin.

The exact numbers depend on the actual loss/RTT profile and resolver behavior; the design carries the levers, the deployment carries the measurement.

## 10. Config & migration

### 10.1 New client config keys (additive)

```toml
# === existing keys (unchanged) ===
[server]
host = "auth.example.com"
encryption_key_file = "client_key.txt"

[resolvers]
list = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]

# === new v2 keys ===
[protocol]
version = "auto"                    # "v1" | "v2" | "auto"

[domains]                            # if present, overrides [server].host
list = [
  { fqdn = "a.example.com", weight = 1 },
  { fqdn = "b.example.net", weight = 1 },
  { fqdn = "c.example.org", weight = 1 },
]
rotation = "per-session"

[transports]
allow = ["udp53", "doh", "dot", "doq"]
prefer = "auto"

[scanner]
active = false
rescan_on_network_change = true
parked_recheck_interval = "10m"

[antidpi]
label_dict_path = ""                # empty = embedded dictionary
rrtype_mix = "auto"
padding_buckets = "auto"
jitter_mean_ms = 80
jitter_sigma = 0.4

[arq]
inflight_udp53 = 16
inflight_doh = 64
inflight_dot = 32
inflight_doq = 128

[compression]
algo = "lz4"

[crypto]
rekey_bytes = "256MB"
rekey_interval = "1h"
```

### 10.2 New server config keys (additive)

```toml
# === existing keys (unchanged) ===
[server]
host = "auth.example.com"
encryption_key_file = "encrypt_key.txt"

# === new v2 keys ===
[protocol]
accept = ["v1", "v2"]

[auth]
domains = ["a.example.com", "b.example.net", "c.example.org"]

[v2]
data_encryption = "chacha20poly1305"
rekey_bytes = "256MB"
rekey_interval = "1h"

[v2.antidpi]
allow_rrtypes = ["A", "AAAA", "HTTPS", "SVCB", "TXT"]
accept_padding = true
```

### 10.3 Migration states

| State | Meaning | Action |
|-------|---------|--------|
| A: v1 client ↔ v1 server | Today's deployment | Works unchanged forever. No action. |
| B: v1 client ↔ v2 server | Server upgraded first | `protocol.accept = ["v1", "v2"]` on server. v1 clients keep working. |
| C: v2 client ↔ v2 server | Full upgrade | Distribute new client config with `[domains]` / `[transports]`. Add `[auth].domains` on server. Same PSK file. |

**Migration is never forced.** v1 deprecation in a future release is a decision for after v2 proves itself in deployment.

### 10.4 Config compatibility shims

- Client: if both `[server].host` and `[domains].list` are present, `[domains].list` wins; `[server].host` is appended with a warning log.
- Client: if only `[server].host` is present, the client behaves as v1 (single domain) and tries v2 only when `[protocol].version` is `"v2"` or `"auto"`.
- Server: if both `[server].host` and `[auth].domains` are present, the union is accepted; one warning log on startup.

### 10.5 Binary rename

- `cmd/client` → `cmd/phantom-client`
- `cmd/server` → `cmd/phantom-server`
- `go.mod` module path stays `stormdns-go`. No import-path churn.
- `server_linux_install.sh` and `client_linux_install.sh` updated to reference new binary names and systemd unit names (`phantom-server.service`, `phantom-client.service`).
- No alias binaries shipped — operators replace old binaries with new during upgrade.

## 11. Out of scope (v1)

Each is a candidate for a later release if measurement justifies it.

| Item | Why excluded from v1 |
|------|----------------------|
| Cover-query traffic (decoy queries) | Burns resolver budget; unproven benefit. Revisit only if DPI fingerprints on aggregate volume. |
| Server-side DoH/DoT/DoQ listeners | The server only receives recursive UDP/53 by design (§2.2). DoH-on-server would invite direct client connections, breaking the guarantee. |
| 0-RTT resumption ticket | Saves ~1 RTT at session start; sessions are long-lived so amortized gain is small. |
| Server-static public-key crypto (drop PSK) | User selected the perf-optimal path. PSK + per-session FS already removes "shared key decrypts all past traffic." |
| DNSSEC on the auth domain | Doesn't help our security model — AEAD on every response (§8.4) already authenticates end-to-end. |
| Multi-server / clustering / HA | Single server per deployment. Operators wanting HA run multiple deployments. |
| Signed-manifest resolver discovery | Bundled known list + operator config + optional active scan covers v1 needs. |
| Dynamic auth-domain registration | N domains are static config; restart required to add/remove. |
| Multi-tenant per-user PSKs | Single PSK per server = single tenant. |
| Web UI for config or stats | Existing HTTP API stays. Web UI is unrelated to the throughput/DPI goals. |
| REALITY-style TLS to public DoH/DoT | The public providers run normal TLS with valid certs — nothing to "REALITY" past. |
| TCP/53 fallback for oversized responses | EDNS0 4096-byte bufsize covers v2 frame sizes; public resolvers handle TCP/53 transparently if they need to. |
| Code sharing with the sibling `phantom` project | Tempting library extraction; out of scope. Each project keeps its own lineage. |
| Hot-reload of all config | Restart-required for v1; hot-reload is a follow-up. |
| Per-client rate limits on the server | StormDNS's recent hardening commits already cover server-side connection tracking and rate limits. |

## 12. Testing strategy

### 12.1 Unit tests per new package

| Package | Tests |
|---------|-------|
| `internal/handshake` | INIT/INIT_ACK round-trip; PSK-AEAD seal/open; replay window rejection; timestamp skew; HKDF matches RFC 5869 test vectors; rekey state machine. |
| `internal/transport` | Per channel: probe success/failure, RTT measurement, error classification, close+reopen; balancer scoring; per-resolver token bucket; "no direct route" validator rejects auth domains. |
| `internal/antidpi` | Label-shape distribution matches spec; RR-type rotation honors weights; EDNS0 padding pads exactly to bucket; jitter distribution; round-trip of bytes through label-encode/decode for every shape. |
| `internal/vpnproto/framing_v2` | Round-trip every packet type at every payload size; multi-frame pack/unpack; v1↔v2 detection; AEAD AAD covers exactly the 10-byte header. |
| `internal/client/domain_health` | Score updates, parking, unparking, per-(resolver,domain) tracking. |

### 12.2 Cross-version compatibility matrix

`internal/integration/compat_test.go` covers:

| Client | Server | Expected |
|--------|--------|----------|
| v1 | v1 | works |
| v1 | v2 (`accept=["v1","v2"]`) | works, v1 mode |
| v1 | v2 (`accept=["v2"]`) | server rejects; client gives up cleanly |
| v2 (`auto`) | v1 | falls back to v1 |
| v2 (`auto`) | v2 | runs v2 |
| v2 (`v2`) | v1 | refuses to downgrade, session fails |

### 12.3 Mock public-resolver harness

`internal/test/mockresolver/` listens on ephemeral ports for all four channels, performs real recursive lookup against an in-test authoritative server (the phantom-server under test), and injects failures: drop X% of packets, add latency, strip selected RR types, truncate responses, simulate ISP sinkhole (NXDOMAIN / REFUSED / fake A).

The sinkhole simulation exercises §8.4 — client must detect via AEAD failure and park the resolver.

### 12.4 Property / fuzz tests

- `vpnproto/framing_v2` parser fuzz (`go test -fuzz=`): arbitrary byte sequences, assert no panic / no amplification.
- `antidpi/labelshape` decoder fuzz: arbitrary label combos, decoder either decodes or returns a clean error.
- `handshake` PSK-AEAD-open fuzz: arbitrary INIT bytes, never panic.

### 12.5 Hostile-network simulation

Chained mock-harness failure modes:

- 5% loss + 200 ms RTT + 4 KB EDNS0 cap: assert v2 sustains ≥ 100 KB/s for 60 s.
- 10% loss + 400 ms RTT + 2 resolvers parked mid-session: assert no session crash, throughput recovers.
- Random resolver disappears mid-session: assert traffic redistributes within 2 s.
- 10-minute continuous session: assert exactly one rekey fires (interval-based at 1 h), seq numbers don't wrap.

### 12.6 Live-resolver smoke (CI, gated)

A single end-to-end test that runs against real public resolvers (1.1.1.1, 8.8.8.8) using a project-owned test auth domain. Gated behind `-tags=livenet`. Verifies four channels actually work in the wild and probe authenticity passes.

### 12.7 Explicitly not tested

- ChaCha20-Poly1305 / X25519 forgery — trust the stdlib AEAD and X25519.
- TLS implementation correctness for DoH/DoT/DoQ — trust `crypto/tls` and `quic-go`.
- Public-resolver-provider behavior changes — outside our test surface; covered as best-effort by §12.6.

## 13. Open questions

None remaining from the brainstorm. All design decisions in §3–§12 were explicitly chosen during the session. Items deferred to "out of scope" (§11) are intentional, not open questions.

## 14. Appendix — quick decision audit

For traceability, the load-bearing brainstorm choices that this design encodes:

- Relation to StormDNS: **evolve in place**, not fork.
- Transports: **UDP/53 + DoH + DoT + DoQ**, all four.
- Camouflage style: **encoded but plausible**, with hardest-tier DPI investment *within* that style.
- Throughput target: **2–3×** StormDNS on hostile network.
- Domain model: **multiple operator-delegated domains with client-side rotation**.
- Crypto: **PSK + per-session forward secrecy via X25519 ephemeral DH**, ChaCha20-Poly1305 (perf-optimal across platforms).
- Connectivity constraint: **no direct route between client and server**, all transports via public resolvers (load-bearing across the whole design).
- Resolver scanner with **authenticity probe** so fake DNS responses are detected by AEAD failure on the probe.
- Binary names: rename `cmd/client` → `cmd/phantom-client`, `cmd/server` → `cmd/phantom-server`; module path unchanged.
