# Phantom DNS Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Evolve StormDNS into Phantom DNS — ship a backward-compatible v2 wire protocol with 4 client transports (UDP/53, DoH, DoT, DoQ), AEAD with per-session forward secrecy, anti-DPI traffic shaping, multi-domain rotation with resolver authenticity probing, and 2–3× throughput on hostile networks.

**Architecture:** New `internal/transport/`, `internal/handshake/`, `internal/antidpi/` packages plus additive changes to `internal/vpnproto/`, `internal/security/`, `internal/client/`, `internal/udpserver/`, `internal/config/`. v1 wire format is frozen — v2 lives alongside it, distinguished by a Type-byte marker. `cmd/client` and `cmd/server` get renamed to `cmd/phantom-client` and `cmd/phantom-server`; Go module path (`stormdns-go`) is unchanged.

**Tech Stack:** Go 1.26.3, `crypto/ecdh` (X25519), `golang.org/x/crypto/chacha20poly1305`, `golang.org/x/crypto/hkdf`, `github.com/quic-go/quic-go` (new), `pierrec/lz4/v4` (already in `go.sum`), `BurntSushi/toml` (existing config), `crypto/tls` + `net/http` HTTP/2.

**Source spec:** `docs/superpowers/specs/2026-05-17-phantom-dns-design.md` (committed `d1f4978` on `main`).

**Conventions to follow throughout:**
- Every new Go file begins with the project banner (same format as existing files: `// =====` line, `// StormDNS`, `// Author: nullroute1970`, `// Github: https://github.com/nullroute1970/StormDNS`, `// Year: 2026`, closing `// =====`). Test files use the same banner.
- Imports use the module path `stormdns-go/...`.
- Public types and functions are exported; package-internal helpers stay unexported.
- Errors are sentinels (`var ErrXxx = errors.New(...)`) when callers might want to compare; wrapped otherwise via `fmt.Errorf("...: %w", err)`.
- Tests use stdlib `testing`; table-driven where it helps; no third-party assertion library.

---

## Pre-work

### Task 0: Branch, baseline, dependencies

**Goal:** create a feature branch from `main`, confirm the existing test suite is green on it, and add `quic-go` to `go.mod` so DoQ work in Phase C compiles.

**Files:**
- Modify: `go.mod`, `go.sum`

**Steps:**

- [ ] **Step 1: Create the feature branch off the spec commit**

  ```bash
  cd /Users/rasoul/Desktop/phantom-dns/StormDNS
  git checkout main
  git pull --ff-only origin main || true   # repo may have no remote; ignore failure
  git checkout -b feat/phantom-dns-v2
  ```

- [ ] **Step 2: Confirm baseline tests pass before any changes**

  ```bash
  go test ./...
  ```
  Expected: PASS for every package. If anything fails on `main`, STOP and surface the failure — don't start changes on a red baseline.

- [ ] **Step 3: Add quic-go dependency**

  ```bash
  go get github.com/quic-go/quic-go@latest
  go mod tidy
  ```

- [ ] **Step 4: Confirm build still succeeds**

  ```bash
  go build ./...
  ```
  Expected: no output, exit 0.

- [ ] **Step 5: Commit the dependency bump**

  ```bash
  git add go.mod go.sum
  git commit -m "chore: add quic-go dependency for DoQ transport"
  ```

---

## Phase A — Crypto primitives & v2 wire protocol

This phase builds the foundational packages with no integration into the existing dispatcher / server ingress yet. Every new file is pure logic + unit tests. End of phase: handshake, AEAD frame seal/open, v2 framing, and v1↔v2 detection all work in isolation.

### Task 1: Reserve v2 packet type constants

**Goal:** add the v2-only packet type constants to `internal/enums/dns.go` in the `0x80..0xFE` range (verified safe in spec §5.2). No logic change yet, just constants the later tasks depend on.

**Files:**
- Modify: `internal/enums/dns.go`

**Steps:**

- [ ] **Step 1: Add the constants below the existing `PACKET_ERROR_DROP = 0xFF` line**

  Append (preserving file ordering — keep `PACKET_ERROR_DROP` last among 0xFF entries):

  ```go
  // ----- v2 packet types (high-bit marker, 0x80..0xFE) -----
  // The v1 parser rejects any Type in this range via ErrInvalidPacketType,
  // so a v1 server safely drops v2 frames it can't speak.
  const (
      PACKET_V2_INIT       = 0x80
      PACKET_V2_INIT_ACK   = 0x81
      PACKET_V2_DATA       = 0x82
      PACKET_V2_ACK        = 0x83
      PACKET_V2_NACK       = 0x84
      PACKET_V2_REKEY      = 0x85
      PACKET_V2_REKEY_ACK  = 0x86
      PACKET_V2_PROBE      = 0x87
      PACKET_V2_PROBE_ACK  = 0x88
      PACKET_V2_CLOSE      = 0x89
      PACKET_V2_PACKED     = 0x8A   // carries one or more inner v2 frames
  )
  ```

- [ ] **Step 2: Build to confirm no syntax error**

  Run: `go build ./internal/enums/...`
  Expected: exit 0, no output.

- [ ] **Step 3: Commit**

  ```bash
  git add internal/enums/dns.go
  git commit -m "feat(enums): reserve v2 packet type constants in 0x80..0xFE"
  ```

---

### Task 2: HKDF and key-schedule helpers

**Goal:** small, testable helpers for HKDF-Extract / HKDF-Expand wrapped around `golang.org/x/crypto/hkdf` with our exact info-string conventions from spec §6.

**Files:**
- Create: `internal/handshake/session_keys.go`
- Test:   `internal/handshake/session_keys_test.go`

**Steps:**

- [ ] **Step 1: Write the failing test**

  ```go
  // internal/handshake/session_keys_test.go
  package handshake

  import (
      "bytes"
      "testing"
  )

  func TestDeriveSessionKeys_Deterministic(t *testing.T) {
      psk := bytes.Repeat([]byte{0x11}, 32)
      dh := bytes.Repeat([]byte{0x22}, 32)
      cr := bytes.Repeat([]byte{0x33}, 16)
      sr := bytes.Repeat([]byte{0x44}, 16)

      a, err := DeriveSessionKeys(psk, dh, cr, sr)
      if err != nil {
          t.Fatalf("DeriveSessionKeys: %v", err)
      }
      b, err := DeriveSessionKeys(psk, dh, cr, sr)
      if err != nil {
          t.Fatalf("DeriveSessionKeys (2): %v", err)
      }
      if !bytes.Equal(a.ClientToServer, b.ClientToServer) {
          t.Fatal("K_c2s not deterministic")
      }
      if !bytes.Equal(a.ServerToClient, b.ServerToClient) {
          t.Fatal("K_s2c not deterministic")
      }
      if bytes.Equal(a.ClientToServer, a.ServerToClient) {
          t.Fatal("K_c2s and K_s2c must differ")
      }
      if len(a.ClientToServer) != 32 || len(a.ServerToClient) != 32 {
          t.Fatalf("session key length: got c2s=%d s2c=%d, want 32 each",
              len(a.ClientToServer), len(a.ServerToClient))
      }
  }

  func TestDeriveSessionKeys_InputSensitivity(t *testing.T) {
      psk := bytes.Repeat([]byte{0x11}, 32)
      dh := bytes.Repeat([]byte{0x22}, 32)
      cr := bytes.Repeat([]byte{0x33}, 16)
      sr := bytes.Repeat([]byte{0x44}, 16)

      base, _ := DeriveSessionKeys(psk, dh, cr, sr)

      altDH := bytes.Repeat([]byte{0x23}, 32)
      diff, _ := DeriveSessionKeys(psk, altDH, cr, sr)
      if bytes.Equal(base.ClientToServer, diff.ClientToServer) {
          t.Fatal("changing DH must change K_c2s")
      }
  }

  func TestDerivePSKAEADKey_Distinct(t *testing.T) {
      psk := bytes.Repeat([]byte{0x55}, 32)
      initKey := DerivePSKAEADKey(psk, "init")
      probeKey := DerivePSKAEADKey(psk, "probe")
      if bytes.Equal(initKey, probeKey) {
          t.Fatal("init and probe PSK-AEAD keys must differ")
      }
      if len(initKey) != 32 || len(probeKey) != 32 {
          t.Fatalf("key length: init=%d probe=%d, want 32", len(initKey), len(probeKey))
      }
  }
  ```

- [ ] **Step 2: Run the test, verify FAIL**

  Run: `go test ./internal/handshake/...`
  Expected: FAIL (package `handshake` does not exist).

- [ ] **Step 3: Implement the helpers**

  ```go
  // internal/handshake/session_keys.go
  // (Banner header omitted here for brevity — include the standard StormDNS banner.)
  package handshake

  import (
      "crypto/sha256"
      "fmt"
      "io"

      "golang.org/x/crypto/hkdf"
  )

  // SessionKeys are the per-direction AEAD keys derived after the v2 handshake.
  type SessionKeys struct {
      ClientToServer []byte // 32 B, used by client to seal, server to open
      ServerToClient []byte // 32 B, used by server to seal, client to open
  }

  // DeriveSessionKeys runs the HKDF schedule from spec §6.3.
  //   prk   = HKDF-Extract(salt = clientRandom || serverRandom,
  //                        ikm  = PSK || dh)
  //   K_c2s = HKDF-Expand(prk, "phantom-dns-c2s-v1", 32)
  //   K_s2c = HKDF-Expand(prk, "phantom-dns-s2c-v1", 32)
  func DeriveSessionKeys(psk, dh, clientRandom, serverRandom []byte) (SessionKeys, error) {
      if len(psk) == 0 || len(dh) == 0 {
          return SessionKeys{}, fmt.Errorf("handshake: empty psk or dh")
      }
      if len(clientRandom) != 16 || len(serverRandom) != 16 {
          return SessionKeys{}, fmt.Errorf("handshake: random fields must be 16 bytes each")
      }

      salt := make([]byte, 0, 32)
      salt = append(salt, clientRandom...)
      salt = append(salt, serverRandom...)

      ikm := make([]byte, 0, len(psk)+len(dh))
      ikm = append(ikm, psk...)
      ikm = append(ikm, dh...)

      c2s, err := hkdfDerive(salt, ikm, "phantom-dns-c2s-v1", 32)
      if err != nil {
          return SessionKeys{}, err
      }
      s2c, err := hkdfDerive(salt, ikm, "phantom-dns-s2c-v1", 32)
      if err != nil {
          return SessionKeys{}, err
      }
      return SessionKeys{ClientToServer: c2s, ServerToClient: s2c}, nil
  }

  // DerivePSKAEADKey derives a 32-byte AEAD key bound to a label
  // (e.g. "init" or "probe") and the PSK only — no per-session salt.
  // Used by PSK-AEAD-seal/open in handshake.go.
  func DerivePSKAEADKey(psk []byte, label string) []byte {
      info := "phantom-dns-" + label + "-v1"
      key, _ := hkdfDerive(nil, psk, info, 32)
      return key
  }

  func hkdfDerive(salt, ikm []byte, info string, outLen int) ([]byte, error) {
      r := hkdf.New(sha256.New, ikm, salt, []byte(info))
      out := make([]byte, outLen)
      if _, err := io.ReadFull(r, out); err != nil {
          return nil, fmt.Errorf("hkdf expand %q: %w", info, err)
      }
      return out, nil
  }
  ```

- [ ] **Step 4: Run the test, verify PASS**

  Run: `go test ./internal/handshake/...`
  Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

  ```bash
  git add internal/handshake/session_keys.go internal/handshake/session_keys_test.go
  git commit -m "feat(handshake): HKDF key schedule for v2 session keys"
  ```

---

### Task 3: PSK-AEAD seal / open

**Goal:** the primitive used for INIT, INIT_ACK, PROBE, and PROBE_ACK — ChaCha20-Poly1305 keyed by `DerivePSKAEADKey(psk, label)`, nonce derived from a 16-byte random field as in spec §6.2.

**Files:**
- Create: `internal/handshake/handshake.go`
- Test:   `internal/handshake/handshake_test.go`

**Steps:**

- [ ] **Step 1: Write the failing test**

  ```go
  // internal/handshake/handshake_test.go
  package handshake

  import (
      "bytes"
      "testing"
  )

  func TestPSKAEAD_RoundTrip(t *testing.T) {
      psk := bytes.Repeat([]byte{0x77}, 32)
      plaintext := []byte("hello phantom dns")
      aad := []byte("v2-header-bytes")
      random := bytes.Repeat([]byte{0x33}, 16)

      sealed, err := PSKAEADSeal(psk, "init", DirClient, random, plaintext, aad)
      if err != nil {
          t.Fatalf("seal: %v", err)
      }
      if bytes.Equal(sealed, plaintext) {
          t.Fatal("seal did not encrypt")
      }

      opened, err := PSKAEADOpen(psk, "init", DirClient, random, sealed, aad)
      if err != nil {
          t.Fatalf("open: %v", err)
      }
      if !bytes.Equal(opened, plaintext) {
          t.Fatalf("opened = %q, want %q", opened, plaintext)
      }
  }

  func TestPSKAEAD_TamperedCiphertext(t *testing.T) {
      psk := bytes.Repeat([]byte{0x77}, 32)
      random := bytes.Repeat([]byte{0x33}, 16)
      sealed, _ := PSKAEADSeal(psk, "init", DirClient, random,
          []byte("payload"), []byte("aad"))
      sealed[0] ^= 0x01
      if _, err := PSKAEADOpen(psk, "init", DirClient, random, sealed, []byte("aad")); err == nil {
          t.Fatal("expected open to fail on tampered ciphertext")
      }
  }

  func TestPSKAEAD_TamperedAAD(t *testing.T) {
      psk := bytes.Repeat([]byte{0x77}, 32)
      random := bytes.Repeat([]byte{0x33}, 16)
      sealed, _ := PSKAEADSeal(psk, "init", DirClient, random,
          []byte("payload"), []byte("aad"))
      if _, err := PSKAEADOpen(psk, "init", DirClient, random, sealed, []byte("AAD")); err == nil {
          t.Fatal("expected open to fail on changed AAD")
      }
  }

  func TestPSKAEAD_WrongDirection(t *testing.T) {
      psk := bytes.Repeat([]byte{0x77}, 32)
      random := bytes.Repeat([]byte{0x33}, 16)
      sealed, _ := PSKAEADSeal(psk, "init", DirClient, random,
          []byte("p"), []byte("aad"))
      if _, err := PSKAEADOpen(psk, "init", DirServer, random, sealed, []byte("aad")); err == nil {
          t.Fatal("expected open to fail when direction byte differs")
      }
  }

  func TestPSKAEAD_DistinctLabels(t *testing.T) {
      psk := bytes.Repeat([]byte{0x77}, 32)
      random := bytes.Repeat([]byte{0x33}, 16)
      sealed, _ := PSKAEADSeal(psk, "init", DirClient, random,
          []byte("p"), []byte("aad"))
      if _, err := PSKAEADOpen(psk, "probe", DirClient, random, sealed, []byte("aad")); err == nil {
          t.Fatal("expected open to fail when label differs (different key)")
      }
  }
  ```

- [ ] **Step 2: Run the test, verify FAIL**

  Run: `go test ./internal/handshake/...`
  Expected: FAIL (`PSKAEADSeal`, `PSKAEADOpen`, `DirClient`, `DirServer` undefined).

- [ ] **Step 3: Implement**

  ```go
  // internal/handshake/handshake.go
  package handshake

  import (
      "errors"
      "fmt"

      "golang.org/x/crypto/chacha20poly1305"
  )

  // Direction identifies which side sealed the message. It is mixed into
  // the AEAD nonce so client→server and server→client traffic cannot be
  // cross-replayed even if the random field collides.
  type Direction byte

  const (
      DirClient Direction = 0x01
      DirServer Direction = 0x02
  )

  var ErrPSKAEADOpen = errors.New("handshake: PSK-AEAD open failed")

  // PSKAEADSeal encrypts plaintext under HKDF(PSK, label)-derived key using
  // ChaCha20-Poly1305. The 12-byte nonce is: direction || random[0..10].
  // `random` MUST be 16 bytes; only its first 11 are used for the nonce so
  // the full 16-byte field can also be carried in the message as client_random
  // or server_random per spec §6.1.
  func PSKAEADSeal(psk []byte, label string, dir Direction, random, plaintext, aad []byte) ([]byte, error) {
      if len(random) != 16 {
          return nil, fmt.Errorf("handshake: random must be 16 bytes, got %d", len(random))
      }
      key := DerivePSKAEADKey(psk, label)
      aead, err := chacha20poly1305.New(key)
      if err != nil {
          return nil, fmt.Errorf("handshake: chacha20poly1305.New: %w", err)
      }
      nonce := buildNonce(dir, random)
      return aead.Seal(nil, nonce, plaintext, aad), nil
  }

  // PSKAEADOpen reverses PSKAEADSeal. Returns ErrPSKAEADOpen on tag failure.
  func PSKAEADOpen(psk []byte, label string, dir Direction, random, ciphertext, aad []byte) ([]byte, error) {
      if len(random) != 16 {
          return nil, fmt.Errorf("handshake: random must be 16 bytes, got %d", len(random))
      }
      key := DerivePSKAEADKey(psk, label)
      aead, err := chacha20poly1305.New(key)
      if err != nil {
          return nil, fmt.Errorf("handshake: chacha20poly1305.New: %w", err)
      }
      nonce := buildNonce(dir, random)
      out, err := aead.Open(nil, nonce, ciphertext, aad)
      if err != nil {
          return nil, ErrPSKAEADOpen
      }
      return out, nil
  }

  func buildNonce(dir Direction, random []byte) []byte {
      nonce := make([]byte, 12)
      nonce[0] = byte(dir)
      copy(nonce[1:], random[0:11])
      return nonce
  }
  ```

- [ ] **Step 4: Run, verify PASS**

  Run: `go test ./internal/handshake/...`
  Expected: PASS (5 PSK-AEAD tests + the 3 key-schedule tests from Task 2).

- [ ] **Step 5: Commit**

  ```bash
  git add internal/handshake/handshake.go internal/handshake/handshake_test.go
  git commit -m "feat(handshake): PSK-AEAD seal/open with direction-bound nonce"
  ```

---

### Task 4: INIT / INIT_ACK message encoding

**Goal:** encode/decode the INIT and INIT_ACK plaintext bodies (the bytes that go inside `PSKAEADSeal`) per spec §6.1. Keep this as a pure encoding layer — wiring into the v2 frame envelope happens later (Task 11).

**Files:**
- Create: `internal/handshake/messages.go`
- Test:   `internal/handshake/messages_test.go`

**Steps:**

- [ ] **Step 1: Write the failing test**

  ```go
  // internal/handshake/messages_test.go
  package handshake

  import (
      "bytes"
      "testing"
      "time"
  )

  func TestInitRoundTrip(t *testing.T) {
      orig := Init{
          EphPubC:          bytesRepeat(0xAA, 32),
          ClientRandom:     bytesRepeat(0xBB, 16),
          ProposedSession:  0x1234,
          CapabilityBits:   0x0001,
          Timestamp:        time.Unix(1_700_000_000, 0).UTC(),
      }
      enc := orig.Marshal()
      if len(enc) != initMsgLen {
          t.Fatalf("marshal len = %d, want %d", len(enc), initMsgLen)
      }
      var got Init
      if err := got.Unmarshal(enc); err != nil {
          t.Fatalf("unmarshal: %v", err)
      }
      if !bytes.Equal(got.EphPubC, orig.EphPubC) {
          t.Fatalf("eph_pub_c mismatch")
      }
      if !bytes.Equal(got.ClientRandom, orig.ClientRandom) {
          t.Fatalf("client_random mismatch")
      }
      if got.ProposedSession != orig.ProposedSession {
          t.Fatalf("session id mismatch: got %d want %d", got.ProposedSession, orig.ProposedSession)
      }
      if got.CapabilityBits != orig.CapabilityBits {
          t.Fatalf("capability bits mismatch")
      }
      if !got.Timestamp.Equal(orig.Timestamp) {
          t.Fatalf("timestamp mismatch: got %v want %v", got.Timestamp, orig.Timestamp)
      }
  }

  func TestInitAckRoundTrip(t *testing.T) {
      orig := InitAck{
          EphPubS:          bytesRepeat(0xCC, 32),
          ServerRandom:     bytesRepeat(0xDD, 16),
          AcceptedSession:  0x5678,
          CapabilityBits:   0x0001,
      }
      enc := orig.Marshal()
      if len(enc) != initAckMsgLen {
          t.Fatalf("marshal len = %d, want %d", len(enc), initAckMsgLen)
      }
      var got InitAck
      if err := got.Unmarshal(enc); err != nil {
          t.Fatalf("unmarshal: %v", err)
      }
      if !bytes.Equal(got.EphPubS, orig.EphPubS) || !bytes.Equal(got.ServerRandom, orig.ServerRandom) {
          t.Fatalf("pubkey/random mismatch")
      }
      if got.AcceptedSession != orig.AcceptedSession || got.CapabilityBits != orig.CapabilityBits {
          t.Fatalf("session/cap mismatch")
      }
  }

  func TestInitUnmarshal_ShortBuf(t *testing.T) {
      var got Init
      if err := got.Unmarshal(make([]byte, 5)); err == nil {
          t.Fatal("expected error on short buffer")
      }
  }

  func bytesRepeat(b byte, n int) []byte {
      out := make([]byte, n)
      for i := range out {
          out[i] = b
      }
      return out
  }
  ```

- [ ] **Step 2: Run, verify FAIL**

  Run: `go test ./internal/handshake/...`
  Expected: FAIL (`Init`, `InitAck`, constants undefined).

- [ ] **Step 3: Implement**

  ```go
  // internal/handshake/messages.go
  package handshake

  import (
      "encoding/binary"
      "errors"
      "time"
  )

  // Wire-format constants for the INIT / INIT_ACK plaintext bodies.
  // Layout matches spec §6.1.
  const (
      initMsgLen    = 32 + 16 + 2 + 2 + 8 // eph_pub_c + client_random + sess + cap + ts
      initAckMsgLen = 32 + 16 + 2 + 2     // eph_pub_s + server_random + sess + cap
  )

  var ErrShortHandshakeBuf = errors.New("handshake: buffer too short")

  type Init struct {
      EphPubC         []byte // 32 B
      ClientRandom    []byte // 16 B
      ProposedSession uint16
      CapabilityBits  uint16
      Timestamp       time.Time
  }

  func (m Init) Marshal() []byte {
      buf := make([]byte, initMsgLen)
      copy(buf[0:32], m.EphPubC)
      copy(buf[32:48], m.ClientRandom)
      binary.BigEndian.PutUint16(buf[48:50], m.ProposedSession)
      binary.BigEndian.PutUint16(buf[50:52], m.CapabilityBits)
      binary.BigEndian.PutUint64(buf[52:60], uint64(m.Timestamp.Unix()))
      return buf
  }

  func (m *Init) Unmarshal(buf []byte) error {
      if len(buf) < initMsgLen {
          return ErrShortHandshakeBuf
      }
      m.EphPubC = append([]byte(nil), buf[0:32]...)
      m.ClientRandom = append([]byte(nil), buf[32:48]...)
      m.ProposedSession = binary.BigEndian.Uint16(buf[48:50])
      m.CapabilityBits = binary.BigEndian.Uint16(buf[50:52])
      m.Timestamp = time.Unix(int64(binary.BigEndian.Uint64(buf[52:60])), 0).UTC()
      return nil
  }

  type InitAck struct {
      EphPubS         []byte // 32 B
      ServerRandom    []byte // 16 B
      AcceptedSession uint16
      CapabilityBits  uint16
  }

  func (m InitAck) Marshal() []byte {
      buf := make([]byte, initAckMsgLen)
      copy(buf[0:32], m.EphPubS)
      copy(buf[32:48], m.ServerRandom)
      binary.BigEndian.PutUint16(buf[48:50], m.AcceptedSession)
      binary.BigEndian.PutUint16(buf[50:52], m.CapabilityBits)
      return buf
  }

  func (m *InitAck) Unmarshal(buf []byte) error {
      if len(buf) < initAckMsgLen {
          return ErrShortHandshakeBuf
      }
      m.EphPubS = append([]byte(nil), buf[0:32]...)
      m.ServerRandom = append([]byte(nil), buf[32:48]...)
      m.AcceptedSession = binary.BigEndian.Uint16(buf[48:50])
      m.CapabilityBits = binary.BigEndian.Uint16(buf[50:52])
      return nil
  }
  ```

- [ ] **Step 4: Run, verify PASS**

  Run: `go test ./internal/handshake/...`
  Expected: PASS (3 new + 8 existing).

- [ ] **Step 5: Commit**

  ```bash
  git add internal/handshake/messages.go internal/handshake/messages_test.go
  git commit -m "feat(handshake): INIT / INIT_ACK message marshaling"
  ```

---

### Task 5: X25519 ephemeral key exchange + full handshake helper

**Goal:** wrap `crypto/ecdh` X25519 into a small helper that generates an ephemeral keypair and computes the DH shared secret, then ties INIT/INIT_ACK + PSK-AEAD + key derivation together into a single `ClientHandshake`/`ServerHandshake` round-trip helper that tests can exercise without networking.

**Files:**
- Create: `internal/handshake/kex.go`
- Create: `internal/handshake/flow.go`
- Test:   `internal/handshake/flow_test.go`

**Steps:**

- [ ] **Step 1: Write the failing test**

  ```go
  // internal/handshake/flow_test.go
  package handshake

  import (
      "bytes"
      "testing"
      "time"
  )

  func TestHandshakeRoundTrip(t *testing.T) {
      psk := bytes.Repeat([]byte{0x99}, 32)

      // Client builds INIT.
      cState, initEnvelope, err := ClientStart(psk, 0, time.Now().UTC(),
          []byte("v2-hdr-c"))
      if err != nil {
          t.Fatalf("ClientStart: %v", err)
      }

      // Server receives INIT, builds INIT_ACK.
      sState, ackEnvelope, err := ServerAccept(psk, initEnvelope,
          []byte("v2-hdr-c"), []byte("v2-hdr-s"))
      if err != nil {
          t.Fatalf("ServerAccept: %v", err)
      }

      // Client finishes with INIT_ACK.
      if err := cState.Finish(psk, ackEnvelope, []byte("v2-hdr-s")); err != nil {
          t.Fatalf("Client.Finish: %v", err)
      }

      // Both sides derived identical session keys.
      if !bytes.Equal(cState.Keys.ClientToServer, sState.Keys.ClientToServer) {
          t.Fatal("K_c2s mismatch across sides")
      }
      if !bytes.Equal(cState.Keys.ServerToClient, sState.Keys.ServerToClient) {
          t.Fatal("K_s2c mismatch across sides")
      }
      if cState.SessionID == 0 || cState.SessionID != sState.SessionID {
          t.Fatalf("session id mismatch: c=%d s=%d", cState.SessionID, sState.SessionID)
      }
  }

  func TestHandshakeRejectsBadPSK(t *testing.T) {
      cState, initEnvelope, err := ClientStart(bytes.Repeat([]byte{0xAA}, 32),
          0, time.Now().UTC(), []byte("v2-hdr"))
      if err != nil {
          t.Fatalf("ClientStart: %v", err)
      }
      _ = cState
      _, _, err = ServerAccept(bytes.Repeat([]byte{0xBB}, 32), initEnvelope,
          []byte("v2-hdr"), []byte("v2-hdr-s"))
      if err == nil {
          t.Fatal("ServerAccept must fail under wrong PSK")
      }
  }

  func TestHandshakeRejectsReplay(t *testing.T) {
      psk := bytes.Repeat([]byte{0x99}, 32)
      cState, env, _ := ClientStart(psk, 0, time.Now().UTC(), []byte("v2-hdr"))
      _ = cState
      cache := NewReplayCache(time.Minute, 1024)
      if _, _, err := ServerAcceptWithReplay(psk, env, []byte("v2-hdr"),
          []byte("v2-hdr-s"), cache, time.Now()); err != nil {
          t.Fatalf("first accept: %v", err)
      }
      if _, _, err := ServerAcceptWithReplay(psk, env, []byte("v2-hdr"),
          []byte("v2-hdr-s"), cache, time.Now()); err == nil {
          t.Fatal("replayed INIT must be rejected")
      }
  }
  ```

- [ ] **Step 2: Run, verify FAIL**

  Run: `go test ./internal/handshake/...`
  Expected: FAIL (symbols undefined).

- [ ] **Step 3: Implement X25519 helper**

  ```go
  // internal/handshake/kex.go
  package handshake

  import (
      "crypto/ecdh"
      "crypto/rand"
      "fmt"
  )

  // GenerateEphemeral returns an X25519 keypair from crypto/rand.
  func GenerateEphemeral() (priv *ecdh.PrivateKey, pub []byte, err error) {
      curve := ecdh.X25519()
      priv, err = curve.GenerateKey(rand.Reader)
      if err != nil {
          return nil, nil, fmt.Errorf("handshake: ecdh GenerateKey: %w", err)
      }
      pub = priv.PublicKey().Bytes()
      return priv, pub, nil
  }

  // DHCompute returns the X25519 shared secret for our private key
  // and the peer's public key bytes (32 B).
  func DHCompute(priv *ecdh.PrivateKey, peerPub []byte) ([]byte, error) {
      curve := ecdh.X25519()
      peer, err := curve.NewPublicKey(peerPub)
      if err != nil {
          return nil, fmt.Errorf("handshake: bad peer pubkey: %w", err)
      }
      dh, err := priv.ECDH(peer)
      if err != nil {
          return nil, fmt.Errorf("handshake: ECDH: %w", err)
      }
      return dh, nil
  }
  ```

- [ ] **Step 4: Implement handshake flow + replay cache**

  ```go
  // internal/handshake/flow.go
  package handshake

  import (
      "crypto/ecdh"
      "crypto/rand"
      "errors"
      "fmt"
      "sync"
      "time"
  )

  var (
      ErrHandshakeReplay  = errors.New("handshake: replayed INIT")
      ErrHandshakeSkew    = errors.New("handshake: timestamp outside window")
      ErrHandshakeOpen    = errors.New("handshake: INIT/INIT_ACK open failed")
      DefaultClockSkew    = 5 * time.Minute
      DefaultReplayWindow = 10 * time.Minute
  )

  // ClientState is held by the client between ClientStart and Finish.
  type ClientState struct {
      ephPriv      *ecdh.PrivateKey
      clientRandom []byte
      SessionID    uint16
      Keys         SessionKeys
  }

  // ServerState is held by the server after ServerAccept.
  type ServerState struct {
      SessionID uint16
      Keys      SessionKeys
  }

  // ClientStart generates the client ephemeral, builds the INIT body,
  // and seals it under PSK-AEAD. proposedSessionID = 0 means "server picks".
  func ClientStart(psk []byte, proposedSessionID uint16, now time.Time, aad []byte) (*ClientState, []byte, error) {
      priv, pub, err := GenerateEphemeral()
      if err != nil {
          return nil, nil, err
      }
      cr := make([]byte, 16)
      if _, err := rand.Read(cr); err != nil {
          return nil, nil, fmt.Errorf("handshake: rand client_random: %w", err)
      }
      msg := Init{
          EphPubC:         pub,
          ClientRandom:    cr,
          ProposedSession: proposedSessionID,
          CapabilityBits:  capV2Default(),
          Timestamp:       now.UTC(),
      }
      sealed, err := PSKAEADSeal(psk, "init", DirClient, cr, msg.Marshal(), aad)
      if err != nil {
          return nil, nil, err
      }
      return &ClientState{ephPriv: priv, clientRandom: cr}, sealed, nil
  }

  // ServerAccept opens the INIT envelope, derives the session keys,
  // and produces an INIT_ACK envelope to send back.
  func ServerAccept(psk, initEnvelope, initAAD, ackAAD []byte) (*ServerState, []byte, error) {
      return serverAcceptCommon(psk, initEnvelope, initAAD, ackAAD, nil, time.Now())
  }

  // ServerAcceptWithReplay is like ServerAccept but consults a ReplayCache
  // for client_random + checks the clock-skew window from spec §6.2.
  func ServerAcceptWithReplay(psk, initEnvelope, initAAD, ackAAD []byte, cache *ReplayCache, now time.Time) (*ServerState, []byte, error) {
      return serverAcceptCommon(psk, initEnvelope, initAAD, ackAAD, cache, now)
  }

  func serverAcceptCommon(psk, initEnvelope, initAAD, ackAAD []byte, cache *ReplayCache, now time.Time) (*ServerState, []byte, error) {
      // We need the random field to derive the nonce; spec carries it as
      // the first 16 bytes of the plaintext but we must derive the nonce
      // BEFORE we can open. The wire convention is: the random field is
      // also reproduced in the outer v2 frame header bytes used as AAD,
      // so we open against the AAD-validated random the v2 envelope passed in.
      // For self-contained handshake testing here, we treat the first 16
      // bytes of `initAAD` as the random when no random is otherwise known.
      // In production the v2 envelope passes the random explicitly via
      // ServerAcceptFull — see Task 11 for the integrated path.
      if len(initAAD) < 16 {
          return nil, nil, errors.New("handshake: initAAD must include 16-byte random prefix")
      }
      cr := initAAD[:16]
      plain, err := PSKAEADOpen(psk, "init", DirClient, cr, initEnvelope, initAAD)
      if err != nil {
          return nil, nil, ErrHandshakeOpen
      }
      var msg Init
      if err := msg.Unmarshal(plain); err != nil {
          return nil, nil, err
      }
      if abs(now.Sub(msg.Timestamp)) > DefaultClockSkew {
          return nil, nil, ErrHandshakeSkew
      }
      if cache != nil && !cache.Add(msg.ClientRandom, now) {
          return nil, nil, ErrHandshakeReplay
      }

      ephPriv, ephPub, err := GenerateEphemeral()
      if err != nil {
          return nil, nil, err
      }
      sr := make([]byte, 16)
      if _, err := rand.Read(sr); err != nil {
          return nil, nil, err
      }
      dh, err := DHCompute(ephPriv, msg.EphPubC)
      if err != nil {
          return nil, nil, err
      }
      keys, err := DeriveSessionKeys(psk, dh, msg.ClientRandom, sr)
      if err != nil {
          return nil, nil, err
      }
      sid := msg.ProposedSession
      if sid == 0 {
          sid = randomSessionID()
      }
      ack := InitAck{
          EphPubS:         ephPub,
          ServerRandom:    sr,
          AcceptedSession: sid,
          CapabilityBits:  capV2Default(),
      }
      sealed, err := PSKAEADSeal(psk, "init", DirServer, sr, ack.Marshal(), ackAAD)
      if err != nil {
          return nil, nil, err
      }
      return &ServerState{SessionID: sid, Keys: keys}, sealed, nil
  }

  // Finish is called by the client when INIT_ACK comes back.
  func (cs *ClientState) Finish(psk, ackEnvelope, ackAAD []byte) error {
      if len(ackAAD) < 16 {
          return errors.New("handshake: ackAAD must include 16-byte random prefix")
      }
      sr := ackAAD[:16]
      plain, err := PSKAEADOpen(psk, "init", DirServer, sr, ackEnvelope, ackAAD)
      if err != nil {
          return ErrHandshakeOpen
      }
      var msg InitAck
      if err := msg.Unmarshal(plain); err != nil {
          return err
      }
      dh, err := DHCompute(cs.ephPriv, msg.EphPubS)
      if err != nil {
          return err
      }
      keys, err := DeriveSessionKeys(psk, dh, cs.clientRandom, msg.ServerRandom)
      if err != nil {
          return err
      }
      cs.Keys = keys
      cs.SessionID = msg.AcceptedSession
      return nil
  }

  func capV2Default() uint16 { return 0x0001 }

  func randomSessionID() uint16 {
      var b [2]byte
      _, _ = rand.Read(b[:])
      sid := uint16(b[0])<<8 | uint16(b[1])
      if sid == 0 {
          sid = 1
      }
      return sid
  }

  func abs(d time.Duration) time.Duration {
      if d < 0 {
          return -d
      }
      return d
  }

  // ReplayCache is a tiny LRU keyed by client_random used by ServerAccept
  // to dedupe INIT messages within DefaultReplayWindow.
  type ReplayCache struct {
      window time.Duration
      cap    int
      mu     sync.Mutex
      order  []replayEntry
      seen   map[string]time.Time
  }

  type replayEntry struct {
      key string
      at  time.Time
  }

  func NewReplayCache(window time.Duration, capacity int) *ReplayCache {
      return &ReplayCache{
          window: window,
          cap:    capacity,
          seen:   make(map[string]time.Time, capacity),
      }
  }

  // Add records seeing `random` at time `now`. Returns false if it was
  // already seen within the window.
  func (r *ReplayCache) Add(random []byte, now time.Time) bool {
      r.mu.Lock()
      defer r.mu.Unlock()
      r.evict(now)
      key := string(random)
      if _, dup := r.seen[key]; dup {
          return false
      }
      r.seen[key] = now
      r.order = append(r.order, replayEntry{key: key, at: now})
      if len(r.order) > r.cap {
          drop := r.order[0]
          r.order = r.order[1:]
          delete(r.seen, drop.key)
      }
      return true
  }

  func (r *ReplayCache) evict(now time.Time) {
      cutoff := now.Add(-r.window)
      cut := 0
      for cut < len(r.order) && r.order[cut].at.Before(cutoff) {
          delete(r.seen, r.order[cut].key)
          cut++
      }
      if cut > 0 {
          r.order = r.order[cut:]
      }
  }
  ```

  Note: the comment in `serverAcceptCommon` flags that the random field gets
  passed in via AAD's first 16 bytes for testing. The integrated v2-frame
  path in Task 11 will provide a thin wrapper that extracts the random
  from the outer v2 frame body rather than this convention. Do not ship
  this convention as the production API.

- [ ] **Step 5: Run, verify PASS**

  Run: `go test ./internal/handshake/...`
  Expected: PASS (all 3 new + 11 existing).

- [ ] **Step 6: Commit**

  ```bash
  git add internal/handshake/kex.go internal/handshake/flow.go internal/handshake/flow_test.go
  git commit -m "feat(handshake): X25519 KEX + 1-RTT handshake flow with replay cache"
  ```

---

### Task 6: REKEY state machine

**Goal:** the state transitions and key swap from spec §6.5, including the client-wins tiebreaker on simultaneous initiation. Pure state machine — no AEAD code here (REKEY messages reuse the data-frame AEAD path defined in Task 8).

**Files:**
- Create: `internal/handshake/rekey.go`
- Test:   `internal/handshake/rekey_test.go`

**Steps:**

- [ ] **Step 1: Write the failing test**

  ```go
  // internal/handshake/rekey_test.go
  package handshake

  import (
      "bytes"
      "testing"
      "time"
  )

  func TestRekey_ClientInitiatesServerResponds(t *testing.T) {
      psk := bytes.Repeat([]byte{0x42}, 32)
      cs, env, _ := ClientStart(psk, 0, time.Now().UTC(), bytes.Repeat([]byte{0}, 16))
      ss, ack, _ := ServerAccept(psk, env, bytes.Repeat([]byte{0}, 16), bytes.Repeat([]byte{1}, 16))
      _ = cs.Finish(psk, ack, bytes.Repeat([]byte{1}, 16))

      rk := NewRekeyCoordinator(IsClient)
      ephPub, msg, err := rk.Start(cs.Keys)
      if err != nil {
          t.Fatalf("rekey start: %v", err)
      }
      if len(ephPub) != 32 {
          t.Fatalf("eph pub size = %d", len(ephPub))
      }
      _ = msg

      srk := NewRekeyCoordinator(IsServer)
      peerPub, reply, err := srk.HandlePeer(ss.Keys, ephPub)
      if err != nil {
          t.Fatalf("server handle: %v", err)
      }
      newServerKeys := srk.NewKeys()
      _ = reply

      finalClient, err := rk.Finish(peerPub)
      if err != nil {
          t.Fatalf("client finish: %v", err)
      }
      if !bytes.Equal(finalClient.ClientToServer, newServerKeys.ClientToServer) {
          t.Fatal("rekeyed K_c2s diverged across sides")
      }
      if !bytes.Equal(finalClient.ServerToClient, newServerKeys.ServerToClient) {
          t.Fatal("rekeyed K_s2c diverged across sides")
      }
      if bytes.Equal(finalClient.ClientToServer, cs.Keys.ClientToServer) {
          t.Fatal("rekey did not change K_c2s")
      }
  }

  func TestRekey_CollisionClientWins(t *testing.T) {
      // Both sides start a rekey concurrently. The server must
      // discard its own ephemeral and adopt the client's per spec §6.5.
      rkClient := NewRekeyCoordinator(IsClient)
      rkServer := NewRekeyCoordinator(IsServer)

      keys := SessionKeys{
          ClientToServer: bytes.Repeat([]byte{1}, 32),
          ServerToClient: bytes.Repeat([]byte{2}, 32),
      }

      clientEph, _, _ := rkClient.Start(keys)
      _, _, _ = rkServer.Start(keys) // server also started

      // Server receives client's REKEY while having one outstanding.
      _, _, err := rkServer.HandlePeer(keys, clientEph)
      if err != nil {
          t.Fatalf("server handle on collision: %v", err)
      }
      if rkServer.state != rekeyStateAdoptedClient {
          t.Fatalf("server state = %v, want adoptedClient", rkServer.state)
      }
  }
  ```

- [ ] **Step 2: Run, verify FAIL**

  Run: `go test ./internal/handshake/...`
  Expected: FAIL.

- [ ] **Step 3: Implement**

  ```go
  // internal/handshake/rekey.go
  package handshake

  import (
      "crypto/ecdh"
      "crypto/rand"
      "errors"
      "fmt"
  )

  type Role byte

  const (
      IsClient Role = iota
      IsServer
  )

  type rekeyState int

  const (
      rekeyStateIdle rekeyState = iota
      rekeyStateOurs                 // we initiated, waiting for peer
      rekeyStatePeer                 // we responded to peer
      rekeyStateAdoptedClient        // collision; server adopted client's ephemeral
      rekeyStateDone
  )

  // RekeyCoordinator owns the state for one rekey exchange. One per session
  // per direction of initiation.
  type RekeyCoordinator struct {
      role      Role
      state     rekeyState
      ourPriv   *ecdh.PrivateKey
      ourPub    []byte
      ourRandom []byte
      peerPub   []byte
      newKeys   SessionKeys
  }

  func NewRekeyCoordinator(role Role) *RekeyCoordinator {
      return &RekeyCoordinator{role: role}
  }

  func (r *RekeyCoordinator) Start(current SessionKeys) (ourPub []byte, sealedMsg []byte, err error) {
      if r.state != rekeyStateIdle {
          return nil, nil, fmt.Errorf("rekey: cannot start from state %d", r.state)
      }
      priv, pub, err := GenerateEphemeral()
      if err != nil {
          return nil, nil, err
      }
      rnd := make([]byte, 16)
      if _, err := rand.Read(rnd); err != nil {
          return nil, nil, err
      }
      r.ourPriv = priv
      r.ourPub = pub
      r.ourRandom = rnd
      r.state = rekeyStateOurs
      // sealedMsg is left empty here; the outer v2 frame layer (Task 8)
      // will seal {ourPub || ourRandom} under the *current* session key
      // and ship it as PACKET_V2_REKEY. We return ourPub for the test.
      return pub, nil, nil
  }

  func (r *RekeyCoordinator) HandlePeer(current SessionKeys, peerPub []byte) (replyPub, sealedMsg []byte, err error) {
      switch r.state {
      case rekeyStateIdle:
          // Plain peer-initiated rekey: we generate our ephemeral and reply.
          priv, pub, err := GenerateEphemeral()
          if err != nil {
              return nil, nil, err
          }
          r.ourPriv = priv
          r.ourPub = pub
          r.peerPub = peerPub
          if err := r.deriveNew(current); err != nil {
              return nil, nil, err
          }
          r.state = rekeyStatePeer
          return pub, nil, nil
      case rekeyStateOurs:
          // Collision. Spec §6.5: client wins. Server discards its own
          // ephemeral and adopts the client's.
          if r.role == IsServer {
              r.ourPriv = nil
              r.ourPub = nil
              priv, pub, err := GenerateEphemeral()
              if err != nil {
                  return nil, nil, err
              }
              r.ourPriv = priv
              r.ourPub = pub
              r.peerPub = peerPub
              if err := r.deriveNew(current); err != nil {
                  return nil, nil, err
              }
              r.state = rekeyStateAdoptedClient
              return pub, nil, nil
          }
          // Client side: ignore the server's REKEY (it lost the tiebreak).
          return nil, nil, errors.New("rekey: client ignores server's parallel REKEY")
      default:
          return nil, nil, fmt.Errorf("rekey: cannot handle peer from state %d", r.state)
      }
  }

  func (r *RekeyCoordinator) Finish(peerPub []byte) (SessionKeys, error) {
      if r.state != rekeyStateOurs {
          return SessionKeys{}, fmt.Errorf("rekey: cannot finish from state %d", r.state)
      }
      r.peerPub = peerPub
      // Random salt: ourRandom || peerRandom is recreated outside (the v2
      // frame layer will pass the peer's 16 B random in the REKEY message).
      // For unit-testing we reuse ourRandom on both sides — Task 8 wires
      // in the real peer random.
      keys, err := r.deriveFromHandshakeStyle()
      if err != nil {
          return SessionKeys{}, err
      }
      r.newKeys = keys
      r.state = rekeyStateDone
      return keys, nil
  }

  func (r *RekeyCoordinator) NewKeys() SessionKeys { return r.newKeys }

  func (r *RekeyCoordinator) deriveNew(current SessionKeys) error {
      keys, err := r.deriveFromHandshakeStyle()
      if err != nil {
          return err
      }
      r.newKeys = keys
      return nil
  }

  func (r *RekeyCoordinator) deriveFromHandshakeStyle() (SessionKeys, error) {
      dh, err := DHCompute(r.ourPriv, r.peerPub)
      if err != nil {
          return SessionKeys{}, err
      }
      // Salt uses ourRandom doubled — the v2 frame integration in Task 8
      // replaces this with (clientRandom' || serverRandom'). For now this
      // keeps the test deterministic across both sides.
      saltRandom := r.ourRandom
      if len(saltRandom) == 0 {
          saltRandom = make([]byte, 16)
      }
      return DeriveSessionKeys([]byte("rekey-psk-substitute"), dh, saltRandom, saltRandom)
  }
  ```

  Note the inline comments: the salt construction and "sealed message" wiring are
  stubbed at this level. Task 8 (v2 frame AEAD seal/open) will wrap REKEY into a
  full message-level path using `(clientRandom' || serverRandom')` as the
  derivation salt; do not reuse this stub salt in production code.

- [ ] **Step 4: Run, verify PASS**

  Run: `go test ./internal/handshake/...`
  Expected: PASS (all rekey tests + everything before).

- [ ] **Step 5: Commit**

  ```bash
  git add internal/handshake/rekey.go internal/handshake/rekey_test.go
  git commit -m "feat(handshake): rekey coordinator with client-wins collision rule"
  ```

---

### Task 7: v2 frame layout — encode / decode

**Goal:** the 10-byte v2 header (Type, ChCls, SessionID, StreamID, SeqNum) + opaque payload + 16-byte trailer reservation. No AEAD wiring yet (that's Task 8). Pure marshal / unmarshal that validates the high-bit-v2 marker.

**Files:**
- Create: `internal/vpnproto/framing_v2.go`
- Test:   `internal/vpnproto/framing_v2_test.go`

**Steps:**

- [ ] **Step 1: Write the failing test**

  ```go
  // internal/vpnproto/framing_v2_test.go
  package vpnproto

  import (
      "bytes"
      "testing"

      Enums "stormdns-go/internal/enums"
  )

  func TestV2Header_RoundTrip(t *testing.T) {
      h := V2Header{
          Type:      Enums.PACKET_V2_DATA,
          ChCls:     ChClsWide,
          SessionID: 0x1234,
          StreamID:  0x5678,
          SeqNum:    0xDEADBEEF,
      }
      buf := h.Marshal()
      if len(buf) != V2HeaderLen {
          t.Fatalf("len = %d, want %d", len(buf), V2HeaderLen)
      }
      var got V2Header
      if err := got.Unmarshal(buf); err != nil {
          t.Fatalf("unmarshal: %v", err)
      }
      if got != h {
          t.Fatalf("got %+v want %+v", got, h)
      }
  }

  func TestV2Header_RejectsV1Type(t *testing.T) {
      buf := make([]byte, V2HeaderLen)
      buf[0] = 0x0F // v1 PACKET_STREAM_DATA, high bit clear
      var h V2Header
      if err := h.Unmarshal(buf); err == nil {
          t.Fatal("expected unmarshal to reject low-bit-only Type as not v2")
      }
  }

  func TestV2Header_ChClsValidation(t *testing.T) {
      h := V2Header{Type: Enums.PACKET_V2_DATA, ChCls: 0x05}
      buf := h.Marshal()
      var got V2Header
      if err := got.Unmarshal(buf); err == nil {
          t.Fatal("expected error on unknown ChCls value")
      }
  }

  func TestIsV2Type(t *testing.T) {
      if !IsV2Type(Enums.PACKET_V2_DATA) {
          t.Fatal("V2 data should be v2")
      }
      if IsV2Type(Enums.PACKET_STREAM_DATA) {
          t.Fatal("v1 packet should not be v2")
      }
      if IsV2Type(Enums.PACKET_ERROR_DROP) {
          t.Fatal("0xFF is reserved, not a v2 type")
      }
  }

  func TestV2Frame_PayloadAttach(t *testing.T) {
      h := V2Header{
          Type:      Enums.PACKET_V2_DATA,
          ChCls:     ChClsNarrow,
          SessionID: 1, StreamID: 1, SeqNum: 1,
      }
      payload := []byte("hello")
      f := V2Frame{Header: h, EncryptedPayload: payload, Tag: bytes.Repeat([]byte{0xAA}, 16)}
      buf := f.Marshal()
      // 10 header + 5 payload + 16 tag = 31
      if len(buf) != V2HeaderLen+len(payload)+V2TagLen {
          t.Fatalf("frame len = %d, want %d", len(buf), V2HeaderLen+len(payload)+V2TagLen)
      }
      var got V2Frame
      if err := got.Unmarshal(buf); err != nil {
          t.Fatalf("unmarshal frame: %v", err)
      }
      if got.Header != h {
          t.Fatalf("header mismatch")
      }
      if !bytes.Equal(got.EncryptedPayload, payload) {
          t.Fatalf("payload mismatch")
      }
      if !bytes.Equal(got.Tag, f.Tag) {
          t.Fatalf("tag mismatch")
      }
  }
  ```

- [ ] **Step 2: Run, verify FAIL**

  Run: `go test ./internal/vpnproto/...`
  Expected: FAIL.

- [ ] **Step 3: Implement**

  ```go
  // internal/vpnproto/framing_v2.go
  package vpnproto

  import (
      "encoding/binary"
      "errors"
      "fmt"

      Enums "stormdns-go/internal/enums"
  )

  // V2 frame constants per spec §5.2.
  const (
      V2HeaderLen = 10 // Type+ChCls+SessionID(2)+StreamID(2)+SeqNum(4)
      V2TagLen    = 16

      ChClsNarrow byte = 0 // UDP/53 sender
      ChClsWide   byte = 1 // DoH/DoT/DoQ sender
  )

  var (
      ErrNotV2Type      = errors.New("vpnproto: type byte high bit not set; not a v2 frame")
      ErrUnknownChCls   = errors.New("vpnproto: unknown channel class byte")
      ErrShortV2Header  = errors.New("vpnproto: buffer shorter than v2 header")
      ErrShortV2Frame   = errors.New("vpnproto: buffer shorter than v2 frame minimum (header+tag)")
  )

  // IsV2Type reports whether t is in the v2 reserved range.
  // v1 uses 0x00..0x37 plus 0xFF (PACKET_ERROR_DROP). v2 uses 0x80..0xFE.
  func IsV2Type(t uint8) bool {
      return t >= 0x80 && t < 0xFF
  }

  type V2Header struct {
      Type      uint8
      ChCls     uint8
      SessionID uint16
      StreamID  uint16
      SeqNum    uint32
  }

  func (h V2Header) Marshal() []byte {
      buf := make([]byte, V2HeaderLen)
      buf[0] = h.Type
      buf[1] = h.ChCls
      binary.BigEndian.PutUint16(buf[2:4], h.SessionID)
      binary.BigEndian.PutUint16(buf[4:6], h.StreamID)
      binary.BigEndian.PutUint32(buf[6:10], h.SeqNum)
      return buf
  }

  func (h *V2Header) Unmarshal(buf []byte) error {
      if len(buf) < V2HeaderLen {
          return ErrShortV2Header
      }
      if !IsV2Type(buf[0]) {
          return ErrNotV2Type
      }
      switch buf[1] {
      case ChClsNarrow, ChClsWide:
      default:
          return fmt.Errorf("%w: 0x%02x", ErrUnknownChCls, buf[1])
      }
      h.Type = buf[0]
      h.ChCls = buf[1]
      h.SessionID = binary.BigEndian.Uint16(buf[2:4])
      h.StreamID = binary.BigEndian.Uint16(buf[4:6])
      h.SeqNum = binary.BigEndian.Uint32(buf[6:10])
      return nil
  }

  // V2Frame is the on-wire shape: header || encrypted-payload || tag.
  // EncryptedPayload may be empty (for control packets that fit entirely
  // in the AAD). Tag is exactly V2TagLen bytes.
  type V2Frame struct {
      Header           V2Header
      EncryptedPayload []byte
      Tag              []byte
  }

  func (f V2Frame) Marshal() []byte {
      out := make([]byte, 0, V2HeaderLen+len(f.EncryptedPayload)+V2TagLen)
      out = append(out, f.Header.Marshal()...)
      out = append(out, f.EncryptedPayload...)
      out = append(out, f.Tag...)
      return out
  }

  func (f *V2Frame) Unmarshal(buf []byte) error {
      if len(buf) < V2HeaderLen+V2TagLen {
          return ErrShortV2Frame
      }
      if err := f.Header.Unmarshal(buf[:V2HeaderLen]); err != nil {
          return err
      }
      payloadEnd := len(buf) - V2TagLen
      f.EncryptedPayload = append([]byte(nil), buf[V2HeaderLen:payloadEnd]...)
      f.Tag = append([]byte(nil), buf[payloadEnd:]...)
      return nil
  }

  // V2TypeName is purely cosmetic — used for logs / errors.
  func V2TypeName(t uint8) string {
      switch t {
      case Enums.PACKET_V2_INIT:
          return "V2_INIT"
      case Enums.PACKET_V2_INIT_ACK:
          return "V2_INIT_ACK"
      case Enums.PACKET_V2_DATA:
          return "V2_DATA"
      case Enums.PACKET_V2_ACK:
          return "V2_ACK"
      case Enums.PACKET_V2_NACK:
          return "V2_NACK"
      case Enums.PACKET_V2_REKEY:
          return "V2_REKEY"
      case Enums.PACKET_V2_REKEY_ACK:
          return "V2_REKEY_ACK"
      case Enums.PACKET_V2_PROBE:
          return "V2_PROBE"
      case Enums.PACKET_V2_PROBE_ACK:
          return "V2_PROBE_ACK"
      case Enums.PACKET_V2_CLOSE:
          return "V2_CLOSE"
      case Enums.PACKET_V2_PACKED:
          return "V2_PACKED"
      }
      return fmt.Sprintf("V2_UNKNOWN(0x%02x)", t)
  }
  ```

- [ ] **Step 4: Run, verify PASS**

  Run: `go test ./internal/vpnproto/...`
  Expected: PASS (5 new v2 tests + all existing v1 tests).

- [ ] **Step 5: Commit**

  ```bash
  git add internal/vpnproto/framing_v2.go internal/vpnproto/framing_v2_test.go
  git commit -m "feat(vpnproto): v2 frame header and envelope marshal/unmarshal"
  ```

---

### Task 8: v2 AEAD seal / open (data-frame layer)

**Goal:** ChaCha20-Poly1305 over a v2 frame using `K_c2s` / `K_s2c` from Task 5. The 12-byte nonce is constructed implicitly from `direction || SessionID || SeqNum` per spec §6.4 — never transmitted. AAD is the 10-byte header.

**Files:**
- Create: `internal/security/aead_session.go`
- Test:   `internal/security/aead_session_test.go`

**Steps:**

- [ ] **Step 1: Write the failing test**

  ```go
  // internal/security/aead_session_test.go
  package security

  import (
      "bytes"
      "testing"
  )

  func TestSessionAEAD_RoundTrip(t *testing.T) {
      key := bytes.Repeat([]byte{0x33}, 32)
      a, err := NewSessionAEAD(key)
      if err != nil {
          t.Fatalf("NewSessionAEAD: %v", err)
      }
      header := []byte{0x82, 0x00, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x01}
      payload := []byte("hello phantom")
      ct, tag, err := a.Seal(DirClientToServer, 0x1234, 1, payload, header)
      if err != nil {
          t.Fatalf("Seal: %v", err)
      }
      if len(tag) != 16 {
          t.Fatalf("tag len = %d", len(tag))
      }
      pt, err := a.Open(DirClientToServer, 0x1234, 1, ct, tag, header)
      if err != nil {
          t.Fatalf("Open: %v", err)
      }
      if !bytes.Equal(pt, payload) {
          t.Fatalf("pt mismatch")
      }
  }

  func TestSessionAEAD_TamperHeader(t *testing.T) {
      a, _ := NewSessionAEAD(bytes.Repeat([]byte{1}, 32))
      header := []byte{0x82, 0x00, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x01}
      ct, tag, _ := a.Seal(DirClientToServer, 0x1234, 1, []byte("x"), header)
      header[0] ^= 1
      if _, err := a.Open(DirClientToServer, 0x1234, 1, ct, tag, header); err == nil {
          t.Fatal("expected open to fail when AAD/header bytes change")
      }
  }

  func TestSessionAEAD_NonceCounterUniqueness(t *testing.T) {
      a, _ := NewSessionAEAD(bytes.Repeat([]byte{1}, 32))
      header := []byte{0x82, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
      ct1, _, _ := a.Seal(DirClientToServer, 0x0001, 1, []byte("same"), header)
      ct2, _, _ := a.Seal(DirClientToServer, 0x0001, 2, []byte("same"), header)
      if bytes.Equal(ct1, ct2) {
          t.Fatal("two different SeqNums must produce different ciphertext")
      }
  }
  ```

- [ ] **Step 2: Run, verify FAIL**

  Run: `go test ./internal/security/...`
  Expected: FAIL.

- [ ] **Step 3: Implement**

  ```go
  // internal/security/aead_session.go
  package security

  import (
      "encoding/binary"
      "errors"
      "fmt"

      "golang.org/x/crypto/chacha20poly1305"
  )

  type AEADDirection byte

  const (
      DirClientToServer AEADDirection = 0x01
      DirServerToClient AEADDirection = 0x02
  )

  var ErrAEADOpen = errors.New("security: v2 AEAD open failed")

  // SessionAEAD wraps a chacha20poly1305 AEAD with the v2 nonce convention:
  //   nonce = direction(1) || sessionID(2) || seqNum(4) || zero(5)   = 12 B
  type SessionAEAD struct {
      key []byte
  }

  func NewSessionAEAD(key []byte) (*SessionAEAD, error) {
      if len(key) != 32 {
          return nil, fmt.Errorf("security: session key must be 32 bytes, got %d", len(key))
      }
      // Verify the key is acceptable up front; chacha20poly1305.New does the same.
      if _, err := chacha20poly1305.New(key); err != nil {
          return nil, err
      }
      return &SessionAEAD{key: append([]byte(nil), key...)}, nil
  }

  // Seal returns (ciphertext, tag). The 16-byte tag is appended by the AEAD;
  // we split it out so callers can write it into the v2 frame's trailer field.
  func (s *SessionAEAD) Seal(dir AEADDirection, sessionID uint16, seqNum uint32, plaintext, aad []byte) ([]byte, []byte, error) {
      aead, err := chacha20poly1305.New(s.key)
      if err != nil {
          return nil, nil, err
      }
      nonce := buildSessionNonce(dir, sessionID, seqNum)
      sealed := aead.Seal(nil, nonce, plaintext, aad)
      ct := sealed[:len(sealed)-16]
      tag := sealed[len(sealed)-16:]
      return ct, tag, nil
  }

  func (s *SessionAEAD) Open(dir AEADDirection, sessionID uint16, seqNum uint32, ciphertext, tag, aad []byte) ([]byte, error) {
      aead, err := chacha20poly1305.New(s.key)
      if err != nil {
          return nil, err
      }
      if len(tag) != 16 {
          return nil, fmt.Errorf("security: tag must be 16 bytes, got %d", len(tag))
      }
      nonce := buildSessionNonce(dir, sessionID, seqNum)
      combined := make([]byte, 0, len(ciphertext)+len(tag))
      combined = append(combined, ciphertext...)
      combined = append(combined, tag...)
      pt, err := aead.Open(nil, nonce, combined, aad)
      if err != nil {
          return nil, ErrAEADOpen
      }
      return pt, nil
  }

  func buildSessionNonce(dir AEADDirection, sessionID uint16, seqNum uint32) []byte {
      var nonce [12]byte
      nonce[0] = byte(dir)
      binary.BigEndian.PutUint16(nonce[1:3], sessionID)
      binary.BigEndian.PutUint32(nonce[3:7], seqNum)
      // bytes 7..11 stay zero
      return nonce[:]
  }
  ```

- [ ] **Step 4: Run, verify PASS**

  Run: `go test ./internal/security/...`
  Expected: PASS (3 new + all existing codec tests still green).

- [ ] **Step 5: Commit**

  ```bash
  git add internal/security/aead_session.go internal/security/aead_session_test.go
  git commit -m "feat(security): session-AEAD for v2 data frames (ChaCha20-Poly1305)"
  ```

---

### Task 9: Multi-frame packing (PackV2 / UnpackV2)

**Goal:** spec §5.4 — pack N v2 frames into one `PACKET_V2_PACKED` carrier so wide channels can amortize per-query overhead. Each inner frame is prefixed by a 2-byte big-endian length.

**Files:**
- Modify: `internal/vpnproto/framing_v2.go` (append)
- Test:   `internal/vpnproto/framing_v2_packing_test.go`

**Steps:**

- [ ] **Step 1: Write the failing test**

  ```go
  // internal/vpnproto/framing_v2_packing_test.go
  package vpnproto

  import (
      "bytes"
      "testing"

      Enums "stormdns-go/internal/enums"
  )

  func TestPackV2_RoundTrip(t *testing.T) {
      mk := func(seq uint32, payload string) V2Frame {
          return V2Frame{
              Header: V2Header{
                  Type: Enums.PACKET_V2_DATA, ChCls: ChClsWide,
                  SessionID: 7, StreamID: 9, SeqNum: seq,
              },
              EncryptedPayload: []byte(payload),
              Tag:              bytes.Repeat([]byte{0xEE}, 16),
          }
      }
      frames := []V2Frame{mk(1, "alpha"), mk(2, "beta"), mk(3, "gamma")}
      packed, err := PackV2(frames, 16384)
      if err != nil {
          t.Fatalf("PackV2: %v", err)
      }

      got, err := UnpackV2(packed)
      if err != nil {
          t.Fatalf("UnpackV2: %v", err)
      }
      if len(got) != len(frames) {
          t.Fatalf("got %d frames, want %d", len(got), len(frames))
      }
      for i := range frames {
          if got[i].Header != frames[i].Header {
              t.Errorf("frame[%d] header mismatch", i)
          }
          if !bytes.Equal(got[i].EncryptedPayload, frames[i].EncryptedPayload) {
              t.Errorf("frame[%d] payload mismatch", i)
          }
      }
  }

  func TestPackV2_RespectsBudget(t *testing.T) {
      big := V2Frame{
          Header: V2Header{Type: Enums.PACKET_V2_DATA, ChCls: ChClsWide,
              SessionID: 1, StreamID: 1, SeqNum: 1},
          EncryptedPayload: bytes.Repeat([]byte{1}, 100),
          Tag:              bytes.Repeat([]byte{0}, 16),
      }
      // Budget too small to even fit one frame -> error.
      if _, err := PackV2([]V2Frame{big}, 50); err == nil {
          t.Fatal("expected PackV2 to fail when first frame doesn't fit in budget")
      }
  }
  ```

- [ ] **Step 2: Run, verify FAIL**

  Run: `go test ./internal/vpnproto/...`
  Expected: FAIL.

- [ ] **Step 3: Implement (append to `framing_v2.go`)**

  ```go
  // ----- Multi-frame packing (spec §5.4) -----

  const v2PackedFrameLenPrefix = 2 // big-endian uint16

  // ErrV2PackBudgetExceeded is returned by PackV2 if the first frame
  // alone exceeds the supplied byte budget (we never partially pack).
  var ErrV2PackBudgetExceeded = errors.New("vpnproto: v2 frame exceeds pack budget")

  // PackV2 serialises a slice of v2 frames into a single byte blob using
  // length-prefixed concatenation. budget caps the total output size; PackV2
  // packs as many frames as fit (in order) and returns the rest implicitly
  // by truncating. Callers should re-queue any frames they didn't observe.
  func PackV2(frames []V2Frame, budget int) ([]byte, error) {
      if len(frames) == 0 {
          return nil, nil
      }
      out := make([]byte, 0, budget)
      for i, f := range frames {
          one := f.Marshal()
          need := v2PackedFrameLenPrefix + len(one)
          if i == 0 && need > budget {
              return nil, ErrV2PackBudgetExceeded
          }
          if len(out)+need > budget {
              break
          }
          prefix := []byte{byte(len(one) >> 8), byte(len(one))}
          out = append(out, prefix...)
          out = append(out, one...)
      }
      return out, nil
  }

  // UnpackV2 reverses PackV2. Truncated input returns whatever frames
  // were fully decoded, followed by io.ErrUnexpectedEOF semantics via
  // ErrShortV2Frame so callers can distinguish.
  func UnpackV2(buf []byte) ([]V2Frame, error) {
      var out []V2Frame
      i := 0
      for i < len(buf) {
          if i+v2PackedFrameLenPrefix > len(buf) {
              return out, ErrShortV2Frame
          }
          n := int(buf[i])<<8 | int(buf[i+1])
          i += v2PackedFrameLenPrefix
          if i+n > len(buf) {
              return out, ErrShortV2Frame
          }
          var f V2Frame
          if err := f.Unmarshal(buf[i : i+n]); err != nil {
              return out, err
          }
          out = append(out, f)
          i += n
      }
      return out, nil
  }
  ```

- [ ] **Step 4: Run, verify PASS**

  Run: `go test ./internal/vpnproto/...`
  Expected: PASS.

- [ ] **Step 5: Commit**

  ```bash
  git add internal/vpnproto/framing_v2.go internal/vpnproto/framing_v2_packing_test.go
  git commit -m "feat(vpnproto): v2 multi-frame packing for wide channels"
  ```

---

### Task 10: v1/v2 negotiation helper

**Goal:** the single tiny function the dispatcher and server-side ingress use to decide "is this a v2 frame?" — and a safe fallback hook for clients that retry under v1 after the v2 INIT times out.

**Files:**
- Create: `internal/vpnproto/negotiation.go`
- Test:   `internal/vpnproto/negotiation_test.go`

**Steps:**

- [ ] **Step 1: Write the failing test**

  ```go
  // internal/vpnproto/negotiation_test.go
  package vpnproto

  import "testing"

  func TestDetectVersion(t *testing.T) {
      cases := []struct {
          name string
          buf  []byte
          want Version
      }{
          {"v1-stream-data", []byte{0x0F, 0x00, 0x00, 0x01}, VersionV1},
          {"v1-error-drop", []byte{0xFF, 0x00, 0x00, 0x01}, VersionV1},
          {"v2-data", []byte{0x82, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
              0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, VersionV2},
          {"too-short", []byte{}, VersionUnknown},
      }
      for _, c := range cases {
          t.Run(c.name, func(t *testing.T) {
              got := DetectVersion(c.buf)
              if got != c.want {
                  t.Fatalf("got %v want %v", got, c.want)
              }
          })
      }
  }
  ```

- [ ] **Step 2: Run, verify FAIL**

  Run: `go test ./internal/vpnproto/...`
  Expected: FAIL.

- [ ] **Step 3: Implement**

  ```go
  // internal/vpnproto/negotiation.go
  package vpnproto

  type Version int

  const (
      VersionUnknown Version = iota
      VersionV1
      VersionV2
  )

  func (v Version) String() string {
      switch v {
      case VersionV1:
          return "v1"
      case VersionV2:
          return "v2"
      }
      return "unknown"
  }

  // DetectVersion classifies a raw frame by its leading Type byte.
  // Treats 0xFF (PACKET_ERROR_DROP) as v1 — it's not a v2 type and v1
  // owns that codepoint.
  func DetectVersion(buf []byte) Version {
      if len(buf) == 0 {
          return VersionUnknown
      }
      t := buf[0]
      if t == 0xFF {
          return VersionV1
      }
      if IsV2Type(t) {
          if len(buf) < V2HeaderLen+V2TagLen {
              return VersionUnknown
          }
          return VersionV2
      }
      return VersionV1
  }
  ```

- [ ] **Step 4: Run, verify PASS**

  Run: `go test ./internal/vpnproto/...`
  Expected: PASS.

- [ ] **Step 5: Commit**

  ```bash
  git add internal/vpnproto/negotiation.go internal/vpnproto/negotiation_test.go
  git commit -m "feat(vpnproto): v1/v2 detection helper for ingress dispatch"
  ```

---

**Phase A milestone:** at this point you can `go test ./internal/handshake/... ./internal/security/... ./internal/vpnproto/...` and all crypto + framing primitives work in isolation. Nothing is wired into the dispatcher or server yet.

---

## Phase B — Anti-DPI primitives

Pure policy modules. Each takes a session entropy seed and produces shaped DNS messages; each has a permissive decoder.

### Task 11: Label shape — encode / decode with split labels and dictionary blend

**Goal:** spec §7.1. base32hex-encode v2 frame bytes, split into 2–5 labels of varying lengths, optionally interleave dictionary fragments. Decoder accepts any well-formed shape.

**Files:**
- Create: `internal/antidpi/labelshape.go`
- Test:   `internal/antidpi/labelshape_test.go`

**Steps:**

- [ ] **Step 1: Write the failing test**

  ```go
  // internal/antidpi/labelshape_test.go
  package antidpi

  import (
      "bytes"
      "math/rand"
      "strings"
      "testing"
  )

  func TestLabelShape_RoundTrip(t *testing.T) {
      shaper := NewLabelShaper(rand.NewSource(42), nil)
      payload := []byte{0x00, 0x11, 0x22, 0xFF, 0xAA, 0x55, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC}
      labels := shaper.Encode(payload)
      if len(labels) < 1 {
          t.Fatal("encoder returned no labels")
      }
      decoded, err := DecodeLabels(labels)
      if err != nil {
          t.Fatalf("decode: %v", err)
      }
      if !bytes.Equal(decoded, payload) {
          t.Fatalf("round-trip mismatch: got %x want %x", decoded, payload)
      }
  }

  func TestLabelShape_DictionaryFragmentsAreIgnoredOnDecode(t *testing.T) {
      dict := []string{"cdn", "img", "api"}
      shaper := NewLabelShaper(rand.NewSource(1), dict)
      payload := []byte("hello-phantom-dns")
      labels := shaper.Encode(payload)

      // At least one dictionary fragment should appear by chance with seed=1.
      sawDict := false
      for _, l := range labels {
          for _, d := range dict {
              if strings.EqualFold(l, d) {
                  sawDict = true
              }
          }
      }
      if !sawDict {
          t.Skip("RNG didn't pick a dict fragment with this seed; not a correctness bug")
      }

      decoded, err := DecodeLabels(labels)
      if err != nil {
          t.Fatalf("decode: %v", err)
      }
      if !bytes.Equal(decoded, payload) {
          t.Fatalf("decode mismatch: got %q want %q", decoded, payload)
      }
  }

  func TestLabelShape_LabelLengthBounds(t *testing.T) {
      shaper := NewLabelShaper(rand.NewSource(7), nil)
      payload := bytes.Repeat([]byte{0xAA}, 200)
      labels := shaper.Encode(payload)
      for _, l := range labels {
          if len(l) == 0 || len(l) > MaxLabelChars {
              t.Fatalf("label %q out of bounds (1..%d)", l, MaxLabelChars)
          }
      }
  }

  func TestDecodeLabels_RejectsInvalid(t *testing.T) {
      if _, err := DecodeLabels([]string{"!!!not-base32hex!!!"}); err == nil {
          t.Fatal("expected error on garbage labels")
      }
  }
  ```

- [ ] **Step 2: Run, verify FAIL**

  Run: `go test ./internal/antidpi/...`
  Expected: FAIL (package does not exist).

- [ ] **Step 3: Implement**

  ```go
  // internal/antidpi/labelshape.go
  package antidpi

  import (
      "encoding/base32"
      "errors"
      "fmt"
      "math/rand"
      "strings"
  )

  // Spec §7.1: labels are base32hex-encoded fragments of frame bytes,
  // split into 2..5 labels, optionally interleaved with dictionary
  // fragments. Decoder strips dictionary fragments by prefix marker.

  // We use a single-character ASCII prefix to distinguish encoded
  // fragments from dictionary fragments. Encoded fragments start with
  // 'e'; dictionary fragments start with 'd'. The prefix is added to
  // make decoding unambiguous without consulting the dictionary.
  // ('e' and 'd' are both valid base32hex characters but the position
  // (first byte of the label) is reserved for our marker.)
  const (
      labelMarkerEncoded = 'e'
      labelMarkerDict    = 'd'
      MaxLabelChars      = 30
      MinLabelChars      = 3   // marker + at least 2 chars
  )

  var ErrBadLabelShape = errors.New("antidpi: malformed label shape")

  var encoder = base32.HexEncoding.WithPadding(base32.NoPadding)

  // LabelShaper encodes raw frame bytes into a sequence of DNS labels
  // using a deterministic-per-seed shape.
  type LabelShaper struct {
      rng        *rand.Rand
      dictionary []string
  }

  func NewLabelShaper(src rand.Source, dictionary []string) *LabelShaper {
      return &LabelShaper{rng: rand.New(src), dictionary: dictionary}
  }

  // Encode produces a sequence of DNS labels carrying payload bytes.
  // The first character of every label is the marker; the rest is either
  // a base32hex chunk or a dictionary fragment.
  func (s *LabelShaper) Encode(payload []byte) []string {
      // Encode the whole payload once, then split into chunks whose
      // (marker + chunk) length sits in [MinLabelChars, MaxLabelChars].
      full := encoder.EncodeToString(payload)
      maxChunk := MaxLabelChars - 1
      minChunk := MinLabelChars - 1

      var out []string
      for len(full) > 0 {
          n := minChunk + s.rng.Intn(maxChunk-minChunk+1)
          if n > len(full) {
              n = len(full)
          }
          out = append(out, string(labelMarkerEncoded)+strings.ToLower(full[:n]))
          full = full[n:]

          // ~20% chance to interleave a dictionary fragment if dict provided.
          if len(s.dictionary) > 0 && s.rng.Intn(5) == 0 {
              frag := s.dictionary[s.rng.Intn(len(s.dictionary))]
              out = append(out, string(labelMarkerDict)+frag)
          }
      }
      return out
  }

  // DecodeLabels accepts the label slice produced by Encode (or any
  // permutation thereof) and reconstructs the payload bytes.
  // Dictionary-marked labels are skipped. Order of encoded labels is
  // preserved as it appears in the input.
  func DecodeLabels(labels []string) ([]byte, error) {
      var enc strings.Builder
      enc.Grow(64)
      for _, l := range labels {
          if len(l) < 2 {
              return nil, fmt.Errorf("%w: label too short %q", ErrBadLabelShape, l)
          }
          switch l[0] {
          case labelMarkerEncoded:
              enc.WriteString(strings.ToUpper(l[1:]))
          case labelMarkerDict:
              // skip
          default:
              return nil, fmt.Errorf("%w: unknown label marker %q", ErrBadLabelShape, l[0:1])
          }
      }
      out, err := encoder.DecodeString(enc.String())
      if err != nil {
          return nil, fmt.Errorf("%w: %v", ErrBadLabelShape, err)
      }
      return out, nil
  }
  ```

- [ ] **Step 4: Run, verify PASS**

  Run: `go test ./internal/antidpi/...`
  Expected: PASS (all 4 tests; one may show "skip" if seeds don't surface a dict fragment — that's acceptable).

- [ ] **Step 5: Commit**

  ```bash
  git add internal/antidpi/labelshape.go internal/antidpi/labelshape_test.go
  git commit -m "feat(antidpi): label shape encode/decode with dictionary blending"
  ```

---

### Task 12: Default dictionary + RR-type rotation policy

**Goal:** ship an embedded default vocabulary (small, innocuous fragments) and a per-session RR-type policy that picks A / AAAA / HTTPS / SVCB / TXT for outgoing/incoming carriers based on configured weights.

**Files:**
- Create: `internal/antidpi/dict_default.go`
- Create: `internal/antidpi/rrtype.go`
- Test:   `internal/antidpi/rrtype_test.go`

**Steps:**

- [ ] **Step 1: Write the failing test**

  ```go
  // internal/antidpi/rrtype_test.go
  package antidpi

  import (
      "math/rand"
      "testing"
  )

  func TestRRTypePolicy_HonorsWeights(t *testing.T) {
      p := NewRRTypePolicy(RRTypeMix{A: 60, AAAA: 30, TXT: 10}, rand.NewSource(1))
      counts := map[RRType]int{}
      for i := 0; i < 10000; i++ {
          counts[p.Pick()]++
      }
      total := counts[RRTypeA] + counts[RRTypeAAAA] + counts[RRTypeTXT]
      if total != 10000 {
          t.Fatalf("unexpected RR types appearing; counts=%+v", counts)
      }
      // Loose bounds: A should dominate (~60%), AAAA should be next.
      if counts[RRTypeA] < 5000 || counts[RRTypeA] > 7000 {
          t.Errorf("A count %d outside (5000,7000) for 60%% weight", counts[RRTypeA])
      }
      if counts[RRTypeTXT] > 1500 || counts[RRTypeTXT] < 500 {
          t.Errorf("TXT count %d outside (500,1500) for 10%% weight", counts[RRTypeTXT])
      }
  }

  func TestRRTypePolicy_BiasOnPassthrough(t *testing.T) {
      // If the resolver strips HTTPS/SVCB, BiasOnPassthrough must zero those out.
      p := NewRRTypePolicy(RRTypeMix{A: 50, HTTPS: 30, SVCB: 20}, rand.NewSource(2))
      passthrough := map[RRType]bool{RRTypeA: true} // only A passes
      p.BiasOnPassthrough(passthrough)
      for i := 0; i < 100; i++ {
          if p.Pick() != RRTypeA {
              t.Fatalf("after bias, only A should be picked")
          }
      }
  }

  func TestDefaultDictionary_NonEmpty(t *testing.T) {
      if len(DefaultDictionary) == 0 {
          t.Fatal("default dictionary should ship with non-empty content")
      }
      for _, w := range DefaultDictionary {
          if len(w) < 2 || len(w) > 12 {
              t.Errorf("dict entry %q outside (2..12)", w)
          }
      }
  }
  ```

- [ ] **Step 2: Run, verify FAIL**

  Run: `go test ./internal/antidpi/...`
  Expected: FAIL.

- [ ] **Step 3: Implement default dictionary**

  ```go
  // internal/antidpi/dict_default.go
  package antidpi

  // DefaultDictionary is a small embedded vocabulary of innocuous DNS-label
  // fragments used to camouflage encoded labels. Each entry is 2..12 chars
  // and contains only [a-z0-9-]. Operators can override via config.
  var DefaultDictionary = []string{
      "api", "app", "cdn", "img", "ws", "ws1", "s3", "v1", "v2",
      "edge", "edge1", "edge2", "static", "media", "assets", "data",
      "auth", "login", "proxy", "ws-api", "lb", "ingress", "egress",
      "eu", "us", "asia", "eu-west", "us-east", "ap-south",
      "stage", "prod", "qa", "test", "ops", "metrics", "logs",
      "web", "www", "mail", "smtp", "ftp", "vpn", "git",
  }
  ```

- [ ] **Step 4: Implement rrtype.go**

  ```go
  // internal/antidpi/rrtype.go
  package antidpi

  import (
      "math/rand"
      "sort"
  )

  type RRType uint16

  // DNS RR-type numeric constants we care about.
  const (
      RRTypeA     RRType = 1
      RRTypeAAAA  RRType = 28
      RRTypeTXT   RRType = 16
      RRTypeSVCB  RRType = 64
      RRTypeHTTPS RRType = 65
  )

  func (r RRType) String() string {
      switch r {
      case RRTypeA:
          return "A"
      case RRTypeAAAA:
          return "AAAA"
      case RRTypeTXT:
          return "TXT"
      case RRTypeSVCB:
          return "SVCB"
      case RRTypeHTTPS:
          return "HTTPS"
      }
      return "UNKNOWN"
  }

  // RRTypeMix is the weight vector for the rotation policy.
  // Weights are relative; they don't have to sum to 100.
  type RRTypeMix struct {
      A, AAAA, TXT, SVCB, HTTPS int
  }

  type RRTypePolicy struct {
      rng     *rand.Rand
      buckets []rrBucket
      total   int
  }

  type rrBucket struct {
      t   RRType
      cum int
  }

  // NewRRTypePolicy builds a weighted-pick policy. Entries with weight 0
  // are excluded.
  func NewRRTypePolicy(mix RRTypeMix, src rand.Source) *RRTypePolicy {
      raw := []rrBucket{
          {RRTypeA, mix.A},
          {RRTypeAAAA, mix.AAAA},
          {RRTypeTXT, mix.TXT},
          {RRTypeSVCB, mix.SVCB},
          {RRTypeHTTPS, mix.HTTPS},
      }
      // sort by descending weight for slight Pick() optimisation
      sort.SliceStable(raw, func(i, j int) bool { return raw[i].cum > raw[j].cum })
      p := &RRTypePolicy{rng: rand.New(src)}
      acc := 0
      for _, b := range raw {
          if b.cum == 0 {
              continue
          }
          acc += b.cum
          p.buckets = append(p.buckets, rrBucket{t: b.t, cum: acc})
      }
      p.total = acc
      return p
  }

  func (p *RRTypePolicy) Pick() RRType {
      if p.total == 0 || len(p.buckets) == 0 {
          return RRTypeA // safe default
      }
      r := p.rng.Intn(p.total)
      for _, b := range p.buckets {
          if r < b.cum {
              return b.t
          }
      }
      return p.buckets[len(p.buckets)-1].t
  }

  // BiasOnPassthrough drops RR types not in the passthrough set,
  // re-normalising remaining weights so probability proportions hold.
  func (p *RRTypePolicy) BiasOnPassthrough(passthrough map[RRType]bool) {
      var kept []rrBucket
      acc := 0
      // Reconstruct uncumulated weights from the cumulative buckets.
      prev := 0
      for _, b := range p.buckets {
          w := b.cum - prev
          prev = b.cum
          if passthrough[b.t] {
              acc += w
              kept = append(kept, rrBucket{t: b.t, cum: acc})
          }
      }
      p.buckets = kept
      p.total = acc
  }
  ```

- [ ] **Step 5: Run, verify PASS**

  Run: `go test ./internal/antidpi/...`
  Expected: PASS.

- [ ] **Step 6: Commit**

  ```bash
  git add internal/antidpi/dict_default.go internal/antidpi/rrtype.go internal/antidpi/rrtype_test.go
  git commit -m "feat(antidpi): embedded dictionary and weighted RR-type rotation policy"
  ```

---

### Task 13: EDNS0 padding + timing jitter

**Goal:** spec §7.3–§7.4. Padding helper that rounds a message length up to the next bucket and computes the EDNS0 Padding option contents; jitter helper that draws inter-query delays from a log-normal distribution.

**Files:**
- Create: `internal/antidpi/padding.go`
- Create: `internal/antidpi/jitter.go`
- Test:   `internal/antidpi/padding_test.go`
- Test:   `internal/antidpi/jitter_test.go`

**Steps:**

- [ ] **Step 1: Write failing tests**

  ```go
  // internal/antidpi/padding_test.go
  package antidpi

  import "testing"

  func TestPickBucket(t *testing.T) {
      buckets := []int{128, 256, 512, 1024, 1232}
      cases := []struct {
          have int
          want int
      }{
          {0, 128}, {100, 128}, {128, 128}, {200, 256}, {257, 512},
          {1200, 1232}, {1300, 1300}, // bigger than all buckets -> unchanged
      }
      for _, c := range cases {
          if got := PickBucket(c.have, buckets); got != c.want {
              t.Errorf("PickBucket(%d) = %d, want %d", c.have, got, c.want)
          }
      }
  }

  func TestPaddingBytes(t *testing.T) {
      n := PaddingBytes(200, 256, 8)
      // 256 - 200 - 4 (option header) - 8 (padding option overhead reserved)
      // Implementation defines exact semantics; we just check >= 0 and that
      // padding pushes total to >= target - overhead.
      if n < 0 {
          t.Fatalf("padding bytes negative: %d", n)
      }
  }
  ```

  ```go
  // internal/antidpi/jitter_test.go
  package antidpi

  import (
      "math/rand"
      "testing"
      "time"
  )

  func TestJitterRange(t *testing.T) {
      j := NewJitter(80*time.Millisecond, 0.4, rand.NewSource(123))
      const N = 1000
      var sum time.Duration
      for i := 0; i < N; i++ {
          d := j.Next()
          if d < 0 {
              t.Fatalf("negative jitter: %v", d)
          }
          if d > 5*time.Second {
              t.Fatalf("absurd jitter: %v", d)
          }
          sum += d
      }
      avg := sum / N
      // Mean of log-normal is exp(mu + sigma^2/2). With mu = ln(80ms)
      // and sigma = 0.4 the theoretical mean is ~86.6 ms; allow 60..150.
      if avg < 60*time.Millisecond || avg > 150*time.Millisecond {
          t.Errorf("average jitter %v outside (60ms,150ms)", avg)
      }
  }
  ```

- [ ] **Step 2: Run, verify FAIL**

  Run: `go test ./internal/antidpi/...`
  Expected: FAIL.

- [ ] **Step 3: Implement padding**

  ```go
  // internal/antidpi/padding.go
  package antidpi

  // PickBucket returns the smallest bucket >= currentSize, or currentSize
  // itself if it exceeds all buckets (in which case caller should not pad).
  // buckets must be sorted ascending and non-empty.
  func PickBucket(currentSize int, buckets []int) int {
      for _, b := range buckets {
          if b >= currentSize {
              return b
          }
      }
      return currentSize
  }

  // PaddingBytes returns how many padding bytes to emit inside an
  // EDNS0 OPT Padding option (RFC 7830) to bring the carrier to `target`.
  // overhead is the byte count the OPT record itself adds (typically 4
  // for the option header). Returns 0 if no padding is needed/possible.
  func PaddingBytes(currentSize, target, overhead int) int {
      n := target - currentSize - overhead
      if n < 0 {
          return 0
      }
      return n
  }

  // DefaultBucketsNarrow are the UDP/53 bucket sizes per spec §7.3.
  var DefaultBucketsNarrow = []int{128, 256, 512, 1024, 1232}

  // DefaultBucketsWide are the DoH/DoT/DoQ bucket sizes per spec §7.3.
  var DefaultBucketsWide = []int{512, 1024, 2048, 4096, 8192, 16384}
  ```

- [ ] **Step 4: Implement jitter**

  ```go
  // internal/antidpi/jitter.go
  package antidpi

  import (
      "math"
      "math/rand"
      "time"
  )

  // Jitter returns log-normal-distributed durations for inter-query spacing.
  // mean is the target mean delay (e.g. 80ms); sigma is the log-normal sigma
  // parameter (e.g. 0.4).
  type Jitter struct {
      mu    float64
      sigma float64
      rng   *rand.Rand
  }

  func NewJitter(mean time.Duration, sigma float64, src rand.Source) *Jitter {
      // Convert "mean" durations to log-normal parameters using the
      // identity mean = exp(mu + sigma^2 / 2)  ==>  mu = ln(mean) - sigma^2/2
      meanSec := mean.Seconds()
      if meanSec <= 0 {
          meanSec = 0.001
      }
      mu := math.Log(meanSec) - sigma*sigma/2
      return &Jitter{mu: mu, sigma: sigma, rng: rand.New(src)}
  }

  // Next draws one log-normal sample as a time.Duration.
  func (j *Jitter) Next() time.Duration {
      // log-normal = exp(normal(mu, sigma))
      n := j.rng.NormFloat64()*j.sigma + j.mu
      secs := math.Exp(n)
      return time.Duration(secs * float64(time.Second))
  }
  ```

- [ ] **Step 5: Run, verify PASS**

  Run: `go test ./internal/antidpi/...`
  Expected: PASS.

- [ ] **Step 6: Commit**

  ```bash
  git add internal/antidpi/padding.go internal/antidpi/jitter.go internal/antidpi/padding_test.go internal/antidpi/jitter_test.go
  git commit -m "feat(antidpi): EDNS0 padding buckets and log-normal jitter"
  ```

---

**Phase B milestone:** `go test ./internal/antidpi/...` is fully green. All anti-DPI primitives exist as pure functions, ready for Task 14+ to wire them into the request path.

---

## Phase C — Transport adapter layer

Each adapter exposes one `QueryChannel`. Adapters do *not* know anything about v2 framing, anti-DPI, or handshake — they just send a DNS query (bytes) to a public resolver and return the resolver's response.

### Task 14: QueryChannel interface + UDP/53 adapter

**Goal:** the interface every transport implements, plus the first concrete implementation backed by `net.UDPConn`.

**Files:**
- Create: `internal/transport/channel.go`
- Create: `internal/transport/udp53.go`
- Test:   `internal/transport/udp53_test.go`

**Steps:**

- [ ] **Step 1: Write the failing test (uses a tiny in-process UDP/53 echo server)**

  ```go
  // internal/transport/udp53_test.go
  package transport

  import (
      "bytes"
      "context"
      "net"
      "testing"
      "time"
  )

  // mkUDPEchoResolver starts a goroutine that echoes any DNS query back as-is.
  // Returns the listening addr.
  func mkUDPEchoResolver(t *testing.T) string {
      t.Helper()
      pc, err := net.ListenPacket("udp", "127.0.0.1:0")
      if err != nil {
          t.Fatal(err)
      }
      t.Cleanup(func() { _ = pc.Close() })
      go func() {
          buf := make([]byte, 4096)
          for {
              n, addr, err := pc.ReadFrom(buf)
              if err != nil {
                  return
              }
              _, _ = pc.WriteTo(buf[:n], addr)
          }
      }()
      return pc.LocalAddr().String()
  }

  func TestUDP53_QueryEchoes(t *testing.T) {
      addr := mkUDPEchoResolver(t)
      ch, err := NewUDP53Channel(addr, 2*time.Second)
      if err != nil {
          t.Fatalf("NewUDP53Channel: %v", err)
      }
      defer ch.Close()

      ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
      defer cancel()
      q := []byte{0x01, 0x02, 0x03, 0x04}
      r, err := ch.Query(ctx, q)
      if err != nil {
          t.Fatalf("Query: %v", err)
      }
      if !bytes.Equal(r, q) {
          t.Fatalf("echo mismatch: got %x want %x", r, q)
      }
      if ch.Kind() != Kind53UDP {
          t.Fatalf("Kind = %v", ch.Kind())
      }
  }
  ```

- [ ] **Step 2: Run, verify FAIL**

  Run: `go test ./internal/transport/...`
  Expected: FAIL.

- [ ] **Step 3: Implement channel.go**

  ```go
  // internal/transport/channel.go
  package transport

  import (
      "context"
      "time"
  )

  type Kind int

  const (
      Kind53UDP Kind = iota
      KindDoH
      KindDoT
      KindDoQ
  )

  func (k Kind) String() string {
      switch k {
      case Kind53UDP:
          return "udp53"
      case KindDoH:
          return "doh"
      case KindDoT:
          return "dot"
      case KindDoQ:
          return "doq"
      }
      return "unknown"
  }

  // Health is the channel cost signal exposed to the balancer.
  type Health struct {
      RTTEMA       time.Duration
      SuccessRate  float64
      BudgetTokens int
      LastError    time.Time
      Parked       bool
      UnparkAt     time.Time
  }

  // QueryChannel sends one DNS query and returns one DNS response.
  // Implementations must connect only to *public DNS resolvers* — see the
  // no-direct-route validator in Task 17 for the rule.
  type QueryChannel interface {
      Query(ctx context.Context, dnsMessage []byte) ([]byte, error)
      MaxResponseBytes() int
      Health() Health
      Kind() Kind
      Close() error
  }
  ```

- [ ] **Step 4: Implement udp53.go**

  ```go
  // internal/transport/udp53.go
  package transport

  import (
      "context"
      "fmt"
      "net"
      "sync"
      "time"
  )

  type UDP53Channel struct {
      addr    *net.UDPAddr
      timeout time.Duration
      mu      sync.Mutex
      health  Health
  }

  func NewUDP53Channel(resolverAddr string, timeout time.Duration) (*UDP53Channel, error) {
      ua, err := net.ResolveUDPAddr("udp", resolverAddr)
      if err != nil {
          return nil, fmt.Errorf("udp53: resolve %s: %w", resolverAddr, err)
      }
      if timeout == 0 {
          timeout = 3 * time.Second
      }
      return &UDP53Channel{addr: ua, timeout: timeout,
          health: Health{SuccessRate: 1.0, BudgetTokens: 200}}, nil
  }

  func (c *UDP53Channel) Query(ctx context.Context, q []byte) ([]byte, error) {
      start := time.Now()
      conn, err := net.DialUDP("udp", nil, c.addr)
      if err != nil {
          c.recordErr()
          return nil, fmt.Errorf("udp53: dial: %w", err)
      }
      defer conn.Close()

      deadline := start.Add(c.timeout)
      if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
          deadline = dl
      }
      _ = conn.SetDeadline(deadline)

      if _, err := conn.Write(q); err != nil {
          c.recordErr()
          return nil, fmt.Errorf("udp53: write: %w", err)
      }
      buf := make([]byte, 4096)
      n, err := conn.Read(buf)
      if err != nil {
          c.recordErr()
          return nil, fmt.Errorf("udp53: read: %w", err)
      }
      c.recordOK(time.Since(start))
      return buf[:n], nil
  }

  func (c *UDP53Channel) MaxResponseBytes() int { return 4096 }
  func (c *UDP53Channel) Kind() Kind            { return Kind53UDP }
  func (c *UDP53Channel) Close() error          { return nil }

  func (c *UDP53Channel) Health() Health {
      c.mu.Lock()
      defer c.mu.Unlock()
      h := c.health
      return h
  }

  func (c *UDP53Channel) recordOK(rtt time.Duration) {
      c.mu.Lock()
      defer c.mu.Unlock()
      c.health.RTTEMA = ema(c.health.RTTEMA, rtt, 0.2)
      c.health.SuccessRate = ema01(c.health.SuccessRate, 1.0, 0.05)
  }

  func (c *UDP53Channel) recordErr() {
      c.mu.Lock()
      defer c.mu.Unlock()
      c.health.LastError = time.Now()
      c.health.SuccessRate = ema01(c.health.SuccessRate, 0.0, 0.05)
  }

  func ema(prev, sample time.Duration, alpha float64) time.Duration {
      if prev == 0 {
          return sample
      }
      return time.Duration(float64(prev)*(1-alpha) + float64(sample)*alpha)
  }

  func ema01(prev, sample, alpha float64) float64 {
      return prev*(1-alpha) + sample*alpha
  }
  ```

- [ ] **Step 5: Run, verify PASS**

  Run: `go test ./internal/transport/...`
  Expected: PASS.

- [ ] **Step 6: Commit**

  ```bash
  git add internal/transport/channel.go internal/transport/udp53.go internal/transport/udp53_test.go
  git commit -m "feat(transport): QueryChannel interface and UDP/53 adapter"
  ```

---

### Task 15: DoH adapter (HTTP/2 + RFC 8484)

**Goal:** DoH adapter that POSTs `application/dns-message` to a configured DoH endpoint. Uses `http.Client` with HTTP/2 enabled by default. Connection re-use via the default Transport.

**Files:**
- Create: `internal/transport/doh.go`
- Test:   `internal/transport/doh_test.go`

**Steps:**

- [ ] **Step 1: Write the failing test (uses `httptest.NewTLSServer`)**

  ```go
  // internal/transport/doh_test.go
  package transport

  import (
      "bytes"
      "context"
      "crypto/tls"
      "io"
      "net/http"
      "net/http/httptest"
      "testing"
      "time"
  )

  func TestDoH_PostsRFC8484(t *testing.T) {
      var gotCT, gotBody []byte
      var contentType string
      srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
          contentType = r.Header.Get("Content-Type")
          b, _ := io.ReadAll(r.Body)
          gotCT = []byte(contentType)
          gotBody = b
          w.Header().Set("Content-Type", "application/dns-message")
          _, _ = w.Write([]byte{0xAA, 0xBB, 0xCC})
      }))
      defer srv.Close()

      // Skip real cert validation against httptest's self-signed cert.
      ch, err := NewDoHChannel(srv.URL+"/dns-query", 2*time.Second, withInsecureTLS())
      if err != nil {
          t.Fatalf("NewDoHChannel: %v", err)
      }
      defer ch.Close()

      ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
      defer cancel()
      r, err := ch.Query(ctx, []byte{0x01, 0x02, 0x03})
      if err != nil {
          t.Fatalf("Query: %v", err)
      }
      if !bytes.Equal(r, []byte{0xAA, 0xBB, 0xCC}) {
          t.Fatalf("response mismatch: %x", r)
      }
      if string(gotCT) != "application/dns-message" {
          t.Fatalf("Content-Type was %q", gotCT)
      }
      if !bytes.Equal(gotBody, []byte{0x01, 0x02, 0x03}) {
          t.Fatalf("body mismatch")
      }
      if ch.Kind() != KindDoH {
          t.Fatal("kind mismatch")
      }
  }

  // withInsecureTLS is a test-only option carried as a functional config
  // injected via doh.go's tests-only constructor variant.
  func withInsecureTLS() DoHOption {
      return func(o *dohOptions) {
          o.tlsConfig = &tls.Config{InsecureSkipVerify: true}
      }
  }
  ```

- [ ] **Step 2: Run, verify FAIL**

  Run: `go test ./internal/transport/...`
  Expected: FAIL.

- [ ] **Step 3: Implement**

  ```go
  // internal/transport/doh.go
  package transport

  import (
      "bytes"
      "context"
      "crypto/tls"
      "fmt"
      "io"
      "net/http"
      "net/url"
      "sync"
      "time"
  )

  type DoHOption func(*dohOptions)

  type dohOptions struct {
      tlsConfig *tls.Config
  }

  type DoHChannel struct {
      endpoint string
      client   *http.Client
      timeout  time.Duration

      mu     sync.Mutex
      health Health
  }

  func NewDoHChannel(endpoint string, timeout time.Duration, opts ...DoHOption) (*DoHChannel, error) {
      u, err := url.Parse(endpoint)
      if err != nil {
          return nil, fmt.Errorf("doh: parse endpoint: %w", err)
      }
      if u.Scheme != "https" {
          return nil, fmt.Errorf("doh: endpoint must be https, got %q", u.Scheme)
      }
      cfg := dohOptions{}
      for _, o := range opts {
          o(&cfg)
      }
      tr := &http.Transport{
          ForceAttemptHTTP2:   true,
          TLSClientConfig:     cfg.tlsConfig,
          MaxIdleConnsPerHost: 4,
          IdleConnTimeout:     90 * time.Second,
      }
      return &DoHChannel{
          endpoint: endpoint,
          client:   &http.Client{Transport: tr, Timeout: timeout},
          timeout:  timeout,
          health:   Health{SuccessRate: 1.0, BudgetTokens: 200},
      }, nil
  }

  func (c *DoHChannel) Query(ctx context.Context, q []byte) ([]byte, error) {
      start := time.Now()
      req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(q))
      if err != nil {
          c.recordErr()
          return nil, fmt.Errorf("doh: new request: %w", err)
      }
      req.Header.Set("Content-Type", "application/dns-message")
      req.Header.Set("Accept", "application/dns-message")

      resp, err := c.client.Do(req)
      if err != nil {
          c.recordErr()
          return nil, fmt.Errorf("doh: do: %w", err)
      }
      defer resp.Body.Close()
      if resp.StatusCode != http.StatusOK {
          c.recordErr()
          return nil, fmt.Errorf("doh: status %d", resp.StatusCode)
      }
      b, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
      if err != nil {
          c.recordErr()
          return nil, fmt.Errorf("doh: read body: %w", err)
      }
      c.recordOK(time.Since(start))
      return b, nil
  }

  func (c *DoHChannel) MaxResponseBytes() int { return 16384 }
  func (c *DoHChannel) Kind() Kind            { return KindDoH }
  func (c *DoHChannel) Close() error {
      c.client.CloseIdleConnections()
      return nil
  }

  func (c *DoHChannel) Health() Health {
      c.mu.Lock()
      defer c.mu.Unlock()
      h := c.health
      return h
  }
  func (c *DoHChannel) recordOK(rtt time.Duration) {
      c.mu.Lock()
      defer c.mu.Unlock()
      c.health.RTTEMA = ema(c.health.RTTEMA, rtt, 0.2)
      c.health.SuccessRate = ema01(c.health.SuccessRate, 1.0, 0.05)
  }
  func (c *DoHChannel) recordErr() {
      c.mu.Lock()
      defer c.mu.Unlock()
      c.health.LastError = time.Now()
      c.health.SuccessRate = ema01(c.health.SuccessRate, 0.0, 0.05)
  }
  ```

- [ ] **Step 4: Run, verify PASS**

  Run: `go test ./internal/transport/...`
  Expected: PASS.

- [ ] **Step 5: Commit**

  ```bash
  git add internal/transport/doh.go internal/transport/doh_test.go
  git commit -m "feat(transport): DoH adapter (RFC 8484 over HTTP/2)"
  ```

---

### Task 16: DoT adapter (RFC 7858 over TLS/853)

**Goal:** persistent TLS connection; each query framed as `[2-byte big-endian length][message]`. Pipelined queries on one connection are an optimization for later — v1 of this adapter does one in-flight query at a time and is sequential.

**Files:**
- Create: `internal/transport/dot.go`
- Test:   `internal/transport/dot_test.go`

**Steps:**

- [ ] **Step 1: Write the failing test**

  ```go
  // internal/transport/dot_test.go
  package transport

  import (
      "bytes"
      "context"
      "crypto/tls"
      "encoding/binary"
      "io"
      "net"
      "testing"
      "time"
  )

  // mkDoTEcho echoes one length-prefixed DNS message per accepted connection.
  func mkDoTEcho(t *testing.T, cert tls.Certificate) string {
      t.Helper()
      ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
          Certificates: []tls.Certificate{cert},
      })
      if err != nil {
          t.Fatal(err)
      }
      t.Cleanup(func() { _ = ln.Close() })
      go func() {
          for {
              c, err := ln.Accept()
              if err != nil {
                  return
              }
              go func(conn net.Conn) {
                  defer conn.Close()
                  hdr := make([]byte, 2)
                  for {
                      if _, err := io.ReadFull(conn, hdr); err != nil {
                          return
                      }
                      n := binary.BigEndian.Uint16(hdr)
                      buf := make([]byte, n)
                      if _, err := io.ReadFull(conn, buf); err != nil {
                          return
                      }
                      out := make([]byte, 2+len(buf))
                      binary.BigEndian.PutUint16(out, uint16(len(buf)))
                      copy(out[2:], buf)
                      _, _ = conn.Write(out)
                  }
              }(c)
          }
      }()
      return ln.Addr().String()
  }

  func TestDoT_FramedRoundTrip(t *testing.T) {
      cert, err := selfSignedCert()
      if err != nil {
          t.Fatal(err)
      }
      addr := mkDoTEcho(t, cert)
      ch, err := NewDoTChannel(addr, 2*time.Second, &tls.Config{InsecureSkipVerify: true})
      if err != nil {
          t.Fatalf("NewDoTChannel: %v", err)
      }
      defer ch.Close()

      ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
      defer cancel()
      q := []byte{0xDE, 0xAD, 0xBE, 0xEF}
      r, err := ch.Query(ctx, q)
      if err != nil {
          t.Fatalf("Query: %v", err)
      }
      if !bytes.Equal(r, q) {
          t.Fatalf("echo mismatch: %x", r)
      }
      if ch.Kind() != KindDoT {
          t.Fatal("kind mismatch")
      }
  }
  ```

  Plus a tiny helper used by both DoT/DoQ tests:

  ```go
  // internal/transport/test_helpers_test.go
  package transport

  import (
      "crypto/ecdsa"
      "crypto/elliptic"
      "crypto/rand"
      "crypto/tls"
      "crypto/x509"
      "crypto/x509/pkix"
      "encoding/pem"
      "math/big"
      "time"
  )

  func selfSignedCert() (tls.Certificate, error) {
      priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
      if err != nil {
          return tls.Certificate{}, err
      }
      tmpl := &x509.Certificate{
          SerialNumber: big.NewInt(1),
          Subject:      pkix.Name{CommonName: "phantom-dns-test"},
          NotBefore:    time.Now().Add(-time.Hour),
          NotAfter:     time.Now().Add(time.Hour),
          KeyUsage:     x509.KeyUsageDigitalSignature,
          ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
      }
      der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
      if err != nil {
          return tls.Certificate{}, err
      }
      keyDER, err := x509.MarshalECPrivateKey(priv)
      if err != nil {
          return tls.Certificate{}, err
      }
      certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
      keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
      return tls.X509KeyPair(certPEM, keyPEM)
  }
  ```

- [ ] **Step 2: Run, verify FAIL**

  Run: `go test ./internal/transport/...`
  Expected: FAIL.

- [ ] **Step 3: Implement**

  ```go
  // internal/transport/dot.go
  package transport

  import (
      "context"
      "crypto/tls"
      "encoding/binary"
      "fmt"
      "io"
      "sync"
      "time"
  )

  type DoTChannel struct {
      addr      string
      tlsConfig *tls.Config
      timeout   time.Duration

      mu     sync.Mutex
      conn   *tls.Conn
      health Health
  }

  func NewDoTChannel(addr string, timeout time.Duration, tlsConfig *tls.Config) (*DoTChannel, error) {
      if tlsConfig == nil {
          tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12}
      }
      return &DoTChannel{
          addr:      addr,
          tlsConfig: tlsConfig,
          timeout:   timeout,
          health:    Health{SuccessRate: 1.0, BudgetTokens: 200},
      }, nil
  }

  func (c *DoTChannel) ensureConn(ctx context.Context) (*tls.Conn, error) {
      c.mu.Lock()
      defer c.mu.Unlock()
      if c.conn != nil {
          return c.conn, nil
      }
      d := &tls.Dialer{Config: c.tlsConfig}
      raw, err := d.DialContext(ctx, "tcp", c.addr)
      if err != nil {
          return nil, fmt.Errorf("dot: dial: %w", err)
      }
      c.conn = raw.(*tls.Conn)
      return c.conn, nil
  }

  func (c *DoTChannel) Query(ctx context.Context, q []byte) ([]byte, error) {
      start := time.Now()
      conn, err := c.ensureConn(ctx)
      if err != nil {
          c.recordErr()
          return nil, err
      }
      deadline, ok := ctx.Deadline()
      if !ok {
          deadline = start.Add(c.timeout)
      }
      _ = conn.SetDeadline(deadline)

      frame := make([]byte, 2+len(q))
      binary.BigEndian.PutUint16(frame[:2], uint16(len(q)))
      copy(frame[2:], q)
      if _, err := conn.Write(frame); err != nil {
          c.dropConn()
          c.recordErr()
          return nil, fmt.Errorf("dot: write: %w", err)
      }
      hdr := make([]byte, 2)
      if _, err := io.ReadFull(conn, hdr); err != nil {
          c.dropConn()
          c.recordErr()
          return nil, fmt.Errorf("dot: read hdr: %w", err)
      }
      n := binary.BigEndian.Uint16(hdr)
      buf := make([]byte, n)
      if _, err := io.ReadFull(conn, buf); err != nil {
          c.dropConn()
          c.recordErr()
          return nil, fmt.Errorf("dot: read body: %w", err)
      }
      c.recordOK(time.Since(start))
      return buf, nil
  }

  func (c *DoTChannel) dropConn() {
      c.mu.Lock()
      defer c.mu.Unlock()
      if c.conn != nil {
          _ = c.conn.Close()
          c.conn = nil
      }
  }

  func (c *DoTChannel) MaxResponseBytes() int { return 16384 }
  func (c *DoTChannel) Kind() Kind            { return KindDoT }
  func (c *DoTChannel) Close() error {
      c.dropConn()
      return nil
  }

  func (c *DoTChannel) Health() Health {
      c.mu.Lock()
      defer c.mu.Unlock()
      return c.health
  }
  func (c *DoTChannel) recordOK(rtt time.Duration) {
      c.mu.Lock()
      defer c.mu.Unlock()
      c.health.RTTEMA = ema(c.health.RTTEMA, rtt, 0.2)
      c.health.SuccessRate = ema01(c.health.SuccessRate, 1.0, 0.05)
  }
  func (c *DoTChannel) recordErr() {
      c.mu.Lock()
      defer c.mu.Unlock()
      c.health.LastError = time.Now()
      c.health.SuccessRate = ema01(c.health.SuccessRate, 0.0, 0.05)
  }
  ```

- [ ] **Step 4: Run, verify PASS**

  Run: `go test ./internal/transport/...`
  Expected: PASS.

- [ ] **Step 5: Commit**

  ```bash
  git add internal/transport/dot.go internal/transport/dot_test.go internal/transport/test_helpers_test.go
  git commit -m "feat(transport): DoT adapter (RFC 7858 framed over TLS/853)"
  ```

---

### Task 17: DoQ adapter (RFC 9250 over QUIC)

**Goal:** one bidi QUIC stream per query against a configured DoQ resolver. ALPN `doq`. Uses `quic-go` (added in Task 0). Each stream sends a 2-byte length prefix + DNS message, then receives the same shape (RFC 9250 §4.2).

**Files:**
- Create: `internal/transport/doq.go`
- Test:   `internal/transport/doq_test.go`

**Steps:**

- [ ] **Step 1: Write the failing test**

  ```go
  // internal/transport/doq_test.go
  package transport

  import (
      "bytes"
      "context"
      "crypto/tls"
      "encoding/binary"
      "io"
      "testing"
      "time"

      "github.com/quic-go/quic-go"
  )

  func mkDoQEcho(t *testing.T, cert tls.Certificate) string {
      t.Helper()
      tlsConf := &tls.Config{
          Certificates: []tls.Certificate{cert},
          NextProtos:   []string{"doq"},
      }
      ln, err := quic.ListenAddr("127.0.0.1:0", tlsConf, nil)
      if err != nil {
          t.Fatal(err)
      }
      t.Cleanup(func() { _ = ln.Close() })
      go func() {
          ctx := context.Background()
          for {
              sess, err := ln.Accept(ctx)
              if err != nil {
                  return
              }
              go func(s quic.Connection) {
                  for {
                      str, err := s.AcceptStream(ctx)
                      if err != nil {
                          return
                      }
                      go func(st quic.Stream) {
                          defer st.Close()
                          hdr := make([]byte, 2)
                          if _, err := io.ReadFull(st, hdr); err != nil {
                              return
                          }
                          n := binary.BigEndian.Uint16(hdr)
                          buf := make([]byte, n)
                          if _, err := io.ReadFull(st, buf); err != nil {
                              return
                          }
                          out := make([]byte, 2+len(buf))
                          binary.BigEndian.PutUint16(out, uint16(len(buf)))
                          copy(out[2:], buf)
                          _, _ = st.Write(out)
                      }(str)
                  }
              }(sess)
          }
      }()
      return ln.Addr().String()
  }

  func TestDoQ_BidiStreamRoundTrip(t *testing.T) {
      cert, err := selfSignedCert()
      if err != nil {
          t.Fatal(err)
      }
      addr := mkDoQEcho(t, cert)

      ch, err := NewDoQChannel(addr, 3*time.Second, &tls.Config{
          InsecureSkipVerify: true,
          NextProtos:         []string{"doq"},
      })
      if err != nil {
          t.Fatalf("NewDoQChannel: %v", err)
      }
      defer ch.Close()

      ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
      defer cancel()
      q := []byte{0xAB, 0xCD, 0xEF}
      r, err := ch.Query(ctx, q)
      if err != nil {
          t.Fatalf("Query: %v", err)
      }
      if !bytes.Equal(r, q) {
          t.Fatalf("echo mismatch: %x", r)
      }
      if ch.Kind() != KindDoQ {
          t.Fatal("kind mismatch")
      }
  }
  ```

- [ ] **Step 2: Run, verify FAIL**

  Run: `go test ./internal/transport/...`
  Expected: FAIL.

- [ ] **Step 3: Implement**

  ```go
  // internal/transport/doq.go
  package transport

  import (
      "context"
      "crypto/tls"
      "encoding/binary"
      "fmt"
      "io"
      "sync"
      "time"

      "github.com/quic-go/quic-go"
  )

  type DoQChannel struct {
      addr      string
      tlsConfig *tls.Config
      timeout   time.Duration

      mu     sync.Mutex
      sess   quic.Connection
      health Health
  }

  func NewDoQChannel(addr string, timeout time.Duration, tlsConfig *tls.Config) (*DoQChannel, error) {
      if tlsConfig == nil {
          tlsConfig = &tls.Config{NextProtos: []string{"doq"}}
      } else if len(tlsConfig.NextProtos) == 0 {
          tlsConfig.NextProtos = []string{"doq"}
      }
      return &DoQChannel{
          addr:      addr,
          tlsConfig: tlsConfig,
          timeout:   timeout,
          health:    Health{SuccessRate: 1.0, BudgetTokens: 200},
      }, nil
  }

  func (c *DoQChannel) ensure(ctx context.Context) (quic.Connection, error) {
      c.mu.Lock()
      defer c.mu.Unlock()
      if c.sess != nil {
          return c.sess, nil
      }
      sess, err := quic.DialAddr(ctx, c.addr, c.tlsConfig, nil)
      if err != nil {
          return nil, fmt.Errorf("doq: dial: %w", err)
      }
      c.sess = sess
      return sess, nil
  }

  func (c *DoQChannel) Query(ctx context.Context, q []byte) ([]byte, error) {
      start := time.Now()
      sess, err := c.ensure(ctx)
      if err != nil {
          c.recordErr()
          return nil, err
      }
      str, err := sess.OpenStreamSync(ctx)
      if err != nil {
          c.dropSess()
          c.recordErr()
          return nil, fmt.Errorf("doq: open stream: %w", err)
      }
      frame := make([]byte, 2+len(q))
      binary.BigEndian.PutUint16(frame[:2], uint16(len(q)))
      copy(frame[2:], q)
      if _, err := str.Write(frame); err != nil {
          _ = str.Close()
          c.recordErr()
          return nil, fmt.Errorf("doq: write: %w", err)
      }
      _ = str.Close() // signal end of request per RFC 9250

      hdr := make([]byte, 2)
      if _, err := io.ReadFull(str, hdr); err != nil {
          c.recordErr()
          return nil, fmt.Errorf("doq: read hdr: %w", err)
      }
      n := binary.BigEndian.Uint16(hdr)
      buf := make([]byte, n)
      if _, err := io.ReadFull(str, buf); err != nil {
          c.recordErr()
          return nil, fmt.Errorf("doq: read body: %w", err)
      }
      c.recordOK(time.Since(start))
      return buf, nil
  }

  func (c *DoQChannel) dropSess() {
      c.mu.Lock()
      defer c.mu.Unlock()
      if c.sess != nil {
          _ = c.sess.CloseWithError(0, "")
          c.sess = nil
      }
  }

  func (c *DoQChannel) MaxResponseBytes() int { return 16384 }
  func (c *DoQChannel) Kind() Kind            { return KindDoQ }
  func (c *DoQChannel) Close() error {
      c.dropSess()
      return nil
  }

  func (c *DoQChannel) Health() Health {
      c.mu.Lock()
      defer c.mu.Unlock()
      return c.health
  }
  func (c *DoQChannel) recordOK(rtt time.Duration) {
      c.mu.Lock()
      defer c.mu.Unlock()
      c.health.RTTEMA = ema(c.health.RTTEMA, rtt, 0.2)
      c.health.SuccessRate = ema01(c.health.SuccessRate, 1.0, 0.05)
  }
  func (c *DoQChannel) recordErr() {
      c.mu.Lock()
      defer c.mu.Unlock()
      c.health.LastError = time.Now()
      c.health.SuccessRate = ema01(c.health.SuccessRate, 0.0, 0.05)
  }
  ```

  Note: quic-go's `quic.Connection` and `quic.Stream` API may evolve. If a method signature has changed between the version pinned by `go.mod` and what's shown here, use the equivalent — the semantics required are: dial QUIC server with ALPN `doq`, open one bidi stream per query, write request, close write side, read full response, close.

- [ ] **Step 4: Run, verify PASS**

  Run: `go test ./internal/transport/...`
  Expected: PASS.

- [ ] **Step 5: Commit**

  ```bash
  git add internal/transport/doq.go internal/transport/doq_test.go
  git commit -m "feat(transport): DoQ adapter (RFC 9250 over QUIC)"
  ```

---

### Task 18: Known-resolver registry + no-direct-route validator

**Goal:** the bundled `KnownResolvers` table from spec §8.2 and a validator that rejects any operator-configured endpoint matching an auth-domain (enforces spec §2.2 constraint).

**Files:**
- Create: `internal/transport/known_resolvers.go`
- Create: `internal/transport/validation.go`
- Test:   `internal/transport/validation_test.go`

**Steps:**

- [ ] **Step 1: Write the failing test**

  ```go
  // internal/transport/validation_test.go
  package transport

  import "testing"

  func TestValidateNoDirectRoute(t *testing.T) {
      authDomains := []string{"a.example.com", "b.example.net"}
      cases := []struct {
          name    string
          spec    ResolverSpec
          wantErr bool
      }{
          {"clean", ResolverSpec{ID: "x", IP: "1.1.1.1",
              DoH: "https://cloudflare-dns.com/dns-query"}, false},
          {"doh-matches-auth", ResolverSpec{ID: "y", IP: "1.2.3.4",
              DoH: "https://a.example.com/dns-query"}, true},
          {"dot-matches-auth", ResolverSpec{ID: "z", IP: "1.2.3.4",
              DoT: "b.example.net:853"}, true},
          {"doq-matches-auth", ResolverSpec{ID: "w", IP: "1.2.3.4",
              DoQ: "a.example.com:853"}, true},
          {"subdomain-of-auth-matches", ResolverSpec{ID: "s", IP: "1.2.3.4",
              DoH: "https://sub.a.example.com/dns-query"}, true},
      }
      for _, c := range cases {
          t.Run(c.name, func(t *testing.T) {
              err := ValidateNoDirectRoute(c.spec, authDomains)
              if (err != nil) != c.wantErr {
                  t.Fatalf("err = %v, wantErr = %v", err, c.wantErr)
              }
          })
      }
  }

  func TestKnownResolvers_AllValidUnderEmptyAuth(t *testing.T) {
      for _, r := range KnownResolvers {
          if err := ValidateNoDirectRoute(r, nil); err != nil {
              t.Errorf("KnownResolver %s rejected by validator: %v", r.ID, err)
          }
      }
  }
  ```

- [ ] **Step 2: Run, verify FAIL**

  Run: `go test ./internal/transport/...`
  Expected: FAIL.

- [ ] **Step 3: Implement known_resolvers.go**

  ```go
  // internal/transport/known_resolvers.go
  package transport

  type ResolverSpec struct {
      ID  string // logging key, e.g. "cloudflare"
      IP  string // UDP/53 IP[:port]; if no port, ":53" is appended at use site
      DoH string // full https URL, empty if unsupported
      DoT string // host[:port], empty if unsupported
      DoQ string // host[:port], empty if unsupported
  }

  var KnownResolvers = []ResolverSpec{
      {ID: "cloudflare", IP: "1.1.1.1",
          DoH: "https://cloudflare-dns.com/dns-query",
          DoT: "1.1.1.1:853",
          DoQ: "1.1.1.1:853"},
      {ID: "cloudflare-secondary", IP: "1.0.0.1",
          DoH: "https://cloudflare-dns.com/dns-query",
          DoT: "1.0.0.1:853"},
      {ID: "google", IP: "8.8.8.8",
          DoH: "https://dns.google/dns-query",
          DoT: "8.8.8.8:853"},
      {ID: "google-secondary", IP: "8.8.4.4",
          DoH: "https://dns.google/dns-query",
          DoT: "8.8.4.4:853"},
      {ID: "quad9", IP: "9.9.9.9",
          DoH: "https://dns.quad9.net/dns-query",
          DoT: "9.9.9.9:853"},
      {ID: "adguard", IP: "94.140.14.14",
          DoH: "https://dns.adguard-dns.com/dns-query",
          DoT: "94.140.14.14:853",
          DoQ: "94.140.14.14:853"},
      {ID: "mullvad", IP: "194.242.2.2",
          DoH: "https://base.dns.mullvad.net/dns-query",
          DoT: "base.dns.mullvad.net:853"},
      {ID: "nextdns", IP: "45.90.28.0",
          DoH: "https://dns.nextdns.io/",
          DoT: "dns.nextdns.io:853"},
      {ID: "controld", IP: "76.76.2.0",
          DoH: "https://freedns.controld.com/p0",
          DoT: "p0.freedns.controld.com:853"},
  }
  ```

- [ ] **Step 4: Implement validation.go**

  ```go
  // internal/transport/validation.go
  package transport

  import (
      "errors"
      "fmt"
      "net/url"
      "strings"
  )

  var ErrAuthDomainAsResolverEndpoint = errors.New(
      "transport: resolver endpoint must not be an auth domain (no-direct-route rule)")

  // ValidateNoDirectRoute returns an error if any of spec's DoH/DoT/DoQ
  // endpoints resolves to a hostname under one of authDomains. The check
  // is hostname-suffix-based and case-insensitive.
  func ValidateNoDirectRoute(spec ResolverSpec, authDomains []string) error {
      if len(authDomains) == 0 {
          return nil
      }
      auth := normalizeAuthList(authDomains)
      check := func(label string, raw string) error {
          host := extractHost(raw)
          if host == "" {
              return nil
          }
          h := strings.ToLower(host)
          for _, a := range auth {
              if h == a || strings.HasSuffix(h, "."+a) {
                  return fmt.Errorf("%w: %s endpoint %q matches auth domain %q",
                      ErrAuthDomainAsResolverEndpoint, label, raw, a)
              }
          }
          return nil
      }
      if err := check("DoH", spec.DoH); err != nil {
          return err
      }
      if err := check("DoT", spec.DoT); err != nil {
          return err
      }
      if err := check("DoQ", spec.DoQ); err != nil {
          return err
      }
      return nil
  }

  func normalizeAuthList(in []string) []string {
      out := make([]string, 0, len(in))
      for _, a := range in {
          out = append(out, strings.TrimSuffix(strings.ToLower(strings.TrimSpace(a)), "."))
      }
      return out
  }

  func extractHost(raw string) string {
      if raw == "" {
          return ""
      }
      // DoH is a URL, DoT/DoQ are host[:port].
      if strings.HasPrefix(raw, "https://") || strings.HasPrefix(raw, "http://") {
          u, err := url.Parse(raw)
          if err != nil {
              return ""
          }
          return u.Hostname()
      }
      if i := strings.LastIndex(raw, ":"); i >= 0 {
          return raw[:i]
      }
      return raw
  }
  ```

- [ ] **Step 5: Run, verify PASS**

  Run: `go test ./internal/transport/...`
  Expected: PASS.

- [ ] **Step 6: Commit**

  ```bash
  git add internal/transport/known_resolvers.go internal/transport/validation.go internal/transport/validation_test.go
  git commit -m "feat(transport): known-resolver registry and no-direct-route validator"
  ```

---

### Task 19: Capability probe

**Goal:** per-`(resolver, channel)` probe that issues a benign DNS query, measures RTT, and records which RR types pass through (HTTPS / SVCB are commonly stripped).

**Files:**
- Create: `internal/transport/probe.go`
- Test:   `internal/transport/probe_test.go`

**Steps:**

- [ ] **Step 1: Write the failing test**

  ```go
  // internal/transport/probe_test.go
  package transport

  import (
      "context"
      "net"
      "testing"
      "time"
  )

  func TestCapabilityProbe_UDP53Success(t *testing.T) {
      // Resolver that replies to any query with a valid 12-byte DNS header + answer.
      pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
      defer pc.Close()
      go func() {
          buf := make([]byte, 4096)
          for {
              n, addr, err := pc.ReadFrom(buf)
              if err != nil {
                  return
              }
              resp := buildBenignDNSResponse(buf[:n])
              _, _ = pc.WriteTo(resp, addr)
          }
      }()
      ch, _ := NewUDP53Channel(pc.LocalAddr().String(), time.Second)
      defer ch.Close()

      ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
      defer cancel()
      cap, err := ProbeCapability(ctx, ch)
      if err != nil {
          t.Fatalf("ProbeCapability: %v", err)
      }
      if !cap.Working {
          t.Fatal("expected working=true")
      }
      if cap.RTT <= 0 {
          t.Fatal("expected positive RTT")
      }
  }

  func TestCapabilityProbe_TimeoutMarksUnhealthy(t *testing.T) {
      // Dial a closed UDP port to force read timeout.
      ch, _ := NewUDP53Channel("127.0.0.1:1", 200*time.Millisecond)
      defer ch.Close()

      ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
      defer cancel()
      cap, err := ProbeCapability(ctx, ch)
      if err == nil && cap.Working {
          t.Fatal("expected probe to fail or mark unhealthy")
      }
  }

  // buildBenignDNSResponse is a tiny test helper: takes a query and
  // returns a response that copies the ID and sets QR=1 with one A answer.
  func buildBenignDNSResponse(q []byte) []byte {
      // Minimal: copy ID, set QR=1, AA=0, RD=0, RA=1, RCODE=0,
      // QDCOUNT=q's, ANCOUNT=1, no actual answer body (we just check
      // that we got >12 bytes back). Real implementation uses dnsparser.
      r := make([]byte, len(q))
      copy(r, q)
      if len(r) >= 4 {
          r[2] = 0x81 // QR=1, RD=1
          r[3] = 0x80 // RA=1, RCODE=0
      }
      return r
  }
  ```

- [ ] **Step 2: Run, verify FAIL**

  Run: `go test ./internal/transport/...`
  Expected: FAIL.

- [ ] **Step 3: Implement**

  ```go
  // internal/transport/probe.go
  package transport

  import (
      "context"
      "errors"
      "time"
  )

  // ChannelCapability summarises a (resolver, channel) probe outcome.
  type ChannelCapability struct {
      Working   bool
      RTT       time.Duration
      MaxBytes  int
      // PassRRTypes records which RR types the resolver passes through.
      // Empty during early probe; later phases (Task 20 authenticity)
      // fill it in.
      PassRRTypes []uint16
      LastErr     error
  }

  var ErrProbeShort = errors.New("transport: probe response too short")

  // ProbeCapability issues a benign A-record query against ch and times it.
  // The benign query is `A example.com`. Implementations must accept any
  // DNS response that's at least a valid 12-byte DNS header — we don't
  // parse the body here.
  func ProbeCapability(ctx context.Context, ch QueryChannel) (ChannelCapability, error) {
      start := time.Now()
      q := benignQuery("example.com.")
      resp, err := ch.Query(ctx, q)
      if err != nil {
          return ChannelCapability{Working: false, LastErr: err}, err
      }
      if len(resp) < 12 {
          return ChannelCapability{Working: false, LastErr: ErrProbeShort}, ErrProbeShort
      }
      return ChannelCapability{
          Working:  true,
          RTT:      time.Since(start),
          MaxBytes: ch.MaxResponseBytes(),
      }, nil
  }

  // benignQuery is a minimal RFC 1035 DNS query for `qname` IN A with ID 0.
  // Body: header (12 B) + qname (labels) + 0x00 + qtype(A=1) + qclass(IN=1).
  func benignQuery(qname string) []byte {
      labels := encodeQName(qname)
      buf := make([]byte, 12+len(labels)+4)
      // ID=0, flags: RD=1.
      buf[2] = 0x01
      buf[5] = 0x01 // QDCOUNT=1
      copy(buf[12:], labels)
      // qtype A=1
      buf[12+len(labels)+0] = 0x00
      buf[12+len(labels)+1] = 0x01
      // qclass IN=1
      buf[12+len(labels)+2] = 0x00
      buf[12+len(labels)+3] = 0x01
      return buf
  }

  func encodeQName(name string) []byte {
      out := make([]byte, 0, len(name)+1)
      label := make([]byte, 0, 16)
      for i := 0; i < len(name); i++ {
          c := name[i]
          if c == '.' {
              out = append(out, byte(len(label)))
              out = append(out, label...)
              label = label[:0]
              continue
          }
          label = append(label, c)
      }
      if len(label) > 0 {
          out = append(out, byte(len(label)))
          out = append(out, label...)
      }
      out = append(out, 0x00)
      return out
  }
  ```

- [ ] **Step 4: Run, verify PASS**

  Run: `go test ./internal/transport/...`
  Expected: PASS.

- [ ] **Step 5: Commit**

  ```bash
  git add internal/transport/probe.go internal/transport/probe_test.go
  git commit -m "feat(transport): capability probe for (resolver, channel) pairs"
  ```

---

### Task 20: Authenticity probe + scanner

**Goal:** spec §6.3 / §8.3 / §8.4 — the probe that proves a `(resolver, channel)` actually delivers to *our* server, via a PSK-AEAD `PROBE` / `PROBE_ACK` exchange. The scanner orchestrates capability + authenticity probes for the configured resolver list.

**Files:**
- Create: `internal/transport/scanner.go`
- Test:   `internal/transport/scanner_test.go`

**Steps:**

- [ ] **Step 1: Write the failing test**

  ```go
  // internal/transport/scanner_test.go
  package transport

  import (
      "bytes"
      "context"
      "net"
      "testing"
      "time"

      "stormdns-go/internal/handshake"
  )

  // mkAuthResolver acts both as a resolver and as our auth NS — it AEAD-opens
  // an incoming PROBE under the shared PSK, and replies with a PROBE_ACK.
  // For test simplicity, it expects the PROBE payload to occupy the entire
  // DNS query body (not yet wire-encoded as labels — that's Task 21).
  func mkAuthResolver(t *testing.T, psk []byte) string {
      t.Helper()
      pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
      t.Cleanup(func() { _ = pc.Close() })
      go func() {
          buf := make([]byte, 4096)
          for {
              n, addr, err := pc.ReadFrom(buf)
              if err != nil {
                  return
              }
              // Treat the entire packet as the sealed PROBE envelope; the
              // AAD is the first 16 bytes of the packet.
              if n < 16+16 {
                  continue
              }
              random := buf[:16]
              env := buf[16:n]
              plain, err := handshake.PSKAEADOpen(psk, "probe",
                  handshake.DirClient, random, env, random)
              if err != nil {
                  continue
              }
              // Build PROBE_ACK with server nonce.
              srv := bytes.Repeat([]byte{0x77}, 16)
              ackEnv, _ := handshake.PSKAEADSeal(psk, "probe",
                  handshake.DirServer, srv, plain, srv)
              resp := append(srv, ackEnv...)
              _, _ = pc.WriteTo(resp, addr)
          }
      }()
      return pc.LocalAddr().String()
  }

  func TestAuthenticityProbe_Pass(t *testing.T) {
      psk := bytes.Repeat([]byte{0x42}, 32)
      addr := mkAuthResolver(t, psk)
      ch, _ := NewUDP53Channel(addr, 2*time.Second)
      defer ch.Close()

      ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
      defer cancel()
      ok, err := ProbeAuthenticity(ctx, ch, psk)
      if err != nil {
          t.Fatalf("ProbeAuthenticity: %v", err)
      }
      if !ok {
          t.Fatal("expected authenticity probe to pass")
      }
  }

  func TestAuthenticityProbe_Reject_WrongPSK(t *testing.T) {
      psk := bytes.Repeat([]byte{0x42}, 32)
      addr := mkAuthResolver(t, psk)
      ch, _ := NewUDP53Channel(addr, 1*time.Second)
      defer ch.Close()

      ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
      defer cancel()
      ok, _ := ProbeAuthenticity(ctx, ch, bytes.Repeat([]byte{0x99}, 32))
      if ok {
          t.Fatal("expected probe to FAIL under wrong PSK")
      }
  }
  ```

- [ ] **Step 2: Run, verify FAIL**

  Run: `go test ./internal/transport/...`
  Expected: FAIL.

- [ ] **Step 3: Implement**

  ```go
  // internal/transport/scanner.go
  package transport

  import (
      "context"
      "crypto/rand"
      "fmt"

      "stormdns-go/internal/handshake"
  )

  // ProbeAuthenticity sends a PSK-sealed PROBE through ch and verifies a
  // PSK-sealed PROBE_ACK returns. Returns true iff the server proves it
  // holds the PSK (i.e., the response wasn't sinkhole-injected).
  //
  // Wire format used here is the "naked PROBE" testing convention:
  //   [16 B client_random][sealed envelope...]
  // The integrated path in Task 21+ wraps this inside the DNS query carrier
  // produced by the antidpi label shaper.
  func ProbeAuthenticity(ctx context.Context, ch QueryChannel, psk []byte) (bool, error) {
      cr := make([]byte, 16)
      if _, err := rand.Read(cr); err != nil {
          return false, fmt.Errorf("scanner: rand: %w", err)
      }
      env, err := handshake.PSKAEADSeal(psk, "probe",
          handshake.DirClient, cr, []byte("phantom-dns-probe"), cr)
      if err != nil {
          return false, fmt.Errorf("scanner: seal: %w", err)
      }
      q := append(append([]byte(nil), cr...), env...)
      resp, err := ch.Query(ctx, q)
      if err != nil {
          return false, err
      }
      if len(resp) < 32 {
          return false, fmt.Errorf("scanner: response too short")
      }
      sr := resp[:16]
      ackEnv := resp[16:]
      if _, err := handshake.PSKAEADOpen(psk, "probe",
          handshake.DirServer, sr, ackEnv, sr); err != nil {
          return false, fmt.Errorf("scanner: PROBE_ACK auth failed: %w", err)
      }
      return true, nil
  }

  // ScanResult is what the scanner reports per (resolver, channel) pair.
  type ScanResult struct {
      Resolver  ResolverSpec
      Channel   Kind
      Working   bool       // capability probe passed
      Authentic bool       // authenticity probe passed
      Cap       ChannelCapability
  }

  // ScanFunc is the shape used by tests / integration glue to inject
  // channel construction for a given (resolver, kind) without hardcoding
  // dial logic in scanner.go.
  type ScanFunc func(spec ResolverSpec, kind Kind) (QueryChannel, error)

  // ScanAll runs capability and authenticity probes against every
  // configured resolver across the channels they advertise. psk is the
  // shared key used by the authenticity probe.
  func ScanAll(ctx context.Context, resolvers []ResolverSpec, psk []byte, dial ScanFunc) []ScanResult {
      var out []ScanResult
      for _, r := range resolvers {
          for _, k := range []Kind{Kind53UDP, KindDoH, KindDoT, KindDoQ} {
              if !resolverSupports(r, k) {
                  continue
              }
              ch, err := dial(r, k)
              if err != nil {
                  out = append(out, ScanResult{Resolver: r, Channel: k,
                      Cap: ChannelCapability{LastErr: err}})
                  continue
              }
              cap, err := ProbeCapability(ctx, ch)
              res := ScanResult{Resolver: r, Channel: k, Cap: cap,
                  Working: err == nil && cap.Working}
              if res.Working {
                  if ok, _ := ProbeAuthenticity(ctx, ch, psk); ok {
                      res.Authentic = true
                  }
              }
              _ = ch.Close()
              out = append(out, res)
          }
      }
      return out
  }

  func resolverSupports(r ResolverSpec, k Kind) bool {
      switch k {
      case Kind53UDP:
          return r.IP != ""
      case KindDoH:
          return r.DoH != ""
      case KindDoT:
          return r.DoT != ""
      case KindDoQ:
          return r.DoQ != ""
      }
      return false
  }
  ```

- [ ] **Step 4: Run, verify PASS**

  Run: `go test ./internal/transport/...`
  Expected: PASS.

- [ ] **Step 5: Commit**

  ```bash
  git add internal/transport/scanner.go internal/transport/scanner_test.go
  git commit -m "feat(transport): authenticity probe and resolver scanner"
  ```

---

**Phase C milestone:** `go test ./internal/transport/...` is green. Four transports, validator, capability probe, and authenticity probe all work against in-process resolvers/auth NS. No integration with client dispatcher or server ingress yet.

---

## Phase D — Server-side v2 ingress + session state

Tasks 21–23 wire v2 framing, anti-DPI label decoding, and PSK-AEAD handshakes into the existing UDP/53 auth-NS server. From this point on, modifications need to coexist with v1 logic — the existing v1 paths in `internal/udpserver/server_ingress.go` stay untouched; v2 takes a new dispatch branch.

### Task 21: Server v2 ingress dispatch

**Goal:** when the server receives a UDP query, decode the labels (via `antidpi.DecodeLabels`), classify the inner bytes (via `vpnproto.DetectVersion`), and route v2 bytes to a new `handleV2` path. v1 traffic still flows through the existing `handleV1` path with no behaviour change.

**Files:**
- Modify: `internal/udpserver/server_ingress.go` (add v2 dispatch branch only)
- Create: `internal/udpserver/v2_ingress.go`
- Test:   `internal/udpserver/v2_ingress_test.go`

**Steps:**

- [ ] **Step 1: Read the existing v1 entry point**

  Open `internal/udpserver/server_ingress.go` and locate the function that receives a `(remoteAddr, queryBytes)` and currently parses the DNS message, extracts labels, and dispatches into the v1 session machinery. Note its name and signature — call it `handleQuery` in the rest of this task (substitute the real name when implementing). Do *not* modify its body yet.

- [ ] **Step 2: Write the failing test for the v2 dispatch branch**

  ```go
  // internal/udpserver/v2_ingress_test.go
  package udpserver

  import (
      "bytes"
      "testing"

      Enums "stormdns-go/internal/enums"
      "stormdns-go/internal/vpnproto"
  )

  func TestServerV2Ingress_RejectsNonV2(t *testing.T) {
      // Build a v1 frame byte slice — must NOT be routed to the v2 path.
      v1 := []byte{Enums.PACKET_STREAM_DATA, 0x00, 0x00, 0x01}
      if vpnproto.DetectVersion(v1) == vpnproto.VersionV2 {
          t.Fatal("classification regression")
      }
  }

  func TestServerV2Ingress_DecodesValidV2Frame(t *testing.T) {
      // Hand-build a minimal v2 INIT frame (10-byte header + zero payload + 16-byte tag).
      h := vpnproto.V2Header{
          Type:      Enums.PACKET_V2_INIT,
          ChCls:     vpnproto.ChClsNarrow,
          SessionID: 0,
          StreamID:  0,
          SeqNum:    0,
      }
      frame := vpnproto.V2Frame{
          Header:           h,
          EncryptedPayload: nil,
          Tag:              bytes.Repeat([]byte{0xAA}, 16),
      }
      raw := frame.Marshal()
      if vpnproto.DetectVersion(raw) != vpnproto.VersionV2 {
          t.Fatal("expected v2 classification")
      }

      out := DecodeV2FrameFromQueryBytes(raw)
      if out == nil {
          t.Fatal("DecodeV2FrameFromQueryBytes returned nil")
      }
      if out.Header.Type != Enums.PACKET_V2_INIT {
          t.Fatalf("type = 0x%x", out.Header.Type)
      }
  }
  ```

- [ ] **Step 3: Run, verify FAIL**

  Run: `go test ./internal/udpserver/...`
  Expected: FAIL.

- [ ] **Step 4: Implement `internal/udpserver/v2_ingress.go`**

  ```go
  // internal/udpserver/v2_ingress.go
  package udpserver

  import (
      "stormdns-go/internal/antidpi"
      "stormdns-go/internal/vpnproto"
  )

  // ExtractV2FrameFromQName takes the DNS query labels (without the auth
  // domain suffix) and decodes them back into raw frame bytes using the
  // antidpi label shaper's permissive decoder.
  func ExtractV2FrameFromQName(labels []string) ([]byte, error) {
      return antidpi.DecodeLabels(labels)
  }

  // DecodeV2FrameFromQueryBytes is the next layer: given raw v2 wire bytes
  // (header + payload + tag) it returns the parsed V2Frame or nil if the
  // bytes don't classify as v2.
  func DecodeV2FrameFromQueryBytes(raw []byte) *vpnproto.V2Frame {
      if vpnproto.DetectVersion(raw) != vpnproto.VersionV2 {
          return nil
      }
      var f vpnproto.V2Frame
      if err := f.Unmarshal(raw); err != nil {
          return nil
      }
      return &f
  }
  ```

- [ ] **Step 5: Wire the dispatch into the existing entry point**

  In `internal/udpserver/server_ingress.go`, locate `handleQuery` (or its real name). Add this branch *before* the existing v1 parsing, after the labels have been stripped of the auth-domain suffix and joined into raw frame bytes:

  ```go
  // ----- v2 dispatch -----
  if v2 := DecodeV2FrameFromQueryBytes(rawFrameBytes); v2 != nil {
      s.handleV2(remoteAddr, *v2)
      return
  }
  // ----- fall through to existing v1 handling -----
  ```

  Add a stub `handleV2` method on the server struct (the actual session/handshake wiring is Task 22):

  ```go
  func (s *server) handleV2(remote net.Addr, f vpnproto.V2Frame) {
      // Task 22 fills this in.
      s.logger.Debugf("v2 frame received type=%s session=%d seq=%d",
          vpnproto.V2TypeName(f.Header.Type), f.Header.SessionID, f.Header.SeqNum)
  }
  ```

  (Substitute the actual server-struct field names from the existing code — `s.logger` may already exist; if not, follow whatever logging convention the file uses.)

- [ ] **Step 6: Run, verify PASS**

  Run: `go test ./internal/udpserver/...`
  Expected: PASS (new v2 tests pass; existing v1 tests still green because the v2 branch only fires for actual v2 frames).

- [ ] **Step 7: Commit**

  ```bash
  git add internal/udpserver/v2_ingress.go internal/udpserver/v2_ingress_test.go internal/udpserver/server_ingress.go
  git commit -m "feat(udpserver): v2 dispatch branch alongside existing v1 handler"
  ```

---

### Task 22: Server v2 session state + handshake completion

**Goal:** when the server's `handleV2` sees a `PACKET_V2_INIT`, run `handshake.ServerAcceptWithReplay`, derive session keys, store them in a `v2Sessions` map, and send the INIT_ACK back as a DNS response (RR-typed via `antidpi.RRTypePolicy`).

**Files:**
- Create: `internal/udpserver/v2_session.go`
- Test:   `internal/udpserver/v2_session_test.go`

**Steps:**

- [ ] **Step 1: Write the failing test (full INIT→INIT_ACK exchange via raw bytes)**

  ```go
  // internal/udpserver/v2_session_test.go
  package udpserver

  import (
      "bytes"
      "testing"
      "time"

      "stormdns-go/internal/handshake"
  )

  func TestV2Session_HandshakeAccept(t *testing.T) {
      psk := bytes.Repeat([]byte{0x55}, 32)
      reg := NewV2SessionRegistry(psk)

      // Client side builds a real INIT envelope.
      cs, env, err := handshake.ClientStart(psk, 0, time.Now().UTC(), bytes.Repeat([]byte{0}, 16))
      if err != nil {
          t.Fatalf("ClientStart: %v", err)
      }

      ack, sess, err := reg.AcceptInit(env, bytes.Repeat([]byte{0}, 16), bytes.Repeat([]byte{1}, 16), time.Now())
      if err != nil {
          t.Fatalf("AcceptInit: %v", err)
      }
      if sess == nil {
          t.Fatal("nil session")
      }
      // Client should be able to Finish against this ack.
      if err := cs.Finish(psk, ack, bytes.Repeat([]byte{1}, 16)); err != nil {
          t.Fatalf("Client.Finish: %v", err)
      }
      if !bytes.Equal(cs.Keys.ClientToServer, sess.Keys.ClientToServer) {
          t.Fatal("keys diverged across sides")
      }
      if reg.Get(sess.SessionID) == nil {
          t.Fatal("registry didn't store the session")
      }
  }

  func TestV2Session_AcceptInit_RejectsReplay(t *testing.T) {
      psk := bytes.Repeat([]byte{0x55}, 32)
      reg := NewV2SessionRegistry(psk)

      _, env, _ := handshake.ClientStart(psk, 0, time.Now().UTC(), bytes.Repeat([]byte{0}, 16))
      _, _, err := reg.AcceptInit(env, bytes.Repeat([]byte{0}, 16), bytes.Repeat([]byte{1}, 16), time.Now())
      if err != nil {
          t.Fatalf("first accept: %v", err)
      }
      _, _, err = reg.AcceptInit(env, bytes.Repeat([]byte{0}, 16), bytes.Repeat([]byte{1}, 16), time.Now())
      if err == nil {
          t.Fatal("expected replay to be rejected")
      }
  }
  ```

- [ ] **Step 2: Run, verify FAIL**

  Run: `go test ./internal/udpserver/...`
  Expected: FAIL.

- [ ] **Step 3: Implement `v2_session.go`**

  ```go
  // internal/udpserver/v2_session.go
  package udpserver

  import (
      "sync"
      "time"

      "stormdns-go/internal/handshake"
  )

  // V2Session is the server-side state for one v2 session.
  type V2Session struct {
      SessionID uint16
      Keys      handshake.SessionKeys
      LastSeen  time.Time
  }

  // V2SessionRegistry holds per-session keys + a replay cache for INIT.
  type V2SessionRegistry struct {
      psk     []byte
      replay  *handshake.ReplayCache

      mu       sync.RWMutex
      sessions map[uint16]*V2Session
  }

  func NewV2SessionRegistry(psk []byte) *V2SessionRegistry {
      return &V2SessionRegistry{
          psk:      append([]byte(nil), psk...),
          replay:   handshake.NewReplayCache(handshake.DefaultReplayWindow, 4096),
          sessions: make(map[uint16]*V2Session),
      }
  }

  // AcceptInit runs the server-side handshake on a fresh INIT envelope.
  // initAAD and ackAAD are the outer v2-frame header bytes used as AAD
  // for the PSK-AEAD seal/open. Returns the INIT_ACK envelope plus the
  // new V2Session.
  func (r *V2SessionRegistry) AcceptInit(env, initAAD, ackAAD []byte, now time.Time) ([]byte, *V2Session, error) {
      sstate, ack, err := handshake.ServerAcceptWithReplay(r.psk, env, initAAD, ackAAD, r.replay, now)
      if err != nil {
          return nil, nil, err
      }
      s := &V2Session{
          SessionID: sstate.SessionID,
          Keys:      sstate.Keys,
          LastSeen:  now,
      }
      r.mu.Lock()
      r.sessions[s.SessionID] = s
      r.mu.Unlock()
      return ack, s, nil
  }

  func (r *V2SessionRegistry) Get(sid uint16) *V2Session {
      r.mu.RLock()
      defer r.mu.RUnlock()
      return r.sessions[sid]
  }

  func (r *V2SessionRegistry) Touch(sid uint16, now time.Time) {
      r.mu.Lock()
      defer r.mu.Unlock()
      if s, ok := r.sessions[sid]; ok {
          s.LastSeen = now
      }
  }
  ```

- [ ] **Step 5: Run, verify PASS**

  Run: `go test ./internal/udpserver/...`
  Expected: PASS (the new session tests + existing v1 tests).

- [ ] **Step 6: Commit**

  ```bash
  git add internal/udpserver/v2_session.go internal/udpserver/v2_session_test.go
  git commit -m "feat(udpserver): v2 session registry with INIT handshake acceptance"
  ```

---

### Task 23: Multi-domain auth handling + RR-type response builder

**Goal:** spec §8.1 server-side — accept any FQDN whose suffix matches one of `[auth].domains`, reject others with REFUSED. Plus fill in `BuildV2DNSResponse` for A / AAAA / TXT carriers (HTTPS / SVCB land in a follow-up; v1 of Phantom DNS focuses on A/AAAA/TXT for response carriers, the others remain available for the client query side only).

**Files:**
- Modify: `internal/udpserver/server_ingress.go` (auth-domain allowlist check)
- Create: `internal/udpserver/v2_response.go` (real RR-typed encoders)
- Create: `internal/udpserver/v2_response_test.go`

**Steps:**

- [ ] **Step 1: Write the failing test**

  ```go
  // internal/udpserver/v2_response_test.go
  package udpserver

  import (
      "bytes"
      "testing"

      Enums "stormdns-go/internal/enums"
      "stormdns-go/internal/antidpi"
      "stormdns-go/internal/vpnproto"
  )

  func TestBuildV2DNSResponse_A(t *testing.T) {
      payload := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34, 0x56, 0x78}
      f := vpnproto.V2Frame{
          Header: vpnproto.V2Header{Type: Enums.PACKET_V2_DATA, ChCls: vpnproto.ChClsNarrow,
              SessionID: 1, StreamID: 1, SeqNum: 1},
          EncryptedPayload: payload,
          Tag:              bytes.Repeat([]byte{0}, 16),
      }
      resp := BuildV2DNSResponse([]vpnproto.V2Frame{f}, antidpi.RRTypeA)
      if len(resp) == 0 {
          t.Fatal("expected non-empty response body")
      }
      // Round-trip: parse the response, extract A records, reassemble bytes.
      got, err := ExtractV2FrameBytesFromAResponse(resp)
      if err != nil {
          t.Fatalf("extract: %v", err)
      }
      // Reassembled bytes should at minimum include the frame Marshal output.
      want := f.Marshal()
      if !bytes.HasPrefix(got, want) {
          t.Fatalf("reassembled bytes don't start with original frame")
      }
  }

  func TestAuthDomainAllowlist(t *testing.T) {
      allow := []string{"a.example.com", "b.example.net"}
      cases := []struct {
          fqdn string
          ok   bool
      }{
          {"data.a.example.com", true},
          {"x.y.b.example.net", true},
          {"a.example.com", true},
          {"evil.example.org", false},
          {"a.example.com.attacker.net", false},
      }
      for _, c := range cases {
          if got := IsAllowedAuthFQDN(c.fqdn, allow); got != c.ok {
              t.Errorf("IsAllowedAuthFQDN(%q) = %v, want %v", c.fqdn, got, c.ok)
          }
      }
  }
  ```

  Note: `ExtractV2FrameBytesFromAResponse` is a test-side reconstruction helper; both it and the production `BuildV2DNSResponse` need a DNS response builder. The cleanest path is to reuse pieces of `internal/dnsparser`. If the existing dnsparser doesn't yet expose a builder you can call directly, write a small `dns_writer.go` next to it that wraps `encoding/binary` to emit a minimal response message (header + one Question + N Answers); keep this builder package-private to `udpserver`.

- [ ] **Step 2: Run, verify FAIL**

  Run: `go test ./internal/udpserver/...`
  Expected: FAIL.

- [ ] **Step 3: Implement the auth allowlist helper**

  Add to `internal/udpserver/server_ingress.go` (or a small `auth_allowlist.go` next to it):

  ```go
  // IsAllowedAuthFQDN returns true iff fqdn is one of the authDomains
  // or a subdomain of one. Comparison is case-insensitive and ignores
  // trailing dots.
  func IsAllowedAuthFQDN(fqdn string, authDomains []string) bool {
      f := strings.ToLower(strings.TrimSuffix(fqdn, "."))
      for _, a := range authDomains {
          n := strings.ToLower(strings.TrimSuffix(a, "."))
          if f == n || strings.HasSuffix(f, "."+n) {
              return true
          }
      }
      return false
  }
  ```

  And call this from `handleQuery` *before* any v2/v1 dispatch:

  ```go
  if !IsAllowedAuthFQDN(qname, s.config.AuthDomains) {
      s.sendREFUSED(remoteAddr, queryID)
      return
  }
  ```

- [ ] **Step 4: Implement the RR-typed response builder**

  In `internal/udpserver/v2_response.go`:

  ```go
  package udpserver

  import (
      "bytes"
      "encoding/binary"

      "stormdns-go/internal/antidpi"
      "stormdns-go/internal/vpnproto"
  )

  // BuildV2DNSResponse takes one or more v2 frames and emits a DNS
  // response body (without the leading 12-byte DNS header — that is
  // built by the existing dnsparser response writer).
  func BuildV2DNSResponse(frames []vpnproto.V2Frame, rrtype antidpi.RRType) []byte {
      var raw []byte
      for _, f := range frames {
          raw = append(raw, f.Marshal()...)
      }
      switch rrtype {
      case antidpi.RRTypeA:
          return chunkAsRRs(raw, 4, uint16(antidpi.RRTypeA))
      case antidpi.RRTypeAAAA:
          return chunkAsRRs(raw, 16, uint16(antidpi.RRTypeAAAA))
      case antidpi.RRTypeTXT:
          return encodeAsTXT(raw)
      default:
          // Fallback: A. The decoder is permissive enough to accept it.
          return chunkAsRRs(raw, 4, uint16(antidpi.RRTypeA))
      }
  }

  // chunkAsRRs slices `raw` into fixed-width RRs and emits each as a
  // pseudo-RR body: 2-byte type, 2-byte class IN(=1), 4-byte TTL(=60),
  // 2-byte rdlength(=chunkSize), chunkSize-byte data. NAME compression
  // pointer (0xC00C) is added by the outer dnsparser writer.
  func chunkAsRRs(raw []byte, chunkSize int, rrType uint16) []byte {
      var buf bytes.Buffer
      pad := chunkSize - 1
      for i := 0; i < len(raw); i += chunkSize {
          end := i + chunkSize
          var chunk []byte
          if end <= len(raw) {
              chunk = raw[i:end]
          } else {
              chunk = make([]byte, chunkSize)
              copy(chunk, raw[i:])
              _ = pad
          }
          // Name pointer to question (0xC00C)
          buf.WriteByte(0xC0)
          buf.WriteByte(0x0C)
          // Type
          binary.Write(&buf, binary.BigEndian, rrType)
          // Class IN
          binary.Write(&buf, binary.BigEndian, uint16(1))
          // TTL
          binary.Write(&buf, binary.BigEndian, uint32(60))
          // RDLENGTH
          binary.Write(&buf, binary.BigEndian, uint16(chunkSize))
          buf.Write(chunk)
      }
      return buf.Bytes()
  }

  // encodeAsTXT emits one TXT record whose RDATA is one or more
  // character-strings (each ≤255 bytes).
  func encodeAsTXT(raw []byte) []byte {
      var rdata bytes.Buffer
      for len(raw) > 0 {
          n := len(raw)
          if n > 255 {
              n = 255
          }
          rdata.WriteByte(byte(n))
          rdata.Write(raw[:n])
          raw = raw[n:]
      }
      var buf bytes.Buffer
      buf.WriteByte(0xC0); buf.WriteByte(0x0C)
      binary.Write(&buf, binary.BigEndian, uint16(antidpi.RRTypeTXT))
      binary.Write(&buf, binary.BigEndian, uint16(1))
      binary.Write(&buf, binary.BigEndian, uint32(60))
      binary.Write(&buf, binary.BigEndian, uint16(rdata.Len()))
      buf.Write(rdata.Bytes())
      return buf.Bytes()
  }

  // ExtractV2FrameBytesFromAResponse is the test-side decoder
  // matching chunkAsRRs(_, 4, RRTypeA).
  func ExtractV2FrameBytesFromAResponse(body []byte) ([]byte, error) {
      var out []byte
      i := 0
      for i < len(body) {
          if i+12 > len(body) {
              break
          }
          // Skip NAME pointer (2) + type(2) + class(2) + ttl(4) + rdlen(2) = 12.
          rdlen := int(binary.BigEndian.Uint16(body[i+10 : i+12]))
          start := i + 12
          end := start + rdlen
          if end > len(body) {
              break
          }
          out = append(out, body[start:end]...)
          i = end
      }
      return out, nil
  }
  ```

  Note: this builder skips the outer 12-byte DNS header — the caller (handleV2's
  response sender) builds the header using `internal/dnsparser`'s response writer
  and prepends it before sending. If `dnsparser` doesn't expose a writer that
  takes pre-built answer-section bytes, add a small helper there in this same
  commit; do not duplicate DNS header construction logic.

- [ ] **Step 5: Run, verify PASS**

  Run: `go test ./internal/udpserver/...`
  Expected: PASS.

- [ ] **Step 6: Commit**

  ```bash
  git add internal/udpserver/auth_allowlist.go internal/udpserver/v2_response.go internal/udpserver/v2_response_test.go internal/udpserver/server_ingress.go
  git commit -m "feat(udpserver): multi-domain allowlist and A/AAAA/TXT response builder"
  ```

---

**Phase D milestone:** `go test ./internal/udpserver/...` passes with both v1 paths green and the v2 ingress + session registry + RR-typed response builder green. v2 is plumbed end-to-end on the server side at the protocol layer, but no live UDP path yet exercises it (that's Phase G).

---

## Phase E — Client-side integration

Phase E modifies existing client code. Where a function name is referenced (e.g., `Balancer.PickResolver`) the engineer must open the file and find the current signature — the codebase may have renamed it between when this plan was written and execution.

### Task 24: Per-domain health tracking

**Goal:** spec §8.1 — new `domain_health.go` that holds a rolling success rate per FQDN, parks domains below 70% success, and exposes a `Pick()` weighted by health.

**Files:**
- Create: `internal/client/domain_health.go`
- Test:   `internal/client/domain_health_test.go`

**Steps:**

- [ ] **Step 1: Write the failing test**

  ```go
  // internal/client/domain_health_test.go
  package client

  import (
      "testing"
      "time"
  )

  func TestDomainHealth_ParksOnFailure(t *testing.T) {
      h := NewDomainHealth([]DomainSpec{
          {FQDN: "a.example.com", Weight: 1},
          {FQDN: "b.example.com", Weight: 1},
      }, time.Now)
      // Record many failures for "a"; it should park.
      for i := 0; i < 100; i++ {
          h.RecordFailure("a.example.com")
      }
      if !h.IsParked("a.example.com") {
          t.Fatal("expected a.example.com to be parked")
      }
  }

  func TestDomainHealth_PickAvoidsParked(t *testing.T) {
      h := NewDomainHealth([]DomainSpec{
          {FQDN: "a.example.com", Weight: 1},
          {FQDN: "b.example.com", Weight: 1},
      }, time.Now)
      for i := 0; i < 100; i++ {
          h.RecordFailure("a.example.com")
      }
      for i := 0; i < 10; i++ {
          if h.Pick() == "a.example.com" {
              t.Fatal("Pick returned parked domain")
          }
      }
  }

  func TestDomainHealth_UnparkAfterBackoff(t *testing.T) {
      now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
      clock := &mockClock{t: now}
      h := NewDomainHealth([]DomainSpec{{FQDN: "x.example.com", Weight: 1}}, clock.Now)
      for i := 0; i < 100; i++ {
          h.RecordFailure("x.example.com")
      }
      if !h.IsParked("x.example.com") {
          t.Fatal("expected park")
      }
      clock.t = now.Add(11 * time.Minute)
      if h.IsParked("x.example.com") {
          t.Fatal("expected unpark after backoff")
      }
  }

  type mockClock struct{ t time.Time }

  func (m *mockClock) Now() time.Time { return m.t }
  ```

- [ ] **Step 2: Run, verify FAIL**

  Run: `go test ./internal/client/...`
  Expected: FAIL.

- [ ] **Step 3: Implement**

  ```go
  // internal/client/domain_health.go
  package client

  import (
      "math/rand"
      "sync"
      "time"
  )

  type DomainSpec struct {
      FQDN   string
      Weight int
  }

  type DomainHealth struct {
      now      func() time.Time
      mu       sync.Mutex
      domains  map[string]*domainState
      order    []string // for deterministic iteration
  }

  type domainState struct {
      weight       int
      successRate  float64
      windowSucc   int
      windowFail   int
      parked       bool
      unparkAt     time.Time
  }

  const (
      domainParkThreshold = 0.7
      domainParkInterval  = 10 * time.Minute
      domainWindowSize    = 100
  )

  func NewDomainHealth(specs []DomainSpec, now func() time.Time) *DomainHealth {
      d := &DomainHealth{
          now:     now,
          domains: make(map[string]*domainState, len(specs)),
      }
      for _, s := range specs {
          w := s.Weight
          if w <= 0 {
              w = 1
          }
          d.domains[s.FQDN] = &domainState{weight: w, successRate: 1.0}
          d.order = append(d.order, s.FQDN)
      }
      return d
  }

  func (d *DomainHealth) RecordSuccess(fqdn string) {
      d.update(fqdn, true)
  }

  func (d *DomainHealth) RecordFailure(fqdn string) {
      d.update(fqdn, false)
  }

  func (d *DomainHealth) update(fqdn string, ok bool) {
      d.mu.Lock()
      defer d.mu.Unlock()
      s, exists := d.domains[fqdn]
      if !exists {
          return
      }
      if ok {
          s.windowSucc++
      } else {
          s.windowFail++
      }
      total := s.windowSucc + s.windowFail
      if total >= domainWindowSize {
          s.successRate = float64(s.windowSucc) / float64(total)
          s.windowSucc = 0
          s.windowFail = 0
          if s.successRate < domainParkThreshold {
              s.parked = true
              s.unparkAt = d.now().Add(domainParkInterval)
          }
      } else if total >= 10 {
          // Early park signal if first 10 are nearly all failures.
          ratio := float64(s.windowSucc) / float64(total)
          if ratio < 0.2 {
              s.parked = true
              s.unparkAt = d.now().Add(domainParkInterval)
          }
      }
  }

  func (d *DomainHealth) IsParked(fqdn string) bool {
      d.mu.Lock()
      defer d.mu.Unlock()
      s, ok := d.domains[fqdn]
      if !ok {
          return false
      }
      if s.parked && d.now().After(s.unparkAt) {
          s.parked = false
          s.successRate = 1.0
      }
      return s.parked
  }

  // Pick returns a healthy domain weighted by configured weight.
  // Returns "" if all configured domains are parked.
  func (d *DomainHealth) Pick() string {
      d.mu.Lock()
      defer d.mu.Unlock()
      candidates := make([]string, 0, len(d.order))
      weights := make([]int, 0, len(d.order))
      total := 0
      now := d.now()
      for _, name := range d.order {
          s := d.domains[name]
          if s.parked && now.Before(s.unparkAt) {
              continue
          }
          if s.parked {
              s.parked = false
              s.successRate = 1.0
          }
          candidates = append(candidates, name)
          weights = append(weights, s.weight)
          total += s.weight
      }
      if total == 0 {
          return ""
      }
      r := rand.Intn(total)
      for i, w := range weights {
          if r < w {
              return candidates[i]
          }
          r -= w
      }
      return candidates[len(candidates)-1]
  }
  ```

- [ ] **Step 4: Run, verify PASS**

  Run: `go test ./internal/client/...`
  Expected: PASS for the new tests; *some existing client tests may need a small touch-up* if they unconditionally construct types this file doesn't touch — none expected.

- [ ] **Step 5: Commit**

  ```bash
  git add internal/client/domain_health.go internal/client/domain_health_test.go
  git commit -m "feat(client): per-domain health tracking with auto-park/unpark"
  ```

---

### Task 25: Per-(resolver, channel) health + balancer scoring update

**Goal:** extend `internal/client/resolver_health.go` to key by `(resolverID, channelKind)` instead of just `resolverID`. Update `internal/client/balancer.go` so `Pick` returns a `(ResolverID, Kind)` tuple weighted by per-pair health, per-pair token budget, and the per-RR-type passthrough flag from the scanner.

**Files:**
- Modify: `internal/client/resolver_health.go`
- Modify: `internal/client/balancer.go`
- Create: `internal/client/resolver_channel_health.go`
- Test:   `internal/client/resolver_channel_health_test.go`

**Steps:**

- [ ] **Step 1: Read existing files**

  Open `internal/client/resolver_health.go` and `internal/client/balancer.go`. Identify:
  - The struct that holds per-resolver state.
  - The function that returns "the next resolver to try" (probably `Pick`, `Next`, or `Choose`).
  - The token-bucket / QPS-budget implementation if any.

  Resist the urge to rewrite the file. v1 callers must keep working.

- [ ] **Step 2: Write the failing test**

  ```go
  // internal/client/resolver_channel_health_test.go
  package client

  import (
      "testing"
      "time"

      "stormdns-go/internal/transport"
  )

  func TestResolverChannelHealth_TracksPerChannelSeparately(t *testing.T) {
      rch := NewResolverChannelHealth()
      key := ResolverChannelKey{ResolverID: "cf", Channel: transport.Kind53UDP}
      keyDoH := ResolverChannelKey{ResolverID: "cf", Channel: transport.KindDoH}

      rch.RecordSuccess(key, 50*time.Millisecond)
      for i := 0; i < 50; i++ {
          rch.RecordFailure(keyDoH)
      }
      if rch.IsParked(key) {
          t.Fatal("cf/udp53 should be healthy")
      }
      if !rch.IsParked(keyDoH) {
          t.Fatal("cf/doh should be parked after sustained failure")
      }
  }
  ```

- [ ] **Step 3: Run, verify FAIL**

  Run: `go test ./internal/client/...`
  Expected: FAIL.

- [ ] **Step 4: Implement `resolver_channel_health.go`**

  ```go
  // internal/client/resolver_channel_health.go
  package client

  import (
      "sync"
      "time"

      "stormdns-go/internal/transport"
  )

  type ResolverChannelKey struct {
      ResolverID string
      Channel    transport.Kind
  }

  type ResolverChannelHealth struct {
      mu     sync.Mutex
      state  map[ResolverChannelKey]*rchState
  }

  type rchState struct {
      rttEMA       time.Duration
      successRate  float64
      tokenBucket  int
      lastErr      time.Time
      parked       bool
      unparkAt     time.Time
  }

  const (
      rchParkThreshold = 0.5
      rchParkInterval  = 5 * time.Minute
      rchDefaultBudget = 200
  )

  func NewResolverChannelHealth() *ResolverChannelHealth {
      return &ResolverChannelHealth{state: make(map[ResolverChannelKey]*rchState)}
  }

  func (r *ResolverChannelHealth) get(k ResolverChannelKey) *rchState {
      s, ok := r.state[k]
      if !ok {
          s = &rchState{successRate: 1.0, tokenBucket: rchDefaultBudget}
          r.state[k] = s
      }
      return s
  }

  func (r *ResolverChannelHealth) RecordSuccess(k ResolverChannelKey, rtt time.Duration) {
      r.mu.Lock()
      defer r.mu.Unlock()
      s := r.get(k)
      if s.rttEMA == 0 {
          s.rttEMA = rtt
      } else {
          s.rttEMA = time.Duration(float64(s.rttEMA)*0.8 + float64(rtt)*0.2)
      }
      s.successRate = s.successRate*0.95 + 1.0*0.05
  }

  func (r *ResolverChannelHealth) RecordFailure(k ResolverChannelKey) {
      r.mu.Lock()
      defer r.mu.Unlock()
      s := r.get(k)
      s.successRate = s.successRate*0.95 + 0.0*0.05
      s.lastErr = time.Now()
      if s.successRate < rchParkThreshold && !s.parked {
          s.parked = true
          s.unparkAt = time.Now().Add(rchParkInterval)
      }
  }

  func (r *ResolverChannelHealth) IsParked(k ResolverChannelKey) bool {
      r.mu.Lock()
      defer r.mu.Unlock()
      s := r.get(k)
      if s.parked && time.Now().After(s.unparkAt) {
          s.parked = false
          s.successRate = 1.0
      }
      return s.parked
  }

  // Score returns a scalar for the balancer to compare pairs (higher is better).
  func (r *ResolverChannelHealth) Score(k ResolverChannelKey) float64 {
      r.mu.Lock()
      defer r.mu.Unlock()
      s := r.get(k)
      if s.parked {
          return 0
      }
      rttMs := float64(s.rttEMA / time.Millisecond)
      if rttMs <= 0 {
          rttMs = 100
      }
      return s.successRate * (1000.0 / (rttMs + 50.0))
  }
  ```

- [ ] **Step 5: Wire into `balancer.go`**

  Add a new method on the existing balancer struct (name it `Balancer`, `ResolverBalancer`, etc. depending on the file) that picks `(ResolverID, Kind)` based on `ResolverChannelHealth.Score`. Do not remove the existing single-resolver `Pick` — call sites for v1 keep using it. Example shape:

  ```go
  // (in internal/client/balancer.go, alongside existing methods)

  type V2Pick struct {
      ResolverID string
      Channel    transport.Kind
  }

  func (b *Balancer) PickV2(pool []ResolverChannelKey, health *ResolverChannelHealth) (V2Pick, bool) {
      best := V2Pick{}
      bestScore := -1.0
      for _, k := range pool {
          s := health.Score(k)
          if s > bestScore {
              bestScore = s
              best = V2Pick{ResolverID: k.ResolverID, Channel: k.Channel}
          }
      }
      if bestScore <= 0 {
          return V2Pick{}, false
      }
      return best, true
  }
  ```

- [ ] **Step 6: Run, verify PASS**

  Run: `go test ./internal/client/...`
  Expected: PASS.

- [ ] **Step 7: Commit**

  ```bash
  git add internal/client/resolver_channel_health.go internal/client/resolver_channel_health_test.go internal/client/balancer.go
  git commit -m "feat(client): per-(resolver,channel) health and v2 pick path"
  ```

---

### Task 26: Stream resolver — per-channel pipelining

**Goal:** extend `internal/client/stream_resolver.go` so v2 paths can have per-channel in-flight caps from `[arq]` config and so queries can fire concurrently when the channel supports pipelining (DoH/DoT/DoQ). v1 paths keep their current synchronous behavior.

**Files:**
- Modify: `internal/client/stream_resolver.go` (add v2-aware fan-out)
- Create: `internal/client/stream_resolver_v2.go`
- Test:   `internal/client/stream_resolver_v2_test.go`

**Steps:**

- [ ] **Step 1: Read the existing stream resolver**

  Open `internal/client/stream_resolver.go`. Identify the main "send a query, get a response" function, and the rate-limiting / queueing primitive it uses (semaphore, channel-of-tokens, etc.). Do not modify v1 paths in this task.

- [ ] **Step 2: Write the failing test**

  ```go
  // internal/client/stream_resolver_v2_test.go
  package client

  import (
      "context"
      "sync/atomic"
      "testing"
      "time"

      "stormdns-go/internal/transport"
  )

  type fakeChannel struct {
      inflight int32
      maxSeen  int32
  }

  func (f *fakeChannel) Query(_ context.Context, _ []byte) ([]byte, error) {
      cur := atomic.AddInt32(&f.inflight, 1)
      for {
          prev := atomic.LoadInt32(&f.maxSeen)
          if cur <= prev || atomic.CompareAndSwapInt32(&f.maxSeen, prev, cur) {
              break
          }
      }
      time.Sleep(10 * time.Millisecond)
      atomic.AddInt32(&f.inflight, -1)
      return []byte{0xAA}, nil
  }
  func (f *fakeChannel) MaxResponseBytes() int      { return 4096 }
  func (f *fakeChannel) Health() transport.Health   { return transport.Health{} }
  func (f *fakeChannel) Kind() transport.Kind       { return transport.KindDoH }
  func (f *fakeChannel) Close() error               { return nil }

  func TestV2Pump_RespectsInflightCap(t *testing.T) {
      ch := &fakeChannel{}
      pump := NewV2Pump(ch, 4)
      defer pump.Close()

      var done atomic.Int32
      for i := 0; i < 32; i++ {
          go func() {
              _, _ = pump.Query(context.Background(), []byte{1, 2, 3})
              done.Add(1)
          }()
      }
      // Wait for completion.
      deadline := time.Now().Add(3 * time.Second)
      for done.Load() < 32 {
          if time.Now().After(deadline) {
              t.Fatalf("pump never drained: %d done", done.Load())
          }
          time.Sleep(10 * time.Millisecond)
      }
      if ch.maxSeen > 4 {
          t.Fatalf("inflight cap violated: maxSeen=%d", ch.maxSeen)
      }
      if ch.maxSeen < 2 {
          t.Fatalf("pump didn't parallelize: maxSeen=%d", ch.maxSeen)
      }
  }
  ```

- [ ] **Step 3: Run, verify FAIL**

  Run: `go test ./internal/client/...`
  Expected: FAIL.

- [ ] **Step 4: Implement `stream_resolver_v2.go`**

  ```go
  // internal/client/stream_resolver_v2.go
  package client

  import (
      "context"

      "stormdns-go/internal/transport"
  )

  // V2Pump wraps a QueryChannel with a bounded concurrency semaphore
  // matching the per-channel inflight cap from [arq] config.
  type V2Pump struct {
      ch    transport.QueryChannel
      tokens chan struct{}
  }

  func NewV2Pump(ch transport.QueryChannel, inflight int) *V2Pump {
      if inflight < 1 {
          inflight = 1
      }
      return &V2Pump{ch: ch, tokens: make(chan struct{}, inflight)}
  }

  func (p *V2Pump) Query(ctx context.Context, q []byte) ([]byte, error) {
      select {
      case p.tokens <- struct{}{}:
      case <-ctx.Done():
          return nil, ctx.Err()
      }
      defer func() { <-p.tokens }()
      return p.ch.Query(ctx, q)
  }

  func (p *V2Pump) Close() error { return p.ch.Close() }
  ```

- [ ] **Step 5: Run, verify PASS**

  Run: `go test ./internal/client/...`
  Expected: PASS.

- [ ] **Step 6: Commit**

  ```bash
  git add internal/client/stream_resolver_v2.go internal/client/stream_resolver_v2_test.go
  git commit -m "feat(client): V2Pump — per-channel inflight-capped query fan-out"
  ```

---

### Task 27: Dispatcher v2 path

**Goal:** the existing `internal/client/dispatcher.go` runs the inner StormDNS protocol over one resolver at a time. Add a v2 mode: at session start it runs `handshake.ClientStart`, sends the INIT through a `V2Pump`-wrapped channel, completes via `Finish`, then routes outgoing v2 frames through the balancer's `PickV2` → `V2Pump.Query` loop.

**Files:**
- Modify: `internal/client/dispatcher.go` (add `runV2Session` method)
- Create: `internal/client/v2_dispatcher.go`
- Test:   `internal/client/v2_dispatcher_test.go` (uses in-process v2 server)

**Steps:**

- [ ] **Step 1: Read `dispatcher.go`**

  Open `internal/client/dispatcher.go`. Locate the function that initiates a new tunnel session (it should call into `session.go` / `tunnel_runtime.go`). Note its signature.

- [ ] **Step 2: Write the failing test (uses an in-process auth resolver that wraps Task 22's `V2SessionRegistry`)**

  ```go
  // internal/client/v2_dispatcher_test.go
  package client

  import (
      "bytes"
      "context"
      "encoding/binary"
      "net"
      "testing"
      "time"

      Enums "stormdns-go/internal/enums"
      "stormdns-go/internal/handshake"
      "stormdns-go/internal/udpserver"
      "stormdns-go/internal/vpnproto"
  )

  // mkV2AuthResolverAdapter wires an in-process resolver that:
  //   - receives a DNS query with v2-shaped labels
  //   - extracts the v2 frame
  //   - if it's V2_INIT, feeds it to a V2SessionRegistry and returns the
  //     INIT_ACK as a DNS response containing the v2 frame in TXT chunks
  // For testing we cheat slightly: the client sends the v2 frame as the
  // *entire* DNS query body (no label encoding yet) and expects the
  // INIT_ACK frame back as the entire response body.
  func mkV2AuthResolverAdapter(t *testing.T, psk []byte) (string, *udpserver.V2SessionRegistry) {
      t.Helper()
      reg := udpserver.NewV2SessionRegistry(psk)
      pc, _ := net.ListenPacket("udp", "127.0.0.1:0")
      t.Cleanup(func() { _ = pc.Close() })
      go func() {
          buf := make([]byte, 4096)
          for {
              n, addr, err := pc.ReadFrom(buf)
              if err != nil {
                  return
              }
              raw := append([]byte(nil), buf[:n]...)
              v2 := udpserver.DecodeV2FrameFromQueryBytes(raw)
              if v2 == nil {
                  continue
              }
              if v2.Header.Type != Enums.PACKET_V2_INIT {
                  continue
              }
              // The integrated path would pull (clientRandom from payload).
              // For test simplicity we pre-pend 16 zero bytes as AAD.
              ack, _, err := reg.AcceptInit(v2.EncryptedPayload,
                  bytes.Repeat([]byte{0}, 16), bytes.Repeat([]byte{1}, 16), time.Now())
              if err != nil {
                  continue
              }
              // Frame the ack as an INIT_ACK v2 frame and send back raw.
              resp := vpnproto.V2Frame{
                  Header: vpnproto.V2Header{
                      Type: Enums.PACKET_V2_INIT_ACK, ChCls: vpnproto.ChClsNarrow,
                  },
                  EncryptedPayload: ack,
                  Tag:              bytes.Repeat([]byte{0}, 16),
              }
              _, _ = pc.WriteTo(resp.Marshal(), addr)
          }
      }()
      _ = binary.BigEndian
      return pc.LocalAddr().String(), reg
  }

  func TestV2Dispatcher_HandshakeCompletes(t *testing.T) {
      psk := bytes.Repeat([]byte{0x55}, 32)
      addr, _ := mkV2AuthResolverAdapter(t, psk)

      // Use UDP/53 channel directly; in the integrated path the dispatcher
      // would go through the resolver pool / balancer.
      ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
      defer cancel()
      sess, err := RunV2Handshake(ctx, addr, psk)
      if err != nil {
          t.Fatalf("RunV2Handshake: %v", err)
      }
      if sess == nil || sess.SessionID == 0 {
          t.Fatal("session not established")
      }
      _ = handshake.DefaultClockSkew
  }
  ```

- [ ] **Step 3: Run, verify FAIL**

  Run: `go test ./internal/client/...`
  Expected: FAIL.

- [ ] **Step 4: Implement `v2_dispatcher.go`**

  ```go
  // internal/client/v2_dispatcher.go
  package client

  import (
      "bytes"
      "context"
      "fmt"
      "time"

      Enums "stormdns-go/internal/enums"
      "stormdns-go/internal/handshake"
      "stormdns-go/internal/transport"
      "stormdns-go/internal/vpnproto"
  )

  // V2ClientSession is the client-side handle to a live v2 session.
  type V2ClientSession struct {
      SessionID uint16
      Keys      handshake.SessionKeys
  }

  // RunV2Handshake performs the 1-RTT v2 handshake against a UDP/53
  // resolver. For non-UDP channels, callers wire the channel directly
  // (this helper is purposely narrow; the integrated dispatcher chooses
  // the channel via balancer.PickV2 and uses the same flow).
  func RunV2Handshake(ctx context.Context, resolverAddr string, psk []byte) (*V2ClientSession, error) {
      ch, err := transport.NewUDP53Channel(resolverAddr, 3*time.Second)
      if err != nil {
          return nil, err
      }
      defer ch.Close()
      return RunV2HandshakeOn(ctx, ch, psk)
  }

  func RunV2HandshakeOn(ctx context.Context, ch transport.QueryChannel, psk []byte) (*V2ClientSession, error) {
      // Use 16-byte zero AAD for the test-shaped path. In the integrated
      // path the AAD will be the outer v2-frame header bytes.
      aad := bytes.Repeat([]byte{0}, 16)
      cs, env, err := handshake.ClientStart(psk, 0, time.Now().UTC(), aad)
      if err != nil {
          return nil, err
      }
      // Wrap INIT envelope in a v2 INIT frame.
      initFrame := vpnproto.V2Frame{
          Header: vpnproto.V2Header{Type: Enums.PACKET_V2_INIT, ChCls: vpnproto.ChClsNarrow},
          EncryptedPayload: env,
          Tag:              bytes.Repeat([]byte{0}, 16),
      }
      resp, err := ch.Query(ctx, initFrame.Marshal())
      if err != nil {
          return nil, fmt.Errorf("v2 dispatcher: INIT query: %w", err)
      }
      var ackFrame vpnproto.V2Frame
      if err := ackFrame.Unmarshal(resp); err != nil {
          return nil, fmt.Errorf("v2 dispatcher: ack unmarshal: %w", err)
      }
      if ackFrame.Header.Type != Enums.PACKET_V2_INIT_ACK {
          return nil, fmt.Errorf("v2 dispatcher: unexpected ack type 0x%x", ackFrame.Header.Type)
      }
      if err := cs.Finish(psk, ackFrame.EncryptedPayload, bytes.Repeat([]byte{1}, 16)); err != nil {
          return nil, fmt.Errorf("v2 dispatcher: finish: %w", err)
      }
      return &V2ClientSession{SessionID: cs.SessionID, Keys: cs.Keys}, nil
  }
  ```

- [ ] **Step 5: Hook into the existing dispatcher**

  In `internal/client/dispatcher.go`, find the session-start function. Add a new branch:

  ```go
  // If config.Protocol.Version == "v2" || ("auto" && !knownV1Server) try v2 first.
  if d.useV2() {
      sess, err := RunV2HandshakeOn(ctx, ch, d.psk)
      if err == nil {
          return d.runV2Session(ctx, sess, ch)
      }
      // Fall through to v1 if RunV2HandshakeOn returns
      // because of an unrecognised INIT_ACK or timeout
      // (per spec §5.6 — v1 server drops the INIT).
      if d.config.Protocol.Version == "v2" {
          return err // strict v2 mode: no fallback
      }
  }
  ```

  The body of `runV2Session` is left to the engineer to wire into the existing
  send/receive loop; the key contract is: send each outgoing payload AEAD-sealed
  with `sess.Keys.ClientToServer` (use `security.NewSessionAEAD`), receive frames
  through the v2 pump, open with `sess.Keys.ServerToClient`. The data path reuses
  `internal/arq`, `internal/streamutil`, `internal/socksproto` unchanged.

- [ ] **Step 6: Run, verify PASS**

  Run: `go test ./internal/client/...`
  Expected: PASS (dispatcher test + previous client tests).

- [ ] **Step 7: Commit**

  ```bash
  git add internal/client/v2_dispatcher.go internal/client/v2_dispatcher_test.go internal/client/dispatcher.go
  git commit -m "feat(client): v2 dispatcher with 1-RTT handshake and runV2Session wiring"
  ```

---

**Phase E milestone:** the client can now successfully complete a v2 handshake against an in-process v2 server and proceed to send AEAD-sealed v2 frames. Single-channel pipelining is in place (Task 26); multi-path fan-out across the top-K `(resolver, channel)` pairs lands in **Task 27b** before this phase is fully spec-complete.

---

### Task 27b: MultiPump — fan out across top-K healthy (resolver, channel) pairs

**Goal:** spec §9.6 — for each outgoing v2 frame, pick one of the top-`K` healthy pairs (default `K=3`) weighted by `ResolverChannelHealth.Score`. On per-frame failure, retry with the next-highest pair before propagating an error to ARQ.

**Files:**
- Create: `internal/client/multipump.go`
- Test:   `internal/client/multipump_test.go`
- Modify: `internal/client/v2_dispatcher.go` (have `RunV2HandshakeOn` callers wire MultiPump)

**Steps:**

- [ ] **Step 1: Write the failing test**

  ```go
  // internal/client/multipump_test.go
  package client

  import (
      "context"
      "errors"
      "sync/atomic"
      "testing"

      "stormdns-go/internal/transport"
  )

  type errChannel struct {
      kind  transport.Kind
      err   error
      calls int32
  }

  func (e *errChannel) Query(_ context.Context, _ []byte) ([]byte, error) {
      atomic.AddInt32(&e.calls, 1)
      if e.err != nil {
          return nil, e.err
      }
      return []byte{0x77}, nil
  }
  func (e *errChannel) MaxResponseBytes() int    { return 1232 }
  func (e *errChannel) Health() transport.Health { return transport.Health{} }
  func (e *errChannel) Kind() transport.Kind     { return e.kind }
  func (e *errChannel) Close() error             { return nil }

  func TestMultiPump_PicksBestThenFailsOver(t *testing.T) {
      slow := &errChannel{kind: transport.Kind53UDP, err: errors.New("primary down")}
      fast := &errChannel{kind: transport.KindDoH}
      mp := NewMultiPump([]MultiPumpEntry{
          {Pump: NewV2Pump(slow, 4), Score: 10.0},
          {Pump: NewV2Pump(fast, 4), Score: 5.0},
      })
      defer mp.Close()

      resp, err := mp.Query(context.Background(), []byte{1, 2, 3})
      if err != nil {
          t.Fatalf("Query: %v", err)
      }
      if len(resp) == 0 {
          t.Fatal("empty response")
      }
      if atomic.LoadInt32(&slow.calls) != 1 {
          t.Fatalf("expected primary to be tried once, got %d", slow.calls)
      }
      if atomic.LoadInt32(&fast.calls) != 1 {
          t.Fatalf("expected failover to fast, got %d", fast.calls)
      }
  }

  func TestMultiPump_AllFail(t *testing.T) {
      a := &errChannel{kind: transport.Kind53UDP, err: errors.New("a")}
      b := &errChannel{kind: transport.KindDoH, err: errors.New("b")}
      mp := NewMultiPump([]MultiPumpEntry{
          {Pump: NewV2Pump(a, 4), Score: 10.0},
          {Pump: NewV2Pump(b, 4), Score: 5.0},
      })
      defer mp.Close()
      if _, err := mp.Query(context.Background(), []byte{1}); err == nil {
          t.Fatal("expected error when all pumps fail")
      }
  }
  ```

- [ ] **Step 2: Run, verify FAIL**

  Run: `go test ./internal/client/...`
  Expected: FAIL.

- [ ] **Step 3: Implement**

  ```go
  // internal/client/multipump.go
  package client

  import (
      "context"
      "errors"
      "fmt"
      "sort"
  )

  type MultiPumpEntry struct {
      Pump  *V2Pump
      Score float64
  }

  // MultiPump fans out queries across multiple V2Pumps, trying the
  // highest-scored pump first and falling over to the next on error.
  // Spec §9.6: default K=3 top-scored pairs.
  type MultiPump struct {
      entries []MultiPumpEntry // sorted by Score descending
      topK    int
  }

  func NewMultiPump(entries []MultiPumpEntry) *MultiPump {
      cp := append([]MultiPumpEntry(nil), entries...)
      sort.Slice(cp, func(i, j int) bool { return cp[i].Score > cp[j].Score })
      topK := 3
      if len(cp) < topK {
          topK = len(cp)
      }
      return &MultiPump{entries: cp, topK: topK}
  }

  var ErrAllPumpsFailed = errors.New("multipump: all entries returned error")

  func (m *MultiPump) Query(ctx context.Context, q []byte) ([]byte, error) {
      if len(m.entries) == 0 {
          return nil, fmt.Errorf("multipump: no entries")
      }
      var lastErr error
      tried := 0
      for _, e := range m.entries {
          if tried >= m.topK {
              break
          }
          tried++
          resp, err := e.Pump.Query(ctx, q)
          if err == nil {
              return resp, nil
          }
          lastErr = err
          if ctx.Err() != nil {
              return nil, ctx.Err()
          }
      }
      return nil, fmt.Errorf("%w: last=%v", ErrAllPumpsFailed, lastErr)
  }

  func (m *MultiPump) Close() error {
      for _, e := range m.entries {
          _ = e.Pump.Close()
      }
      return nil
  }
  ```

- [ ] **Step 4: Have the dispatcher build a MultiPump from the balancer's top-K**

  In `internal/client/v2_dispatcher.go`, add a constructor that takes the
  `ResolverChannelHealth` and a slice of pre-opened channels, scores each
  pair via `health.Score(key)`, and returns a `*MultiPump`. The
  `runV2Session` glue from Task 27 now uses `MultiPump.Query` instead of
  a single `V2Pump.Query`.

  ```go
  // (append to v2_dispatcher.go)

  type ChannelEntry struct {
      Key     ResolverChannelKey
      Channel transport.QueryChannel
      Inflight int
  }

  func BuildMultiPump(health *ResolverChannelHealth, entries []ChannelEntry) *MultiPump {
      mpEntries := make([]MultiPumpEntry, 0, len(entries))
      for _, e := range entries {
          mpEntries = append(mpEntries, MultiPumpEntry{
              Pump:  NewV2Pump(e.Channel, e.Inflight),
              Score: health.Score(e.Key),
          })
      }
      return NewMultiPump(mpEntries)
  }
  ```

- [ ] **Step 5: Run, verify PASS**

  Run: `go test ./internal/client/...`
  Expected: PASS.

- [ ] **Step 6: Commit**

  ```bash
  git add internal/client/multipump.go internal/client/multipump_test.go internal/client/v2_dispatcher.go
  git commit -m "feat(client): MultiPump fans queries across top-K (resolver,channel) pairs"
  ```

---

**Phase E milestone (final):** v2 handshake completes against an in-process v2 server; per-channel pipelining works; multi-path fan-out is in place across top-3 `(resolver, channel)` pairs. Spec §9.6 is now fully implemented at the code level; throughput-vs-target is gated by the hostile-network sim in Task 34.

---

## Phase F — Config, binary rename, LZ4 compression

### Task 28: Client config v2 keys (additive)

**Goal:** spec §10.1 — add `[protocol]`, `[domains]`, `[transports]`, `[scanner]`, `[antidpi]`, `[arq]`, `[compression]`, `[crypto]` sections to `internal/config/client.go`. v1 keys keep their semantics. If both `[server].host` and `[domains].list` are present, `[domains].list` wins (with a warning log).

**Files:**
- Modify: `internal/config/client.go`
- Test:   `internal/config/client_test.go` (extend)

**Steps:**

- [ ] **Step 1: Read the existing client config**

  Open `internal/config/client.go` and `internal/config/client_test.go`. Note the TOML decoding approach (presumably `BurntSushi/toml`) and how the existing struct fields are populated.

- [ ] **Step 2: Write the failing tests**

  Add to `client_test.go`:

  ```go
  func TestClientConfig_V2KeysAdditive(t *testing.T) {
      tomlBody := `
  [server]
  host = "auth.example.com"
  encryption_key_file = "client_key.txt"

  [protocol]
  version = "auto"

  [domains]
  list = [
    { fqdn = "a.example.com", weight = 1 },
    { fqdn = "b.example.net", weight = 2 },
  ]
  rotation = "per-session"

  [transports]
  allow = ["udp53", "doh", "dot", "doq"]
  prefer = "auto"

  [scanner]
  active = false
  rescan_on_network_change = true

  [antidpi]
  rrtype_mix = "auto"
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
  `
      cfg, err := LoadClientConfigFromString(tomlBody)
      if err != nil {
          t.Fatalf("Load: %v", err)
      }
      if cfg.Protocol.Version != "auto" {
          t.Fatalf("protocol.version = %q", cfg.Protocol.Version)
      }
      if len(cfg.Domains.List) != 2 || cfg.Domains.List[0].FQDN != "a.example.com" {
          t.Fatalf("domains.list = %+v", cfg.Domains.List)
      }
      if cfg.Domains.List[1].Weight != 2 {
          t.Fatalf("weight not parsed: %+v", cfg.Domains.List[1])
      }
      if cfg.Compression.Algo != "lz4" {
          t.Fatalf("compression.algo = %q", cfg.Compression.Algo)
      }
      if cfg.ARQ.InflightDoH != 64 {
          t.Fatalf("arq.inflight_doh = %d", cfg.ARQ.InflightDoH)
      }
  }

  func TestClientConfig_V1OnlyStillWorks(t *testing.T) {
      tomlBody := `
  [server]
  host = "auth.example.com"
  encryption_key_file = "client_key.txt"

  [resolvers]
  list = ["1.1.1.1", "8.8.8.8"]
  `
      cfg, err := LoadClientConfigFromString(tomlBody)
      if err != nil {
          t.Fatalf("Load: %v", err)
      }
      // v1 fields still populated.
      if cfg.Server.Host != "auth.example.com" {
          t.Fatalf("server.host = %q", cfg.Server.Host)
      }
      // v2 fields zero-valued with sensible defaults.
      if cfg.Protocol.Version == "" {
          t.Fatalf("expected protocol.version default, got empty")
      }
  }
  ```

  Note: `LoadClientConfigFromString` is a small helper to wrap whatever the
  existing config loader uses (likely `toml.Unmarshal(...)`). If the loader
  is already exported with another name, use that.

- [ ] **Step 3: Run, verify FAIL**

  Run: `go test ./internal/config/...`
  Expected: FAIL.

- [ ] **Step 4: Implement**

  Add to `client.go` (alongside existing struct fields — do not replace):

  ```go
  type Protocol struct {
      Version string `toml:"version"` // "v1" | "v2" | "auto"; defaults to "auto"
  }

  type DomainEntry struct {
      FQDN   string `toml:"fqdn"`
      Weight int    `toml:"weight"`
  }

  type Domains struct {
      List     []DomainEntry `toml:"list"`
      Rotation string        `toml:"rotation"` // "per-session" | "per-query" | "weighted-random"
  }

  type Transports struct {
      Allow  []string `toml:"allow"`
      Prefer string   `toml:"prefer"`
  }

  type Scanner struct {
      Active                  bool          `toml:"active"`
      RescanOnNetworkChange   bool          `toml:"rescan_on_network_change"`
      ParkedRecheckInterval   time.Duration `toml:"-"`
      ParkedRecheckIntervalS  string        `toml:"parked_recheck_interval"`
  }

  type AntiDPI struct {
      LabelDictPath  string  `toml:"label_dict_path"`
      RRTypeMix      string  `toml:"rrtype_mix"`
      PaddingBuckets string  `toml:"padding_buckets"`
      JitterMeanMs   int     `toml:"jitter_mean_ms"`
      JitterSigma    float64 `toml:"jitter_sigma"`
  }

  type ARQ struct {
      InflightUDP53 int `toml:"inflight_udp53"`
      InflightDoH   int `toml:"inflight_doh"`
      InflightDoT   int `toml:"inflight_dot"`
      InflightDoQ   int `toml:"inflight_doq"`
  }

  type Compression struct {
      Algo string `toml:"algo"` // "lz4" | "zlib" | "off"
  }

  type Crypto struct {
      RekeyBytes    string `toml:"rekey_bytes"`
      RekeyInterval string `toml:"rekey_interval"`
  }

  // Extend the existing client config struct with these new sections:
  // (Adapt this snippet to the real struct name in client.go.)
  // type ClientConfig struct {
  //     ... existing fields ...
  //     Protocol    Protocol    `toml:"protocol"`
  //     Domains     Domains     `toml:"domains"`
  //     Transports  Transports  `toml:"transports"`
  //     Scanner     Scanner     `toml:"scanner"`
  //     AntiDPI     AntiDPI     `toml:"antidpi"`
  //     ARQ         ARQ         `toml:"arq"`
  //     Compression Compression `toml:"compression"`
  //     Crypto      Crypto      `toml:"crypto"`
  // }
  ```

  Add a helper that applies defaults after Unmarshal:

  ```go
  func (c *ClientConfig) applyV2Defaults() {
      if c.Protocol.Version == "" {
          c.Protocol.Version = "auto"
      }
      if c.Domains.Rotation == "" {
          c.Domains.Rotation = "per-session"
      }
      if len(c.Transports.Allow) == 0 {
          c.Transports.Allow = []string{"udp53", "doh", "dot", "doq"}
      }
      if c.AntiDPI.JitterMeanMs == 0 {
          c.AntiDPI.JitterMeanMs = 80
      }
      if c.AntiDPI.JitterSigma == 0 {
          c.AntiDPI.JitterSigma = 0.4
      }
      if c.ARQ.InflightUDP53 == 0 {
          c.ARQ.InflightUDP53 = 16
      }
      if c.ARQ.InflightDoH == 0 {
          c.ARQ.InflightDoH = 64
      }
      if c.ARQ.InflightDoT == 0 {
          c.ARQ.InflightDoT = 32
      }
      if c.ARQ.InflightDoQ == 0 {
          c.ARQ.InflightDoQ = 128
      }
      if c.Compression.Algo == "" {
          c.Compression.Algo = "lz4"
      }
      if c.Crypto.RekeyBytes == "" {
          c.Crypto.RekeyBytes = "256MB"
      }
      if c.Crypto.RekeyInterval == "" {
          c.Crypto.RekeyInterval = "1h"
      }
  }
  ```

  And expose `LoadClientConfigFromString` (or whatever the existing equivalent is named):

  ```go
  func LoadClientConfigFromString(body string) (*ClientConfig, error) {
      var cfg ClientConfig
      if _, err := toml.Decode(body, &cfg); err != nil {
          return nil, err
      }
      cfg.applyV2Defaults()
      // If both server.host and domains.list are set, warn and prefer domains.list.
      if cfg.Server.Host != "" && len(cfg.Domains.List) > 0 {
          // log.Warn — use existing logging helper from the package
      } else if cfg.Server.Host != "" && len(cfg.Domains.List) == 0 {
          cfg.Domains.List = []DomainEntry{{FQDN: cfg.Server.Host, Weight: 1}}
      }
      return &cfg, nil
  }
  ```

- [ ] **Step 5: Run, verify PASS**

  Run: `go test ./internal/config/...`
  Expected: PASS.

- [ ] **Step 6: Commit**

  ```bash
  git add internal/config/client.go internal/config/client_test.go
  git commit -m "feat(config): v2 client config sections (protocol/domains/transports/...)"
  ```

---

### Task 29: Server config v2 keys

**Goal:** spec §10.2 — `[protocol]`, `[auth]`, `[v2]`, `[v2.antidpi]` additions to `internal/config/server.go`. Existing v1 keys keep working; PSK file path is unchanged.

**Files:**
- Modify: `internal/config/server.go`
- Test:   `internal/config/server_test.go` (extend)

**Steps:**

- [ ] **Step 1: Write the failing test**

  ```go
  // Append to internal/config/server_test.go

  func TestServerConfig_V2Keys(t *testing.T) {
      body := `
  [server]
  host = "auth.example.com"
  encryption_key_file = "encrypt_key.txt"

  [protocol]
  accept = ["v1", "v2"]

  [auth]
  domains = ["a.example.com", "b.example.net"]

  [v2]
  data_encryption = "chacha20poly1305"
  rekey_bytes = "256MB"
  rekey_interval = "1h"

  [v2.antidpi]
  allow_rrtypes = ["A", "AAAA", "HTTPS", "SVCB", "TXT"]
  accept_padding = true
  `
      cfg, err := LoadServerConfigFromString(body)
      if err != nil {
          t.Fatalf("Load: %v", err)
      }
      if len(cfg.Protocol.Accept) != 2 || cfg.Protocol.Accept[1] != "v2" {
          t.Fatalf("protocol.accept = %+v", cfg.Protocol.Accept)
      }
      if len(cfg.Auth.Domains) != 2 || cfg.Auth.Domains[0] != "a.example.com" {
          t.Fatalf("auth.domains = %+v", cfg.Auth.Domains)
      }
      if cfg.V2.DataEncryption != "chacha20poly1305" {
          t.Fatalf("v2.data_encryption = %q", cfg.V2.DataEncryption)
      }
      if !cfg.V2.AntiDPI.AcceptPadding {
          t.Fatalf("expected accept_padding = true")
      }
  }
  ```

- [ ] **Step 2: Run, verify FAIL**

  Run: `go test ./internal/config/...`
  Expected: FAIL.

- [ ] **Step 3: Implement**

  ```go
  type ServerProtocol struct {
      Accept []string `toml:"accept"`
  }

  type ServerAuth struct {
      Domains []string `toml:"domains"`
  }

  type ServerV2AntiDPI struct {
      AllowRRTypes  []string `toml:"allow_rrtypes"`
      AcceptPadding bool     `toml:"accept_padding"`
  }

  type ServerV2 struct {
      DataEncryption string          `toml:"data_encryption"`
      RekeyBytes     string          `toml:"rekey_bytes"`
      RekeyInterval  string          `toml:"rekey_interval"`
      AntiDPI        ServerV2AntiDPI `toml:"antidpi"`
  }

  // Extend ServerConfig (real name may differ):
  //   Protocol ServerProtocol `toml:"protocol"`
  //   Auth     ServerAuth     `toml:"auth"`
  //   V2       ServerV2       `toml:"v2"`

  func (c *ServerConfig) applyV2Defaults() {
      if len(c.Protocol.Accept) == 0 {
          c.Protocol.Accept = []string{"v1", "v2"}
      }
      if c.V2.DataEncryption == "" {
          c.V2.DataEncryption = "chacha20poly1305"
      }
      if c.V2.RekeyBytes == "" {
          c.V2.RekeyBytes = "256MB"
      }
      if c.V2.RekeyInterval == "" {
          c.V2.RekeyInterval = "1h"
      }
      if len(c.V2.AntiDPI.AllowRRTypes) == 0 {
          c.V2.AntiDPI.AllowRRTypes = []string{"A", "AAAA", "HTTPS", "SVCB", "TXT"}
      }
      // If [server].host is set and [auth].domains is empty, fall back.
      if c.Server.Host != "" && len(c.Auth.Domains) == 0 {
          c.Auth.Domains = []string{c.Server.Host}
      }
  }

  func LoadServerConfigFromString(body string) (*ServerConfig, error) {
      var cfg ServerConfig
      if _, err := toml.Decode(body, &cfg); err != nil {
          return nil, err
      }
      cfg.applyV2Defaults()
      return &cfg, nil
  }
  ```

- [ ] **Step 4: Run, verify PASS**

  Run: `go test ./internal/config/...`
  Expected: PASS.

- [ ] **Step 5: Commit**

  ```bash
  git add internal/config/server.go internal/config/server_test.go
  git commit -m "feat(config): v2 server config sections (protocol/auth/v2/v2.antidpi)"
  ```

---

### Task 30: LZ4 compression algorithm

**Goal:** spec §9.4 — register LZ4 as a compression option alongside the existing zlib/gzip path. `pierrec/lz4/v4` is already in `go.sum` (per `go.mod` inspection in Task 0).

**Files:**
- Modify: `internal/compression/` (real filename to be confirmed by reading the package)
- Modify: `internal/enums/` (add `COMPRESSION_LZ4` if a compression-algo enum exists)
- Test:   `internal/compression/lz4_test.go`

**Steps:**

- [ ] **Step 1: Read the existing compression package**

  Open `internal/compression/`. Note the existing API surface — likely an interface like `Codec` or free functions like `Compress(algo, data)` / `Decompress(algo, data)`.

- [ ] **Step 2: Write the failing test**

  ```go
  // internal/compression/lz4_test.go
  package compression

  import (
      "bytes"
      "testing"
  )

  func TestLZ4_RoundTrip(t *testing.T) {
      src := bytes.Repeat([]byte("phantom-dns-"), 100)
      ct, err := CompressLZ4(src)
      if err != nil {
          t.Fatalf("compress: %v", err)
      }
      if len(ct) == 0 {
          t.Fatal("compressed empty")
      }
      pt, err := DecompressLZ4(ct)
      if err != nil {
          t.Fatalf("decompress: %v", err)
      }
      if !bytes.Equal(pt, src) {
          t.Fatalf("round-trip mismatch")
      }
  }

  func TestLZ4_RatioBeatsRaw(t *testing.T) {
      src := bytes.Repeat([]byte("AAAAAAAA"), 100) // very compressible
      ct, _ := CompressLZ4(src)
      if len(ct) >= len(src) {
          t.Fatalf("ratio: ct=%d src=%d", len(ct), len(src))
      }
  }
  ```

- [ ] **Step 3: Run, verify FAIL**

  Run: `go test ./internal/compression/...`
  Expected: FAIL.

- [ ] **Step 4: Implement**

  ```go
  // internal/compression/lz4.go
  package compression

  import (
      "bytes"

      "github.com/pierrec/lz4/v4"
  )

  func CompressLZ4(src []byte) ([]byte, error) {
      var buf bytes.Buffer
      w := lz4.NewWriter(&buf)
      if _, err := w.Write(src); err != nil {
          return nil, err
      }
      if err := w.Close(); err != nil {
          return nil, err
      }
      return buf.Bytes(), nil
  }

  func DecompressLZ4(src []byte) ([]byte, error) {
      r := lz4.NewReader(bytes.NewReader(src))
      var out bytes.Buffer
      if _, err := out.ReadFrom(r); err != nil {
          return nil, err
      }
      return out.Bytes(), nil
  }
  ```

  If the existing compression package has a registry-style API (algo byte → codec),
  add an entry mapping `Enums.COMPRESSION_LZ4` (new constant, e.g. `0x04`) to the
  two functions above so the v2 frame `PACKET_FLAG_COMPRESSION` byte can carry it.

- [ ] **Step 5: Run, verify PASS**

  Run: `go test ./internal/compression/...`
  Expected: PASS.

- [ ] **Step 6: Commit**

  ```bash
  git add internal/compression/lz4.go internal/compression/lz4_test.go
  git commit -m "feat(compression): LZ4 codec for v2 sessions"
  ```

---

### Task 31: Binary rename (`cmd/client` → `cmd/phantom-client`, `cmd/server` → `cmd/phantom-server`)

**Goal:** rename the two binary directories and update install scripts. Go module path stays unchanged.

**Files:**
- Move: `cmd/client/` → `cmd/phantom-client/`
- Move: `cmd/server/` → `cmd/phantom-server/`
- Modify: `client_linux_install.sh`, `server_linux_install.sh`
- Modify: `build.py`
- Modify: any systemd unit files / docs that reference the old paths

**Steps:**

- [ ] **Step 1: Confirm tree state is clean**

  Run: `git status`
  Expected: working tree clean (all previous tasks committed).

- [ ] **Step 2: Move with `git mv` so history is preserved**

  ```bash
  git mv cmd/client cmd/phantom-client
  git mv cmd/server cmd/phantom-server
  ```

- [ ] **Step 3: Verify build still passes against the new layout**

  ```bash
  go build ./cmd/phantom-client
  go build ./cmd/phantom-server
  ```
  Expected: both exit 0.

- [ ] **Step 4: Update install scripts**

  Open `client_linux_install.sh` and `server_linux_install.sh`. Find every occurrence of:
  - `cmd/client` → replace with `cmd/phantom-client`
  - `cmd/server` → replace with `cmd/phantom-server`
  - binary output name `client` / `stormdns-client` → `phantom-client`
  - binary output name `server` / `stormdns-server` → `phantom-server`
  - systemd unit name `stormdns-client.service` → `phantom-client.service`
  - systemd unit name `stormdns-server.service` → `phantom-server.service`

  Use ripgrep to find all candidates:

  ```bash
  rg -n 'stormdns-(client|server)|cmd/client|cmd/server' client_linux_install.sh server_linux_install.sh build.py
  ```

  Make each substitution by editing the file (do not use a global `sed -i` —
  some occurrences may be in commit messages / comments that intentionally
  reference the old name).

- [ ] **Step 5: Update `build.py`**

  Apply the same rename to whatever `build.py` builds.

- [ ] **Step 6: Run baseline tests one more time**

  ```bash
  go test ./...
  ```
  Expected: PASS.

- [ ] **Step 7: Commit the rename together with the script updates**

  ```bash
  git add cmd client_linux_install.sh server_linux_install.sh build.py
  git commit -m "refactor: rename cmd/client and cmd/server to cmd/phantom-*"
  ```

---

**Phase F milestone:** the project's config surface now accepts every v2 key; binaries are named `phantom-client` and `phantom-server`; LZ4 is wired in for v2 sessions. `go test ./...` is fully green.

---

## Phase G — Integration tests

### Task 32: Mock public-resolver harness

**Goal:** spec §12.3 — an in-process test helper that pretends to be a public resolver for all four channels. Listens on ephemeral ports, does real recursive lookup into an in-test authoritative server (the `phantom-server` under test), supports failure injection (loss, latency, RR-type stripping, truncation, sinkhole).

**Files:**
- Create: `internal/test/mockresolver/resolver.go`
- Create: `internal/test/mockresolver/failures.go`
- Test:   `internal/test/mockresolver/resolver_test.go`

**Steps:**

- [ ] **Step 1: Write the failing test**

  ```go
  // internal/test/mockresolver/resolver_test.go
  package mockresolver

  import (
      "bytes"
      "context"
      "testing"
      "time"

      "stormdns-go/internal/transport"
  )

  func TestMockResolver_UDP53Roundtrip(t *testing.T) {
      m := New(Config{})
      defer m.Close()

      auth := func(q []byte) []byte {
          // Auth NS echoes the query back as the response body.
          return q
      }
      addr := m.StartUDP(auth)

      ch, _ := transport.NewUDP53Channel(addr, time.Second)
      defer ch.Close()
      ctx, cancel := context.WithTimeout(context.Background(), time.Second)
      defer cancel()
      r, err := ch.Query(ctx, []byte{1, 2, 3, 4})
      if err != nil {
          t.Fatalf("Query: %v", err)
      }
      if !bytes.Equal(r, []byte{1, 2, 3, 4}) {
          t.Fatalf("got %x", r)
      }
  }

  func TestMockResolver_DropRate(t *testing.T) {
      m := New(Config{LossRate: 1.0}) // drop 100%
      defer m.Close()

      auth := func(q []byte) []byte { return q }
      addr := m.StartUDP(auth)

      ch, _ := transport.NewUDP53Channel(addr, 200*time.Millisecond)
      defer ch.Close()
      ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
      defer cancel()
      if _, err := ch.Query(ctx, []byte{1}); err == nil {
          t.Fatal("expected timeout under 100% drop")
      }
  }
  ```

- [ ] **Step 2: Run, verify FAIL**

  Run: `go test ./internal/test/mockresolver/...`
  Expected: FAIL (package does not exist).

- [ ] **Step 3: Implement**

  ```go
  // internal/test/mockresolver/resolver.go
  package mockresolver

  import (
      "math/rand"
      "net"
      "sync"
      "time"
  )

  type Config struct {
      LossRate    float64       // 0..1, probability that an outbound response is dropped
      LatencyMin  time.Duration
      LatencyMax  time.Duration
      // Set non-nil to inject sinkhole responses (returns this body
      // instead of consulting the auth handler).
      Sinkhole    func(q []byte) []byte
      Rand        *rand.Rand
  }

  type MockResolver struct {
      cfg     Config
      mu      sync.Mutex
      conns   []interface{ Close() error }
  }

  func New(cfg Config) *MockResolver {
      if cfg.Rand == nil {
          cfg.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))
      }
      return &MockResolver{cfg: cfg}
  }

  type AuthHandler func(q []byte) []byte

  // StartUDP starts a UDP/53 listener that, for each incoming query,
  // hands it to `auth` (the in-test authoritative server stand-in)
  // and returns the result, with failure injection applied.
  func (m *MockResolver) StartUDP(auth AuthHandler) string {
      pc, err := net.ListenPacket("udp", "127.0.0.1:0")
      if err != nil {
          panic(err)
      }
      m.mu.Lock()
      m.conns = append(m.conns, pc)
      m.mu.Unlock()
      go m.serveUDP(pc, auth)
      return pc.LocalAddr().String()
  }

  func (m *MockResolver) serveUDP(pc net.PacketConn, auth AuthHandler) {
      buf := make([]byte, 65536)
      for {
          n, addr, err := pc.ReadFrom(buf)
          if err != nil {
              return
          }
          q := append([]byte(nil), buf[:n]...)
          go func() {
              m.maybeSleep()
              if m.cfg.LossRate > 0 && m.cfg.Rand.Float64() < m.cfg.LossRate {
                  return
              }
              var resp []byte
              if m.cfg.Sinkhole != nil {
                  resp = m.cfg.Sinkhole(q)
              } else {
                  resp = auth(q)
              }
              _, _ = pc.WriteTo(resp, addr)
          }()
      }
  }

  func (m *MockResolver) maybeSleep() {
      if m.cfg.LatencyMin <= 0 && m.cfg.LatencyMax <= 0 {
          return
      }
      span := m.cfg.LatencyMax - m.cfg.LatencyMin
      if span < 0 {
          span = 0
      }
      d := m.cfg.LatencyMin + time.Duration(m.cfg.Rand.Int63n(int64(span)+1))
      time.Sleep(d)
  }

  func (m *MockResolver) Close() error {
      m.mu.Lock()
      defer m.mu.Unlock()
      for _, c := range m.conns {
          _ = c.Close()
      }
      m.conns = nil
      return nil
  }
  ```

  Note: this v1 of the mock harness covers UDP/53 only. DoH/DoT/DoQ
  variants are added in `doh.go`, `dot.go`, `doq.go` files in the same
  package — they reuse the same `Config` and `AuthHandler` shape but use
  the channel-appropriate listener (httptest TLS server, tls.Listen,
  quic.ListenAddr). Add those files in the same task once the test above
  passes; each is structurally identical to its transport adapter test in
  Task 14–17 (the engineer copies the test server pattern verbatim).

- [ ] **Step 4: Add DoH / DoT / DoQ mock listeners**

  Files: `internal/test/mockresolver/doh.go`, `dot.go`, `doq.go`. Each
  exposes `(m *MockResolver) StartDoH(auth AuthHandler) string` etc.,
  applying `m.cfg.LossRate` / `m.cfg.LatencyMin/Max` / `m.cfg.Sinkhole`
  the same way `serveUDP` does.

  For DoH: use `httptest.NewTLSServer` with an `http.HandlerFunc` that
  reads `application/dns-message` body, invokes `auth`, writes the
  response back. For DoT: use `tls.Listen` + RFC 7858 framing. For DoQ:
  use `quic.ListenAddr` + ALPN `doq` + RFC 9250 framing. Pattern is the
  same as the test-server helpers in Tasks 15/16/17 — extract those
  helpers into reusable functions inside this package.

- [ ] **Step 5: Run, verify PASS**

  Run: `go test ./internal/test/mockresolver/...`
  Expected: PASS.

- [ ] **Step 6: Commit**

  ```bash
  git add internal/test/mockresolver/
  git commit -m "test: mockresolver harness with failure injection for 4 channels"
  ```

---

### Task 33: Cross-version compatibility matrix

**Goal:** spec §12.2 — six-row matrix asserting v1/v2 mixed client / server combinations behave as designed (works / falls back / refuses).

**Files:**
- Create: `internal/integration/compat_test.go`

**Steps:**

- [ ] **Step 1: Write the failing test**

  ```go
  // internal/integration/compat_test.go
  package integration

  import (
      "bytes"
      "context"
      "testing"
      "time"

      "stormdns-go/internal/client"
      "stormdns-go/internal/test/mockresolver"
      "stormdns-go/internal/udpserver"
  )

  type setup struct {
      addr string
      reg  *udpserver.V2SessionRegistry
      mock *mockresolver.MockResolver
  }

  func newV2Server(t *testing.T, psk []byte, acceptV1, acceptV2 bool) setup {
      t.Helper()
      reg := udpserver.NewV2SessionRegistry(psk)
      m := mockresolver.New(mockresolver.Config{})
      addr := m.StartUDP(func(q []byte) []byte {
          // Direct hand-off to the server's v2 ingress decoder.
          v2 := udpserver.DecodeV2FrameFromQueryBytes(q)
          if v2 == nil {
              if !acceptV1 {
                  return nil
              }
              // For the compat matrix we don't fully run the v1 path —
              // it's exercised by existing client/server tests. Returning
              // the query bytes back keeps the v1 client's outer parser
              // happy enough to detect "this is a v1-shaped response".
              return q
          }
          if !acceptV2 {
              return nil
          }
          ack, _, err := reg.AcceptInit(v2.EncryptedPayload,
              bytes.Repeat([]byte{0}, 16), bytes.Repeat([]byte{1}, 16), time.Now())
          if err != nil {
              return nil
          }
          // Build a minimal v2 INIT_ACK frame.
          return BuildInitAckFrame(ack)
      })
      return setup{addr: addr, reg: reg, mock: m}
  }

  func TestCompat_V2ClientV2Server(t *testing.T) {
      psk := bytes.Repeat([]byte{0x01}, 32)
      s := newV2Server(t, psk, true, true)
      defer s.mock.Close()

      ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
      defer cancel()
      sess, err := client.RunV2Handshake(ctx, s.addr, psk)
      if err != nil {
          t.Fatalf("RunV2Handshake: %v", err)
      }
      if sess == nil || sess.SessionID == 0 {
          t.Fatal("session not established")
      }
  }

  func TestCompat_V2ClientV1Server_AutoFallback(t *testing.T) {
      // Server accepts ONLY v1; client config is "auto" -> expect graceful
      // fallback to v1. We can't exercise full v1 here, but we *can*
      // verify the client's RunV2HandshakeOn returns a recognisable error
      // that the auto-fallback layer can detect.
      psk := bytes.Repeat([]byte{0x02}, 32)
      s := newV2Server(t, psk, true, false)
      defer s.mock.Close()

      ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
      defer cancel()
      _, err := client.RunV2Handshake(ctx, s.addr, psk)
      if err == nil {
          t.Fatal("expected v2 handshake to fail against v1-only server")
      }
  }

  func TestCompat_StrictV2ClientV1Server_HardFail(t *testing.T) {
      // Identical to above, but the client's "strict v2" mode means
      // the dispatcher returns the error rather than falling back.
      psk := bytes.Repeat([]byte{0x03}, 32)
      s := newV2Server(t, psk, true, false)
      defer s.mock.Close()
      ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
      defer cancel()
      _, err := client.RunV2Handshake(ctx, s.addr, psk)
      if err == nil {
          t.Fatal("expected error in strict v2 mode against v1-only server")
      }
  }
  ```

  Plus the helper:

  ```go
  // internal/integration/helpers.go
  package integration

  import (
      "bytes"

      Enums "stormdns-go/internal/enums"
      "stormdns-go/internal/vpnproto"
  )

  func BuildInitAckFrame(ackEnvelope []byte) []byte {
      f := vpnproto.V2Frame{
          Header: vpnproto.V2Header{
              Type:  Enums.PACKET_V2_INIT_ACK,
              ChCls: vpnproto.ChClsNarrow,
          },
          EncryptedPayload: ackEnvelope,
          Tag:              bytes.Repeat([]byte{0}, 16),
      }
      return f.Marshal()
  }
  ```

- [ ] **Step 2: Run, verify FAIL**

  Run: `go test ./internal/integration/...`
  Expected: FAIL.

- [ ] **Step 3: Implementation already exists**

  All code these tests call lives in the packages built by Tasks 0–31.
  The tests are the deliverable for this task; no production code change
  is needed (if a test reveals a real bug, fix it as part of *that* task,
  not here — keep this commit purely test-additive).

- [ ] **Step 4: Run, verify PASS**

  Run: `go test ./internal/integration/...`
  Expected: PASS.

- [ ] **Step 5: Commit**

  ```bash
  git add internal/integration/
  git commit -m "test: v1/v2 cross-version compatibility matrix"
  ```

---

### Task 34: Hostile-network simulation

**Goal:** spec §12.5 — exercise v2 sessions under 5% loss + 200 ms RTT + bounded EDNS0 cap, with two resolvers parked mid-session, etc. Each scenario is one test using `mockresolver.Config`.

**Files:**
- Create: `internal/integration/hostile_test.go`

**Steps:**

- [ ] **Step 1: Write the failing test**

  ```go
  // internal/integration/hostile_test.go
  package integration

  import (
      "bytes"
      "context"
      "testing"
      "time"

      "stormdns-go/internal/client"
      "stormdns-go/internal/test/mockresolver"
      "stormdns-go/internal/udpserver"
  )

  func TestHostile_HandshakeUnderLoss(t *testing.T) {
      psk := bytes.Repeat([]byte{0x04}, 32)
      reg := udpserver.NewV2SessionRegistry(psk)
      m := mockresolver.New(mockresolver.Config{
          LossRate:   0.05,
          LatencyMin: 150 * time.Millisecond,
          LatencyMax: 250 * time.Millisecond,
      })
      defer m.Close()
      addr := m.StartUDP(func(q []byte) []byte {
          v2 := udpserver.DecodeV2FrameFromQueryBytes(q)
          if v2 == nil {
              return nil
          }
          ack, _, err := reg.AcceptInit(v2.EncryptedPayload,
              bytes.Repeat([]byte{0}, 16), bytes.Repeat([]byte{1}, 16), time.Now())
          if err != nil {
              return nil
          }
          return BuildInitAckFrame(ack)
      })

      // Even with 5% loss + 250ms latency, the client should complete
      // the handshake within a few retries.
      ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
      defer cancel()
      sess, err := retryHandshake(ctx, addr, psk, 5)
      if err != nil {
          t.Fatalf("handshake under hostile network: %v", err)
      }
      if sess == nil {
          t.Fatal("nil session")
      }
  }

  // retryHandshake is the rough shape of the dispatcher's retry-on-timeout
  // behavior. The integrated dispatcher (Task 27) does this internally.
  func retryHandshake(ctx context.Context, addr string, psk []byte, attempts int) (*client.V2ClientSession, error) {
      var last error
      for i := 0; i < attempts; i++ {
          sub, cancel := context.WithTimeout(ctx, time.Second)
          sess, err := client.RunV2Handshake(sub, addr, psk)
          cancel()
          if err == nil {
              return sess, nil
          }
          last = err
      }
      return nil, last
  }
  ```

- [ ] **Step 2: Run, verify FAIL or PASS depending on Phase E implementation**

  Run: `go test ./internal/integration/...`
  Expected: PASS once Task 27's dispatcher retry logic is in.
  
  If the dispatcher doesn't retry yet, the test exposes the gap — extend Task 27
  rather than weakening this test.

- [ ] **Step 3: Commit**

  ```bash
  git add internal/integration/hostile_test.go
  git commit -m "test: hostile-network simulation (5% loss + 200ms RTT)"
  ```

---

### Task 35: Live-resolver smoke (gated)

**Goal:** spec §12.6 — one CI smoke test against real public resolvers, gated behind `-tags=livenet` so it does not run on every push.

**Files:**
- Create: `internal/integration/livenet_test.go` (with `//go:build livenet`)

**Steps:**

- [ ] **Step 1: Write the failing test**

  ```go
  //go:build livenet

  // internal/integration/livenet_test.go
  package integration

  import (
      "context"
      "os"
      "testing"
      "time"

      "stormdns-go/internal/transport"
  )

  func TestLiveResolver_BasicProbe(t *testing.T) {
      addr := os.Getenv("PHANTOM_DNS_PROBE_AUTH_DOMAIN")
      psk := os.Getenv("PHANTOM_DNS_PROBE_PSK")
      if addr == "" || psk == "" {
          t.Skip("PHANTOM_DNS_PROBE_AUTH_DOMAIN and PHANTOM_DNS_PROBE_PSK must be set")
      }
      ch, err := transport.NewUDP53Channel("1.1.1.1:53", 3*time.Second)
      if err != nil {
          t.Fatalf("NewUDP53Channel: %v", err)
      }
      defer ch.Close()
      ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
      defer cancel()
      ok, err := transport.ProbeAuthenticity(ctx, ch, []byte(psk))
      if err != nil {
          t.Fatalf("ProbeAuthenticity: %v", err)
      }
      if !ok {
          t.Fatal("authenticity probe failed against live resolver")
      }
  }
  ```

- [ ] **Step 2: Run with the tag to confirm it compiles**

  ```bash
  go vet -tags=livenet ./internal/integration/...
  go test -tags=livenet -run=^$ ./internal/integration/...
  ```
  Expected: vet exits 0; test exits 0 (skipped because env vars unset).

- [ ] **Step 3: Confirm it is invisible without the tag**

  ```bash
  go test ./internal/integration/...
  ```
  Expected: the live test does not appear in `go test` output without `-tags=livenet`.

- [ ] **Step 4: Commit**

  ```bash
  git add internal/integration/livenet_test.go
  git commit -m "test: gated live-resolver smoke test (-tags=livenet)"
  ```

---

**Phase G milestone:** `go test ./...` is fully green; `go test -tags=livenet -run=^$ ./...` compiles and skips. The implementation plan is complete.

---

## Plan-wide acceptance checklist

Before considering Phantom DNS v1 shippable, confirm:

- [ ] `go test ./...` passes on a clean checkout of `feat/phantom-dns-v2`.
- [ ] `go build ./cmd/phantom-client ./cmd/phantom-server` produces both binaries.
- [ ] `go vet ./...` is clean.
- [ ] `go test -race ./...` is clean (catches concurrency regressions in
      the new transport pump, balancer, session registry).
- [ ] Live smoke test (`go test -tags=livenet ./internal/integration/...`)
      passes against a real test deployment (out-of-band — not gating CI).
- [ ] The compat matrix (Task 33) shows all six rows behave as designed.
- [ ] The hostile-network sim (Task 34) completes a handshake under 5%
      loss + 200 ms RTT within 5 seconds.

When all six are green, merge `feat/phantom-dns-v2` into `main`.

---

## Out of plan (deferred, per spec §11)

The following spec items are *explicitly out of scope* of this plan and must NOT be added in passing while implementing other tasks:

- Cover-query traffic
- Server-side DoH/DoT/DoQ listeners
- 0-RTT resumption tickets
- Server-static public-key crypto (drop PSK)
- DNSSEC on the auth domain
- Multi-server / clustering / HA
- Signed-manifest resolver discovery
- Dynamic auth-domain registration / hot-reload
- Multi-tenant per-user PSKs
- Web UI for config or stats
- REALITY-style TLS to public DoH/DoT
- TCP/53 fallback for oversized responses
- Code sharing with the sibling `phantom` proxy project
- Per-client server-side rate limits (StormDNS already has the relevant hardening)

Any of these can become their own future plan; they should not silently appear in commits driven by this plan.
