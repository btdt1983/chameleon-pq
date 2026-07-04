# Chameleon-PQ

*🇬🇧 English | [🇩🇪 Deutsch](README.de.md)*

Experimental hybrid post-quantum VPN written in Rust. Combines ML-KEM-768 (KEM)
with X25519 for key agreement and a hybrid Ed25519 + ML-DSA-65 (FIPS 204)
signature for peer authentication, over UDP with a TUN interface on
Linux/macOS/Windows.

## ⚠️ Security Status: EXPERIMENTAL

**This code has not been independently audited and should not be used to
protect real traffic.** A self-built cryptographic protocol is a red flag
until someone qualified has reviewed it. Use this as a learning project,
an architecture reference, or a starting point for a properly audited
system — not as a production VPN.

Known scope limits:
- No external security audit has been performed — this remains the single
  most important caveat for any self-built cryptographic protocol
- The **data path**, the **handshake envelope**, AND now **packet timing** are
  all obfuscated — every datagram looks like uniform random bytes, and optional
  traffic shaping (`[traffic]`, on by default in **Adaptive** mode; **CBR**
  available for full constant-rate) sends on a fixed schedule with cover packets
  filling idle slots, so bursts and idle-vs-active dissolve into a steady
  stream. Residual (documented, not claimed as *full* resistance): the tunnel's
  existence and total duration are inherent to a fixed site-to-site link, the
  **initial** handshake burst is pre-pacer, and the handshake obfuscation key is
  pubkey-derived by default (`[obfuscation].psk_hex` closes that). Shaping has a
  real bandwidth/latency cost — the configured rate is both the floor (in CBR)
  and the
  throughput ceiling
- ML-DSA is integrated for authentication, but the key exchange still pairs
  ML-KEM-768 with X25519 (no second PQ KEM)

## What works

- Hybrid post-quantum handshake (ML-KEM-768 + X25519, both ephemeral → PFS)
- Mutual authentication: 3-message (2-RTT) handshake where both peers sign
  the transcript; the responder withholds trust until the initiator's
  Confirm verifies
- Return-routability cookie (WireGuard-style, stateless): the responder does no
  expensive ML-KEM/DH/ML-DSA work until the initiator echoes a cookie tied to its
  source address, so a spoofed/unverified source can't trigger the expensive
  handshake or a large reflected response. The CookieChallenge is a full-size
  obfuscated message, so it blends with the rest of the handshake
- Hybrid Ed25519 + ML-DSA-65 (FIPS 204) transcript signing for peer
  authentication (pre-shared identities) — the signature holds as long as
  *either* scheme is unbroken; falls back to Ed25519-only when no ML-DSA
  keys are configured
- Pluggable data-path AEAD: ChaCha20-Poly1305 (via `ring`, constant-time,
  the universal default) and AEGIS-256X2 (CAESAR winner, faster on CPUs
  with AES hardware), chosen by hardware-aware negotiation with the choice
  bound in the transcript against downgrade
- Obfuscated data path (QUIC-style header protection): every data datagram
  looks like uniform random bytes — no static type byte, no visible session_id,
  no visible monotonic counter. The header is masked with a keystream derived
  (via HMAC-SHA256) from a sample of the AEAD tag, and the real frame type is
  carried *inside* the encrypted payload, so keepalives are indistinguishable
  from data. Configurable length padding (off / bucketed / full) hides packet
  sizes. Header integrity still comes from the AEAD (the recovered header is the
  associated data), exactly as before — the mask is confidentiality-only
- Obfuscated handshake envelope (static-key, `hsobf.rs`): the handshake message
  is wrapped in a ChaCha20-Poly1305 layer keyed from the pre-shared identities
  (or an optional `psk_hex`) and split into size-jittered fragments with a
  masked header — the handshake burst no longer shows a constant type byte or a
  fixed fragment structure. The real handshake crypto is unchanged; this is a
  pure outer obfuscation layer (no forward secrecy on the obf layer)
- Timing / cover-traffic shaping (`pacer.rs`, `[traffic]`, on by default in
  Adaptive mode): packets go out on a fixed schedule and empty slots are filled
  with cover (dummy) packets the receiver silently discards, so burst and
  idle-vs-active patterns are hidden. Cover packets are ordinary obf datagrams
  with an encrypted `Padding` inner type, constant-size under `Full` padding, so
  they are wire-indistinguishable from real data. Adaptive (default) paces during
  activity + cooldown and goes quiet when idle (no bandwidth at rest); **CBR**
  streams constantly for the strongest hiding at a constant cost. No wire/proto
  change — a peer that predates this safely drops cover packets
- Per-direction keys; 2048-entry sliding-window replay protection
- Rekey with anti-storm gate, retry on packet loss, current+previous session
  overlap so in-flight traffic survives the swap
- Fragment reassembly with DoS-resistant pruning of stale partials
- Keepalive / dead-peer detection
- Cross-platform TUN: Linux, macOS, Windows (Wintun)
- Performance (no wire change): the data-path AEAD is auto-selected at startup
  by a quick benchmark (AEGIS-256X2 where it's fastest, ChaCha20 where AEGIS
  would fall back to slow software AES); UDP I/O is batched with GSO on send /
  GRO on receive (via `quinn-udp`, per-packet fallback on old kernels /
  non-Linux) — a microbench lifts the send path from ~0.18 to ~9.6 Mpps; and the
  seal/open runs in parallel across all cores (rayon, `[engine].workers`),
  measured at ~4.5× (seal) / ~13× (open) on a 12-thread box. Note: the parallel
  path helps the **fast mode** (`traffic.enabled = false`); with timing-shaping
  on (default) the configured rate caps throughput, so speed vs.
  timing-obfuscation are opposed dimensions you choose between
- 83 tests covering handshake (incl. mutual-auth + fragmentation), hybrid
  ML-DSA auth (and that a wrong PQ key fails even when Ed25519 matches),
  AEAD negotiation and AEGIS sessions, associated-data header binding, data
  path, replay (incl. wide reordering), MITM (both directions), rekey,
  prune behaviour, the obfuscated data path (round-trip on both ciphers,
  tamper rejection, trial-demux across current+previous sessions, length
  padding, empty keepalives, cleartext-handshake fall-through), and the
  obfuscated handshake envelope (symmetric key derivation, wrap-then-fragment
  round-trip with jitter, full mutual handshake, wrong-key/noise rejection,
  reassembler cap + prune, and that a 0.1.x cleartext frame is not accepted),
  timing/cover traffic (the pure pacer scheduler's CBR/Adaptive/cooldown logic,
  that a cover packet round-trips as `Padding`, and that cover and data are
  equal-length + header-distinct under `Full` padding), parallel crypto
  (parallel-sealed packets all decrypt with unique counters, and
  `decrypt_batch_par` classifies data vs noise), role-separated handshake
  signatures (a reflected responder signature is rejected as a Confirm, even
  under a shared identity key), the bounded UDP handshake (mutual completion
  over real sockets + a clean timeout when no responder answers), identity
  binding (symmetric, peer-dependent), low-order/all-zero X25519 rejection, and
  the return-routability cookie (deterministic + input-dependent, and a
  cookie-less Init is answered with a CookieChallenge, not an expensive Response)
- Fuzzing of the attacker-facing parsers (frame + handshake decode, the data-path
  and handshake obfuscation parsers, the reassembler, and the inbound
  decrypt path): a stable random + edge-case harness runs with `cargo test`
  (`tests/fuzz_parsers.rs`), plus coverage-guided `cargo-fuzz` targets in `fuzz/`
  (nightly; a weekly CI job). ~18 M executions across the targets found no panic

## Build

Requires a recent Rust toolchain (1.80+; install via
[rustup](https://rustup.rs/)).

```bash
cargo build --release
cargo test
```

Or install from crates.io:

```bash
cargo install chameleon-pq
```

## Quick start

```bash
# 1. Generate keypairs on both nodes
./target/release/chameleon-pq keygen

# 2. Copy config.example.toml to config.toml, fill in your seed and the
#    peer's public key (exchange these out-of-band)

# 3. Validate
./target/release/chameleon-pq --config config.toml check

# 4. Run as server (needs CAP_NET_ADMIN on Linux for TUN)
sudo ./target/release/chameleon-pq --config config.toml server

# 5. Run as client
sudo ./target/release/chameleon-pq --config config.toml client \
    --server 1.2.3.4:51820
```

On Windows you also need `wintun.dll` from <https://www.wintun.net> next
to the binary.

## Architecture

- `crypto.rs` — `Authenticator` trait with `Ed25519Auth` (via `ring`) and
  `MlDsaAuth` (ML-DSA-65 via `pqcrypto-mldsa`), combined by `HybridAuth`
  (all legs must verify); transcript hash, HKDF
- `aead.rs` — pluggable data-path AEAD: `ChaCha20-Poly1305` and
  `AEGIS-256X2` behind a trait (with associated-data support); a startup
  micro-benchmark auto-selects the faster cipher for the machine, and the
  choice is downgrade-safe (bound in the handshake transcript)
- `session.rs` — per-direction AEAD keys, nonce management, header binding
  via AAD, sliding-window replay, `SessionManager` with rekey
- `tunnel.rs` — 8192-byte handshake (single KEM slot, noise-padded; sized
  for the hybrid PQ signature), fragmentation/reassembly, state machine with
  transcript signing
- `frame.rs` — MTU-safe, magic-free frame (<1280 B) for the handshake
  envelope and the legacy (obfuscation-off) data path
- `obf.rs` — data-path obfuscation: QUIC-style header protection (13-byte
  header masked with a keystream derived from an AEAD-tag sample), inner
  type framing (real frame type encrypted inside the payload), and
  configurable length padding
- `hsobf.rs` — handshake-envelope obfuscation: a static key (derived from the
  pre-shared Ed25519 pubkeys, or an optional PSK) wraps the whole handshake
  message in ChaCha20-Poly1305 and splits it into size-jittered fragments with
  a masked header (`derive_hs_obf_key` / `seal_and_fragment` / `unmask_fragment`
  / `open`)
- `pacer.rs` — pure (tokio-free) constant-rate scheduler for timing/cover-traffic
  shaping: `Pacer::next_emit` decides per slot whether to send a real packet,
  a cover packet, or nothing (`ShapeMode` CBR/Adaptive); the async loop in
  `main.rs` drives it
- `engine.rs` — CPU encryption engine: batch seal/open, run **in parallel
  across cores** via rayon (`encrypt_batch_par` / `decrypt_batch_par`, bridged
  from the async loops with `spawn_blocking`); constant-time, low-latency, no GPU
  path (see DESIGN.md §11–§12 for why)
- `net.rs` — UDP loops; clear in/out API points to the TUN layer
- `udp.rs` — batched UDP I/O (GSO on send, GRO on receive) via `quinn-udp`,
  with a per-packet fallback on older kernels / non-Linux; the only module that
  touches the dependency (`batch_send` / `batch_recv` / `group_equal_sized`)
- `rekey.rs` — rekey driver that solves the shared-socket problem
  (inbound loop is the sole socket reader; rekey driver receives via channel)
- `tun_iface.rs` — cross-platform TUN with mock for tests
- `config.rs` — TOML loader, CLI

## License

Apache 2.0 — see [LICENSE](LICENSE).
