# Chameleon-PQ

*🇬🇧 English | [🇩🇪 Deutsch](README.de.md)*

Experimental hybrid post-quantum VPN written in Rust. Combines Kyber768 (KEM)
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
- The **data path** is now obfuscated (QUIC-style header protection + length
  padding — no visible type byte, session id or counter, and sizes are hidden),
  but the **handshake envelope** is still sent as a cleartext frame and timing
  masking / cover traffic are not implemented, so full traffic-analysis
  resistance is not yet claimed
- ML-DSA is integrated for authentication, but the key exchange still pairs
  Kyber768 with X25519 (no second PQ KEM)

## What works

- Hybrid post-quantum handshake (Kyber768 + X25519, both ephemeral → PFS)
- Mutual authentication: 3-message (2-RTT) handshake where both peers sign
  the transcript; the responder withholds trust until the initiator's
  Confirm verifies
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
- Per-direction keys; 2048-entry sliding-window replay protection
- Rekey with anti-storm gate, retry on packet loss, current+previous session
  overlap so in-flight traffic survives the swap
- Fragment reassembly with DoS-resistant pruning of stale partials
- Keepalive / dead-peer detection
- Cross-platform TUN: Linux, macOS, Windows (Wintun)
- 41 tests covering handshake (incl. mutual-auth + fragmentation), hybrid
  ML-DSA auth (and that a wrong PQ key fails even when Ed25519 matches),
  AEAD negotiation and AEGIS sessions, associated-data header binding, data
  path, replay (incl. wide reordering), MITM (both directions), rekey,
  prune behaviour, and the obfuscated data path (round-trip on both ciphers,
  tamper rejection, trial-demux across current+previous sessions, length
  padding, empty keepalives, and that a cleartext handshake frame is not
  swallowed)

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
  `AEGIS-256X2` behind a trait (now with associated-data support), CPU AES
  detection and downgrade-safe negotiation
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
- `engine.rs` — CPU encryption engine (constant-time, low-latency; no GPU
  path — see DESIGN.md §11–§12 for why)
- `net.rs` — UDP loops; clear in/out API points to the TUN layer
- `rekey.rs` — rekey driver that solves the shared-socket problem
  (inbound loop is the sole socket reader; rekey driver receives via channel)
- `tun_iface.rs` — cross-platform TUN with mock for tests
- `config.rs` — TOML loader, CLI

## License

Apache 2.0 — see [LICENSE](LICENSE).
