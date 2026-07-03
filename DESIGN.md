# Design & Rationale — Chameleon-PQ

*🇬🇧 English | [🇩🇪 Deutsch](DESIGN.de.md)*

This document explains *why* Chameleon-PQ is built the way it is. Every
significant choice is recorded with its reasoning and its trade-offs, so
that reviewers, contributors, and future-me can understand the decisions
rather than guess at them.

> **Status reminder:** this is experimental, unaudited software. The
> reasoning below explains the intent of the design; it is not a claim
> that the implementation is proven secure. See `SECURITY.md`.

---

## 1. Threat model & scope

Chameleon-PQ targets **site-to-site tunnels between known endpoints** —
infrastructure-to-infrastructure traffic where the peers are configured
in advance with pre-shared identities. It is *not* designed as a
consumer anonymity service (à la commercial VPN providers).

Adversaries considered:
- **Passive network observer** — can read all ciphertext. Defended by
  AEAD encryption of the data path.
- **Active man-in-the-middle** — can inject, drop, reorder, replay.
  Defended by authenticated handshake + replay protection.
- **Future quantum adversary ("harvest now, decrypt later")** — records
  traffic today to decrypt once a quantum computer exists. This is the
  central reason for the post-quantum key agreement: site-to-site traffic
  can remain sensitive for years, so the key exchange must resist a
  quantum attack made *later* against traffic captured *now*.

Explicitly **out of scope** for now: traffic-analysis resistance beyond
fixed-length padded handshakes, and protection against a compromised
endpoint.

---

## 2. Hybrid post-quantum key agreement

**Decision:** combine X25519 (classical ECDH) with Kyber768 (post-quantum
KEM), both ephemeral, and derive the session key from *both* shared
secrets concatenated through HKDF.

**Why hybrid and not pure post-quantum:** post-quantum algorithms are
young. Their mathematical assumptions have far fewer years of scrutiny
than classical ECDH. By combining the two, the session stays secure as
long as *either* leg holds. A break in Kyber alone does not break the
session (X25519 still protects it); a quantum computer that breaks X25519
does not break the session (Kyber still protects it). You are only
vulnerable if both fall at once. This is strictly safer than betting on
one alone.

**Why concatenation and not XOR of the secrets:** XOR would destroy the
hybrid guarantee — if one secret were known, it could cancel out. Feeding
both into HKDF as concatenated input keying material preserves the
"secure if either holds" property.

**Why both legs are ephemeral:** forward secrecy. Ephemeral keys are
discarded after the handshake, so a later compromise of any long-term
key cannot decrypt previously recorded sessions.

---

## 3. Peer authentication (hybrid Ed25519 + ML-DSA-65)

**Decision:** authenticate the handshake by signing the transcript hash
with a *hybrid* scheme — Ed25519 **and** ML-DSA-65 (FIPS 204) — using
pre-shared peer public keys (exchanged out-of-band). Both signing schemes
sit behind an `Authenticator` trait and are combined by `HybridAuth`, which
requires **every** leg to verify. If no ML-DSA keys are configured the
system falls back to Ed25519-only (classical) and says so loudly in the log.

**Why pre-shared identities:** in a site-to-site setting the peers are
known in advance. Pre-sharing public keys means an unknown signer is
rejected immediately — there is no trust-on-first-use window for a MITM
to exploit.

**Why keep Ed25519 as a leg at all:** authentication only needs to hold
*during* the handshake — an attacker must break it in real time to
impersonate a peer. The "harvest now, decrypt later" threat does **not**
apply to signatures (a forged signature next year cannot retroactively
break today's session), so the urgency for PQ signatures is genuinely lower
than for the PQ key exchange. Ed25519 via `ring` is fast, small, and
constant-time, and it is decades-scrutinised. We keep it as one leg rather
than dropping it.

**Why also ML-DSA, and why hybrid:** the same "young assumptions" argument
from §2 applies to signatures — ML-DSA's lattice assumptions have far less
scrutiny than Ed25519's discrete log. By signing with *both* and requiring
both to verify (`HybridAuth`), authentication holds as long as *either*
scheme is unbroken: a break in ML-DSA alone does not let an attacker
impersonate a peer (Ed25519 still gates), and a quantum computer that
breaks Ed25519 does not either (ML-DSA still gates). The `Authenticator`
trait made this cheap — `MlDsaAuth` is one struct implementing the trait,
wrapped alongside `Ed25519Auth` in `HybridAuth`; the state machine did not
change. (See §9 for the message-size consequence, which is now realised.)

**Why ML-DSA-65 specifically:** it targets the ~192-bit (NIST level 3)
security category, the common middle choice, matching the level of Kyber768
in the KEM. Keys and signatures are large (public key ~1952 B, signature
~3309 B), which is exactly why the handshake had to grow (§9). ML-DSA keys
are not derivable from a short seed, so `keygen` emits a full keypair and
the secret key is stored in the config (hex); the peer's public key is
pre-shared out-of-band like the Ed25519 identity.

**Mutual authentication (implemented):** the handshake is a 3-message,
2-RTT exchange — Init, Response, Confirm. The responder signs the
transcript in the Response (authenticating itself to the initiator), and
the initiator signs the same transcript in the Confirm (authenticating
itself to the responder). Crucially, the responder does **not** trust the
session until it has verified the Confirm: it holds the derived session in
a `SentResponse` state and only transitions to `Established` after the
initiator's signature checks out. This closes the earlier one-way gap —
both peers now prove their identity, and an attacker who cannot produce
the expected initiator signature is rejected at the Confirm step.

---

## 4. Data-path encryption (pluggable AEAD: ChaCha20-Poly1305 + AEGIS-256X2)

**Decision:** the data path encrypts through an `Aead` trait with two
implementations — ChaCha20-Poly1305 (via `ring`) and AEGIS-256X2 (via the
`aegis` crate). The cipher is chosen per session by hardware-aware
negotiation, with ChaCha20 as the universal default and fallback.

**Why ChaCha20 is the default and fallback:** ChaCha20-Poly1305 is
constant-time on *all* hardware, because it uses only add/rotate/XOR
operations with no data-dependent table lookups. It is provided by `ring`,
among the most heavily audited crypto libraries available. It is the safe
floor that works correctly and securely on any CPU.

**Why AEGIS-256X2 is offered as the fast option:** AEGIS won the
performance category of the CAESAR competition, is fully open, and has an
IETF draft for inclusion in TLS 1.3. It uses the AES round function (the
hardware-accelerated primitive) in a stream-cipher construction, which is
both faster and a stronger AEAD than AES-GCM on CPUs with AES instructions
— and faster than ChaCha20 there too. On modern server and desktop
hardware (which almost always has AES acceleration) it is the better
choice on speed and on AEAD robustness.

**Why it is negotiated, not hard-wired:** AEGIS's advantage is conditional
on AES hardware. Without it, AEGIS falls back to software AES, which is
slower *and* vulnerable to cache-timing attacks — exactly what ChaCha20
avoids. So the choice is made by capability detection, not assumption:

- At session setup each side computes `AeadAlgo::preferred()`, which
  returns AEGIS only if the CPU reports AES support (AES-NI on x86, the
  AES extension on aarch64), otherwise ChaCha20.
- The initiator advertises its preference in the Init; the responder
  negotiates with `negotiate(local, peer)` — AEGIS only if *both* sides
  prefer it, ChaCha20 otherwise. A fast server therefore interoperates
  safely with a constrained client without anyone running software AES.
- The negotiated algorithm id is **bound into the handshake transcript**,
  so a downgrade attempt (forcing the weaker cipher) breaks the transcript
  hash and fails the signature/MAC verification. This is the §10 transcript
  binding doing exactly the job it was built for.

**Nonce widths differ and are handled per cipher:** ChaCha20 uses a 96-bit
nonce, AEGIS-256X2 a 256-bit nonce. The session builds the nonce at the
width the chosen cipher requires (salt ‖ counter, zero-padded), so the
monotonic-counter uniqueness guarantee (§5) holds for both.

**A note on "post-quantum" and the cipher:** AEGIS does not add quantum
resistance. Symmetric ciphers with 256-bit keys (both ChaCha20-Poly1305
and AEGIS-256) already retain ~128-bit strength against Grover's
algorithm. The post-quantum protection lives entirely in the Kyber key
exchange (§2), independent of which AEAD is chosen. AEGIS buys speed and a
stronger AEAD, not extra quantum safety.

---

## 4a. Throughput: auto-selected cipher, batched I/O, multi-core crypto

None of the following changes the wire format or the crypto — they only
remove the three ceilings that sit between the negotiated AEAD and real
line rate. Each is measured, not assumed.

1. **Cipher auto-select is a benchmark, not just a feature flag.** AES *NI*
   capability detection (§4) is necessary but not sufficient: on a CPU with
   AES-NI but narrow SIMD (e.g. Westmere, AES-NI without AVX) the `aegis`
   crate's fast path does not kick in and AEGIS runs an order of magnitude
   *slower* than ChaCha20. So `preferred()` runs a one-shot startup
   micro-benchmark (seal a fixed buffer many times under each cipher) and
   picks whichever is actually faster on this silicon, defaulting to
   ChaCha20 when there is no AES-NI. The negotiation and transcript binding
   above are unchanged — the benchmark only decides this node's
   *preference*.
2. **Batched UDP I/O (GSO/GRO).** The per-packet `sendto`/`recvmmsg` syscall
   is the first wall: a microbench tops out near ~0.18 Mpps sending one
   datagram at a time. `udp.rs` wraps `quinn-udp` to segment many datagrams
   into one syscall with UDP GSO on send and coalesce with GRO on receive
   (per-packet fallback on old kernels / non-Linux), lifting the send path to
   ~9.6 Mpps. No wire change: GSO segments are ordinary datagrams on the wire.
3. **Multi-core seal/open.** With the syscall wall gone the next ceiling is
   the single-core AEAD (~2 Gbit/s obf seal/open) — the crypto ran in one
   outbound and one inbound task. `engine.rs` now seals/opens a GSO/GRO batch
   **in parallel across all cores** with rayon (`encrypt_batch_par` /
   `decrypt_batch_par`), bridged from the async loops with `spawn_blocking`
   (one hand-off per batch, amortised over 64–256 packets; a small-batch
   threshold keeps light traffic on the sequential inline path). This is
   safe with no change to the crypto: the tx counter is an `AtomicU64`
   (`fetch_add` → a unique nonce per packet across threads, §5), `decrypt`
   opens **lock-free** and only the cheap check/commit take the per-session
   replay `Mutex`, and the 2048-entry window (§6) absorbs any
   parallel-completion reorder. `Session`/`SessionManager` are `Send + Sync`,
   so `Arc<SessionManager>` seals from N rayon workers directly. Measured
   ~4.5× (seal) / ~13× (open) on a 12-thread box. Operators can cap the pool
   with `[engine].workers` (0 = auto = all cores) to reserve cores for the
   reactor/TUN.

**Scope, stated plainly:** the parallel path only helps the *unpaced* fast
path (`traffic.enabled = false`). With timing/cover shaping on (the default,
§9a) the configured `rate_pps × burst` caps throughput on purpose, so the
crypto is not the bound and the paced path stays single-threaded to keep its
exact rate/burst/size guarantee. Raw speed and timing-analysis resistance are
opposed dimensions; this design lets you choose, it does not pretend you get
both at once.

---

## 5. Nonce management

**Decision:** each direction gets a 96-bit nonce built from a 4-byte
per-direction salt plus a 64-bit monotonic counter. The counter never
repeats without a rekey.

**Why this matters:** ChaCha20-Poly1305 with a repeated (key, nonce) pair
is a catastrophic break — an attacker can XOR two ciphertexts and recover
plaintext. The monotonic counter guarantees uniqueness within a session;
the rekey-before-exhaustion rule (see §7) guarantees the counter never
wraps under a live key. Per-direction salts ensure the two directions
never collide on a nonce.

---

## 6. Replay protection (sliding window)

**Decision:** a 2048-entry sliding-window bitset (32 × `u64` words) per
receiving direction. Order of operations on receive is **check → decrypt
→ commit**.

**Why that order:** if the window were updated before AEAD verification,
an attacker could pollute it with forged packets and cause legitimate
packets to be rejected — a denial of service. By committing only after
successful decryption, a forged packet can never affect the window. A
cheap pre-check before decryption avoids wasting crypto work on the
common case of an obvious replay; an authoritative re-check under lock at
commit time closes the race when packets are processed in parallel.

**Window size:** 2048 packets, matching WireGuard's scale, which is ample
for paths with heavy reordering. The mechanism is a multi-word bitset; the
bit at distance *d* below the highest seen counter records whether that
counter has arrived. Advancing the window shifts the bitset; the logic is
identical to a single-word version, just spread across 32 words.

---

## 7. Rekey

**Decision:** rekey before the nonce counter approaches exhaustion, with
a current+previous session overlap, an anti-storm minimum interval, and
bounded retries on packet loss.

**Why current+previous overlap:** during a rekey the new session becomes
active for outbound traffic, but in-flight packets encrypted under the old
session must still decrypt. Keeping the previous session alive for a short
grace period prevents packet loss during the swap. After the grace period
the old session is retired and its key is destroyed.

**Why an anti-storm interval:** without a minimum time between rekey
attempts, a failed rekey could retrigger in a tight loop. A 5-second floor
prevents the storm while still allowing a later retry.

**Why retry on loss (and why keys stay constant across retries):** a
handshake packet can be lost. The initiator resends the init message and
waits again, up to a bounded number of attempts. Crucially, the ephemeral
keys are generated once and reused across resends — generating fresh keys
per retry would break the handshake.

---

## 8. The shared-socket problem (rekey demux)

**Decision:** during a live tunnel, the inbound loop is the *only* reader
of the UDP socket. A mid-session handshake frame is demultiplexed — routed
to an in-progress rekey driver via a channel, or answered directly if the
peer initiated the rekey.

**Why this is non-obvious and necessary:** a naive rekey would call a
handshake routine that does its own `recv_from` on the socket. But the
data loop is already reading that same socket. Two readers race: the rekey
response gets consumed by the data loop and dropped as an unknown frame,
and the rekey hangs forever. Making the inbound loop the sole reader, and
feeding the rekey driver through a channel, eliminates the race.

---

## 9. Handshake framing & DPI resistance

**Decision:** handshake messages are a fixed 8192 bytes, padded with
cryptographically random noise, with a single KEM slot that carries the
Kyber public key (init) or ciphertext (response). The data path uses a
separate, MTU-safe frame (<1280 B). Handshake messages are fragmented for
transport; the data path is not.

**Why 8192 and not 2048:** the original 2048 fit only the Ed25519 (64 B)
signature. The hybrid signature is Ed25519 (64 B) + ML-DSA-65 (3309 B) =
3373 B, which together with the Kyber public key in the KEM slot overflows
2048. 8192 leaves comfortable headroom and keeps Init/Response/Confirm all
the same size regardless of which signature scheme is in use — so the
message size leaks neither the message type nor whether ML-DSA is enabled.
This is exactly the growth anticipated in the first draft (see below).

**Why fixed length with noise padding:** so that an observer cannot
distinguish an init message from a response by size, and the padded tail
has no recognizable structure. This is a first step toward making the
handshake hard to fingerprint.

**Why a single shared KEM slot:** the Kyber public key (1184 B) and
ciphertext (1088 B) differ in size. Using one fixed-size slot for both,
with the unused tail filled with noise, keeps the wire layout identical
in shape between the two message types. Phase validation (is this a valid
Kyber public key / ciphertext?) plus the transcript MAC ensure a noise
field is never mistaken for real data.

**Why handshake size forces fragmentation:** post-quantum keys are large.
You cannot fit a Kyber-bearing handshake in a single MTU-safe datagram —
this is inherent to PQ crypto, not a design flaw. The handshake is a
once-per-session event, so a handful of fragments there cost nothing
meaningful. The data path stays under the MTU. With the hybrid ML-DSA
signature now integrated (§3), `HANDSHAKE_MSG_LEN` is 8192 and a message
spans eight fragments — fine for a one-time handshake.

**Data-path frame (now obfuscated — `obf.rs`):** the data path used to keep a
small header in the clear (frame type, session_id, counter). Even without a
magic value that is a strong fingerprint: the type byte is a constant `0x01`,
the session_id is constant for the whole session, and the counter is a
monotonic 8-byte value incrementing by one — a trivially matchable flow
signature, and the packet length leaked the exact plaintext length. The data
path is now obfuscated so that every datagram looks like uniform random bytes.

The construction is **QUIC-style header protection** (RFC 9001 §5.4), adapted:

- The inner AEAD / nonce / replay core is **unchanged**. The payload is sealed
  exactly as before, with the logical header `H = type ‖ session_id ‖ counter`
  as associated data.
- A 16-byte `sample` is taken from the ciphertext tail (always inside the AEAD
  tag — ≥16 bytes even for an empty keepalive), and a 13-byte mask is derived:
  `mask = HMAC-SHA256(obf_key, sample)[..13]`, where `obf_key` is a per-direction
  key derived from the session secret with its own HKDF label. The visible
  header becomes `masked_H = H XOR mask`, and the wire datagram is
  `masked_H ‖ ciphertext`.
- **The real frame type is not on the wire at all.** Data / KeepAlive / Close
  are folded into an *inner* framing `inner_type ‖ real_len ‖ plaintext ‖ pad`
  that is sealed inside the AEAD, so every datagram is structurally identical
  and a keepalive is indistinguishable from data (the old `session_id = 0`
  keepalive tell is gone).
- **Length padding** (config `[obfuscation].padding`: off / bucketed / full)
  pads the inner framing before sealing, hiding the plaintext length. Bucketed
  rounds up to size classes (the default); full pads every packet to the
  MTU-safe maximum.

**Why the mask comes from the tag, and why it is safe:** header integrity is
*not* provided by the (malleable) XOR mask — it is provided by the AEAD, because
the receiver feeds the *recovered* `H` back in as associated data. Tampering
with `masked_H` yields a wrong counter/session (dropped, or the nonce is wrong
→ tag fails); tampering with the ciphertext changes both the sample (→ a random
recovered header) and the tag → it fails. This is exactly QUIC's split: the mask
is confidentiality-only, the tag is the authentication. The receiver recovers
the session by trial-decrypting over the small active set (current + previous
during a rekey overlap, ≤2 attempts); a datagram that opens under neither key is
dropped as noise.

**Handshake envelope (now obfuscated too — `hsobf.rs`, Phase 2):** the data
path could be keyed from the session secret, but the handshake has no session
secret yet while it runs, so it needs a key from *pre-shared* material (obfs4's
model). The static handshake-obfuscation key is derived by HKDF from the
already-pre-shared Ed25519 public keys (byte-sorted so both sides agree), or
from an optional `[obfuscation].psk_hex` for users who want a stronger secret.
With that key the whole 8192-byte handshake message is sealed in an outer
ChaCha20-Poly1305 layer (random nonce) and only *then* fragmented — so the
fragment header travels inside the ciphertext. Each fragment carries a random
`msg_id` (for blind reassembly) and a masked `index/total`; the fragments are
cut to **randomised sizes** so the old fixed burst of eight ~1032-byte
fragments is gone. The receiver reassembles blind on the `msg_id`, opens with
the static key (the AEAD tag is what rejects noise), and then runs the
unchanged `HandshakeMessage::decode`.

**Why this is obfuscation, not extra security:** the static key gives no forward
secrecy and no real authentication — the genuine handshake security (ephemeral
Kyber+X25519, transcript signing, §2–§3) is untouched. It is a pure outer
wrapper whose only job is to erase the wire fingerprint.

**Honest limitation (what remains):** the handshake obfuscation key is derived
from the pre-shared *public* keys by default, so an adversary who already holds
both public keys can de-obfuscate (setting `psk_hex` closes this). And even with
every static/structural fingerprint gone, the **~8 KB total handshake size** and
its **2-RTT burst timing** are still observable, and a burst's fragments share a
(random) `msg_id`. The *data-path* timing dimension is addressed below (§9a);
the initial handshake burst remains a residual because it precedes the pacer.

### 9a. Timing / cover traffic (`pacer.rs`, Phase 3)

Phases 1–2 made every datagram look random and hid its size, but a passive
observer could still see *when* data flowed — bursts, idle gaps, the overall
envelope. Phase 3 adds **constant-rate traffic shaping**: the sender emits on a
**fixed schedule** and fills empty slots with **cover (dummy) packets** the
receiver silently discards, so bursts and idle-vs-active dissolve into a steady
stream.

**Mechanism.** A cover packet is an ordinary obfuscated data-path datagram whose
*inner* type decrypts to a new `FrameType::Padding` — the receiver's
`decrypt_obf` returns `Padding` and the inbound loop drops it (but still counts
it as peer liveness). No new crypto, and **no wire/proto change**: `PROTO_VERSION`
lives in the handshake, not the data path, so a peer that predates Phase 3 simply
gets `UnknownFrameType` on a cover packet and drops it — real data still flows,
and pacing can even be **asymmetric per direction** with no negotiation. The
outbound loop (`main.rs`) replaces the batch-linger flush with a fixed-interval
ticker that emits `burst` datagrams per slot via the pure `pacer::Pacer`
scheduler: each slot dequeues a real packet if one is queued, else emits a cover
packet (CBR / Adaptive-within-cooldown) or nothing (Adaptive-idle). Every paced
datagram — real and cover — is padded to one **constant size** (`Full`), so both
the rate *and* the size are constant. A bounded queue tail-drops real packets
when offered load exceeds the rate (TCP recovers), which is what keeps the rate
constant.

**Modes & cost (config `[traffic]`, on by default in Adaptive):** **Adaptive**
(the default) paces only during activity plus a cooldown and goes quiet when
genuinely idle — no bandwidth at rest, but coarse active-vs-idle reappears.
**CBR** streams at the configured rate 24/7 — strongest, but the rate is then a
constant bandwidth floor *and* the throughput ceiling, so operators size
`rate_pps × burst` to their link. In both modes the rate is the throughput
ceiling (traffic above it tail-drops); the MTU is capped so a packet + overhead
fits one datagram (like WireGuard sizing the tunnel MTU to the path).

**Honest limitation (what remains):** timing shaping hides the *shape* of the
traffic, not the **existence** of the tunnel (the endpoints are known,
site-to-site) or its **total duration**; the **initial handshake burst** is
pre-pacer and still visible (rekey pacing is a documented follow-up); CBR costs
constant bandwidth and adds up to ~`1/rate` latency per packet; and in Adaptive
mode coarse volume-over-time still leaks. So this closes the timing dimension for
the data path under CBR, but "full traffic-analysis resistance" remains a
qualified claim.

---

## 10. Transcript binding (downgrade & tamper resistance)

**Decision:** a rolling SHA-256 transcript absorbs every handshake
message (the meaningful fields, not the noise), and the final
authentication signs and MACs that transcript hash.

**Why:** it binds the entire handshake — protocol version, both public
keys, the ciphertext — into one value. An active attacker who modifies any
field, strips a message, or attempts to downgrade a negotiated parameter
breaks the hash, and the signature/MAC verification fails. This is what
makes future cipher-agility (§4) safe: any attempt to force the weaker
option is caught because the choice is inside the bound transcript.

---

## 11. GPU bulk encryption (removed — the engine is CPU-only)

**Decision:** there is no GPU path. The engine encrypts on the CPU, full
stop. Earlier drafts carried a "GPU bulk" module behind a byte threshold,
but it always fell back to computing on the CPU.

**Why it was removed rather than kept as a stub:** shipping a module called
`GpuBulk` that silently computes on the CPU is misleading — it advertises an
acceleration that does not exist. The design-phase WGSL shader did ChaCha20
only, without the Poly1305 tag, and was not constant-time; wiring it in
would have been *false security* (a path that encrypts but does not
authenticate is a hole, not a speed-up). Rather than maintain a stub that
overstates the system, the honest move for a published crate is to remove it
and state plainly that the data path is CPU-only.

**Why the GPU is probably the wrong optimization anyway:** per-packet GPU
encryption is slower than CPU because the round-trip latency (upload,
dispatch, poll, read-back) dwarfs the few hundred nanoseconds ChaCha20
takes on a CPU core. The GPU only pays off for huge batches where latency
does not matter — and even then, a fast CPU cipher (or simply multiple
cores) usually saturates the NIC first. If a GPU path is ever revisited it
must be justified by measurement and must carry Poly1305 + constant-time
guarantees; until then, its absence is a feature, not a gap.

---

## 12. CPU vs GPU, stated plainly

For the record, because it is counter-intuitive: the heavy, once-per-
connection mathematics (Kyber, ML-DSA, the signatures) belongs on the
**CPU**, not the GPU — there is no volume to parallelize over. The simple,
endlessly-repeated mathematics (per-packet AEAD) is the *only* GPU
candidate, and even that wins only at extreme bulk. So the architecture
keeps the CPU as the engine for everything; a GPU path would have to be
justified by measurement, never by intuition, which is why none ships.

---

## Summary of honest limitations

These are stated plainly so no one mistakes intent for proof:

1. **No external security audit.** A self-built protocol is unproven
   until reviewed by qualified cryptographers. This remains the single
   most important caveat, and it is not something code changes can fix.
2. **Single PQ KEM.** The key exchange is Kyber768 + X25519 (hybrid
   classical/PQ), not a hybrid of two independent PQ KEMs.
3. **Partial traffic-analysis resistance.** The data path, the handshake
   envelope, and (optionally) packet *timing* are now obfuscated — random-looking
   datagrams, hidden sizes, and constant-rate cover traffic that dissolves
   bursts and idle-vs-active (§9, §9a). Still open: the tunnel's existence and
   total duration are inherent to a fixed site-to-site link, the initial
   handshake burst precedes the pacer, the handshake obfuscation key is
   pubkey-derived by default (an optional PSK closes that), and constant-rate
   shaping has a real bandwidth/latency cost. A large step, not a completed
   property.

### Resolved since the first draft

- **Mutual authentication.** The handshake was 1.5-RTT (responder-only
  auth); it is now a 3-message, 2-RTT exchange where both peers prove
  their identity and the responder withholds trust until the initiator's
  Confirm is verified. See §3.
- **PQ signatures integrated.** Peer authentication is now hybrid
  Ed25519 + ML-DSA-65 via `HybridAuth` (all legs must verify), and the
  handshake grew to 8192 B to carry it. See §3 and §9.
- **GPU stub removed.** The misleading CPU-backed "GPU bulk" path is gone;
  the engine is honestly CPU-only. See §11.
- **Data-path frame hardened.** The static magic value and redundant length
  field were removed, and the visible header is bound as AEAD associated
  data. See §9.
- **Data path obfuscated.** QUIC-style header protection (`obf.rs`): the header
  is masked with a keystream derived from an AEAD-tag sample, the real frame
  type is encrypted inside the payload, and configurable length padding hides
  sizes — every datagram now looks like random bytes. See §9.
- **Handshake envelope obfuscated.** Static-key wrap-then-fragment (`hsobf.rs`):
  the whole handshake message is sealed under a key bootstrapped from the
  pre-shared identities (or a PSK) and split into size-jittered fragments with a
  masked header — the old constant type byte and fixed fragment burst are gone.
  See §9.
- **Timing / cover traffic.** Constant-rate shaping (`pacer.rs`): the sender
  emits on a fixed schedule and fills idle slots with cover packets (an encrypted
  `Padding` inner type the receiver discards), dissolving bursts and
  idle-vs-active. No wire/proto change; on by default in Adaptive mode. See §9a.
- **Replay window.** Widened from 64 to 2048 entries (WireGuard scale).
  See §6.
- **Batched UDP I/O.** GSO on send / GRO on receive via `quinn-udp`
  (`udp.rs`), removing the per-packet syscall wall (~0.18 → ~9.6 Mpps on a
  microbench). No wire change. See §4a.
- **Multi-core crypto.** Batch seal/open now run in parallel across all cores
  via rayon (`engine.rs`, `spawn_blocking`-bridged), ~4.5×/~13× on 12 threads,
  capped by `[engine].workers`. Unpaced fast path only; no wire/crypto change.
  See §4a.
