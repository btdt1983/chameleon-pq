# Security Policy

*🇬🇧 English | [🇩🇪 Deutsch](SECURITY.de.md)*

## Status

Chameleon-PQ is **experimental, unaudited cryptographic software**. It
has not been reviewed by independent security professionals and should
not be used to protect real traffic.

## Reporting a vulnerability

If you find a security issue, please **do not** open a public GitHub
issue. Instead, contact the maintainer privately so the issue can be
addressed before disclosure.

For non-security bugs, regular GitHub issues are welcome.

## Known limits (not bugs, design constraints)

- No external audit has been performed
- Authentication is hybrid (Ed25519 + ML-DSA-65), but the key exchange is
  Kyber768 + X25519 — a single PQ KEM, not a hybrid of two PQ KEMs
- The data path, the handshake envelope, and (optionally) packet timing are
  obfuscated — random-looking datagrams, hidden sizes, and constant-rate cover
  traffic that hides bursts and idle-vs-active. But the tunnel's existence and
  total duration are inherent to a fixed link, the initial handshake burst
  precedes the pacer, the handshake obfuscation key is pubkey-derived by default
  (optional psk_hex for a stronger secret), and constant-rate shaping costs
  bandwidth/latency — so full traffic-analysis resistance is not claimed
- No protection against traffic analysis beyond the above
