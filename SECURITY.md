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
- The data path and the handshake envelope are both obfuscated (no visible type
  byte, session id, counter or fragment structure; sizes padded/jittered), but
  the ~8 KB handshake volume and its 2-RTT burst timing remain observable, the
  handshake obfuscation key is derived from the pre-shared pubkeys by default
  (optional psk_hex for a stronger secret), and timing masking / cover traffic
  are not implemented — so full traffic-analysis resistance is not yet claimed
- No protection against traffic analysis beyond the above
