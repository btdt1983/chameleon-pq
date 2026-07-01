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
- The data path is obfuscated (QUIC-style header protection + length padding:
  no visible type byte, session id or counter, and sizes are hidden), but the
  handshake envelope is still a cleartext frame, and timing masking / cover
  traffic are not implemented — so full traffic-analysis resistance is not yet
  claimed
- No protection against traffic analysis beyond the above
