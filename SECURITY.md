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
- The data-path frame header is authenticated and carries no static magic,
  but full traffic-analysis resistance (obfuscated framing, timing/size
  masking) is not implemented — only the handshake is fixed-length and
  noise-padded
- No protection against traffic analysis beyond the above
