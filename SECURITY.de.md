# Sicherheitsrichtlinie

*[🇬🇧 English](SECURITY.md) | 🇩🇪 Deutsch*

## Status

Chameleon-PQ ist **experimentelle, nicht auditierte kryptografische
Software**. Sie wurde nicht von unabhängigen Sicherheitsfachleuten geprüft
und sollte nicht zum Schutz von echtem Datenverkehr eingesetzt werden.

## Eine Schwachstelle melden

Wenn Sie ein Sicherheitsproblem finden, öffnen Sie **bitte kein**
öffentliches GitHub-Issue. Kontaktieren Sie stattdessen den Maintainer
privat, damit das Problem vor einer Veröffentlichung behoben werden kann.

Für nicht sicherheitsrelevante Fehler sind reguläre GitHub-Issues
willkommen.

## Bekannte Grenzen (keine Fehler, sondern bewusste Designentscheidungen)

- Es wurde kein externes Audit durchgeführt
- Die Authentifizierung ist hybrid (Ed25519 + ML-DSA-65), aber der
  Schlüsselaustausch ist Kyber768 + X25519 – ein einzelnes PQ-KEM, kein
  Hybrid aus zwei PQ-KEMs
- Der Datenpfad ist verschleiert (QUIC-artiger Header-Schutz + Längen-Padding:
  kein sichtbares Typ-Byte, keine session_id, kein Zähler, und die Größen sind
  verborgen), aber die Handshake-Hülle ist weiterhin ein Klartext-Frame, und
  Timing-Maskierung / Cover-Traffic sind nicht implementiert – vollständige
  Verkehrsanalyse-Resistenz wird also noch nicht behauptet
- Kein Schutz gegen Verkehrsanalyse über das oben Genannte hinaus
