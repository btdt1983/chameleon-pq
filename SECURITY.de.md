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
- Der Header des Datenpfad-Frames ist authentifiziert und trägt keinen
  statischen Magic-Wert mehr, aber vollständige Verkehrsanalyse-Resistenz
  (verschleiertes Framing, Timing-/Größen-Maskierung) ist nicht
  implementiert – nur der Handshake ist längenfest und mit Rauschen aufgefüllt
- Kein Schutz gegen Verkehrsanalyse über das oben Genannte hinaus
