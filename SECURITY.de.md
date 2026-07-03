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
  Schlüsselaustausch ist ML-KEM-768 + X25519 – ein einzelnes PQ-KEM, kein
  Hybrid aus zwei PQ-KEMs
- Der Datenpfad, die Handshake-Hülle und (optional) das Paket-Timing sind
  verschleiert – Zufallsbytes-Datagramme, verborgene Größen und Constant-Rate-
  Cover-Traffic, der Bursts und Aktiv-vs-Idle verbirgt. Aber Existenz und
  Gesamtdauer der Tunnel sind einer festen Verbindung inhärent, der initiale
  Handshake-Burst liegt vor dem Pacer, der Handshake-Schlüssel ist standardmäßig
  pubkey-abgeleitet (optionales psk_hex), und Constant-Rate kostet
  Bandbreite/Latenz – vollständige Verkehrsanalyse-Resistenz wird also nicht
  behauptet
- Kein Schutz gegen Verkehrsanalyse über das oben Genannte hinaus
