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
- Der Datenpfad und die Handshake-Hülle sind beide verschleiert (kein sichtbares
  Typ-Byte, keine session_id, kein Zähler, keine Fragment-Struktur; Größen
  gepaddet/gejittert), aber die ~8 KB Handshake-Größe und ihr 2-RTT-Burst-Timing
  bleiben beobachtbar, der Handshake-Verschleierungsschlüssel wird standardmäßig
  aus den vorab geteilten Pubkeys abgeleitet (optionales psk_hex für ein
  stärkeres Geheimnis), und Timing-Maskierung / Cover-Traffic sind nicht
  implementiert – vollständige Verkehrsanalyse-Resistenz wird also noch nicht
  behauptet
- Kein Schutz gegen Verkehrsanalyse über das oben Genannte hinaus
