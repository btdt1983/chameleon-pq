# Chameleon-PQ

*[🇬🇧 English](README.md) | 🇩🇪 Deutsch*

Experimentelles hybrides Post-Quanten-VPN, geschrieben in Rust. Kombiniert
Kyber768 (KEM) mit X25519 für den Schlüsselaustausch und eine hybride
Ed25519 + ML-DSA-65 (FIPS 204)-Signatur für die Peer-Authentifizierung,
über UDP mit einer TUN-Schnittstelle unter Linux/macOS/Windows.

## ⚠️ Sicherheitsstatus: EXPERIMENTELL

**Dieser Code wurde nicht unabhängig auditiert und sollte nicht zum Schutz
von echtem Datenverkehr eingesetzt werden.** Ein selbst entwickeltes
kryptografisches Protokoll ist ein Warnsignal, bis jemand mit
entsprechender Qualifikation es geprüft hat. Nutzen Sie dies als
Lernprojekt, als Architekturreferenz oder als Ausgangspunkt für ein
ordnungsgemäß auditiertes System – nicht als Produktiv-VPN.

Bekannte Einschränkungen des Geltungsbereichs:
- Es wurde kein externes Sicherheitsaudit durchgeführt – das bleibt der mit
  Abstand wichtigste Vorbehalt für jedes selbst entwickelte Protokoll
- Der Frame des Datenpfads trägt keinen statischen Magic-Wert mehr und sein
  Header ist authentifiziert, aber vollständige Verkehrsanalyse-Resistenz
  (obfs4-/Shadowsocks-artiges Framing, Timing-/Größen-Maskierung) ist noch
  Zukunftsarbeit
- ML-DSA ist für die Authentifizierung integriert, der Schlüsselaustausch
  kombiniert aber weiterhin Kyber768 mit X25519 (kein zweites PQ-KEM)

## Was funktioniert

- Hybrider Post-Quanten-Handshake (Kyber768 + X25519, beide ephemer → PFS)
- Gegenseitige Authentifizierung: 3-Nachrichten-Handshake (2-RTT), bei dem
  beide Peers das Transcript signieren; der Responder gewährt kein
  Vertrauen, bis das Confirm des Initiators verifiziert ist
- Hybride Ed25519 + ML-DSA-65 (FIPS 204)-Transcript-Signierung zur
  Peer-Authentifizierung (vorab geteilte Identitäten) – die Signatur hält,
  solange *eines* der beiden Verfahren ungebrochen ist; fällt auf
  Ed25519-only zurück, wenn keine ML-DSA-Schlüssel konfiguriert sind
- Austauschbares AEAD für den Datenpfad: ChaCha20-Poly1305 (über `ring`,
  konstantzeitfähig, der universelle Standard) und AEGIS-256X2
  (CAESAR-Gewinner, schneller auf CPUs mit AES-Hardware), gewählt durch
  hardwarebewusste Aushandlung, wobei die Wahl im Transcript gegen Downgrade
  gebunden ist
- Magic-freier Datenpfad-Frame: kein statisches Fingerprint-Byte, und der
  sichtbare Header (Typ / session_id / Zähler) ist als AEAD Associated Data
  gebunden, sodass Manipulation den Tag bricht
- Richtungsabhängige Schlüssel; Replay-Schutz per Sliding-Window mit 2048
  Einträgen
- Rekey mit Anti-Storm-Sperre, Wiederholung bei Paketverlust und
  Überlappung von aktueller und vorheriger Session, sodass laufender
  Datenverkehr den Wechsel übersteht
- Fragment-Reassemblierung mit DoS-resistentem Entfernen veralteter
  Teilstücke
- Keepalive / Erkennung toter Peers
- Plattformübergreifendes TUN: Linux, macOS, Windows (Wintun)
- 23 Tests, die Handshake (inkl. gegenseitiger Auth + Fragmentierung),
  hybride ML-DSA-Auth (und dass ein falscher PQ-Schlüssel scheitert, selbst
  wenn Ed25519 passt), AEAD-Aushandlung und AEGIS-Sessions, Associated-Data-
  Header-Bindung, Datenpfad, Replay (inkl. weitem Reordering), MITM (beide
  Richtungen), Rekey und Prune-Verhalten abdecken

## Build

Erfordert eine aktuelle Rust-Toolchain (1.80+; Installation über
[rustup](https://rustup.rs/)).

```bash
cargo build --release
cargo test
```

Oder von crates.io installieren:

```bash
cargo install chameleon-pq
```

## Schnellstart

```bash
# 1. Schlüsselpaare auf beiden Knoten erzeugen
./target/release/chameleon-pq keygen

# 2. config.example.toml nach config.toml kopieren, den eigenen Seed und den
#    öffentlichen Schlüssel des Peers eintragen (out-of-band austauschen)

# 3. Validieren
./target/release/chameleon-pq --config config.toml check

# 4. Als Server starten (benötigt CAP_NET_ADMIN unter Linux für TUN)
sudo ./target/release/chameleon-pq --config config.toml server

# 5. Als Client starten
sudo ./target/release/chameleon-pq --config config.toml client \
    --server 1.2.3.4:51820
```

Unter Windows benötigen Sie zusätzlich `wintun.dll` von
<https://www.wintun.net> neben der Binärdatei.

## Architektur

- `crypto.rs` – `Authenticator`-Trait mit `Ed25519Auth` (über `ring`) und
  `MlDsaAuth` (ML-DSA-65 über `pqcrypto-mldsa`), kombiniert durch
  `HybridAuth` (alle Legs müssen verifizieren); Transcript-Hash, HKDF
- `aead.rs` – austauschbares AEAD für den Datenpfad: `ChaCha20-Poly1305`
  und `AEGIS-256X2` hinter einem Trait (jetzt mit Associated-Data-Support),
  CPU-AES-Erkennung und downgrade-sicherer Aushandlung
- `session.rs` – richtungsabhängige AEAD-Schlüssel, Nonce-Verwaltung,
  Header-Bindung per AAD, Sliding-Window-Replay, `SessionManager` mit Rekey
- `tunnel.rs` – 8192-Byte-Handshake (einzelner KEM-Slot, mit Rauschen
  aufgefüllt; dimensioniert für die hybride PQ-Signatur),
  Fragmentierung/Reassemblierung, Zustandsmaschine mit Transcript-Signierung
- `frame.rs` – MTU-sicherer, Magic-freier Frame für den Datenpfad (<1280 B)
- `engine.rs` – CPU-Verschlüsselungs-Engine (konstantzeitfähig, geringe
  Latenz; kein GPU-Pfad – siehe DESIGN.md §11–§12 zur Begründung)
- `net.rs` – UDP-Schleifen; klare Ein-/Ausgangspunkte zur TUN-Schicht
- `rekey.rs` – Rekey-Treiber, der das Problem des gemeinsam genutzten
  Sockets löst (die Inbound-Schleife ist der einzige Socket-Leser; der
  Rekey-Treiber empfängt über einen Channel)
- `tun_iface.rs` – plattformübergreifendes TUN mit Mock für Tests
- `config.rs` – TOML-Loader, CLI

## Lizenz

Apache 2.0 – siehe [LICENSE](LICENSE).
