# Chameleon-PQ

*[🇬🇧 English](README.md) | 🇩🇪 Deutsch*

Experimentelles hybrides Post-Quanten-VPN, geschrieben in Rust. Kombiniert
ML-KEM-768 (KEM) mit X25519 für den Schlüsselaustausch und eine hybride
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
- Der **Datenpfad**, die **Handshake-Hülle** UND jetzt das **Paket-Timing** sind
  verschleiert – jedes Datagramm sieht aus wie Zufallsbytes, und optionales
  Traffic-Shaping (`[traffic]`, standardmäßig an im **Adaptive**-Modus;
  **CBR** für volle Constant-Rate verfügbar) sendet auf einem festen Takt und
  füllt leere Slots mit Cover-Paketen, sodass Bursts und Aktiv-vs-Idle in einem
  gleichmäßigen Strom aufgehen. Rest (dokumentiert, keine *vollständige*
  Resistenz-Behauptung): Existenz und Gesamtdauer der Tunnel sind einer festen
  Site-to-Site-Verbindung inhärent, der **initiale** Handshake-Burst liegt vor
  dem Pacer, und der Handshake-Schlüssel ist standardmäßig pubkey-abgeleitet
  (`[obfuscation].psk_hex` schließt das). Shaping kostet Bandbreite/Latenz – die
  konfigurierte Rate ist zugleich die Untergrenze
  und das Durchsatz-Limit
- ML-DSA ist für die Authentifizierung integriert, der Schlüsselaustausch
  kombiniert aber weiterhin ML-KEM-768 mit X25519 (kein zweites PQ-KEM)

## Was funktioniert

- Hybrider Post-Quanten-Handshake (ML-KEM-768 + X25519, beide ephemer → PFS)
- Gegenseitige Authentifizierung: 3-Nachrichten-Handshake (2-RTT), bei dem
  beide Peers das Transcript signieren; der Responder gewährt kein
  Vertrauen, bis das Confirm des Initiators verifiziert ist
- Return-Routability-Cookie (WireGuard-Stil, stateless): der Responder macht
  keine teure ML-KEM/DH/ML-DSA-Arbeit, bis der Initiator ein an seine
  Quelladresse gebundenes Cookie zurückspiegelt — eine gespoofte/unverifizierte
  Quelle kann so weder den teuren Handshake noch eine große reflektierte Antwort
  auslösen. Die CookieChallenge ist eine vollwertige verschleierte Nachricht und
  fällt daher nicht auf
- Hybride Ed25519 + ML-DSA-65 (FIPS 204)-Transcript-Signierung zur
  Peer-Authentifizierung (vorab geteilte Identitäten) – die Signatur hält,
  solange *eines* der beiden Verfahren ungebrochen ist; fällt auf
  Ed25519-only zurück, wenn keine ML-DSA-Schlüssel konfiguriert sind
- Austauschbares AEAD für den Datenpfad: ChaCha20-Poly1305 (über `ring`,
  konstantzeitfähig, der universelle Standard) und AEGIS-256X2
  (CAESAR-Gewinner, schneller auf CPUs mit AES-Hardware), gewählt durch
  hardwarebewusste Aushandlung, wobei die Wahl im Transcript gegen Downgrade
  gebunden ist
- Verschleierter Datenpfad (QUIC-artiger Header-Schutz): jedes Daten-Datagramm
  sieht aus wie gleichverteilte Zufallsbytes – kein statisches Typ-Byte, keine
  sichtbare session_id, kein sichtbarer monotoner Zähler. Der Header wird mit
  einem Keystream maskiert, der (per HMAC-SHA256) aus einer Probe des AEAD-Tags
  abgeleitet wird, und der echte Frame-Typ steckt *innerhalb* der
  verschlüsselten Payload, sodass Keepalives nicht von Daten zu unterscheiden
  sind. Konfigurierbares Längen-Padding (off / bucketed / full) verbirgt die
  Paketgrößen. Die Header-Integrität kommt weiterhin vom AEAD (der
  zurückgewonnene Header ist die Associated Data) – die Maske dient nur der
  Vertraulichkeit
- Verschleierte Handshake-Hülle (statischer Schlüssel, `hsobf.rs`): die
  Handshake-Nachricht wird in einer ChaCha20-Poly1305-Schicht verpackt (Schlüssel
  aus den vorab geteilten Identitäten oder einem optionalen `psk_hex`) und in
  größen-jitterte Fragmente mit maskiertem Header aufgeteilt – der Handshake-Burst
  zeigt kein konstantes Typ-Byte und keine feste Fragment-Struktur mehr. Die echte
  Handshake-Krypto bleibt unverändert; reine äußere Verschleierung (keine Forward
  Secrecy auf der Verschleierungsschicht)
- Timing-/Cover-Traffic-Shaping (`pacer.rs`, `[traffic]`, standardmäßig an im
  Adaptive-Modus): Pakete gehen auf einem festen Takt raus und leere Slots werden
  mit Cover-(Dummy-)Paketen gefüllt, die der Empfänger stillschweigend verwirft,
  sodass Burst- und Aktiv-vs-Idle-Muster verborgen werden. Cover-Pakete sind
  gewöhnliche obf-Datagramme mit einem verschlüsselten `Padding`-Inner-Type,
  konstante Größe unter `Full`-Padding, also nicht von echten Daten zu
  unterscheiden. Adaptive (Standard) pact während Aktivität + Cooldown und wird
  in Ruhe still (keine Bandbreite idle); **CBR** sendet konstant für die stärkste
  Verbergung zu konstanten Kosten. Keine Wire-/Proto-Änderung – ein älterer Peer
  verwirft Cover-Pakete gefahrlos
- Richtungsabhängige Schlüssel; Replay-Schutz per Sliding-Window mit 2048
  Einträgen
- Rekey mit Anti-Storm-Sperre, Wiederholung bei Paketverlust und
  Überlappung von aktueller und vorheriger Session, sodass laufender
  Datenverkehr den Wechsel übersteht
- Fragment-Reassemblierung mit DoS-resistentem Entfernen veralteter
  Teilstücke
- Keepalive / Erkennung toter Peers
- Plattformübergreifendes TUN: Linux, macOS, Windows (Wintun)
- Performance (keine Wire-Änderung): das Datenpfad-AEAD wird beim Start per
  Kurz-Benchmark automatisch gewählt (AEGIS-256X2 wo am schnellsten, sonst
  ChaCha20 — z. B. wenn AEGIS auf Software-AES zurückfällt); die UDP-I/O ist
  gebündelt mit GSO/GRO (via `quinn-udp`, Per-Paket-Fallback) — ein Microbench
  hebt den Sendepfad von ~0,18 auf ~9,6 Mpps; und Seal/Open laufen PARALLEL über
  alle Cores (rayon, `[engine].workers`), gemessen ~4,5× (seal) / ~13× (open) auf
  einer 12-Thread-Maschine. Hinweis: der parallele Pfad hilft im **schnellen
  Modus** (`traffic.enabled = false`); mit Timing-Shaping an (Standard) begrenzt
  die Rate den Durchsatz — Geschwindigkeit und Timing-Verschleierung sind
  gegensätzliche Dimensionen, zwischen denen man wählt
- 83 Tests, die Handshake (inkl. gegenseitiger Auth + Fragmentierung),
  hybride ML-DSA-Auth (und dass ein falscher PQ-Schlüssel scheitert, selbst
  wenn Ed25519 passt), AEAD-Aushandlung und AEGIS-Sessions, Associated-Data-
  Header-Bindung, Datenpfad, Replay (inkl. weitem Reordering), MITM (beide
  Richtungen), Rekey, Prune-Verhalten, den verschleierten Datenpfad (Round-Trip
  mit beiden Ciphern, Manipulations-Ablehnung, Trial-Demux über aktuelle +
  vorherige Session, Längen-Padding, leere Keepalives) und die verschleierte
  Handshake-Hülle (symmetrische Schlüsselableitung, Wrap-then-Fragment-Round-Trip
  mit Jitter, vollständiger gegenseitiger Handshake, Ablehnung falscher
  Schlüssel/Rauschen, Reassembler-Cap + Prune), Timing-/Cover-Traffic (die
  CBR-/Adaptive-/Cooldown-Logik des reinen Pacers, dass ein Cover-Paket als
  `Padding` zurückkommt und unter `Full`-Padding gleich lang + Header-verschieden
  ist), parallele Krypto (parallel versiegelte Pakete entschlüsseln alle mit
  eindeutigen Countern, und `decrypt_batch_par` trennt Daten von Rauschen),
  rollen-getrennte Handshake-Signaturen (eine reflektierte Responder-Signatur
  wird als Confirm abgelehnt, selbst bei geteiltem Identitätsschlüssel), den
  bounded UDP-Handshake (gegenseitiger Abschluss über echte Sockets + sauberer
  Timeout, wenn kein Responder antwortet), Identitätsbindung (symmetrisch,
  peer-abhängig), die Ablehnung von low-order/all-zero-X25519-Punkten und das
  Return-Routability-Cookie (deterministisch + eingabeabhängig, und eine Init
  ohne Cookie wird mit einer CookieChallenge statt einer teuren Response
  beantwortet) abdecken
- Fuzzing der Parser für Angreifer-Eingaben (Frame- + Handshake-Decode, die
  Verschleierungs-Parser von Datenpfad und Handshake, der Reassembler und der
  Inbound-Entschlüsselungspfad): eine stabile Random-/Edge-Case-Harness läuft mit
  `cargo test` (`tests/fuzz_parsers.rs`), dazu coverage-guided `cargo-fuzz`-Targets
  in `fuzz/` (Nightly; wöchentlicher CI-Job). ~18 Mio. Ausführungen fanden keinen
  Panic

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
  ein Start-Microbenchmark wählt automatisch die schnellere Chiffre für die
  Maschine, und die Wahl ist downgrade-sicher (im Handshake-Transcript gebunden)
- `session.rs` – richtungsabhängige AEAD-Schlüssel, Nonce-Verwaltung,
  Header-Bindung per AAD, Sliding-Window-Replay, `SessionManager` mit Rekey
- `tunnel.rs` – 8192-Byte-Handshake (einzelner KEM-Slot, mit Rauschen
  aufgefüllt; dimensioniert für die hybride PQ-Signatur),
  Fragmentierung/Reassemblierung, Zustandsmaschine mit Transcript-Signierung
- `frame.rs` – MTU-sicherer, Magic-freier Frame (<1280 B) für die
  Handshake-Hülle und den Legacy-Datenpfad (bei ausgeschalteter Verschleierung)
- `obf.rs` – Verschleierung des Datenpfads: QUIC-artiger Header-Schutz
  (13-Byte-Header maskiert mit einem Keystream aus einer AEAD-Tag-Probe),
  Inner-Type-Framing (echter Frame-Typ verschlüsselt in der Payload) und
  konfigurierbares Längen-Padding
- `hsobf.rs` – Verschleierung der Handshake-Hülle: ein statischer Schlüssel (aus
  den vorab geteilten Ed25519-Pubkeys oder einem optionalen PSK) verpackt die
  ganze Handshake-Nachricht in ChaCha20-Poly1305 und teilt sie in größen-jitterte
  Fragmente mit maskiertem Header (`derive_hs_obf_key` / `seal_and_fragment` /
  `unmask_fragment` / `open`)
- `pacer.rs` – reiner (tokio-freier) Constant-Rate-Scheduler für
  Timing-/Cover-Traffic-Shaping: `Pacer::next_emit` entscheidet pro Slot, ob ein
  echtes Paket, ein Cover-Paket oder nichts gesendet wird (`ShapeMode`
  CBR/Adaptive); die async-Schleife in `main.rs` treibt ihn an
- `engine.rs` – CPU-Verschlüsselungs-Engine: Batch-Seal/Open, **parallel über
  alle Cores** via rayon (`encrypt_batch_par` / `decrypt_batch_par`, aus den
  async-Schleifen mit `spawn_blocking` überbrückt); konstantzeitfähig, geringe
  Latenz, kein GPU-Pfad (siehe DESIGN.md §11–§12 zur Begründung)
- `net.rs` – UDP-Schleifen; klare Ein-/Ausgangspunkte zur TUN-Schicht
- `udp.rs` – gebündelte UDP-I/O (GSO beim Senden, GRO beim Empfangen) via
  `quinn-udp`, mit Per-Paket-Fallback auf älteren Kernels / Nicht-Linux; das
  einzige Modul, das die Dependency berührt (`batch_send` / `batch_recv` /
  `group_equal_sized`)
- `rekey.rs` – Rekey-Treiber, der das Problem des gemeinsam genutzten
  Sockets löst (die Inbound-Schleife ist der einzige Socket-Leser; der
  Rekey-Treiber empfängt über einen Channel)
- `tun_iface.rs` – plattformübergreifendes TUN mit Mock für Tests
- `config.rs` – TOML-Loader, CLI

## Lizenz

Apache 2.0 – siehe [LICENSE](LICENSE).
