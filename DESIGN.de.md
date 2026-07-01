# Design & Begründung — Chameleon-PQ

*[🇬🇧 English](DESIGN.md) | 🇩🇪 Deutsch*

Dieses Dokument erläutert, *warum* Chameleon-PQ so aufgebaut ist, wie es
ist. Jede wesentliche Entscheidung wird mit ihrer Begründung und ihren
Abwägungen festgehalten, damit Prüfer, Mitwirkende und das künftige Ich die
Entscheidungen nachvollziehen können, statt sie erraten zu müssen.

> **Status-Hinweis:** Dies ist experimentelle, nicht auditierte Software.
> Die folgende Begründung erläutert die Absicht des Designs; sie ist keine
> Behauptung, dass die Implementierung nachweislich sicher ist. Siehe
> `SECURITY.md`.

---

## 1. Bedrohungsmodell & Geltungsbereich

Chameleon-PQ zielt auf **Site-to-Site-Tunnel zwischen bekannten Endpunkten**
ab – Infrastruktur-zu-Infrastruktur-Verkehr, bei dem die Peers vorab mit
vorab geteilten Identitäten konfiguriert werden. Es ist *nicht* als
Anonymitätsdienst für Endnutzer konzipiert (wie bei kommerziellen
VPN-Anbietern).

Berücksichtigte Angreifer:
- **Passiver Netzwerkbeobachter** – kann den gesamten Chiffretext lesen.
  Abgewehrt durch AEAD-Verschlüsselung des Datenpfads.
- **Aktiver Man-in-the-Middle** – kann einschleusen, verwerfen, umordnen,
  wiederholen (Replay). Abgewehrt durch authentifizierten Handshake +
  Replay-Schutz.
- **Künftiger Quantenangreifer („harvest now, decrypt later“)** – zeichnet
  heute Datenverkehr auf, um ihn zu entschlüsseln, sobald ein
  Quantencomputer existiert. Dies ist der zentrale Grund für den
  Post-Quanten-Schlüsselaustausch: Site-to-Site-Verkehr kann über Jahre
  hinweg vertraulich bleiben, daher muss der Schlüsselaustausch einem
  Quantenangriff standhalten, der *später* gegen *heute* aufgezeichneten
  Verkehr geführt wird.

Ausdrücklich **außerhalb des Geltungsbereichs** für den Moment:
Widerstandsfähigkeit gegen Verkehrsanalyse über längenfeste, aufgefüllte
Handshakes hinaus sowie Schutz gegen einen kompromittierten Endpunkt.

---

## 2. Hybrider Post-Quanten-Schlüsselaustausch

**Entscheidung:** X25519 (klassisches ECDH) mit Kyber768 (Post-Quanten-KEM)
kombinieren, beide ephemer, und den Sessionschlüssel aus *beiden* gemeinsamen
Geheimnissen ableiten, verkettet über HKDF.

**Warum hybrid und nicht reines Post-Quantum:** Post-Quanten-Algorithmen
sind jung. Ihre mathematischen Annahmen haben weit weniger Jahre der Prüfung
hinter sich als klassisches ECDH. Durch die Kombination beider bleibt die
Session sicher, solange *einer* der beiden Teile hält. Ein Bruch allein von
Kyber bricht die Session nicht (X25519 schützt sie weiterhin); ein
Quantencomputer, der X25519 bricht, bricht die Session nicht (Kyber schützt
sie weiterhin). Verwundbar ist man nur, wenn beide gleichzeitig fallen. Das
ist eindeutig sicherer, als auf einen allein zu setzen.

**Warum Verkettung und nicht XOR der Geheimnisse:** XOR würde die hybride
Garantie zerstören – wäre ein Geheimnis bekannt, könnte es sich aufheben.
Beide als verkettetes Eingangs-Schlüsselmaterial in HKDF einzuspeisen,
bewahrt die Eigenschaft „sicher, solange eines hält“.

**Warum beide Teile ephemer sind:** Forward Secrecy. Ephemere Schlüssel
werden nach dem Handshake verworfen, sodass eine spätere Kompromittierung
eines beliebigen Langzeitschlüssels zuvor aufgezeichnete Sessions nicht
entschlüsseln kann.

---

## 3. Peer-Authentifizierung (hybrid Ed25519 + ML-DSA-65)

**Entscheidung:** den Handshake authentifizieren, indem der Transcript-Hash
mit einem *hybriden* Verfahren signiert wird – Ed25519 **und** ML-DSA-65
(FIPS 204) – unter Verwendung vorab geteilter öffentlicher Peer-Schlüssel
(out-of-band ausgetauscht). Beide Signaturverfahren liegen hinter einem
`Authenticator`-Trait und werden durch `HybridAuth` kombiniert, das verlangt,
dass **jeder** Teil verifiziert. Sind keine ML-DSA-Schlüssel konfiguriert,
fällt das System auf Ed25519-only (klassisch) zurück und meldet das laut im
Log.

**Warum vorab geteilte Identitäten:** In einem Site-to-Site-Szenario sind
die Peers im Voraus bekannt. Das vorherige Teilen öffentlicher Schlüssel
bedeutet, dass ein unbekannter Signierer sofort abgewiesen wird – es gibt
kein Trust-on-First-Use-Fenster, das ein MITM ausnutzen könnte.

**Warum Ed25519 überhaupt als ein Teil bleibt:** Authentifizierung muss nur
*während* des Handshakes halten – ein Angreifer müsste sie in Echtzeit
brechen, um sich als Peer auszugeben. Die Bedrohung „harvest now, decrypt
later“ gilt **nicht** für Signaturen (eine im nächsten Jahr gefälschte
Signatur kann die heutige Session nicht rückwirkend brechen), daher ist die
Dringlichkeit für PQ-Signaturen wirklich geringer als für den
PQ-Schlüsselaustausch. Ed25519 über `ring` ist schnell, klein,
konstantzeitfähig und seit Jahrzehnten geprüft – wir behalten es als einen
Teil, statt es fallenzulassen.

**Warum zusätzlich ML-DSA und warum hybrid:** Dasselbe Argument der „jungen
Annahmen“ aus §2 gilt für Signaturen – die Gitter-Annahmen von ML-DSA sind
weit weniger geprüft als der diskrete Logarithmus von Ed25519. Indem mit
*beiden* signiert wird und beide verifizieren müssen (`HybridAuth`), hält die
Authentifizierung, solange *eines* der Verfahren ungebrochen ist: Ein Bruch
allein von ML-DSA erlaubt keine Peer-Identitätsfälschung (Ed25519 sperrt
weiter), und ein Quantencomputer, der Ed25519 bricht, auch nicht (ML-DSA
sperrt weiter). Der `Authenticator`-Trait machte das günstig – `MlDsaAuth`
ist eine Struktur, die den Trait implementiert, neben `Ed25519Auth` in
`HybridAuth` gekapselt; die Zustandsmaschine änderte sich nicht. (Siehe §9
für die Folge bezüglich der Nachrichtengröße, die nun eingetreten ist.)

**Warum gerade ML-DSA-65:** Es zielt auf die ~192-Bit-Kategorie (NIST
Level 3), die übliche mittlere Wahl, passend zum Niveau von Kyber768 im KEM.
Schlüssel und Signaturen sind groß (öffentlicher Schlüssel ~1952 B, Signatur
~3309 B), was genau der Grund ist, weshalb der Handshake wachsen musste (§9).
ML-DSA-Schlüssel sind nicht aus einem kurzen Seed ableitbar, daher gibt
`keygen` ein vollständiges Schlüsselpaar aus, der geheime Schlüssel wird in
der Konfiguration gespeichert (hex); der öffentliche Schlüssel des Peers wird
out-of-band vorab geteilt wie die Ed25519-Identität.

**Gegenseitige Authentifizierung (implementiert):** Der Handshake ist ein
Austausch aus 3 Nachrichten und 2 RTT – Init, Response, Confirm. Der
Responder signiert das Transcript in der Response (authentifiziert sich
gegenüber dem Initiator), und der Initiator signiert dasselbe Transcript im
Confirm (authentifiziert sich gegenüber dem Responder). Entscheidend: Der
Responder vertraut der Session **nicht**, bis er das Confirm verifiziert hat
– er hält die abgeleitete Session in einem `SentResponse`-Zustand und geht
erst zu `Established` über, wenn die Signatur des Initiators stimmt. Dies
schließt die frühere einseitige Lücke – beide Peers weisen nun ihre
Identität nach, und ein Angreifer, der die erwartete Initiator-Signatur
nicht erzeugen kann, wird im Confirm-Schritt abgewiesen.

---

## 4. Datenpfad-Verschlüsselung (austauschbares AEAD: ChaCha20-Poly1305 + AEGIS-256X2)

**Entscheidung:** Der Datenpfad verschlüsselt über einen `Aead`-Trait mit
zwei Implementierungen – ChaCha20-Poly1305 (über `ring`) und AEGIS-256X2
(über die `aegis`-Crate). Die Chiffre wird pro Session durch hardwarebewusste
Aushandlung gewählt, mit ChaCha20 als universellem Standard und Fallback.

**Warum ChaCha20 der Standard und Fallback ist:** ChaCha20-Poly1305 ist auf
*jeder* Hardware konstantzeitfähig, weil es nur Additions-, Rotations- und
XOR-Operationen ohne datenabhängige Tabellenzugriffe verwendet. Es wird von
`ring` bereitgestellt, einer der am gründlichsten auditierten
Krypto-Bibliotheken überhaupt. Es ist die sichere Untergrenze, die auf jeder
CPU korrekt und sicher funktioniert.

**Warum AEGIS-256X2 als die schnelle Option angeboten wird:** AEGIS gewann
die Performance-Kategorie des CAESAR-Wettbewerbs, ist vollständig offen und
hat einen IETF-Entwurf für die Aufnahme in TLS 1.3. Es verwendet die
AES-Rundenfunktion (das hardwarebeschleunigte Primitiv) in einer
Stream-Cipher-Konstruktion, die sowohl schneller als auch ein stärkeres AEAD
ist als AES-GCM auf CPUs mit AES-Instruktionen – und dort auch schneller als
ChaCha20. Auf moderner Server- und Desktop-Hardware (die fast immer
AES-Beschleunigung besitzt) ist es die bessere Wahl in puncto Geschwindigkeit
und AEAD-Robustheit.

**Warum es ausgehandelt und nicht fest verdrahtet ist:** Der Vorteil von
AEGIS hängt von AES-Hardware ab. Ohne sie fällt AEGIS auf Software-AES
zurück, das langsamer *und* anfällig für Cache-Timing-Angriffe ist – genau
das, was ChaCha20 vermeidet. Daher wird die Wahl durch Fähigkeitserkennung
getroffen, nicht durch Annahme:

- Beim Sessionaufbau berechnet jede Seite `AeadAlgo::preferred()`, das AEGIS
  nur dann zurückgibt, wenn die CPU AES-Unterstützung meldet (AES-NI auf x86,
  die AES-Erweiterung auf aarch64), andernfalls ChaCha20.
- Der Initiator gibt seine Präferenz im Init bekannt; der Responder handelt
  mit `negotiate(local, peer)` aus – AEGIS nur, wenn *beide* Seiten es
  bevorzugen, andernfalls ChaCha20. Ein schneller Server arbeitet daher
  sicher mit einem eingeschränkten Client zusammen, ohne dass irgendjemand
  Software-AES ausführt.
- Die ausgehandelte Algorithmus-ID wird **in das Handshake-Transcript
  gebunden**, sodass ein Downgrade-Versuch (Erzwingen der schwächeren
  Chiffre) den Transcript-Hash bricht und die Signatur-/MAC-Verifikation
  fehlschlägt. Das ist die Transcript-Bindung aus §10, die genau die Aufgabe
  erfüllt, für die sie gebaut wurde.

**Nonce-Breiten unterscheiden sich und werden pro Chiffre behandelt:**
ChaCha20 verwendet eine 96-Bit-Nonce, AEGIS-256X2 eine 256-Bit-Nonce. Die
Session baut die Nonce in der Breite auf, die die gewählte Chiffre erfordert
(Salt ‖ Counter, mit Nullen aufgefüllt), sodass die Eindeutigkeitsgarantie
des monotonen Zählers (§5) für beide gilt.

**Ein Hinweis zu „Post-Quantum“ und der Chiffre:** AEGIS fügt keine
Quantenresistenz hinzu. Symmetrische Chiffren mit 256-Bit-Schlüsseln (sowohl
ChaCha20-Poly1305 als auch AEGIS-256) behalten gegenüber Grovers Algorithmus
bereits ~128 Bit Stärke. Der Post-Quanten-Schutz liegt vollständig im
Kyber-Schlüsselaustausch (§2), unabhängig davon, welches AEAD gewählt wird.
AEGIS bringt Geschwindigkeit und ein stärkeres AEAD, nicht zusätzliche
Quantensicherheit.

---

## 5. Nonce-Verwaltung

**Entscheidung:** Jede Richtung erhält eine 96-Bit-Nonce, aufgebaut aus einem
4-Byte-Salt pro Richtung plus einem monotonen 64-Bit-Zähler. Der Zähler
wiederholt sich nie ohne Rekey.

**Warum das wichtig ist:** ChaCha20-Poly1305 mit einem wiederholten
(Schlüssel, Nonce)-Paar ist ein katastrophaler Bruch – ein Angreifer kann
zwei Chiffretexte per XOR verknüpfen und Klartext wiederherstellen. Der
monotone Zähler garantiert Eindeutigkeit innerhalb einer Session; die Regel
„Rekey vor Erschöpfung“ (siehe §7) garantiert, dass der Zähler unter einem
aktiven Schlüssel nie überläuft. Salts pro Richtung stellen sicher, dass die
beiden Richtungen nie auf derselben Nonce kollidieren.

---

## 6. Replay-Schutz (Sliding Window)

**Entscheidung:** ein Sliding-Window-Bitset mit 2048 Einträgen (32 ×
`u64`-Wörter) pro empfangender Richtung. Die Reihenfolge der Operationen beim
Empfang ist **prüfen → entschlüsseln → festschreiben (commit)**.

**Warum diese Reihenfolge:** Würde das Fenster vor der AEAD-Verifikation
aktualisiert, könnte ein Angreifer es mit gefälschten Paketen verunreinigen
und legitime Pakete zur Abweisung bringen – ein Denial of Service. Indem erst
nach erfolgreicher Entschlüsselung festgeschrieben wird, kann ein gefälschtes
Paket das Fenster niemals beeinflussen. Eine günstige Vorprüfung vor der
Entschlüsselung vermeidet verschwendete Krypto-Arbeit im häufigen Fall eines
offensichtlichen Replays; eine maßgebliche erneute Prüfung unter Sperre zum
Commit-Zeitpunkt schließt die Race Condition, wenn Pakete parallel
verarbeitet werden.

**Fenstergröße:** 2048 Pakete, entsprechend dem Maßstab von WireGuard, was
für Pfade mit starkem Reordering reichlich ist. Der Mechanismus ist ein
Bitset über mehrere Wörter; das Bit im Abstand *d* unterhalb des höchsten
gesehenen Zählers gibt an, ob dieser Zähler eingetroffen ist. Das Vorrücken
des Fensters verschiebt das Bitset; die Logik ist identisch zu einer
Ein-Wort-Version, nur über 32 Wörter verteilt.

---

## 7. Rekey

**Entscheidung:** Rekey, bevor der Nonce-Zähler sich der Erschöpfung nähert,
mit einer Überlappung von aktueller und vorheriger Session, einem
Anti-Storm-Mindestintervall und begrenzten Wiederholungen bei Paketverlust.

**Warum die Überlappung aktuell+vorherig:** Während eines Rekeys wird die
neue Session für ausgehenden Verkehr aktiv, aber noch unterwegs befindliche
Pakete, die unter der alten Session verschlüsselt wurden, müssen sich noch
entschlüsseln lassen. Die vorherige Session für eine kurze Schonfrist am
Leben zu halten, verhindert Paketverlust während des Wechsels. Nach der
Schonfrist wird die alte Session stillgelegt und ihr Schlüssel vernichtet.

**Warum ein Anti-Storm-Intervall:** Ohne eine Mindestzeit zwischen
Rekey-Versuchen könnte ein fehlgeschlagener Rekey in einer engen Schleife
erneut auslösen. Eine Untergrenze von 5 Sekunden verhindert den Sturm und
erlaubt dennoch einen späteren erneuten Versuch.

**Warum Wiederholung bei Verlust (und warum Schlüssel über Wiederholungen
konstant bleiben):** Ein Handshake-Paket kann verloren gehen. Der Initiator
sendet die Init-Nachricht erneut und wartet wieder, bis zu einer begrenzten
Anzahl von Versuchen. Entscheidend: Die ephemeren Schlüssel werden einmal
erzeugt und über die erneuten Sendungen hinweg wiederverwendet – frische
Schlüssel pro Wiederholung würden den Handshake brechen.

---

## 8. Das Problem des gemeinsam genutzten Sockets (Rekey-Demux)

**Entscheidung:** Während eines laufenden Tunnels ist die Inbound-Schleife
der *einzige* Leser des UDP-Sockets. Ein Handshake-Frame mitten in der
Session wird demultiplext – über einen Channel an einen laufenden
Rekey-Treiber weitergeleitet oder direkt beantwortet, wenn der Peer den Rekey
initiiert hat.

**Warum das nicht offensichtlich und doch notwendig ist:** Ein naiver Rekey
würde eine Handshake-Routine aufrufen, die ihr eigenes `recv_from` auf dem
Socket ausführt. Aber die Datenschleife liest bereits denselben Socket. Zwei
Leser konkurrieren: Die Rekey-Antwort wird von der Datenschleife konsumiert
und als unbekannter Frame verworfen, und der Rekey hängt für immer. Indem die
Inbound-Schleife zum alleinigen Leser gemacht und der Rekey-Treiber über
einen Channel gespeist wird, wird die Race Condition beseitigt.

---

## 9. Handshake-Framing & DPI-Resistenz

**Entscheidung:** Handshake-Nachrichten sind feste 8192 Byte, aufgefüllt mit
kryptografisch zufälligem Rauschen, mit einem einzigen KEM-Slot, der den
öffentlichen Kyber-Schlüssel (Init) oder den Chiffretext (Response) trägt.
Der Datenpfad verwendet einen separaten, MTU-sicheren Frame (<1280 B).
Handshake-Nachrichten werden für den Transport fragmentiert; der Datenpfad
nicht.

**Warum 8192 und nicht 2048:** Die ursprünglichen 2048 fassten nur die
Ed25519-Signatur (64 B). Die hybride Signatur ist Ed25519 (64 B) + ML-DSA-65
(3309 B) = 3373 B, was zusammen mit dem öffentlichen Kyber-Schlüssel im
KEM-Slot 2048 überschreitet. 8192 lässt bequemen Spielraum und hält
Init/Response/Confirm alle gleich groß, unabhängig davon, welches
Signaturverfahren genutzt wird – so verrät die Nachrichtengröße weder den
Nachrichtentyp noch, ob ML-DSA aktiv ist. Genau dieses Wachstum wurde im
ersten Entwurf vorhergesehen (siehe unten).

**Warum feste Länge mit Rausch-Auffüllung:** damit ein Beobachter eine
Init-Nachricht nicht anhand der Größe von einer Response unterscheiden kann
und der aufgefüllte Schwanz keine erkennbare Struktur hat. Dies ist ein
erster Schritt, um den Handshake schwer per Fingerprinting erkennbar zu
machen.

**Warum ein einzelner gemeinsamer KEM-Slot:** Der öffentliche Kyber-Schlüssel
(1184 B) und der Chiffretext (1088 B) unterscheiden sich in der Größe. Einen
einzigen Slot fester Größe für beide zu verwenden, mit dem ungenutzten
Schwanz voller Rauschen, hält das Wire-Layout in der Form zwischen den beiden
Nachrichtentypen identisch. Phasenvalidierung (ist dies ein gültiger
öffentlicher Kyber-Schlüssel / Chiffretext?) plus der Transcript-MAC stellen
sicher, dass ein Rauschfeld nie mit echten Daten verwechselt wird.

**Warum die Handshake-Größe Fragmentierung erzwingt:**
Post-Quanten-Schlüssel sind groß. Man kann einen Kyber-tragenden Handshake
nicht in ein einzelnes MTU-sicheres Datagramm packen – das ist der PQ-Krypto
inhärent, kein Designfehler. Der Handshake ist ein einmaliges Ereignis pro
Session, daher kosten dort einige Fragmente nichts Nennenswertes. Der
Datenpfad bleibt unter der MTU. Mit der nun integrierten hybriden
ML-DSA-Signatur (§3) ist `HANDSHAKE_MSG_LEN` 8192, und eine Nachricht
erstreckt sich über acht Fragmente – für einen einmaligen Handshake
unproblematisch.

**Datenpfad-Frame (jetzt verschleiert – `obf.rs`):** Früher hielt der
Datenpfad einen kleinen Header im Klartext (Frame-Typ, session_id, Zähler).
Auch ohne Magic-Wert ist das ein starker Fingerabdruck: Das Typ-Byte ist eine
Konstante `0x01`, die session_id ist für die gesamte Session konstant, und der
Zähler ist ein monotoner 8-Byte-Wert, der um eins hochzählt – eine trivial
matchbare Flow-Signatur, und die Paketlänge verriet die exakte Klartextlänge.
Der Datenpfad ist nun so verschleiert, dass jedes Datagramm wie gleichverteilte
Zufallsbytes aussieht.

Die Konstruktion ist **QUIC-artiger Header-Schutz** (RFC 9001 §5.4), angepasst:

- Der innere AEAD-/Nonce-/Replay-Kern bleibt **unverändert**. Die Payload wird
  genau wie zuvor verschlüsselt, mit dem logischen Header
  `H = Typ ‖ session_id ‖ Zähler` als Associated Data.
- Eine 16-Byte-`sample` wird aus dem Ende der Ciphertext genommen (immer
  innerhalb des AEAD-Tags – ≥16 Bytes selbst bei leerem Keepalive), und daraus
  wird eine 13-Byte-Maske abgeleitet: `mask = HMAC-SHA256(obf_key, sample)[..13]`,
  wobei `obf_key` ein richtungsabhängiger, aus dem Session-Secret mit eigenem
  HKDF-Label abgeleiteter Schlüssel ist. Der sichtbare Header wird zu
  `masked_H = H XOR mask`, und das Wire-Datagramm ist `masked_H ‖ Ciphertext`.
- **Der echte Frame-Typ steht gar nicht auf der Leitung.** Data / KeepAlive /
  Close stecken in einem *inneren* Framing `inner_type ‖ real_len ‖ Payload ‖
  Pad`, das innerhalb des AEAD verschlüsselt wird, sodass jedes Datagramm
  strukturell identisch ist und ein Keepalive nicht von Daten zu unterscheiden
  ist (die alte `session_id = 0`-Keepalive-Signatur ist weg).
- **Längen-Padding** (Config `[obfuscation].padding`: off / bucketed / full)
  füllt das innere Framing vor dem Versiegeln auf und verbirgt so die Länge.
  Bucketed rundet auf Größenklassen (Standard); full füllt jedes Paket auf das
  MTU-sichere Maximum auf.

**Warum die Maske aus dem Tag kommt und warum das sicher ist:** Die
Header-Integrität kommt *nicht* von der (malleablen) XOR-Maske – sie kommt vom
AEAD, weil der Empfänger den *zurückgewonnenen* `H` wieder als Associated Data
einspeist. Manipulation an `masked_H` ergibt einen falschen Zähler/eine falsche
Session (verworfen, oder die Nonce stimmt nicht → Tag scheitert); Manipulation
an der Ciphertext ändert sowohl die Probe (→ zufälliger zurückgewonnener Header)
als auch den Tag → sie scheitert. Das ist genau QUICs Aufteilung: Die Maske
dient nur der Vertraulichkeit, der Tag der Authentifizierung. Der Empfänger
gewinnt die Session per Trial-Entschlüsselung über die kleine aktive Menge
zurück (aktuell + vorherige während einer Rekey-Überlappung, ≤2 Versuche); ein
Datagramm, das unter keinem Schlüssel öffnet, wird als Rauschen verworfen.

**Handshake-Hülle (jetzt ebenfalls verschleiert – `hsobf.rs`, Phase 2):** Der
Datenpfad ließ sich aus dem Session-Secret ableiten, aber der Handshake hat noch
kein Session-Secret, während er läuft, braucht also einen Schlüssel aus *vorab
geteiltem* Material (obfs4s Modell). Der statische Handshake-Verschleierungs-
schlüssel wird per HKDF aus den bereits vorab geteilten Ed25519-Pubkeys
abgeleitet (byte-sortiert, damit beide Seiten übereinstimmen) oder aus einem
optionalen `[obfuscation].psk_hex` für ein stärkeres Geheimnis. Damit wird die
ganze 8192-Byte-Handshake-Nachricht in eine äußere ChaCha20-Poly1305-Schicht
(zufällige Nonce) versiegelt und *erst dann* fragmentiert – der Fragment-Header
reist also innerhalb der Ciphertext. Jedes Fragment trägt eine zufällige
`msg_id` (für blindes Reassemblieren) und ein maskiertes `index/total`; die
Fragmente werden auf **zufällige Größen** geschnitten, sodass der alte feste
Burst aus acht ~1032-Byte-Fragmenten weg ist. Der Empfänger reassembliert blind
über die `msg_id`, öffnet mit dem statischen Schlüssel (der AEAD-Tag lehnt
Rauschen ab) und führt dann das unveränderte `HandshakeMessage::decode` aus.

**Warum das Verschleierung ist, keine zusätzliche Sicherheit:** Der statische
Schlüssel gibt keine Forward Secrecy und keine echte Authentifizierung – die
eigentliche Handshake-Sicherheit (ephemeres Kyber+X25519, Transcript-Signierung,
§2–§3) bleibt unberührt. Es ist eine reine äußere Hülle, deren einzige Aufgabe
das Löschen des Wire-Fingerabdrucks ist.

**Ehrliche Einschränkung (was bleibt):** Der Handshake-Verschleierungsschlüssel
wird standardmäßig aus den vorab geteilten *öffentlichen* Schlüsseln abgeleitet,
also kann ein Angreifer, der beide Pubkeys bereits besitzt, de-verschleiern
(`psk_hex` schließt das). Und selbst wenn jeder statische/strukturelle
Fingerabdruck weg ist, bleiben die **~8 KB Gesamt-Handshake-Größe** und ihr
**2-RTT-Burst-Timing** beobachtbar, und die Fragmente eines Bursts teilen eine
(zufällige) `msg_id`. Timing-Maskierung / Cover-Traffic / konstantes Pacing sind
nicht implementiert. Das ist also ein großer Schritt zur Verkehrsanalyse-
Resistenz, keine abgeschlossene Behauptung.

---

## 10. Transcript-Bindung (Downgrade- & Manipulationsresistenz)

**Entscheidung:** Ein rollierendes SHA-256-Transcript nimmt jede
Handshake-Nachricht auf (die bedeutungstragenden Felder, nicht das Rauschen),
und die abschließende Authentifizierung signiert und MACt diesen
Transcript-Hash.

**Warum:** Es bindet den gesamten Handshake – Protokollversion, beide
öffentlichen Schlüssel, den Chiffretext – in einen einzigen Wert. Ein aktiver
Angreifer, der ein beliebiges Feld verändert, eine Nachricht entfernt oder
versucht, einen ausgehandelten Parameter herabzustufen, bricht den Hash, und
die Signatur-/MAC-Verifikation schlägt fehl. Das ist es, was die künftige
Cipher-Agilität (§4) sicher macht: Jeder Versuch, die schwächere Option zu
erzwingen, wird erkannt, weil die Wahl innerhalb des gebundenen Transcripts
liegt.

---

## 11. GPU-Bulk-Verschlüsselung (entfernt – die Engine ist CPU-only)

**Entscheidung:** Es gibt keinen GPU-Pfad. Die Engine verschlüsselt auf der
CPU, Punkt. Frühere Entwürfe trugen ein „GPU-Bulk“-Modul hinter einem
Byte-Schwellenwert, aber es fiel stets auf die CPU-Berechnung zurück.

**Warum es entfernt statt als Platzhalter behalten wurde:** Ein Modul namens
`GpuBulk` auszuliefern, das still auf der CPU rechnet, ist irreführend – es
wirbt mit einer Beschleunigung, die es nicht gibt. Der WGSL-Shader aus der
Entwurfsphase führte nur ChaCha20 aus, ohne den Poly1305-Tag, und war nicht
konstantzeitfähig; ihn anzuschließen wäre *Scheinsicherheit* gewesen (ein
Pfad, der verschlüsselt, aber nicht authentifiziert, ist ein Loch, kein
Geschwindigkeitsgewinn). Statt einen Platzhalter zu pflegen, der das System
überzeichnet, ist der ehrliche Schritt für eine veröffentlichte Crate, ihn zu
entfernen und klar zu sagen, dass der Datenpfad CPU-only ist.

**Warum die GPU ohnehin wahrscheinlich die falsche Optimierung ist:**
GPU-Verschlüsselung pro Paket ist langsamer als die CPU, weil die
Roundtrip-Latenz (Upload, Dispatch, Poll, Read-back) die wenigen hundert
Nanosekunden, die ChaCha20 auf einem CPU-Kern braucht, weit übersteigt. Die
GPU lohnt sich nur bei riesigen Stapeln, bei denen Latenz keine Rolle spielt
– und selbst dann sättigt eine schnelle CPU-Chiffre (oder einfach mehrere
Kerne) meist zuerst die Netzwerkkarte. Wird ein GPU-Pfad je erneut
betrachtet, muss er durch Messung gerechtfertigt sein und Poly1305- +
Konstantzeit-Garantien tragen; bis dahin ist seine Abwesenheit ein Vorteil,
keine Lücke.

---

## 12. CPU vs. GPU, klar gesagt

Fürs Protokoll, weil es kontraintuitiv ist: Die schwere, einmal pro
Verbindung anfallende Mathematik (Kyber, die Signaturen) gehört auf die
**CPU**, nicht auf die GPU – es gibt kein Volumen, über das parallelisiert
werden könnte. Die einfache, endlos wiederholte Mathematik (AEAD pro Paket)
ist der *einzige* GPU-Kandidat, und selbst der gewinnt nur bei extremem
Massendurchsatz. Daher behält die Architektur die CPU als Engine für alles
bei; ein GPU-Pfad müsste durch Messung gerechtfertigt werden, niemals durch
Intuition – weshalb keiner ausgeliefert wird.

---

## Zusammenfassung der ehrlichen Einschränkungen

Diese werden klar benannt, damit niemand Absicht mit Beweis verwechselt:

1. **Kein externes Sicherheitsaudit.** Ein selbst entwickeltes Protokoll ist
   unbewiesen, bis es von qualifizierten Kryptografen geprüft wurde. Dies
   bleibt der wichtigste Vorbehalt und lässt sich nicht durch Code-Änderungen
   beheben.
2. **Einzelnes PQ-KEM.** Der Schlüsselaustausch ist Kyber768 + X25519
   (hybrid klassisch/PQ), kein Hybrid aus zwei unabhängigen PQ-KEMs.
3. **Teilweise Verkehrsanalyse-Resistenz.** Der **Datenpfad** und die
   **Handshake-Hülle** sind nun verschleiert – jedes Datagramm sieht wie
   Zufallsbytes aus, ohne sichtbaren Typ, session_id, Zähler oder
   Fragment-Struktur, und die Größen sind gepaddet/gejittert (§9). Noch offen:
   die ~8 KB Handshake-Größe und das 2-RTT-Burst-*Timing* bleiben beobachtbar,
   der Handshake-Schlüssel ist standardmäßig pubkey-abgeleitet (ein optionaler
   PSK schließt das), und Cover-Traffic / Pacing sind nicht implementiert. Es ist
   also ein großer Schritt, keine abgeschlossene Eigenschaft.

### Seit dem ersten Entwurf gelöst

- **Gegenseitige Authentifizierung.** Der Handshake war 1,5-RTT (nur der
  Responder authentifiziert sich); er ist jetzt ein Austausch aus 3
  Nachrichten und 2 RTT, bei dem beide Peers ihre Identität nachweisen und
  der Responder kein Vertrauen gewährt, bis das Confirm des Initiators
  verifiziert ist. Siehe §3.
- **PQ-Signaturen integriert.** Die Peer-Authentifizierung ist nun hybrid
  Ed25519 + ML-DSA-65 über `HybridAuth` (alle Teile müssen verifizieren), und
  der Handshake wuchs auf 8192 B, um sie zu tragen. Siehe §3 und §9.
- **GPU-Platzhalter entfernt.** Der irreführende CPU-gestützte
  „GPU-Bulk“-Pfad ist weg; die Engine ist ehrlich CPU-only. Siehe §11.
- **Datenpfad-Frame gehärtet.** Der statische Magic-Wert und das redundante
  Längenfeld wurden entfernt, und der sichtbare Header ist als AEAD
  Associated Data gebunden. Siehe §9.
- **Handshake-Hülle verschleiert.** Statische-Schlüssel Wrap-then-Fragment
  (`hsobf.rs`): die ganze Handshake-Nachricht wird unter einem aus den vorab
  geteilten Identitäten (oder einem PSK) gebootstrappten Schlüssel versiegelt und
  in größen-gejitterte Fragmente mit maskiertem Header aufgeteilt – das alte
  konstante Typ-Byte und der feste Fragment-Burst sind weg. Siehe §9.
- **Datenpfad verschleiert.** QUIC-artiger Header-Schutz (`obf.rs`): Der Header
  wird mit einem Keystream aus einer AEAD-Tag-Probe maskiert, der echte
  Frame-Typ wird in der Payload verschlüsselt, und konfigurierbares
  Längen-Padding verbirgt die Größen – jedes Datagramm sieht jetzt wie
  Zufallsbytes aus. Die Handshake-Hülle bleibt Klartext (Phase 2). Siehe §9.
- **Replay-Fenster.** Von 64 auf 2048 Einträge erweitert (WireGuard-Maßstab).
  Siehe §6.
