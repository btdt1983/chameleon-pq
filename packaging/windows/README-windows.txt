Chameleon-PQ — Windows x64 bundle
=================================

Experimental hybrid post-quantum VPN (ML-KEM-768 + X25519, Ed25519 + ML-DSA-65).
UNAUDITED — for learning and reference, not for protecting real traffic.

Contents
--------
  chameleon-gui.exe    Desktop client (recommended). Connect/disconnect UI.
  chameleon-pq.exe      Command-line tool (keygen / check / server / client).
  wintun.dll            TUN driver (amd64). MUST stay in the same folder as
                        the .exe you run — the client loads it at runtime.
  config.example.toml   Annotated example configuration.
  README-windows.txt    This file.

Requirements
------------
  * 64-bit Windows.
  * Run as Administrator. Creating the TUN adapter (via Wintun) needs
    elevated rights; without admin the connect step fails.
  * Keep wintun.dll next to the executable. Do not move or rename it.

Quick start (GUI, standalone)
-----------------------------
  Used when the Windows service below is NOT installed.
  1. Right-click chameleon-gui.exe -> "Run as administrator".
  2. Point it at your config (or generate keys first with the CLI, below).

Managed mode (Windows service, no administrator for the user)
--------------------------------------------------------------
  EXPERIMENTAL - not yet verified on a real machine. For a managed
  installation an administrator installs a background service that owns the
  tunnel, routes, DNS and kill switch. Users then run chameleon-gui.exe as
  themselves; it only connects/disconnects and picks a traffic profile.

  Administrator, once (elevated prompt). The program and wintun.dll must be
  in a folder only administrators can write, normally under Program Files;
  the installer refuses anything else:
      chameleon-pq.exe --config "C:\ProgramData\Chameleon-PQ\config.toml" service install
      sc start ChameleonPQ

  Check the registered path is quoted:   sc qc ChameleonPQ
  Service log:   C:\ProgramData\Chameleon-PQ\logs\service.log
  Remove:        chameleon-pq.exe service uninstall
  Debug in a console instead of the SCM:
      chameleon-pq.exe --config config.toml service console

  If the service is installed, the GUI always runs in managed mode: it has
  no config/server fields and never starts a tunnel of its own. If the
  kill switch is left on, an administrator can remove it with:
      chameleon-pq.exe killswitch off

Quick start (CLI)
-----------------
  Generate a keypair:
      chameleon-pq.exe keygen

  Validate a config:
      chameleon-pq.exe --config config.toml check

  Run as client:
      chameleon-pq.exe --config config.toml client --server <host>:51820

  See config.example.toml for every option (identity keys, network,
  tun, obfuscation, traffic profile, engine tuning).

Third-party notice — Wintun
---------------------------
  wintun.dll is the official, unmodified Wintun 0.14.1 (amd64) driver by
  WireGuard LLC (https://www.wintun.net/), redistributed here for
  convenience. It is Microsoft-signed (EV code signing).
      SHA-256: e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce
  Wintun is a separate work under its own license; see https://www.wintun.net/
  for terms. Chameleon-PQ merely loads it at runtime.
