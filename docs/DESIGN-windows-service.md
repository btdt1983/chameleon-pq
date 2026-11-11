# Windows client: privileged service + unprivileged GUI

Status: **proposal** (nothing implemented). Target: managed, enterprise-deployable
Windows client. Written against v0.9.3.

## 1. Problem

Today `chameleon-gui.exe` does everything in-process and must be started with
"Run as administrator" (`packaging/windows/README-windows.txt`): it creates the
Wintun adapter, installs routes, sets DNS, engages the kill switch
(PowerShell firewall rules) and runs the tunnel loops (`gui/src/main.rs`,
`Message::Connect`, ~L524-640).

Consequences for a managed fleet:

- Users have no admin rights, so the client cannot run at all.
- Giving users admin rights makes them able to disable the kill switch, read the
  private key, and point the client at any server.
- The kill switch lives in the GUI process (`App.ks`). Closing or crashing the GUI
  leaves the machine either unprotected or stranded offline (`ks_orphan`).
- No connection before logon, no central policy.

## 2. Goals / non-goals

Goals

1. The tunnel, routes, DNS and kill switch are owned by a **Windows service running
   as LocalSystem**. The GUI runs as the normal user with no elevation.
2. The user can only do what an administrator-provisioned **policy** allows.
3. The service survives GUI crashes/logoff; kill-switch state is not tied to a UI.
4. Core logic stays cross-platform and testable on Linux CI.

Non-goals (separate work): MSI/installer, code signing, user identity/SSO,
multi-peer server, Slint migration, Event Log forwarding details. This design must
not block them (see section 9).

## 3. Process model

```
 user session                         session 0 / SYSTEM
┌──────────────────┐   named pipe    ┌────────────────────────────────────┐
│ chameleon-gui.exe│ ◄─────────────► │ chameleon-pq.exe service           │
│ (unprivileged)   │  JSON frames    │  ├─ IPC server (pipe)              │
│  - connect/disc. │                 │  ├─ Supervisor (state machine)     │
│  - status, log   │                 │  │    └─ Client::connect, TUN,     │
│  - profile pick  │                 │  │       routes, DNS, KillSwitch   │
└──────────────────┘                 │  └─ Policy + config (ProgramData)  │
                                     └────────────────────────────────────┘
```

- The service is a subcommand of the existing binary (`chameleon-pq.exe service`),
  registered with the SCM via the `windows-service` crate. Same binary means one
  artifact to sign/audit.
- Start type: automatic. Runs `Supervisor` regardless of whether any user is
  logged on.
- GUI and CLI are both clients of the pipe. `chameleon-pq.exe client` (foreground,
  admin) stays as the dev/debug path.

## 4. Code structure

New module `src/control/` in the core crate, **cross-platform except the pipe
transport**:

| File | Content | Platform |
|---|---|---|
| `protocol.rs` | `Request`, `Response`, `Event`, `State` types, versioning, frame codec | all |
| `supervisor.rs` | Connect/disconnect state machine; the logic moved out of `gui/src/main.rs` (TUN create, routes, DNS, kill switch, `Client::connect`, orphan cleanup) | all |
| `policy.rs` | Policy model + loading + validation | all |
| `ipc_windows.rs` | Named-pipe server (tokio `named_pipe`), ACL, peer checks | Windows |
| `service_windows.rs` | SCM entry point, stop/shutdown handling | Windows |

`gui/src/main.rs` shrinks to: a `ServiceClient` (async pipe client) plus the
existing view code. `Message::Connect` becomes "send `Connect`, render state
events". The 1 s `Tick` poll is replaced by pushed `State` events.

Because `supervisor.rs` and `protocol.rs` are platform-neutral, they can be tested
with the existing mock TUN (`TunPair::new_mock`) in `tests/`.

Open: keep an in-process "direct" backend for Linux/dev (Supervisor called
directly, no pipe), or Windows-only service? Recommendation: both, behind a small
`ControlBackend` trait, so Linux dev and CI keep working.

## 5. IPC protocol

- Transport: named pipe `\\.\pipe\chameleon-pq-control`, byte mode.
- Framing: 4-byte big-endian length + UTF-8 JSON, **max 64 KiB**, read timeout,
  max N concurrent connections (e.g. 8).
- First message each way is `Hello { protocol_version }`; mismatched major version
  closes the connection with a readable error (GUI and service can be updated at
  different moments).

Requests (GUI to service):

| Request | Notes |
|---|---|
| `GetState` | Snapshot (also pushed on change). |
| `Connect { profile: Option<ProfileName> }` | Server/keys come from the admin config, never from the request. |
| `Disconnect` | Allowed or denied by policy. |
| `SetProfile { profile }` | Live re-profile (`Client::set_traffic`), only profiles the policy allows. |
| `ClearKillSwitch` | Policy-gated; default admin-only (see 6). |
| `GetLog { since }` | Tail of the service log for the GUI log pane. |

Events (service to GUI): `State { phase, status, warnings, kill_switch, policy_summary }`
where `phase` is `Disconnected | Connecting | Connected | Reconnecting | Error(code)`.

**Hard rule:** the protocol carries no file paths, no raw config, no server
address, no free-form commands. Every field is an enum or a bounded value. A
compromised or malicious user process must not be able to make a SYSTEM process
read a file of its choosing or talk to a server of its choosing. (The current GUI
"Browse config" and editable server field disappear in managed mode.)

## 6. Policy and configuration

The folder holding the service config is the **data folder**; it must be a
dedicated subfolder of `%ProgramData%` (for example
`C:\ProgramData\Chameleon-PQ\`).

| File | Contents | Access |
|---|---|---|
| `<config>.toml` | Existing `AppConfig`, **including secret keys** | SYSTEM + Administrators only |
| `policy.toml` | What users may do (optional) | SYSTEM + Administrators only |
| `logs\service.log` | Service log | SYSTEM + Administrators only |

Nobody else needs access: the GUI never reads these files, it gets everything it
shows (including a summary of the policy) from the service over the pipe.

**Startup order, and why.** Before the service reads or writes anything it
verifies the data folder; only then does it start its log, load the config and
load the policy:

1. The folder (and the config, policy and `logs` in it) must be owned by SYSTEM or
   Administrators, grant access to nobody but SYSTEM, Administrators and CREATOR
   OWNER, and the folder's DACL must be *protected* (not inheriting ProgramData's
   permissive defaults). The folder and `logs` must not be junctions or symlinks.
   On failure the service **refuses to start**, exits with service-specific code 2
   and writes the reason to the Windows Event Log (Application, source
   `ChameleonPQ`). It does not write a log file into a folder it just decided it
   cannot trust.
2. A *missing* `policy.toml` means the default policy. That is only safe because of
   step 1: otherwise any user could plant the file.
3. An *invalid* policy (unknown key, bad value, profile list that excludes the
   config's own profile, `enforced` without `tun.route_all`) also stops the service.

`service install` locks the folder down first (`icacls` with well-known SIDs, so it
works on any Windows language), and `service harden` re-applies that and the crash
recovery settings to an installed service. Hardening re-permissions a whole tree,
so it refuses any folder that is not a subfolder of `%ProgramData%`.

Policy fields:

```toml
allow_user_disconnect = true                  # connecting is always allowed
allowed_profiles   = ["balanced", "stealth"]  # omit = all; must include the config's profile
kill_switch        = "user_choice"            # user_choice | enforced | off
allow_update_check = false                    # GUI GitHub check; off by default when managed
```

`auto_connect` is intentionally not offered yet: it needs a reconnect/backoff
design first, and an option that does nothing is worse than none.

`kill_switch`:

* `user_choice`: follow `tun.kill_switch` in the service config (today's behaviour).
* `off`: never engage it.
* `enforced`: engaged at **every connect**, whatever the config says, and kept
  engaged when a user disconnects (the user is offline rather than unprotected).
  A connection whose kill switch could not be engaged is closed. Users cannot
  clear it; administrators can (`chameleon-pq.exe killswitch off`, or stopping the
  service). This is **not** "traffic blocked whenever the service runs": engaging
  needs the TUN adapter to exist, so it takes effect from the first connect.
  `allow_user_disconnect = false` is the stricter knob (no Disconnect at all).

The pipe protocol is version 2: the pushed state carries a policy summary so the
GUI can offer only the allowed profiles and hide Disconnect or the update check.
The service enforces the policy regardless of what the GUI shows.

**Crash recovery.** The service is registered to restart 5 s and then 30 s after a
crash, and only after a crash: a deliberate exit with an error code (like the
folder check above) must not become a restart loop. The tunnel does not come back
on its own; the service and its pipe do, so a user can reconnect.

Later (not now): the same fields read from `HKLM\Software\Policies\Chameleon-PQ`
(ADMX/GPO/Intune) with registry taking precedence over `policy.toml`.

## 7. Security design

Threat: an unprivileged local user (or malware running as that user) talks to
the pipe, or impersonates the service/GUI.

| Risk | Mitigation |
|---|---|
| Arbitrary user controls SYSTEM service | Restricted request set (section 5); policy checks server-side; no paths/addresses in requests |
| Remote pipe access | `PIPE_REJECT_REMOTE_CLIENTS` |
| Wrong principals on the pipe | DACL via SDDL `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;AU)`; later narrowed to a dedicated local group. The Authenticated Users mask is an explicit `FILE_GENERIC_READ \| FILE_GENERIC_WRITE` **without** `FILE_CREATE_PIPE_INSTANCE` (0x4, which shares its bit with `FILE_APPEND_DATA`): the generic `GW` right would let any user create a rogue instance of the pipe and impersonate the service. The same descriptor is applied to every instance, not just the first |
| Pipe squatting (fake service) | Service creates the pipe with `first_pipe_instance(true)`. The GUI keeps tokio's `SECURITY_IDENTIFICATION` QoS (a look-alike server cannot impersonate the user) and requires the pipe object's **owner** to be SYSTEM or Administrators, which a standard user cannot arrange. A process-path check was rejected: anyone can run the installed exe unelevated, or script a pipe from an interpreter under Program Files |
| Malformed/oversized input | Length cap, strict serde types, per-connection timeouts, connection cap, fuzz target for the codec |
| DLL hijack of `wintun.dll` | Load from the install directory (admin-writable only) by full path; no search-path loading; verify Authenticode signature of `wintun.dll` at load |
| Key exposure | `config.toml` readable by SYSTEM/Admins only; the GUI never sees key material |
| Crash leaves host unprotected/stranded | Service start cleans or re-engages the leftover kill switch per policy; the service, not the GUI, owns it |

`unsafe` budget: the core crate has `#![deny(unsafe_code)]`, with a handful of
reviewed exceptions (`udp.rs`, `dns.rs`, `killswitch.rs`, ...). ACL/SDDL and peer
checks need a small amount of `unsafe` (`windows-sys`); confine it to
`ipc_windows.rs`, document each block, and list it in the audit scope up front.

## 8. Behaviour details

- **Service stop/shutdown:** graceful `disconnect_and_wait`, restore routes/DNS,
  then remove the kill switch **unless** policy is `enforced` and the stop is a
  system shutdown (fail-closed is preferred; decision needed, see 10).
- **Multiple sessions** (fast user switching, RDP): one machine-wide tunnel, N
  GUIs; state is broadcast to all; actions are checked against policy, not against
  who asked.
- **Reconnect:** the Supervisor owns reconnect/backoff (today a tunnel drop just
  clears `client` in the GUI).
- **Logging:** keep the "no per-packet DEBUG" rule (it cost ~450 Mbit/s once, see
  the throughput work). Service log to file now; Windows Event Log later for
  connect/auth-failed/rekey.
- **Updates:** no auto-update. The GUI update check is policy-gated (default off
  when managed).

## 9. Forward compatibility

- **Identity (later):** `Connect` already carries no credentials. When per-user
  identity arrives, the service obtains it (user token or certificate) without the
  protocol changing shape; `config.toml` per-machine key is the interim model.
- **Slint migration:** the GUI is only a pipe client plus views, so swapping the
  toolkit does not touch the privileged part.
- **MSI:** installs the service, creates ProgramData with ACLs, places
  `wintun.dll`; nothing here assumes manual setup.

## 10. Decisions needed

1. **Kill switch on shutdown/stop** with `enforced`: fail-closed (stay blocked) or
   release? Recommendation: fail-closed while the service is merely stopped by an
   admin is surprising; release on admin stop, stay engaged on crash.
2. **Always-on:** connect before logon (`auto_connect`), yes or no? Needed for
   domain-joined laptops (GPO, Kerberos at logon).
3. **Direct backend** kept for Linux/dev (recommended) or Windows-only service?
4. **Who may disconnect?** Default `true`, or admin-only for the strictest setup?
5. **Per-machine key** as the interim identity model: acceptable for a pilot?

Defaults implemented (no explicit recommendation was given for 2 and 4, so
these are the conservative picks; both are policy and can change in M4):

- Decision 2: no auto-connect. It will be an opt-in policy field once reconnect/backoff exists.
- Decision 4: users may disconnect (`allow_user_disconnect = true`).
- Until policy exists (M4), `ClearKillSwitch` over the pipe is always `Denied`;
  admins use the elevated `chameleon-pq killswitch off`.

## 11. Milestones (each shippable and testable on its own)

| M | Scope | Verification |
|---|---|---|
| M1 | `protocol.rs` + `supervisor.rs`; GUI calls Supervisor in-process. **No behaviour change.** | Existing tests + new Supervisor tests with mock TUN; Windows regression on the Hyper-V VM |
| M2 | Service host + pipe server + ACLs; CLI `service install/uninstall/run/console` (**implemented**: protocol + codec, controller actor, transport-independent connection server, pipe transport, SCM host) | Linux: duplex-stream tests. Windows CI: real-pipe tests. Manual: install and run the service on the VM |
| M3 | GUI on `ServiceClient` (**implemented**: `control::client`, Windows pipe client with pipe-owner check, GUI service mode; standalone mode kept for Linux/dev). Mode is decided by "service installed", never by pipe reachability, and never changes mid-session | Linux: client tested against the real server over duplex streams; GUI view-model tests. Manual: standard user on the VM |
| M4 | Data-folder checks and hardening, `policy.toml`, enforced kill switch, crash recovery, protocol v2 (**implemented**) | Linux: policy matrix through the controller, GUI policy tests. Windows CI: DACL check against a hardened, widened and inheriting folder, junction rejection. Manual: upgrade steps in `README-windows.txt` |
| M5 | Codec fuzz target, threat-model review, docs | Fuzz in CI; reviewed against section 7 |

MSI/signing (next phase) builds on M4.
