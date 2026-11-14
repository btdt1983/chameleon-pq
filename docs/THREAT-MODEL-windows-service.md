# Threat-model review: Windows service and control pipe

Status: M5c review, 2026-11-13, against the code at the time of the M5b branch.
Scope: the privileged Windows service (`chameleon-pq.exe service run`), its named
pipe, its data folder, the kill switch and the policy file. The tunnel protocol
itself is out of scope here; it is covered by `DESIGN.md` and the planned audit.

It reviews section 7 of `DESIGN-windows-service.md` row by row: is each promise
true in the code, where is the evidence, and what is still open. Where a promise
was not kept, this file says so instead of adjusting the claim.

## Assets and attackers

Assets: the machine's private keys (`config.toml`), the right to start and stop
the tunnel and the kill switch, and the machine's network connectivity.

Attackers considered:

* **A standard local user**, or malware running as one. May open the pipe.
* **A second logged-in session** (fast user switching, RDP). Same rights as a
  standard user; the service has no caller identity yet, so policy applies to
  everyone alike.
* **A network attacker.** Cannot reach the pipe (remote clients are rejected).
* **A local administrator** is trusted. Administrators can stop the service and
  clear the kill switch by design.

## Row-by-row review

| # | Promise (section 7) | Verdict | Evidence / note |
|---|---|---|---|
| 1 | Restricted request set; policy checked server-side; no paths or addresses in requests | **Holds** | `Request` has six variants and carries only a profile and a log cursor. Policy is checked in `controller.rs`, not in the GUI. `ClearKillSwitch` is always `Denied` over the pipe. Tests: `policy_*`, `clear_kill_switch_is_denied` |
| 2 | Remote pipe access rejected | **Holds** | `reject_remote_clients(true)` in `pipe_windows.rs` |
| 3 | Pipe DACL without `FILE_CREATE_PIPE_INSTANCE` for users, same descriptor on every instance | **Holds by construction, not tested end to end** | `PIPE_SDDL` (Authenticated Users mask `0x12019b`, reviewed by hand) is applied in `create_instance` for every instance; `the_sddl_is_valid` only checks that it parses. No automated test tries to create an extra instance as a standard user. Worth adding on the VM or in Windows CI before the audit |
| 4 | Pipe squatting: `first_pipe_instance(true)`; client checks the pipe owner | **Holds** | `serve` fails if the name is taken; client `pipe_owner` accepts only SYSTEM or Administrators; verified on the VM ("pipe owner: Administrators") |
| 5 | Malformed or oversized input: length cap, strict types, timeouts, connection cap, fuzz target | **Holds, one gap closed in this PR** | `MAX_FRAME` 64 KiB checked before allocation; `deny_unknown_fields` everywhere; `HELLO_TIMEOUT`; `MAX_CONNECTIONS` 8. **New:** fuzz target `control_codec` (also the policy parser), stable regression test `fuzz_control_codec`, and the write deadline below |
| 6 | DLL hijack of `wintun.dll`: load by full path, verify Authenticode | **Does not hold (open)** | Neither is implemented. `wintun-bindings` loads `wintun.dll` by name with the default search order (application directory first). Mitigations that exist: `service install` refuses a program directory that is not under Program Files, and checks that `wintun.dll` sits next to the exe. A planted DLL therefore needs administrator rights already. Recommended for the installer phase: load by absolute path, pin the SHA-256 published in `README-windows.txt`, or verify the Microsoft signature before first use |
| 7 | Key exposure: config readable by SYSTEM and Administrators only; GUI never sees keys | **Holds** | Data-folder check at start (owner, DACL protected, no junctions) with a real-ACL Windows CI test; `service harden` repairs it; the GUI protocol has no key material. Verified on the VM, including the Explorer "Continue" case that adds a user ACE |
| 8 | Crash leaves host unprotected or stranded: service start cleans or re-engages the kill switch per policy | **Holds in part** | `enforced` and `auto_connect` with a kill switch now re-engage the base rules at start (M5b). A leftover switch under `user_choice` without `auto_connect` is neither cleared nor re-engaged: the GUI shows it as stranded and an administrator clears it (`killswitch off`). A crash with the kill switch engaged keeps the host blocked until the service returns (restart after 5 s and 30 s) |

## Findings from this review

| # | Finding | Severity | Status |
|---|---|---|---|
| F1 | A client that connects, says Hello and never reads its replies kept its connection slot forever; eight of them lock every other session out of the service | Low (availability, local) | **Fixed here:** `WRITE_TIMEOUT` 10 s on every write, test `a_client_that_never_reads_is_dropped` |
| F2 | A client that connects and stays silent after Hello also holds a slot (no idle timeout) | Low (availability, local) | **Open.** The GUI sends requests regularly, but the exact interval is not a contract, so an idle timeout needs a keepalive in the protocol first. Without a caller identity there is no per-user cap either |
| F3 | `wintun.dll` is not verified (row 6) | Low while program files stay admin-only | **Open**, installer phase |
| F4 | Any authenticated user can press Disconnect when the policy allows it (default), including malware running as that user. Policy applies to everyone, administrators included, because requests carry no identity | By design | Documented. `allow_user_disconnect = false` or `auto_connect = true` removes it. A per-user identity is a later step |
| F5 | The kill switch is a firewall default-outbound-Block. Any pre-existing outbound Allow rule overrides it (known gap, see `killswitch.rs`) | Medium for a high-assurance deployment | **Open.** Closing it needs WFP-level filters. The GUI log reports how many such rules exist. Keep in the audit scope |
| F6 | Section 7 names a file (`ipc_windows.rs`) for the `unsafe` code that does not exist; it is in two files | Documentation | **Fixed:** section 7 and the file table now name `pipe_windows.rs` and `winsec_windows.rs` |
| F7 | While the base kill switch is engaged at start, captive-portal sign-in pages cannot be reached | By design | Documented in `README-windows.txt` and the managed policy example |
| F8 | Windows Event Log only receives the refusal to start; connect, auth-failure and rekey events are not forwarded | Operational | Open, listed under "Later" in the design |

## `unsafe` inventory (audit scope)

Counted with `grep -E "unsafe[[:space:]]*(\{|fn |impl )"` on 2026-11-13. The crate
has `#![deny(unsafe_code)]`; each exception below is an explicit
`#[allow(unsafe_code)]`.

| File | Blocks | Purpose |
|---|---|---|
| `src/control/pipe_windows.rs` | 8 | Security descriptor from SDDL, pipe creation with attributes, pipe-owner query |
| `src/control/winsec_windows.rs` | 10 | Data-folder owner and DACL inspection, reparse-point check, Event Log |
| `src/udp.rs` | 1 | `setsockopt` for `SO_RCVBUFFORCE` / `SO_SNDBUFFORCE` |

Section 7 of the design names a file `ipc_windows.rs` that does not exist; the
control-plane `unsafe` lives in the first two files. Every block carries a
`SAFETY:` comment.

## What was added in M5 that needs review

* **Reconnect loop** (`reconnect.rs`, `controller.rs`): attacker-influenced input is
  the server's behaviour only. Delays are bounded (30 s, or 5 min after a failed
  identity check), the log ring is capped (`LOG_CAP`), and a permanent config
  error stops the loop. A server that does not trust the client stays silent and
  is retried every 30 s, which costs one handshake per attempt.
* **Base kill switch at start** (`killswitch.rs`, `service_windows.rs`): a failure
  to engage is logged and not fatal, so a service whose firewall engine is down
  keeps running; under `enforced` the connect then refuses a tunnel without a
  kill switch. The service depends on `BFE` so this is unlikely in practice.
* **Stop versus shutdown**: an administrator stop releases the switch; a system
  shutdown keeps it, and the Block default survives the reboot. The matching risk
  (machine stays blocked if the service cannot start) is documented with its
  remedy.

## Residual risk summary

Highest remaining items for a government deployment: F5 (kill switch can be
bypassed by existing Allow rules), F3 (`wintun.dll` not verified), F2 (idle slot
exhaustion), and the absence of a per-user identity (F4). None is exploitable
by a network attacker; all need a local foothold.
