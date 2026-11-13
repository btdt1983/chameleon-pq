//! Windows file-system trust for the service's data directory.
//!
//! The service runs as SYSTEM and reads its config (which holds the private key)
//! and its policy from one directory. If a non-administrator could write there,
//! they could plant a policy, swap the config, or redirect SYSTEM's log writes
//! with a junction; if they could read it, they would read the key. So before
//! reading anything the service checks the directory, and refuses to start when
//! the check fails. [`harden_dir`] is the matching fix.
//!
//! Rule: the directory (and every file in it we care about) is owned by SYSTEM
//! or Administrators and its DACL grants access only to SYSTEM, Administrators
//! and CREATOR OWNER (an inherit-only placeholder). The directory's DACL must
//! also be protected, i.e. not inherit the permissive ProgramData defaults.
//!
//! The `unsafe` here is the DACL walk and the Event Log call; it is confined to
//! this file together with `pipe_windows.rs`.

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::ptr;
use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetAce, GetSecurityDescriptorControl, IsWellKnownSid, WinBuiltinAdministratorsSid,
    WinCreatorOwnerSid, WinLocalSystemSid, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
    DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
};
use windows_sys::Win32::System::EventLog::{
    DeregisterEventSource, RegisterEventSourceW, ReportEventW, EVENTLOG_ERROR_TYPE,
};

const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
/// ACE types we understand: access-allowed and access-denied. Anything else
/// (object, callback, ...) makes the check fail rather than be guessed at.
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;
/// Inherit-only ACEs do not apply to the object itself.
const INHERIT_ONLY_ACE: u8 = 0x08;

fn wide(p: &Path) -> Vec<u16> {
    p.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// A reparse point (junction or symlink) in place of a real directory/file.
pub fn is_reparse_point(p: &Path) -> std::io::Result<bool> {
    Ok(std::fs::symlink_metadata(p)?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0)
}

fn sid_text(sid: *mut c_void) -> String {
    let mut out: *mut u16 = ptr::null_mut();
    // SAFETY: `sid` points to a valid SID inside a live security descriptor;
    // `out` is a valid out-pointer.
    #[allow(unsafe_code)]
    unsafe {
        if ConvertSidToStringSidW(sid, &mut out) == 0 || out.is_null() {
            return "<unknown SID>".into();
        }
        let mut len = 0;
        while *out.add(len) != 0 {
            len += 1;
        }
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(out, len));
        LocalFree(out as _);
        s
    }
}

/// `true` for SYSTEM, Administrators and (when `allow_creator_owner`) CREATOR OWNER.
#[allow(unsafe_code)]
fn is_trusted_sid(sid: *mut c_void, allow_creator_owner: bool) -> bool {
    // SAFETY: `sid` is a valid SID inside a live security descriptor.
    unsafe {
        IsWellKnownSid(sid, WinLocalSystemSid) != 0
            || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0
            || (allow_creator_owner && IsWellKnownSid(sid, WinCreatorOwnerSid) != 0)
    }
}

/// Check one file-system object. `require_protected` demands that the DACL does
/// not inherit (used for the directory itself).
#[allow(unsafe_code)]
fn check_object(path: &Path, require_protected: bool) -> Result<(), String> {
    let name = wide(path);
    let mut owner: *mut c_void = ptr::null_mut();
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `name` is NUL-terminated and outlives the call; the out-pointers
    // are valid; unused ones are null as documented for these flags.
    let err = unsafe {
        GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut sd,
        )
    };
    if err != ERROR_SUCCESS {
        return Err(format!(
            "cannot read the permissions of {} (Win32 error {err})",
            path.display()
        ));
    }
    // From here on `sd` must be freed on every path.
    let result = (|| {
        if !is_trusted_sid(owner, false) {
            return Err(format!(
                "{} is owned by {} (must be SYSTEM or Administrators)",
                path.display(),
                sid_text(owner)
            ));
        }
        if dacl.is_null() {
            return Err(format!(
                "{} has no access control list, which means everyone has full access",
                path.display()
            ));
        }
        if require_protected {
            let mut control: u16 = 0;
            let mut rev: u32 = 0;
            // SAFETY: `sd` is the live descriptor returned above.
            if unsafe { GetSecurityDescriptorControl(sd, &mut control, &mut rev) } == 0 {
                return Err(format!(
                    "cannot read the control flags of {}",
                    path.display()
                ));
            }
            if control & SE_DACL_PROTECTED == 0 {
                return Err(format!(
                    "{} inherits permissions from its parent (ProgramData lets every user \
                     read it); run `service harden`",
                    path.display()
                ));
            }
        }
        // SAFETY: `dacl` points into `sd`; AceCount bounds the walk.
        let count = unsafe { (*dacl).AceCount };
        for i in 0..count {
            let mut ace: *mut c_void = ptr::null_mut();
            // SAFETY: index < AceCount; `ace` is a valid out-pointer.
            if unsafe { GetAce(dacl, i as u32, &mut ace) } == 0 || ace.is_null() {
                return Err(format!("cannot read an access entry of {}", path.display()));
            }
            // SAFETY: GetAce returned a pointer to an ACE inside the ACL.
            let header = unsafe { *(ace as *const ACE_HEADER) };
            match header.AceType {
                ACCESS_DENIED_ACE_TYPE => {} // only ever narrows access
                ACCESS_ALLOWED_ACE_TYPE => {
                    if header.AceFlags & INHERIT_ONLY_ACE != 0 {
                        continue;
                    }
                    // SAFETY: an ACCESS_ALLOWED_ACE_TYPE entry has this layout; the
                    // SID starts at `SidStart`.
                    let sid = unsafe {
                        let a = ace as *const ACCESS_ALLOWED_ACE;
                        ptr::addr_of!((*a).SidStart) as *mut c_void
                    };
                    if !is_trusted_sid(sid, true) {
                        return Err(format!(
                            "{} grants access to {} (only SYSTEM and Administrators are allowed); \
                             run `service harden`",
                            path.display(),
                            sid_text(sid)
                        ));
                    }
                }
                other => {
                    return Err(format!(
                        "{} has an access entry of type {other} that this check does not \
                         understand; run `service harden`",
                        path.display()
                    ));
                }
            }
        }
        Ok(())
    })();
    // SAFETY: `sd` was allocated by GetNamedSecurityInfoW; freed exactly once.
    unsafe {
        LocalFree(sd as _);
    }
    result
}

/// Verify the data directory and the named files in it. Everything must be
/// admin-only; the directory must not inherit, must not be a reparse point, and
/// neither may its `logs` subdirectory.
pub fn check_data_dir(dir: &Path, files: &[PathBuf]) -> Result<(), String> {
    match is_reparse_point(dir) {
        Ok(false) => {}
        Ok(true) => return Err(format!("{} is a junction or symlink", dir.display())),
        Err(e) => return Err(format!("cannot inspect {}: {e}", dir.display())),
    }
    check_object(dir, true)?;
    for f in files {
        if f.exists() {
            if is_reparse_point(f).unwrap_or(true) {
                return Err(format!("{} is a junction or symlink", f.display()));
            }
            check_object(f, false)?;
        }
    }
    let logs = dir.join("logs");
    if logs.exists() {
        if is_reparse_point(&logs).unwrap_or(true) {
            return Err(format!("{} is a junction or symlink", logs.display()));
        }
        check_object(&logs, false)?;
    }
    Ok(())
}

const SID_SYSTEM: &str = "*S-1-5-18";
const SID_ADMINS: &str = "*S-1-5-32-544";

fn run_icacls(args: &[&str]) -> Result<(), String> {
    let out = Command::new("icacls")
        .args(args)
        .output()
        .map_err(|e| format!("cannot run icacls: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "icacls {} failed: {}{}",
            args.join(" "),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

/// Make `dir` admin-only: no inheritance, full control for SYSTEM and
/// Administrators only, children reset to inherit from it, owner Administrators.
/// Idempotent. Uses well-known SIDs, so it works on any Windows language.
///
/// No path policy here (see [`harden_data_dir`]); this is the raw operation.
pub fn apply_admin_only(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    let d = dir.to_string_lossy().to_string();
    let grant_system = format!("{SID_SYSTEM}:(OI)(CI)F");
    let grant_admins = format!("{SID_ADMINS}:(OI)(CI)F");
    // 1. The directory itself: drop inherited entries, keep only ours.
    run_icacls(&[
        &d,
        "/inheritance:r",
        "/grant:r",
        &grant_system,
        &grant_admins,
    ])?;
    // 2. Everything inside: reset to inherit from the now-clean directory.
    //    /L: act on a link itself instead of following it.
    let inner = format!("{d}\\*");
    run_icacls(&[&inner, "/reset", "/T", "/C", "/L"])?;
    // 3. Ownership.
    run_icacls(&[&d, "/setowner", SID_ADMINS, "/T", "/C", "/L"])?;
    Ok(())
}

/// Folders where hardening is allowed: a dedicated subfolder of ProgramData.
/// Hardening re-permissions a whole directory tree, so it must never be pointed
/// at a user's own folders by a typo in `--config`.
pub fn is_acceptable_data_dir(dir: &Path) -> bool {
    let Some(pd) = std::env::var_os("ProgramData") else {
        return false;
    };
    let pd = PathBuf::from(pd);
    let (d, p) = (
        dir.to_string_lossy().to_lowercase(),
        pd.to_string_lossy().to_lowercase(),
    );
    let prefix = format!("{}\\", p.trim_end_matches('\\'));
    d.starts_with(&prefix) && d.len() > prefix.len()
}

pub fn harden_data_dir(dir: &Path) -> Result<(), String> {
    if !is_acceptable_data_dir(dir) {
        return Err(format!(
            "refusing to change permissions of {}: the service config must live in its own \
             folder under %ProgramData% (for example C:\\ProgramData\\Chameleon-PQ)",
            dir.display()
        ));
    }
    apply_admin_only(dir)
}

/// Write an error to the Windows Event Log (Application log, source
/// "ChameleonPQ"). Used when the service cannot trust its own directory and so
/// must not write a log file there. The message text shows without a registered
/// message file; Event Viewer adds a note about that, which is harmless.
#[allow(unsafe_code)]
pub fn report_error_event(message: &str) {
    let source: Vec<u16> = "ChameleonPQ\0".encode_utf16().collect();
    let text: Vec<u16> = message.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: both buffers are NUL-terminated and live across the calls; the
    // handle is checked and released.
    unsafe {
        let h = RegisterEventSourceW(ptr::null(), source.as_ptr());
        if h == 0 {
            return;
        }
        let strings = [text.as_ptr()];
        ReportEventW(
            h,
            EVENTLOG_ERROR_TYPE,
            0,
            1,
            ptr::null_mut(),
            1,
            0,
            strings.as_ptr(),
            ptr::null(),
        );
        DeregisterEventSource(h);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("chameleon-winsec-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn data_dir_must_be_a_subfolder_of_programdata() {
        std::env::set_var("ProgramData", r"C:\ProgramData");
        assert!(is_acceptable_data_dir(Path::new(
            r"C:\ProgramData\Chameleon-PQ"
        )));
        assert!(is_acceptable_data_dir(Path::new(r"c:\programdata\x\y")));
        assert!(!is_acceptable_data_dir(Path::new(r"C:\ProgramData")));
        assert!(!is_acceptable_data_dir(Path::new(r"C:\ProgramData\")));
        assert!(!is_acceptable_data_dir(Path::new(r"C:\ProgramDataEvil\x")));
        assert!(!is_acceptable_data_dir(Path::new(r"C:\Users\me\Desktop")));
    }

    #[test]
    fn hardening_refuses_a_folder_outside_programdata() {
        std::env::set_var("ProgramData", r"C:\ProgramData");
        assert!(harden_data_dir(Path::new(r"C:\Users\me\Desktop")).is_err());
    }

    #[test]
    fn a_hardened_directory_passes_and_a_widened_one_fails() {
        let dir = temp_dir("acl");
        apply_admin_only(&dir).expect("harden");
        let file = dir.join("config.toml");
        std::fs::write(&file, "x").unwrap();
        // A fresh child inherits the clean ACL.
        if let Err(e) = check_data_dir(&dir, &[file.clone()]) {
            // Diagnostic for CI: show the real ACL the check objected to.
            let acl = Command::new("icacls").arg(&dir).output().unwrap();
            let sids = Command::new("icacls")
                .arg(&dir)
                .arg("/save")
                .arg(dir.with_extension("acl.txt"))
                .output()
                .unwrap();
            let saved = std::fs::read(dir.with_extension("acl.txt")).unwrap_or_default();
            panic!(
                "hardened dir passes: {e}\n--- icacls ---\n{}\n--- icacls /save ({:?}) ---\n{}",
                String::from_utf8_lossy(&acl.stdout),
                sids.status,
                String::from_utf16_lossy(
                    &saved
                        .chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect::<Vec<_>>()
                )
            );
        }

        // Add read access for the BUILTIN\Users group (S-1-5-32-545).
        run_icacls(&[&dir.to_string_lossy(), "/grant", "*S-1-5-32-545:(OI)(CI)R"]).unwrap();
        let err = check_data_dir(&dir, &[file]).expect_err("Users:R must be rejected");
        assert!(err.contains("S-1-5-32-545"), "{err}");

        // Hardening again repairs it (idempotent).
        apply_admin_only(&dir).unwrap();
        check_data_dir(&dir, &[]).expect("repaired");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_inheriting_directory_is_rejected() {
        // A plain temp subfolder inherits its parent's ACL (not protected).
        let dir = temp_dir("inherit");
        std::fs::create_dir_all(&dir).unwrap();
        assert!(check_data_dir(&dir, &[]).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_junction_in_place_of_the_logs_folder_is_rejected() {
        let dir = temp_dir("junction");
        apply_admin_only(&dir).unwrap();
        let target = temp_dir("junction-target");
        std::fs::create_dir_all(&target).unwrap();
        // mklink /J needs no elevation.
        let status = Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(dir.join("logs"))
            .arg(&target)
            .output()
            .unwrap();
        assert!(status.status.success(), "mklink failed");
        let err = check_data_dir(&dir, &[]).expect_err("junction must be rejected");
        assert!(err.contains("junction"), "{err}");
        let _ = Command::new("cmd")
            .args(["/C", "rmdir"])
            .arg(dir.join("logs"))
            .output();
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&target);
    }

    #[test]
    fn the_event_log_call_does_not_crash() {
        report_error_event("chameleon-pq test event (safe to ignore)");
    }
}
