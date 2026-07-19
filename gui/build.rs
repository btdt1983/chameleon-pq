// Embeds assets/chameleon.ico into the Windows executable's own resources
// (PE resource, not iced's runtime window icon) so Explorer, the taskbar
// button, and Alt-Tab show the chameleon mark instead of a generic default —
// those are read from the .exe itself. No-op on every other target: the
// `embed-resource` build-dependency itself is Windows-target-gated in
// Cargo.toml, so this whole function must be too (there's nothing to call
// otherwise).
fn main() {
    #[cfg(target_os = "windows")]
    {
        println!("cargo:rerun-if-changed=assets/chameleon.rc");
        println!("cargo:rerun-if-changed=assets/chameleon.ico");
        // The compile result documents build/link failure modes we can't
        // recover from anyway (missing rc.exe/windres) — a broken icon
        // resource shouldn't fail the whole build, so this is intentionally
        // not `.unwrap()`ed; `cargo:warning` still surfaces problems.
        let _ = embed_resource::compile("assets/chameleon.rc", embed_resource::NONE);
    }
}
