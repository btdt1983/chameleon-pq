# Chameleon-PQ for Android

MVP Android client. See `/root/.claude/plans/nifty-enchanting-crab.md` (or the
git history around this directory's introduction) for the full design —
this file only covers what's needed to build and run it.

## Layout

```
android/
├── rust-jni/     Rust crate — JNI bridge between the Kotlin app shell and
│                 the core `chameleon` crate (repo root). Own Cargo.toml,
│                 NOT a workspace member (repo root has no [workspace]),
│                 same pattern as ../gui and ../fuzz.
└── app/          Gradle project — Kotlin app shell (VpnService, UI).
```

The core crate needed exactly one addition to support this:
`TunPair::from_raw_fd` (`src/tun_iface.rs`) — everything else Android-specific
lives in `rust-jni/` or `app/`.

## Building the native library

No Gradle-integrated `cargo ndk` task for v1 (deliberate — see the plan's
Phase D tradeoff). Build the `.so` manually before a Gradle build picks it up:

```sh
# One-time setup:
rustup target add aarch64-linux-android
cargo install cargo-ndk
# Install the NDK (any recent version) and point ANDROID_NDK_HOME at it.

# Build (arm64-v8a only for v1 — matches the real test device; see the plan
# for why x86/x86_64/armeabi-v7a are out of scope):
cargo ndk -t arm64-v8a -P 34 \
  -o android/app/src/main/jniLibs \
  --manifest-path android/rust-jni/Cargo.toml \
  build --release
```

`-P 34` matches this app's `minSdk`/`targetSdk` (Android 14). Output lands at
`android/app/src/main/jniLibs/arm64-v8a/libchameleon_jni.so`, loaded by
`NativeBridge.kt` via `System.loadLibrary("chameleon_jni")`. Re-run this
whenever `rust-jni/` or the core crate changes; Gradle does not do it for you.

## Packaging note

`android/` is excluded from the published `chameleon-pq` crates.io package
(root `Cargo.toml`'s `exclude`). `rust-jni/Cargo.lock` IS git-tracked (matches
`../gui/Cargo.lock`, `../fuzz/Cargo.lock`) — everything else under `android/`
that's build output or local toolchain state is gitignored (see the root
`.gitignore`'s Android section).
