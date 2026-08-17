package com.chameleonpq.android

/**
 * The entire JNI surface — nothing outside this object should touch an
 * `external fun` directly. Matches `android/rust-jni/src/lib.rs`'s four
 * `Java_com_chameleonpq_android_NativeBridge_*` exports one for one; see
 * that file for what each one actually does on the Rust side.
 */
object NativeBridge {
    init {
        System.loadLibrary("chameleon_jni")
    }

    /**
     * Parses [configToml] and returns `{"address","netmask","mtu","dns":[...]}`
     * as JSON — everything [ChameleonVpnService] needs to build a
     * `VpnService.Builder`. Throws (a `RuntimeException`) if the config is
     * invalid — this IS the app's only config-validation step, no second
     * TOML parser exists on the Kotlin side.
     */
    external fun nativeTunParams(configToml: String): String

    /**
     * Starts the tunnel over the already-established tun file descriptor
     * [fd] (from `ParcelFileDescriptor.getFd()`). Blocks the calling thread
     * for the duration of a real network handshake — MUST be called from a
     * background dispatcher (e.g. `Dispatchers.IO`), never from the main
     * thread. Throws on failure.
     */
    external fun nativeStart(fd: Int, configToml: String): Boolean

    /**
     * Tears the tunnel down and does not return until teardown has fully
     * completed. MUST be called from a background dispatcher. The caller's
     * `ParcelFileDescriptor.close()` MUST wait for this to return before
     * closing the fd — see `TunPair::from_raw_fd`'s doc comment for why.
     */
    external fun nativeStop()

    /**
     * Always succeeds (never throws). Returns a JSON status snapshot with
     * keys `connected`, `session_id`, `tx_bytes`, `rx_bytes`, `uptime_secs` —
     * snake_case, matching the Rust struct's field names as-is (no rename).
     */
    external fun nativeStatus(): String
}
