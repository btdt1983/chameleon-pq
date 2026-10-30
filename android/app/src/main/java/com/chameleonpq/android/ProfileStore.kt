package com.chameleonpq.android

import android.content.Context

/**
 * Traffic profiles, as offered in the app. [key] is the config-file spelling
 * the Rust side parses (`nativeSetProfile`); the labels follow the desktop GUI.
 */
enum class TrafficProfile(val key: String, val label: String, val blurb: String, val warning: String? = null) {
    Off("off", "Fastest", "No timing shaping. Full line speed, like WireGuard."),
    Balanced(
        "balanced", "Balanced", "Hides when you are active. Uploads capped at ~115 Mbit/s.",
        warning = "Every bit of activity triggers a burst of cover traffic at full speed. Measured: tens of MB " +
            "per minute even when idle, up to several GB per hour. Uses mobile data and battery.",
    ),
    Throughput(
        "throughput", "High speed", "Hides timing at high speed. Uploads capped at ~460 Mbit/s.",
        warning = "Cover bursts reach ~170 Mbit/s on the wire, more than most uplinks. On a ~150 Mbit/s line " +
            "this can starve download ACKs: speed tests fail or fluctuate. Uses a lot of mobile data and battery.",
    ),
    Stealth(
        "stealth", "Max privacy", "Constant traffic around the clock, capped at ~5 Mbit/s.",
        warning = "Sends cover traffic all the time while connected and slows downloads to ~5-10 Mbit/s. " +
            "Uses mobile data and battery.",
    ),
}

/** The user's choice, kept across app restarts. Default matches the config default (`off`). */
object ProfileStore {
    private const val PREFS = "settings"
    private const val KEY = "traffic_profile"

    fun get(context: Context): TrafficProfile {
        val key = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString(KEY, null)
        return TrafficProfile.values().firstOrNull { it.key == key } ?: TrafficProfile.Off
    }

    fun set(context: Context, profile: TrafficProfile) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putString(KEY, profile.key).apply()
    }
}
