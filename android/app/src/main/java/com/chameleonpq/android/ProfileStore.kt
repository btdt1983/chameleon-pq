package com.chameleonpq.android

import android.content.Context

/**
 * Traffic profiles, as offered in the app. [key] is the config-file spelling
 * the Rust side parses (`nativeSetProfile`); the labels follow the desktop GUI.
 */
enum class TrafficProfile(val key: String, val label: String, val blurb: String, val warning: String? = null) {
    Off("off", "Fastest", "No timing shaping. Full line speed, like WireGuard."),
    Balanced("balanced", "Balanced", "Hides when you are active. Up to ~115 Mbit/s, silent when idle."),
    Throughput("throughput", "High speed", "Hides timing at high speed. Up to ~460 Mbit/s, silent when idle."),
    Stealth(
        "stealth", "Max privacy", "Constant traffic around the clock, capped at ~5 Mbit/s.",
        warning = "Sends cover traffic all the time while connected: uses mobile data and battery.",
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
