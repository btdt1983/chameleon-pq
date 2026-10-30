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
        warning = "Adds a limited amount of cover traffic around activity (a few dozen KB per burst, about " +
            "+25% on real traffic).",
    ),
    Throughput(
        "throughput", "High speed", "Hides timing at high speed. Uploads capped at ~460 Mbit/s.",
        warning = "Same limited cover as Balanced, but uploads may run up to ~460 Mbit/s, more than most " +
            "uplinks can carry. Prefer Balanced on a slow upload line.",
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
