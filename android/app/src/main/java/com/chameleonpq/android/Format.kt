package com.chameleonpq.android

import java.util.Locale

/** Link speeds are shown in bits/s (what speed tests and ISPs use), not bytes/s. */
fun formatRate(bytesPerSec: Long): String {
    val bits = bytesPerSec * 8.0
    return when {
        bits >= 1e9 -> String.format(Locale.US, "%.2f Gbit/s", bits / 1e9)
        bits >= 1e6 -> String.format(Locale.US, "%.1f Mbit/s", bits / 1e6)
        bits >= 1e3 -> String.format(Locale.US, "%.0f kbit/s", bits / 1e3)
        else -> "0 kbit/s"
    }
}

fun formatBytes(bytes: Long): String = when {
    bytes >= 1L shl 30 -> String.format(Locale.US, "%.2f GB", bytes / (1L shl 30).toDouble())
    bytes >= 1L shl 20 -> String.format(Locale.US, "%.1f MB", bytes / (1L shl 20).toDouble())
    bytes >= 1L shl 10 -> String.format(Locale.US, "%.0f KB", bytes / 1024.0)
    else -> "$bytes B"
}

fun formatDuration(totalSeconds: Long): String {
    val s = totalSeconds.coerceAtLeast(0)
    return String.format(Locale.US, "%02d:%02d:%02d", s / 3600, (s % 3600) / 60, s % 60)
}
