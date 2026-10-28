package com.chameleonpq.android

import android.content.Context
import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * On-device diagnostics for when `adb logcat` isn't at hand. Every line is
 * appended to `filesDir/diag.log` immediately (so it survives a process
 * death), and the tail is exposed to the UI. Contains no config contents or
 * key material — step names and error messages only.
 */
object DiagLog {
    private const val TAG = "chameleonpq"
    private const val MAX_LINES = 60

    private var file: File? = null
    private val fmt = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)

    private val _lines = MutableStateFlow<List<String>>(emptyList())
    val lines: StateFlow<List<String>> = _lines.asStateFlow()

    @Synchronized
    fun init(context: Context) {
        if (file != null) return
        val f = File(context.filesDir, "diag.log")
        file = f
        val previous = try { if (f.exists()) f.readLines().takeLast(MAX_LINES) else emptyList() } catch (_: Exception) { emptyList() }
        _lines.value = previous

        val old = Thread.getDefaultUncaughtExceptionHandler()
        Thread.setDefaultUncaughtExceptionHandler { t, e ->
            log("CRASH on thread ${t.name}: ${Log.getStackTraceString(e).lineSequence().take(8).joinToString(" | ")}")
            old?.uncaughtException(t, e)
        }
    }

    @Synchronized
    fun log(msg: String) {
        Log.i(TAG, msg)
        val line = "${fmt.format(Date())} $msg"
        _lines.value = (_lines.value + line).takeLast(MAX_LINES)
        try { file?.appendText(line + "\n") } catch (_: Exception) { }
    }
}
