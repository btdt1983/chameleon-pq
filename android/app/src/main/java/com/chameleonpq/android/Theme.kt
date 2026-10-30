package com.chameleonpq.android

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

/** Status colours, shared by the power button, status text and notifications. */
object StatusColors {
    val Connected = Color(0xFF3DDC84)
    val Busy = Color(0xFFF5B642)
    val Off = Color(0xFF7C8A82)
    val Warning = Color(0xFFFF6B5E)
}

// Background matches the launcher icon (#0E1B14) so the app feels like one piece.
private val Dark = darkColorScheme(
    primary = StatusColors.Connected,
    background = Color(0xFF0E1B14),
    surface = Color(0xFF16261D),
    surfaceVariant = Color(0xFF1E3226),
    onBackground = Color(0xFFE6F0EA),
    onSurface = Color(0xFFE6F0EA),
    onSurfaceVariant = Color(0xFFA7B8AE),
    error = StatusColors.Warning,
)

private val Light = lightColorScheme(
    primary = Color(0xFF14833F),
    background = Color(0xFFF4F8F5),
    surface = Color(0xFFFFFFFF),
    surfaceVariant = Color(0xFFE3EDE6),
    onBackground = Color(0xFF0E1B14),
    onSurface = Color(0xFF0E1B14),
    onSurfaceVariant = Color(0xFF4A5A50),
    error = Color(0xFFC0392B),
)

@Composable
fun ChameleonTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = if (isSystemInDarkTheme()) Dark else Light, content = content)
}
