package com.chameleonpq.android

import android.content.Intent
import android.provider.Settings
import androidx.activity.compose.BackHandler
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.FilterChip
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay

private enum class Phase { Off, Busy, On }

@Composable
fun AppRoot(
    hasConfig: Boolean,
    importResult: String?,
    serverAddr: String?,
    profile: TrafficProfile,
    onProfile: (TrafficProfile) -> Unit,
    onImport: () -> Unit,
    onToggleConnection: (currentlyActive: Boolean) -> Unit,
) {
    var showDiag by rememberSaveable { mutableStateOf(false) }
    if (showDiag) {
        BackHandler { showDiag = false }
        DiagnosticsScreen(onBack = { showDiag = false })
    } else {
        MainScreen(hasConfig, importResult, serverAddr, profile, onProfile, onImport, onToggleConnection, onShowDiagnostics = { showDiag = true })
    }
}

@Composable
private fun MainScreen(
    hasConfig: Boolean,
    importResult: String?,
    serverAddr: String?,
    profile: TrafficProfile,
    onProfile: (TrafficProfile) -> Unit,
    onImport: () -> Unit,
    onToggleConnection: (currentlyActive: Boolean) -> Unit,
    onShowDiagnostics: () -> Unit,
) {
    val status by ChameleonVpnService.status.collectAsState()
    val active = status.connected || status.connecting
    val phase = when {
        status.connected -> Phase.On
        status.connecting -> Phase.Busy
        else -> Phase.Off
    }
    val context = LocalContext.current

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Image(painterResource(R.drawable.ic_chameleon), contentDescription = null, modifier = Modifier.height(32.dp))
            Spacer(Modifier.width(10.dp))
            Text("Chameleon-PQ", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.weight(1f))
            TextButton(onClick = onShowDiagnostics) { Text("Diagnostics") }
        }

        Spacer(Modifier.height(36.dp))
        PowerButton(phase = phase, enabled = hasConfig, onClick = { onToggleConnection(active) })
        Spacer(Modifier.height(20.dp))

        val statusText = when {
            status.reconnecting -> "Reconnecting…"
            status.connecting -> "Connecting…"
            status.connected -> "Protected"
            else -> "Not connected"
        }
        Text(
            statusText,
            style = MaterialTheme.typography.headlineSmall,
            fontWeight = FontWeight.SemiBold,
            color = phaseColor(phase),
        )
        Spacer(Modifier.height(4.dp))
        Text(
            when {
                status.reconnecting -> "Traffic is blocked until the tunnel is back"
                status.connected -> ConnectionClock(status.connectedSinceMs)
                !hasConfig -> "Import a config to get started"
                else -> "Tap the button to connect"
            },
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
        status.error?.let {
            Spacer(Modifier.height(8.dp))
            Text("Error: $it", color = MaterialTheme.colorScheme.error, textAlign = TextAlign.Center)
        }

        Spacer(Modifier.height(28.dp))
        Card {
            InfoRow("Server", serverAddr ?: "—")
            Spacer(Modifier.height(12.dp))
            Row(Modifier.fillMaxWidth()) {
                Stat("↓ Download", if (status.connected) formatRate(status.rxRate) else "—", Modifier.weight(1f))
                Stat("↑ Upload", if (status.connected) formatRate(status.txRate) else "—", Modifier.weight(1f))
            }
            if (status.connected) {
                Spacer(Modifier.height(12.dp))
                Row(Modifier.fillMaxWidth()) {
                    Stat("Received", formatBytes(status.rxBytes), Modifier.weight(1f))
                    Stat("Sent", formatBytes(status.txBytes), Modifier.weight(1f))
                }
            }
        }

        Spacer(Modifier.height(12.dp))
        ProfileCard(profile, onProfile)

        if (status.connected || status.reconnecting) {
            Spacer(Modifier.height(12.dp))
            KillSwitchCard(lockdown = status.lockdown, onOpenSettings = {
                context.startActivity(Intent(Settings.ACTION_VPN_SETTINGS).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            })
        }

        Spacer(Modifier.height(20.dp))
        OutlinedButton(onClick = onImport, enabled = !active) {
            Text(if (hasConfig) "Replace config" else "Import config")
        }
        importResult?.let {
            Text(it, modifier = Modifier.padding(top = 8.dp), color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

@Composable
private fun phaseColor(phase: Phase): Color = when (phase) {
    Phase.On -> StatusColors.Connected
    Phase.Busy -> StatusColors.Busy
    Phase.Off -> StatusColors.Off
}

/** Live "HH:MM:SS" since [sinceMs]; ticks every second independent of status updates. */
@Composable
private fun ConnectionClock(sinceMs: Long): String {
    var now by remember { mutableLongStateOf(System.currentTimeMillis()) }
    LaunchedEffect(sinceMs) {
        while (true) {
            now = System.currentTimeMillis()
            delay(1000)
        }
    }
    return "Connected for " + formatDuration((now - sinceMs) / 1000)
}

@Composable
private fun PowerButton(phase: Phase, enabled: Boolean, onClick: () -> Unit) {
    val color = phaseColor(phase)
    val pulse = rememberInfiniteTransition(label = "pulse")
    val busyAlpha by pulse.animateFloat(
        initialValue = 0.35f, targetValue = 1f,
        animationSpec = infiniteRepeatable(tween(800), RepeatMode.Reverse), label = "busy",
    )
    val ringAlpha = if (phase == Phase.Busy) busyAlpha else 1f
    Box(
        modifier = Modifier
            .size(176.dp)
            .clip(CircleShape)
            .background(MaterialTheme.colorScheme.surface)
            .alpha(if (enabled) 1f else 0.4f)
            .clickable(enabled = enabled, onClick = onClick),
        contentAlignment = Alignment.Center,
    ) {
        Canvas(Modifier.fillMaxSize().padding(8.dp)) {
            val ring = 6.dp.toPx()
            drawCircle(color.copy(alpha = 0.18f * ringAlpha), style = Stroke(ring))
            drawCircle(color.copy(alpha = ringAlpha), radius = size.minDimension / 2 - ring / 2, style = Stroke(ring))
        }
        Canvas(Modifier.size(64.dp)) {
            val w = 6.dp.toPx()
            val inset = w / 2
            drawArc(
                color = color, startAngle = -50f, sweepAngle = 280f, useCenter = false,
                topLeft = Offset(inset, inset + 6.dp.toPx()),
                size = Size(size.width - w, size.height - w - 6.dp.toPx()),
                style = Stroke(w, cap = StrokeCap.Round),
            )
            drawLine(color, Offset(size.width / 2, inset), Offset(size.width / 2, size.height * 0.5f), strokeWidth = w, cap = StrokeCap.Round)
        }
    }
}

@Composable
private fun Card(content: @Composable () -> Unit) {
    Column(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp))
            .background(MaterialTheme.colorScheme.surface)
            .padding(16.dp),
    ) { content() }
}

@Composable
private fun InfoRow(label: String, value: String) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, fontFamily = FontFamily.Monospace)
    }
}

@Composable
private fun Stat(label: String, value: String, modifier: Modifier = Modifier) {
    Column(modifier) {
        Text(label, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Medium)
    }
}

/** Traffic-profile picker; a change applies live when connected (see ChameleonVpnService). */
@Composable
private fun ProfileCard(selected: TrafficProfile, onSelect: (TrafficProfile) -> Unit) {
    val onCellular by ChameleonVpnService.onCellular.collectAsState()
    Card {
        Text("Traffic profile", fontWeight = FontWeight.SemiBold)
        Spacer(Modifier.height(8.dp))
        Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            for (p in TrafficProfile.values()) {
                FilterChip(
                    selected = p == selected,
                    onClick = { onSelect(p) },
                    label = { Text(p.label) },
                )
            }
        }
        Spacer(Modifier.height(8.dp))
        Text(selected.blurb, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        selected.warning?.let {
            Spacer(Modifier.height(4.dp))
            Text(it, style = MaterialTheme.typography.bodySmall, color = StatusColors.Busy)
            if (onCellular && selected != TrafficProfile.Off) {
                Spacer(Modifier.height(8.dp))
                Text(
                    "You are on mobile data right now.",
                    style = MaterialTheme.typography.bodySmall,
                    fontWeight = FontWeight.SemiBold,
                    color = StatusColors.Warning,
                )
                TextButton(onClick = { onSelect(TrafficProfile.Off) }) { Text("Switch to Fastest") }
            }
        }
    }
}

/**
 * Android only lets the USER enable the real kill switch ("Always-on VPN" +
 * "Block connections without VPN"); an app can read it but not set it. So we
 * show whether it is on and otherwise point at the right settings page.
 */
@Composable
private fun KillSwitchCard(lockdown: Boolean, onOpenSettings: () -> Unit) {
    Column(
        Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(16.dp))
            .background(if (lockdown) MaterialTheme.colorScheme.surface else StatusColors.Warning.copy(alpha = 0.14f))
            .padding(16.dp),
    ) {
        if (lockdown) {
            Text("Kill switch active", fontWeight = FontWeight.SemiBold, color = StatusColors.Connected)
            Text(
                "Android blocks all traffic outside the VPN.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else {
            Text("Kill switch not enabled", fontWeight = FontWeight.SemiBold, color = StatusColors.Warning)
            Text(
                "While the tunnel is up and during reconnects the app blocks leaks itself, but if " +
                    "Android stops the app your traffic would use the open network. Turn on " +
                    "\"Always-on VPN\" and \"Block connections without VPN\" for Chameleon-PQ.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.height(8.dp))
            Button(
                onClick = onOpenSettings,
                colors = ButtonDefaults.buttonColors(containerColor = StatusColors.Warning, contentColor = Color.White),
            ) { Text("Open VPN settings") }
        }
    }
}

@Composable
private fun DiagnosticsScreen(onBack: () -> Unit) {
    val diag by DiagLog.lines.collectAsState()
    val clipboard = LocalClipboardManager.current
    val scroll = rememberScrollState()
    LaunchedEffect(diag.size, diag.lastOrNull()) { scroll.scrollTo(scroll.maxValue) }
    Column(Modifier.fillMaxSize().padding(16.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            TextButton(onClick = onBack) { Text("← Back") }
            Spacer(Modifier.weight(1f))
            Button(onClick = { clipboard.setText(AnnotatedString(diag.joinToString("\n"))) }) { Text("Copy log") }
        }
        Spacer(Modifier.height(8.dp))
        Text(
            diag.joinToString("\n"),
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            fontSize = 11.sp,
            modifier = Modifier.weight(1f).fillMaxWidth().verticalScroll(scroll),
        )
    }
}
