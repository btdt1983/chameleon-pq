package com.chameleonpq.android

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat

/**
 * One screen: import a config, then toggle the connection. Status is owned
 * by [ChameleonVpnService] (the single source of truth) and only observed
 * here — this Activity never talks to [NativeBridge] directly except via
 * [ConfigStore]'s validation call during import.
 */
class MainActivity : ComponentActivity() {

    private var hasConfig by mutableStateOf(false)
    private var importResult by mutableStateOf<String?>(null)

    private val notificationPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { /* granted or not, nothing else to do here */ }

    private val vpnPrepareLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            DiagLog.log("activity: vpn prepare result=${result.resultCode}")
            if (result.resultCode == RESULT_OK) {
                startVpnService()
                requestBatteryExemption()
            }
        }

    private val importLauncher =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri == null) return@registerForActivityResult
            try {
                ConfigStore.importFrom(this, uri)
                importResult = "Config imported"
                hasConfig = true
            } catch (e: Exception) {
                importResult = "Import failed: ${e.message}"
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        DiagLog.init(this)
        DiagLog.log("activity: onCreate")

        hasConfig = ConfigStore.hasConfig(this)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }

        setContent {
            MaterialTheme {
                Surface(modifier = Modifier.fillMaxSize()) {
                    MainScreen(
                        hasConfig = hasConfig,
                        importResult = importResult,
                        onImport = { importLauncher.launch(arrayOf("*/*")) },
                        onToggleConnection = { currentlyActive ->
                            if (currentlyActive) disconnect() else connect()
                        },
                    )
                }
            }
        }
    }

    private fun connect() {
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            vpnPrepareLauncher.launch(prepareIntent)
        } else {
            startVpnService()
            requestBatteryExemption()
        }
    }

    private fun disconnect() {
        val intent = Intent(this, ChameleonVpnService::class.java)
            .setAction(ChameleonVpnService.ACTION_DISCONNECT)
        startService(intent)
    }

    /** One-time ask to be exempt from battery optimisation (Doze freezes the tunnel with the screen off). */
    private fun requestBatteryExemption() {
        val pm = getSystemService(PowerManager::class.java)
        if (pm.isIgnoringBatteryOptimizations(packageName)) return
        try {
            DiagLog.log("activity: requesting battery-optimisation exemption")
            startActivity(
                Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS)
                    .setData(Uri.parse("package:$packageName")),
            )
        } catch (t: Throwable) {
            DiagLog.log("activity: battery exemption request FAILED ${t.javaClass.simpleName}")
        }
    }

    private fun startVpnService() {
        DiagLog.log("activity: startForegroundService")
        val intent = Intent(this, ChameleonVpnService::class.java)
            .setAction(ChameleonVpnService.ACTION_CONNECT)
        ContextCompat.startForegroundService(this, intent)
    }
}

@Composable
private fun MainScreen(
    hasConfig: Boolean,
    importResult: String?,
    onImport: () -> Unit,
    onToggleConnection: (currentlyActive: Boolean) -> Unit,
) {
    val status by ChameleonVpnService.status.collectAsState()
    val active = status.connected || status.connecting
    val diag by DiagLog.lines.collectAsState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Image(
            painter = painterResource(R.drawable.ic_chameleon),
            contentDescription = "Chameleon-PQ",
            modifier = Modifier.height(96.dp),
        )
        Spacer(Modifier.height(8.dp))
        Text("Chameleon-PQ", style = MaterialTheme.typography.headlineMedium)
        Spacer(Modifier.height(24.dp))

        Button(onClick = onImport) { Text("Import config") }
        importResult?.let { Text(it, modifier = Modifier.padding(top = 8.dp)) }

        Spacer(Modifier.height(24.dp))

        Text(
            when {
                status.reconnecting -> "Reconnecting…"
                status.connecting -> "Connecting…"
                status.connected -> "Connected"
                else -> "Disconnected"
            },
        )
        if (status.connected) {
            Text("↑ ${status.txBytes} bytes   ↓ ${status.rxBytes} bytes")
        }
        status.error?.let { Text("Error: $it") }

        Spacer(Modifier.height(16.dp))

        Button(onClick = { onToggleConnection(active) }, enabled = hasConfig) {
            Text(if (active) "Disconnect" else "Connect")
        }
        if (!hasConfig) {
            Text("Import a config first", modifier = Modifier.padding(top = 8.dp))
        }

        Spacer(Modifier.height(16.dp))
        val clipboard = LocalClipboardManager.current
        val logScroll = rememberScrollState()
        LaunchedEffect(diag.size, diag.lastOrNull()) { logScroll.scrollTo(logScroll.maxValue) }
        Text(
            diag.joinToString("\n"),
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
            modifier = Modifier
                .fillMaxWidth()
                .height(200.dp)
                .verticalScroll(logScroll),
        )
        Button(onClick = { clipboard.setText(AnnotatedString(diag.joinToString("\n"))) }) {
            Text("Copy log")
        }
    }
}
