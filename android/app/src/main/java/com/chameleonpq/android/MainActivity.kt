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
    private var serverAddr by mutableStateOf<String?>(null)
    private var profile by mutableStateOf(TrafficProfile.Off)

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
                serverAddr = ConfigStore.serverAddr(this)
            } catch (e: Exception) {
                importResult = "Import failed: ${e.message}"
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        DiagLog.init(this)
        DiagLog.log("activity: onCreate")

        hasConfig = ConfigStore.hasConfig(this)
        serverAddr = ConfigStore.serverAddr(this)
        profile = ProfileStore.get(this)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }

        setContent {
            ChameleonTheme {
                Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                    AppRoot(
                        hasConfig = hasConfig,
                        importResult = importResult,
                        serverAddr = serverAddr,
                        profile = profile,
                        onProfile = { selectProfile(it) },
                        onImport = { importLauncher.launch(arrayOf("*/*")) },
                        onToggleConnection = { currentlyActive ->
                            if (currentlyActive) disconnect() else connect()
                        },
                    )
                }
            }
        }
    }

    /** Saves the choice and, if a tunnel is up, switches it live via the service. */
    private fun selectProfile(p: TrafficProfile) {
        profile = p
        ProfileStore.set(this, p)
        val st = ChameleonVpnService.status.value
        if (st.connected || st.connecting) {
            startService(
                Intent(this, ChameleonVpnService::class.java)
                    .setAction(ChameleonVpnService.ACTION_SET_PROFILE),
            )
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
