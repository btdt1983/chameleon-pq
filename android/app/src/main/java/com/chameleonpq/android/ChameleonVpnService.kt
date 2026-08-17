package com.chameleonpq.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject

/**
 * Owns the actual tunnel lifecycle. `onStartCommand` runs on the main
 * thread, but [NativeBridge.nativeStart] blocks for the duration of a real
 * network handshake — every native call here runs on [Dispatchers.IO],
 * never inline, or this would ANR (see the plan's Finding 5).
 */
class ChameleonVpnService : VpnService() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var pfd: ParcelFileDescriptor? = null
    private var statusJob: kotlinx.coroutines.Job? = null

    companion object {
        const val ACTION_CONNECT = "com.chameleonpq.android.CONNECT"
        const val ACTION_DISCONNECT = "com.chameleonpq.android.DISCONNECT"
        private const val NOTIFICATION_CHANNEL_ID = "chameleon_vpn"
        private const val NOTIFICATION_ID = 1

        // The service is the single source of truth for connection state;
        // MainActivity only observes this, it never calls NativeBridge
        // directly.
        private val _status = MutableStateFlow(StatusUi())
        val status: StateFlow<StatusUi> = _status.asStateFlow()
    }

    data class StatusUi(
        val connecting: Boolean = false,
        val connected: Boolean = false,
        val txBytes: Long = 0,
        val rxBytes: Long = 0,
        val error: String? = null,
    )

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_DISCONNECT) {
            stopTunnel()
        } else {
            startTunnel()
        }
        return START_NOT_STICKY
    }

    private fun startTunnel() {
        ensureNotificationChannel()
        showForeground("Connecting…")
        _status.value = StatusUi(connecting = true)

        serviceScope.launch(Dispatchers.IO) {
            try {
                val configToml = ConfigStore.readConfig(this@ChameleonVpnService)
                    ?: error("no config imported")
                val params = TunParams.parse(NativeBridge.nativeTunParams(configToml))

                val builder = Builder()
                    .setSession("Chameleon-PQ")
                    .addAddress(params.address, netmaskToPrefixLength(params.netmask))
                    .addRoute("0.0.0.0", 0)
                    .setMtu(params.mtu)
                    // `Client::connect` binds its own UDP control-plane
                    // socket internally — Kotlin never sees that fd, so
                    // VpnService.protect() isn't an option here. Excluding
                    // this app's whole process from the 0.0.0.0/0 route
                    // above is the MVP fix: without it the tunnel's own
                    // traffic loops into itself.
                    .addDisallowedApplication(packageName)
                for (server in params.dns) {
                    builder.addDnsServer(server)
                }

                val established = builder.establish()
                    ?: error("VpnService.Builder.establish() returned null (permission revoked?)")
                pfd = established

                val ok = NativeBridge.nativeStart(established.fd, configToml)
                if (!ok) error("nativeStart reported failure")

                _status.value = StatusUi(connected = true)
                withContext(Dispatchers.Main) { showForeground("Connected") }
                startStatusPolling()
            } catch (e: Exception) {
                _status.value = StatusUi(error = e.message)
                withContext(Dispatchers.Main) {
                    showForeground("Connection failed: ${e.message}")
                }
                stopTunnel()
            }
        }
    }

    private fun startStatusPolling() {
        statusJob?.cancel()
        statusJob = serviceScope.launch(Dispatchers.IO) {
            while (isActive) {
                val s = JSONObject(NativeBridge.nativeStatus())
                val connected = s.getBoolean("connected")
                val tx = s.getLong("tx_bytes")
                val rx = s.getLong("rx_bytes")
                _status.value = StatusUi(connected = connected, txBytes = tx, rxBytes = rx)
                if (connected) {
                    withContext(Dispatchers.Main) {
                        showForeground("Connected — ↑${tx}B ↓${rx}B")
                    }
                }
                delay(1000)
            }
        }
    }

    /**
     * Same teardown [MainActivity]'s Disconnect button and [onRevoke] both
     * use. `nativeStop` must fully complete BEFORE `pfd.close()` — Rust's
     * TUN read task may still reference the fd until it returns (see
     * `TunPair::from_raw_fd`'s doc comment for the full reasoning).
     */
    private fun stopTunnel() {
        statusJob?.cancel()
        statusJob = null
        serviceScope.launch(Dispatchers.IO) {
            NativeBridge.nativeStop()
            withContext(Dispatchers.Main) {
                pfd?.close()
                pfd = null
                _status.value = StatusUi()
                ServiceCompat.stopForeground(
                    this@ChameleonVpnService,
                    ServiceCompat.STOP_FOREGROUND_REMOVE,
                )
                stopSelf()
            }
        }
    }

    override fun onRevoke() {
        // The user revoked VPN permission from system settings — same
        // teardown as an explicit disconnect.
        stopTunnel()
        super.onRevoke()
    }

    override fun onDestroy() {
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun ensureNotificationChannel() {
        val mgr = getSystemService(NotificationManager::class.java)
        if (mgr.getNotificationChannel(NOTIFICATION_CHANNEL_ID) == null) {
            mgr.createNotificationChannel(
                NotificationChannel(
                    NOTIFICATION_CHANNEL_ID,
                    "Chameleon-PQ VPN",
                    NotificationManager.IMPORTANCE_LOW,
                ),
            )
        }
    }

    private fun showForeground(text: String) {
        ServiceCompat.startForeground(
            this,
            NOTIFICATION_ID,
            buildNotification(text),
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
        )
    }

    private fun buildNotification(text: String): Notification {
        val stopIntent = Intent(this, ChameleonVpnService::class.java).setAction(ACTION_DISCONNECT)
        val stopPending = PendingIntent.getService(
            this,
            0,
            stopIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle("Chameleon-PQ")
            .setContentText(text)
            // Placeholder platform icon — swap for a real app icon before
            // any real release; not v1-blocking.
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .addAction(0, "Disconnect", stopPending)
            .build()
    }
}

/** `VpnService.Builder.addAddress` wants a CIDR prefix length, not a dotted
 *  netmask — the core config gives a dotted netmask (e.g. "255.255.255.0"). */
private fun netmaskToPrefixLength(netmask: String): Int =
    netmask.split(".").sumOf { Integer.bitCount(it.toInt()) }
