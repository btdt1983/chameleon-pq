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
    // Written from Dispatchers.IO/Main (both routed through this instance's
    // single serviceScope, so no risk of a torn write), but ALSO read/written
    // from onDestroy/onRevoke, which run on whatever thread the system
    // dispatches them on — @Volatile costs nothing and closes that gap.
    @Volatile private var pfd: ParcelFileDescriptor? = null
    @Volatile private var statusJob: kotlinx.coroutines.Job? = null

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
        DiagLog.init(this)
        DiagLog.log("service: onStartCommand action=${intent?.action}")
        if (intent?.action == ACTION_DISCONNECT) {
            stopTunnel()
        } else {
            startTunnel()
        }
        return START_NOT_STICKY
    }

    private fun startTunnel() {
        try {
            ensureNotificationChannel()
            showForeground("Connecting…")
            DiagLog.log("service: foreground ok")
        } catch (t: Throwable) {
            DiagLog.log("service: foreground FAILED ${t.javaClass.simpleName}: ${t.message}")
            _status.value = StatusUi(error = "foreground: ${t.message}")
            stopSelf()
            return
        }
        _status.value = StatusUi(connecting = true)

        serviceScope.launch(Dispatchers.IO) {
            // Idempotent no-op if nothing is running (nativeStop handles a
            // None CLIENT cleanly) — but if the PREVIOUS session ended
            // without going through stopTunnel() (a dead-peer timeout the
            // status poller merely observed, a process restart), the Rust
            // side's single-instance CLIENT can be left stale, and
            // nativeStart below would hard-fail with "already connected"
            // forever. Clearing it first makes every connect attempt
            // self-healing instead of depending on every teardown path
            // being perfectly clean.
            try {
                DiagLog.log("start: nativeStop (clear stale)")
                NativeBridge.nativeStop()
                val configToml = ConfigStore.readConfig(this@ChameleonVpnService)
                    ?: error("no config imported")
                DiagLog.log("start: config read (${configToml.length} chars)")
                val params = TunParams.parse(NativeBridge.nativeTunParams(configToml))
                DiagLog.log("start: params ${params.address}/${params.netmask} mtu=${params.mtu} dns=${params.dns}")

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
                DiagLog.log("start: tun established fd=${established.fd}")

                DiagLog.log("start: nativeStart (handshake)…")
                val ok = NativeBridge.nativeStart(established.fd, configToml)
                if (!ok) error("nativeStart reported failure")
                DiagLog.log("start: nativeStart OK")

                _status.value = StatusUi(connected = true)
                withContext(Dispatchers.Main) { showForeground("Connected") }
                startStatusPolling()
            } catch (t: Throwable) {
                DiagLog.log("start: FAILED ${t.javaClass.simpleName}: ${t.message}")
                stopTunnel(reason = "${t.javaClass.simpleName}: ${t.message ?: "unknown error"}")
            }
        }
    }

    private fun startStatusPolling() {
        statusJob?.cancel()
        statusJob = serviceScope.launch(Dispatchers.IO) {
            while (isActive) {
                val s = JSONObject(NativeBridge.nativeStatus())
                val connected = s.getBoolean("connected")
                if (connected != _status.value.connected) DiagLog.log("poll: connected=$connected")
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
     * The Disconnect button's teardown path — deliberate, user/app-initiated,
     * not a forced shutdown, so it's fine for this to be async. [reason],
     * when set (a failed connect attempt cleaning up after itself), survives
     * into the status the UI reads instead of being wiped by a bare
     * `StatusUi()` reset — Phase E's failure debugging depends on this being
     * visible somewhere other than logcat.
     *
     * `nativeStop` must fully complete BEFORE `pfd.close()` — Rust's TUN read
     * task may still reference the fd until it returns (see
     * `TunPair::from_raw_fd`'s doc comment for the full reasoning). This is
     * NOT the only teardown path — see `onDestroy`/`onRevoke` for why a
     * forced shutdown can't rely on this coroutine surviving to completion.
     */
    private fun stopTunnel(reason: String? = null) {
        DiagLog.log("stopTunnel reason=$reason")
        statusJob?.cancel()
        statusJob = null
        serviceScope.launch(Dispatchers.IO) {
            NativeBridge.nativeStop()
            withContext(Dispatchers.Main) {
                pfd?.close()
                pfd = null
                _status.value = StatusUi(error = reason)
                ServiceCompat.stopForeground(
                    this@ChameleonVpnService,
                    ServiceCompat.STOP_FOREGROUND_REMOVE,
                )
                stopSelf()
            }
        }
    }

    override fun onRevoke() {
        DiagLog.log("service: onRevoke")
        // The user revoked VPN permission from system settings. Tear down
        // SYNCHRONOUSLY here rather than launching a coroutine in
        // serviceScope: the AOSP default VpnService.onRevoke() (called via
        // super below) itself calls stopSelf(), which can reach onDestroy()
        // — cancelling serviceScope — before an async job in it finishes.
        // nativeStop (abort already-running tasks + await their drop, no
        // network I/O) is expected to be fast, unlike nativeStart's real
        // handshake — an intentional, bounded exception to "never call
        // native synchronously off a background dispatcher".
        teardownSync()
        super.onRevoke()
    }

    override fun onDestroy() {
        DiagLog.log("service: onDestroy")
        // Belt and suspenders: whatever path got us here (an explicit
        // disconnect already did this and nativeStop no-ops cleanly on a
        // None CLIENT; onRevoke above already did it too; or the system is
        // killing this service directly), make sure the Rust side is torn
        // down and the fd is closed before the service is actually gone —
        // done synchronously, not via the scope this cancels next.
        teardownSync()
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun teardownSync() {
        statusJob?.cancel()
        statusJob = null
        NativeBridge.nativeStop()
        pfd?.close()
        pfd = null
        _status.value = StatusUi()
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
