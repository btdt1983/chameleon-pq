package com.chameleonpq.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.cancel
import kotlinx.coroutines.cancelAndJoin
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
    @Volatile private var tunnelJob: kotlinx.coroutines.Job? = null
    @Volatile private var userStopped = false
    private var netCallback: ConnectivityManager.NetworkCallback? = null
    @Volatile private var lastNetwork: Network? = null

    companion object {
        const val ACTION_CONNECT = "com.chameleonpq.android.CONNECT"
        const val ACTION_DISCONNECT = "com.chameleonpq.android.DISCONNECT"
        const val ACTION_SET_PROFILE = "com.chameleonpq.android.SET_PROFILE"
        private const val NOTIFICATION_CHANNEL_ID = "chameleon_vpn"
        private const val NOTIFICATION_ID = 1
        private val RECONNECT_BACKOFF_SECS = intArrayOf(2, 5, 10, 15, 20, 30)

        // The service is the single source of truth for connection state;
        // MainActivity only observes this, it never calls NativeBridge
        // directly.
        private val _status = MutableStateFlow(StatusUi())
        val status: StateFlow<StatusUi> = _status.asStateFlow()

        // True while the underlying (non-VPN) network is mobile data. Kept apart
        // from StatusUi, which is rebuilt every second.
        private val _onCellular = MutableStateFlow(false)
        val onCellular: StateFlow<Boolean> = _onCellular.asStateFlow()
    }

    data class StatusUi(
        val connecting: Boolean = false,
        val connected: Boolean = false,
        val reconnecting: Boolean = false,
        val txBytes: Long = 0,
        val rxBytes: Long = 0,
        /** Bytes/second over the last poll interval. */
        val txRate: Long = 0,
        val rxRate: Long = 0,
        /** Epoch millis when this session was established (0 = not connected). */
        val connectedSinceMs: Long = 0,
        /** System "Always-on VPN" / "Block connections without VPN" state (the real kill switch). */
        val alwaysOn: Boolean = false,
        val lockdown: Boolean = false,
        val error: String? = null,
    )

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        DiagLog.init(this)
        DiagLog.log("service: onStartCommand action=${intent?.action}")
        if (intent?.action == ACTION_DISCONNECT) {
            stopTunnel()
        } else if (intent?.action == ACTION_SET_PROFILE) {
            // Live switch while connected; the choice itself is already saved
            // by the UI and is re-applied on every (re)connect in connectOnce.
            val profile = ProfileStore.get(this)
            serviceScope.launch(Dispatchers.IO) {
                try {
                    NativeBridge.nativeSetProfile(profile.key)
                    DiagLog.log("profile: now ${profile.key}")
                } catch (t: Throwable) {
                    DiagLog.log("profile: FAILED ${t.javaClass.simpleName}: ${t.message}")
                }
            }
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
        userStopped = false
        registerNetworkCallback()

        tunnelJob?.cancel()
        tunnelJob = serviceScope.launch(Dispatchers.IO) { supervise() }
    }

    /**
     * Keeps the tunnel up. The FIRST attempt failing is reported to the user
     * and not retried (almost always a bad config or a revoked permission —
     * retrying would just spin). Once a session has been established, any
     * loss (the Rust dead-peer timeout) tears down and reconnects with
     * backoff, because on a phone that is routine (CGNAT mappings expiring
     * while the screen is off, a server too old to follow a network change).
     */
    private suspend fun supervise() {
        var everConnected = false
        var attempt = 0
        while (!userStopped) {
            try {
                connectOnce()
                everConnected = true
                attempt = 0
                val since = System.currentTimeMillis()
                _status.value = StatusUi(connected = true, connectedSinceMs = since, alwaysOn = isAlwaysOn, lockdown = isLockdownEnabled)
                withContext(Dispatchers.Main) { showForeground("Connected") }
                val why = monitor(since)
                DiagLog.log("supervise: tunnel lost ($why)")
            } catch (e: CancellationException) {
                throw e
            } catch (t: Throwable) {
                DiagLog.log("start: FAILED ${t.javaClass.simpleName}: ${t.message}")
                if (!everConnected) {
                    stopTunnel(reason = "${t.javaClass.simpleName}: ${t.message ?: "unknown error"}")
                    return
                }
            }
            if (userStopped) return
            // Stop the native client but KEEP the tun interface (and with it the
            // 0.0.0.0/0 route) established: nothing reads it, so apps' packets
            // are dropped instead of leaking onto the open network while we
            // reconnect. This is a kill switch in its own right.
            NativeBridge.nativeStop()
            _status.value = StatusUi(connecting = true, reconnecting = true, alwaysOn = isAlwaysOn, lockdown = isLockdownEnabled)
            withContext(Dispatchers.Main) { showForeground("Reconnecting…") }
            // The server refuses a new handshake while it still holds the old
            // session (it declares it dead after ~60s of silence), so early
            // retries may be rejected; keep trying.
            val wait = RECONNECT_BACKOFF_SECS[minOf(attempt, RECONNECT_BACKOFF_SECS.size - 1)]
            attempt++
            DiagLog.log("supervise: reconnect attempt $attempt in ${wait}s")
            delay(wait * 1000L)
        }
    }

    private suspend fun connectOnce() {
        // Idempotent no-op if nothing is running (nativeStop handles a None
        // CLIENT cleanly); clears a stale single-instance CLIENT so nativeStart
        // can never hard-fail with "already connected" forever.
        DiagLog.log("start: nativeStop (clear stale)")
        NativeBridge.nativeStop()
        val configToml = ConfigStore.readConfig(this@ChameleonVpnService)
            ?: error("no config imported")
        // The profile chosen in the UI wins over the config's, on every (re)connect.
        NativeBridge.nativeSetProfile(ProfileStore.get(this@ChameleonVpnService).key)
        // Reconnects reuse the tun established by the first attempt (see
        // `supervise`): only a missing tun gets (re)built here.
        pfd?.let { existing ->
            DiagLog.log("start: reusing tun fd=${existing.fd}")
            DiagLog.log("start: nativeStart (handshake)…")
            if (!NativeBridge.nativeStart(existing.fd, configToml)) error("nativeStart reported failure")
            DiagLog.log("start: nativeStart OK")
            return
        }
        DiagLog.log("start: config read (${configToml.length} chars)")
        val params = TunParams.parse(NativeBridge.nativeTunParams(configToml))
        DiagLog.log("start: params ${params.address}/${params.netmask} mtu=${params.mtu} dns=${params.dns}")

        val builder = Builder()
            .setSession("Chameleon-PQ")
            .addAddress(params.address, netmaskToPrefixLength(params.netmask))
            .addRoute("0.0.0.0", 0)
            .setMtu(params.mtu)
            // `Client::connect` binds its own UDP control-plane socket
            // internally — Kotlin never sees that fd, so VpnService.protect()
            // isn't an option here. Excluding this app's whole process from the
            // 0.0.0.0/0 route above is the MVP fix: without it the tunnel's own
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
    }

    /** Polls the native status until the tunnel is lost; returns why. */
    private suspend fun monitor(since: Long): String {
        var prevTx = -1L
        var prevRx = -1L
        var prevAt = 0L
        while (true) {
            val s = JSONObject(NativeBridge.nativeStatus())
            if (!s.getBoolean("connected")) return "native reports disconnected"
            val tx = s.getLong("tx_bytes")
            val rx = s.getLong("rx_bytes")
            val now = System.nanoTime()
            val dt = if (prevAt == 0L) 0.0 else (now - prevAt) / 1e9
            val txRate = if (dt > 0 && tx >= prevTx) ((tx - prevTx) / dt).toLong() else 0L
            val rxRate = if (dt > 0 && rx >= prevRx) ((rx - prevRx) / dt).toLong() else 0L
            prevTx = tx; prevRx = rx; prevAt = now
            _status.value = StatusUi(
                connected = true, txBytes = tx, rxBytes = rx, txRate = txRate, rxRate = rxRate,
                connectedSinceMs = since, alwaysOn = isAlwaysOn, lockdown = isLockdownEnabled,
            )
            withContext(Dispatchers.Main) {
                showForeground("Connected — ↓${formatRate(rxRate)}  ↑${formatRate(txRate)}")
            }
            delay(1000)
        }
    }

    private fun registerNetworkCallback() {
        if (netCallback != null) return
        val cm = getSystemService(ConnectivityManager::class.java)
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                // Our own VPN can show up as a network; only real underlying
                // paths matter.
                if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return
                _onCellular.value = caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
                val previous = lastNetwork
                if (previous == network) return
                lastNetwork = network
                DiagLog.log("net: default network now $network (was $previous)")
                // No reconnect here on purpose: the server follows an
                // authenticated client to its new address (roaming), so the
                // existing session simply continues. If the server is too old
                // to roam, the Rust dead-peer timeout ends the session and the
                // supervisor reconnects. A forced re-handshake now would only
                // be refused while the server still holds the old session.
            }

            override fun onLost(network: Network) {
                DiagLog.log("net: lost $network")
                if (lastNetwork == network) lastNetwork = null
            }
        }
        try {
            cm.registerDefaultNetworkCallback(cb)
            netCallback = cb
        } catch (t: Throwable) {
            DiagLog.log("net: callback registration FAILED ${t.javaClass.simpleName}: ${t.message}")
        }
    }

    private fun unregisterNetworkCallback() {
        val cb = netCallback ?: return
        netCallback = null
        lastNetwork = null
        try { getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(cb) } catch (_: Exception) { }
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
        userStopped = true
        unregisterNetworkCallback()
        val job = tunnelJob
        tunnelJob = null
        serviceScope.launch(Dispatchers.IO) {
            // The supervisor may be inside a blocking nativeStart; wait for it
            // to wind down before tearing the native side down underneath it.
            // (When the supervisor itself called us after a first-attempt
            // failure it returns right away, so the join cannot deadlock.)
            job?.cancelAndJoin()
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
        userStopped = true
        unregisterNetworkCallback()
        tunnelJob?.cancel()
        tunnelJob = null
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
