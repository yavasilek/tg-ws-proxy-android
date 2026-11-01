package com.amurcanov.tgwsproxy

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import android.os.SystemClock
import com.amurcanov.tgwsproxy.AppLog as Log
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket

enum class ConnectionState { STOPPED, STARTING, NO_NETWORK, RECONNECTING, READY, UNVERIFIED, ERROR }

class ProxyService : Service() {

    private var wakeLock: PowerManager.WakeLock? = null
    private var statsJob: Job? = null
    private var restartJob: Job? = null
    private var lastNotificationContent: String = ""
    private var lastNotificationAtMs: Long = 0L
    private var notificationStartedAtMs: Long = 0L
    @Volatile
    private var stopInProgress = false
    private val serviceScope = CoroutineScope(Dispatchers.Main.immediate + SupervisorJob())
    private var requested = false
    private var generation = 0
    private var engineReady = false
    private var recoveryPending = false
    private var restartAgain = false
    private var networkJob: Job? = null
    private var monitor: NetworkMonitor? = null
    private var network = NetworkSnapshot(null, false, false)
    private var hasNetworkSnapshot = false

    // Saved intent extras for restart on kill / onTaskRemoved
    private var lastBindIp: String = "127.0.0.1"
    private var lastPort: Int = 1443
    private var lastIps: String = ""
    private var lastPoolSize: Int = 4
    private var lastCfEnabled: Boolean = true
    private var lastCfPriority: Boolean = true
    private var lastCfDomain: String = ""
    private var lastSecretKey: String = ""
    private var lastEngineOptions: String = "{}"

    companion object {
        private val lifecycleMutex = Mutex()
        const val ACTION_START = "com.amurcanov.tgwsproxy.START"
        const val ACTION_STOP = "com.amurcanov.tgwsproxy.STOP"
        const val ACTION_RESTART = "com.amurcanov.tgwsproxy.RESTART"
        const val EXTRA_BIND_IP = "EXTRA_BIND_IP"
        const val EXTRA_PORT = "EXTRA_PORT"
        const val EXTRA_IPS = "EXTRA_IPS"
        const val EXTRA_POOL_SIZE = "EXTRA_POOL_SIZE"
        const val EXTRA_CFPROXY_ENABLED = "EXTRA_CFPROXY_ENABLED"
        const val EXTRA_CFPROXY_PRIORITY = "EXTRA_CFPROXY_PRIORITY"
        const val EXTRA_CFPROXY_DOMAIN = "EXTRA_CFPROXY_DOMAIN"
        const val EXTRA_SECRET_KEY = "EXTRA_SECRET_KEY"
        const val EXTRA_ENGINE_OPTIONS = "EXTRA_ENGINE_OPTIONS"
        
        private const val NOTIFICATION_ID = 101
        private const val CHANNEL_ID = "TG_WS_Proxy_Service_v4"
        private const val TAG = "ProxyService"

        // Bounded leases, renewed only while a client is active. Idle never holds the CPU.
        private const val WAKELOCK_TIMEOUT_MS = 30_000L

        // Stats/notification update interval
        private const val STATS_UPDATE_MS = 3_000L
        private const val NOTIFICATION_MIN_UPDATE_MS = 3_000L

        private val _isRunning = MutableStateFlow(false)
        val isRunning: StateFlow<Boolean> = _isRunning
        private val _isVerifiedRunning = MutableStateFlow(false)
        val isVerifiedRunning: StateFlow<Boolean> = _isVerifiedRunning
        private val _connectionState = MutableStateFlow(ConnectionState.STOPPED)
        val connectionState: StateFlow<ConnectionState> = _connectionState
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        monitor = NetworkMonitor(this, ::onNetworkChanged).also { it.start() }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Even a redundant start racing a stop must acknowledge startForegroundService.
        if (intent?.action == ACTION_START) promoteToForeground()
        when (intent?.action) {
            ACTION_START -> {
                Log.i(TAG, "Start requested")
                val bindIp = intent.getStringExtra(EXTRA_BIND_IP) ?: "127.0.0.1"
                val port = intent.getIntExtra(EXTRA_PORT, 1443)
                val ips = intent.getStringExtra(EXTRA_IPS) ?: ""
                val poolSize = intent.getIntExtra(EXTRA_POOL_SIZE, 4)
                val cfEnabled = intent.getBooleanExtra(EXTRA_CFPROXY_ENABLED, true)
                val cfPriority = intent.getBooleanExtra(EXTRA_CFPROXY_PRIORITY, true)
                val cfDomain = intent.getStringExtra(EXTRA_CFPROXY_DOMAIN) ?: ""
                val secretKey = intent.getStringExtra(EXTRA_SECRET_KEY) ?: ""
                startProxy(bindIp, port, ips, poolSize, cfEnabled, cfPriority, cfDomain, secretKey,
                    intent.getStringExtra(EXTRA_ENGINE_OPTIONS) ?: "{}")
            }
            ACTION_STOP -> {
                stopProxy()
            }
            ACTION_RESTART -> {
                if (requested) restartProxy()
                else serviceScope.launch { ProxyController.startFromSavedSettings(this@ProxyService) }
            }
            null -> {
                // Service restarted by system after being killed (START_REDELIVER_INTENT)
                // If we had saved params, try to restart
                if (lastPort > 0 && lastSecretKey.isNotEmpty()) {
                    Log.w(TAG, "Service restarted by system, re-starting proxy")
                    startProxy(lastBindIp, lastPort, lastIps, lastPoolSize, lastCfEnabled, lastCfPriority, lastCfDomain, lastSecretKey, lastEngineOptions)
                } else {
                    stopSelf()
                }
            }
        }
        // START_REDELIVER_INTENT: if the system kills the service, it will restart it
        // and re-deliver the last intent, so we don't lose the config.
        return START_REDELIVER_INTENT
    }

    private fun isPortAvailable(bindIp: String, port: Int): Boolean {
        return try {
            ServerSocket().use { socket ->
                socket.reuseAddress = true
                socket.bind(InetSocketAddress(InetAddress.getByName(bindIp), port))
                true
            }
        } catch (_: Exception) {
            // (Если надо, то тут может быть IOException или SecurityException) (IOException добавляет новый import так что "_", по-моему, лучше)
            return false
        }
    }


    private fun startProxy(bindIp: String, port: Int, ips: String, poolSize: Int = 4,
                           cfEnabled: Boolean = true, cfPriority: Boolean = true,
                           cfDomain: String = "", secretKey: String = "", engineOptions: String = "{}") {
        if (requested || stopInProgress) return
        requested = true
        generation++
        engineReady = false
        updateRunningState(true)
        _isVerifiedRunning.value = false
        _connectionState.value = ConnectionState.STARTING

        // Save params for restart
        lastBindIp = bindIp
        lastPort = port
        lastIps = ips
        lastPoolSize = poolSize
        lastCfEnabled = cfEnabled
        lastCfPriority = cfPriority
        lastCfDomain = cfDomain
        lastSecretKey = secretKey
        lastEngineOptions = engineOptions
        notificationStartedAtMs = System.currentTimeMillis()
        lastNotificationContent = getString(R.string.notification_starting)
        lastNotificationAtMs = notificationStartedAtMs

        promoteToForeground()

        stopInProgress = false
        val token = generation
        serviceScope.launch {
            lifecycleMutex.withLock {
                if (requested && generation == token) startEngine(token)
            }
        }
    }

    private fun promoteToForeground() {
        val notification = createNotification(lastNotificationContent.ifEmpty { getString(R.string.notification_starting) })
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }

    }

    // All native start/stop calls are serialized. Late completions cannot undo a user stop.
    private suspend fun startEngine(token: Int) {
        acquireWakeLock()
        val result = try {
            withContext(Dispatchers.IO) {
                check(isPortAvailable(lastBindIp, lastPort)) { getString(R.string.port_is_not_available, lastPort) }
                val options = EngineOptions.fromJson(lastEngineOptions)
                check(options.isValid()) { getString(R.string.invalid_network_settings) }
                NativeProxy.setH2Enabled(options.h2)
                NativeProxy.setDisableSecure(options.noSecure)
                NativeProxy.setCfWorkerDomains(options.workers)
                NativeProxy.setFakeTlsDomain(options.fakeTls.trim())
                NativeProxy.setForceTestDc(options.testDc)
                NativeProxy.setProxyProtocol(options.proxyProtocol)
                NativeProxy.setBufferSizeKb(options.bufferKb)
                NativeProxy.setPoolSize(lastPoolSize)
                NativeProxy.setCfProxyCacheDir(cacheDir.absolutePath)
                NativeProxy.setCfProxyConfig(lastCfEnabled, lastCfPriority, lastCfDomain)
                NativeProxy.startProxy(lastBindIp, lastPort, lastIps, lastSecretKey, 1)
            }
        } catch (e: Exception) {
            if (e is CancellationException) throw e
            Log.e(TAG, "Proxy start failed", e)
            -1
        } catch (e: LinkageError) {
            Log.e(TAG, "Native library could not be loaded", e)
            -1
        }
        releaseWakeLock()
        if (!requested || token != generation) return
        if (result != 0) {
            _connectionState.value = ConnectionState.ERROR
            updateNotification(getString(R.string.status_service_error), force = true)
            stopProxy(error = true)
            return
        }
        engineReady = true
        recoveryPending = networkJob?.isActive == true && recoveryPending
        Log.i(TAG, "Proxy ready: listening on port $lastPort")
        publishConnectionState()
        statsJob?.cancel()
        statsJob = serviceScope.launch {
            var active = 0
            var holdCpu = false
            val lease = TrafficWakeLease()
            while (isActive && requested && token == generation) {
                try {
                    if (engineReady) {
                        val raw = withContext(Dispatchers.IO) { NativeProxy.getStats() }
                        if (raw != null && token == generation && requested) {
                            active = extractStat(raw, "active=").toIntOrNull() ?: 0
                            holdCpu = lease.update(SystemClock.elapsedRealtime(), network.available, active,
                                extractStat(raw, "up_bytes=").toLongOrNull() ?: 0L,
                                extractStat(raw, "down_bytes=").toLongOrNull() ?: 0L)
                            if (holdCpu) acquireWakeLock() else releaseWakeLock()
                            val total = parseHumanBytes(extractStat(raw, "up=")) + parseHumanBytes(extractStat(raw, "down="))
                            val prefix = getString(connectionStatusResource(_connectionState.value))
                            updateNotification(prefix + " - " + getString(R.string.notification_traffic, formatBytes(total), active))
                        }
                    }
                } catch (e: Exception) {
                    if (e is CancellationException) throw e
                    releaseWakeLock()
                    Log.w(TAG, "Stats update failed", e)
                }
                delay(if (!network.available) 30_000L else if (!holdCpu) 15_000L else STATS_UPDATE_MS)
            }
        }
    }

    private fun onNetworkChanged(value: NetworkSnapshot) {
        val recover = hasNetworkSnapshot && value.needsRecoveryAfter(network)
        hasNetworkSnapshot = true
        network = value
        if (!requested || stopInProgress) return
        if (!value.available) {
            networkJob?.cancel()
            releaseWakeLock()
        }
        publishConnectionState()
        if (recover) {
            recoveryPending = true
            _isVerifiedRunning.value = false
            _connectionState.value = ConnectionState.RECONNECTING
            updateNotification(getString(R.string.status_reconnecting), force = true)
            networkJob?.cancel()
            networkJob = serviceScope.launch {
                delay(1_200L)
                if (requested && network.available) restartProxy()
            }
        }
    }

    private fun publishConnectionState() {
        val state = when {
            !network.available -> ConnectionState.NO_NETWORK
            !engineReady || recoveryPending -> ConnectionState.RECONNECTING
            !network.validated -> ConnectionState.UNVERIFIED
            else -> ConnectionState.READY
        }
        if (state != _connectionState.value) Log.i(TAG, "Connection state: $state")
        _connectionState.value = state
        _isVerifiedRunning.value = engineReady && network.available && state != ConnectionState.RECONNECTING
        updateNotification(getString(connectionStatusResource(state)), force = true)
    }

    private fun updateNotification(content: String, force: Boolean = false) {
        val now = System.currentTimeMillis()
        if (!force) {
            if (content == lastNotificationContent) return
            if (lastNotificationAtMs != 0L && now - lastNotificationAtMs < NOTIFICATION_MIN_UPDATE_MS) return
        }

        lastNotificationContent = content
        lastNotificationAtMs = now
        try {
            val manager = getSystemService(NOTIFICATION_SERVICE) as? NotificationManager
            manager?.notify(NOTIFICATION_ID, createNotification(content))
        } catch (e: Exception) {
            Log.w(TAG, "Failed to update notification", e)
        }
    }

    private fun restartProxy() {
        if (!requested || stopInProgress) return
        if (restartJob?.isActive == true) { restartAgain = true; return }
        recoveryPending = false
        val token = ++generation
        engineReady = false
        _isVerifiedRunning.value = false
        _connectionState.value = ConnectionState.RECONNECTING
        updateNotification(getString(R.string.status_reconnecting), force = true)
        statsJob?.cancel()
        releaseWakeLock()
        restartJob = serviceScope.launch {
            lifecycleMutex.withLock {
                if (!requested || token != generation) return@withLock
                Log.i(TAG, "Rebuilding proxy connections")
                try {
                    withContext(Dispatchers.IO) { NativeProxy.stopProxy() }
                    if (requested && token == generation) startEngine(token)
                } catch (e: Exception) {
                    if (e is CancellationException) throw e
                    Log.e(TAG, "Proxy restart failed", e)
                    stopProxy(error = true)
                }
            }
            restartJob = null
            if (restartAgain && requested && network.available) {
                restartAgain = false
                restartProxy()
            }
        }
    }

    private fun extractStat(stats: String, key: String): String {
        val idx = stats.indexOf(key)
        if (idx == -1) return "0B"
        val start = idx + key.length
        val end = stats.indexOf(" ", start)
        return if (end == -1) stats.substring(start) else stats.substring(start, end)
    }
    
    private fun parseHumanBytes(s: String): Double {
        val num = s.replace(Regex("[^0-9.]"), "").toDoubleOrNull() ?: 0.0
        return when {
            s.endsWith("TB") -> num * 1024.0 * 1024 * 1024 * 1024
            s.endsWith("GB") -> num * 1024.0 * 1024 * 1024
            s.endsWith("MB") -> num * 1024.0 * 1024
            s.endsWith("KB") -> num * 1024.0
            else -> num
        }
    }
    
    private fun formatBytes(bytes: Double): String {
        if (bytes < 1024) return "%.0fB".format(bytes)
        if (bytes < 1024 * 1024) return "%.1fKB".format(bytes / 1024)
        if (bytes < 1024 * 1024 * 1024) return "%.1fMB".format(bytes / (1024 * 1024))
        return "%.2fGB".format(bytes / (1024 * 1024 * 1024))
    }

    private fun stopProxy(error: Boolean = false) {
        if (stopInProgress) return
        requested = false
        generation++
        stopInProgress = true
        engineReady = false
        networkJob?.cancel()
        statsJob?.cancel()
        releaseWakeLock()
        _isVerifiedRunning.value = false
        _connectionState.value = if (error) ConnectionState.ERROR else ConnectionState.STOPPED
        serviceScope.launch {
            lifecycleMutex.withLock {
                try { withContext(Dispatchers.IO) { NativeProxy.stopProxy() } }
                catch (e: Exception) { Log.w(TAG, "Proxy stop failed", e) }
                catch (e: LinkageError) { Log.w(TAG, "Native library unavailable", e) }
            }
            updateRunningState(false)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) stopForeground(STOP_FOREGROUND_REMOVE)
            else { @Suppress("DEPRECATION") stopForeground(true) }
            stopSelf()
        }
    }

    /**
     * Called when the user swipes the app from recents.
     * Without this, the service would be killed on many OEM Androids.
     */
    override fun onTaskRemoved(rootIntent: Intent?) {
        super.onTaskRemoved(rootIntent)
        if (_isRunning.value) {
            Log.w(TAG, "onTaskRemoved: proxy is running, service stays alive")
            // The service continues because stopWithTask=false in manifest
            // No action needed — the service keeps running.
        }
    }

    private fun acquireWakeLock() {
        try {
            val powerManager = getSystemService(POWER_SERVICE) as PowerManager
            if (wakeLock == null) wakeLock = powerManager.newWakeLock(
                PowerManager.PARTIAL_WAKE_LOCK,
                "TgWsProxy::ServiceWakeLock"
            ).apply { setReferenceCounted(false) }
            wakeLock?.acquire(WAKELOCK_TIMEOUT_MS)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to acquire WakeLock", e)
        }
    }

    private fun releaseWakeLock() {
        try {
            wakeLock?.let {
                if (it.isHeld) {
                    it.release()
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to release WakeLock", e)
        }
        wakeLock = null
    }

    private fun updateRunningState(isRunning: Boolean) {
        _isRunning.value = isRunning
        if (!isRunning) {
            _isVerifiedRunning.value = false
        }
        ProxyTileSync.requestSync(this)
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val serviceChannel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.notification_channel_name),
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = getString(R.string.notification_channel_description)
                setShowBadge(false)
                setSound(null, null)
                enableVibration(false)
                enableLights(false)
                lockscreenVisibility = Notification.VISIBILITY_PUBLIC
            }
            val manager = getSystemService(NOTIFICATION_SERVICE) as? NotificationManager
            manager?.createNotificationChannel(serviceChannel)
        }
    }

    private fun createNotification(content: String): Notification {
        val openIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val openPendingIntent = PendingIntent.getActivity(
            this, 1, openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val stopIntent = Intent(this, ProxyService::class.java).apply {
            action = ACTION_STOP
        }
        val restartIntent = Intent(this, ProxyService::class.java).apply {
            action = ACTION_RESTART
        }
        val restartPendingIntent = PendingIntent.getService(
            this, 2, restartIntent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val stopPendingIntent = PendingIntent.getService(
            this, 0, stopIntent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Telegram WS Proxy")
            .setContentText(content)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentIntent(openPendingIntent) // Tap notification → open app
            .addAction(android.R.drawable.ic_popup_sync, getString(R.string.notification_restart), restartPendingIntent)
            .addAction(android.R.drawable.ic_menu_close_clear_cancel, getString(R.string.notification_disconnect), stopPendingIntent)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setSilent(true)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setWhen(notificationStartedAtMs.takeIf { it > 0L } ?: System.currentTimeMillis())
            .setShowWhen(false)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .build()
    }

    override fun onDestroy() {
        val needsCleanup = requested
        requested = false
        generation++
        monitor?.stop()
        networkJob?.cancel()
        statsJob?.cancel()
        statsJob = null
        releaseWakeLock()
        if (_isRunning.value) {
            updateRunningState(false)
        }
        serviceScope.cancel()
        // Also cover an unexpected Service destruction while a native start was in flight.
        if (needsCleanup) CoroutineScope(Dispatchers.IO).launch {
            lifecycleMutex.withLock {
                runCatching { NativeProxy.stopProxy() }
            }
        }
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? {
        return null
    }
}

fun connectionStatusResource(state: ConnectionState): Int = when (state) {
    ConnectionState.STOPPED -> R.string.status_disconnected
    ConnectionState.STARTING -> R.string.status_connecting
    ConnectionState.NO_NETWORK -> R.string.status_no_network
    ConnectionState.RECONNECTING -> R.string.status_reconnecting
    ConnectionState.READY -> R.string.status_proxy_ready
    ConnectionState.UNVERIFIED -> R.string.status_network_unverified
    ConnectionState.ERROR -> R.string.status_service_error
}
