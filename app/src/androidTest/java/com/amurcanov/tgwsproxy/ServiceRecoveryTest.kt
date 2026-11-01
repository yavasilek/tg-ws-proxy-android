package com.amurcanov.tgwsproxy

import android.content.Intent
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.SystemClock
import android.os.ParcelFileDescriptor
import android.os.Build
import androidx.core.content.ContextCompat
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import org.junit.Assume.assumeTrue
import org.junit.runner.RunWith
import java.net.ServerSocket
import java.net.Socket

@RunWith(AndroidJUnit4::class)
class ServiceRecoveryTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    private fun await(condition: () -> Boolean) {
        val deadline = SystemClock.elapsedRealtime() + 15_000
        while (!condition() && SystemClock.elapsedRealtime() < deadline) SystemClock.sleep(50)
        assertTrue("Condition not reached within 15 seconds", condition())
    }

    private fun command(action: String, port: Int = 1443) {
        instrumentation.runOnMainSync {
            val intent = Intent(context, ProxyService::class.java).setAction(action)
                .putExtra(ProxyService.EXTRA_PORT, port)
                .putExtra(ProxyService.EXTRA_SECRET_KEY, "0123456789abcdef0123456789abcdef")
                .putExtra(ProxyService.EXTRA_POOL_SIZE, 0)
                .putExtra(ProxyService.EXTRA_CFPROXY_ENABLED, false)
            if (action == ProxyService.ACTION_START) ContextCompat.startForegroundService(context, intent)
            else context.startService(intent)
        }
    }

    private fun shell(command: String): String = ParcelFileDescriptor.AutoCloseInputStream(
        instrumentation.uiAutomation.executeShellCommand(command)
    ).bufferedReader().use { it.readText().trim() }

    @After fun stop() {
        command(ProxyService.ACTION_STOP)
        await { !ProxyService.isRunning.value }
        SystemClock.sleep(200)
    }

    @Test fun stopDuringStartupDoesNotResurrectListener() {
        val port = ServerSocket(0).use { it.localPort }
        command(ProxyService.ACTION_START, port)
        command(ProxyService.ACTION_STOP)
        await { !ProxyService.isRunning.value }
        SystemClock.sleep(700)
        assertFalse(ProxyService.isRunning.value)
        ServerSocket(port).close()
    }

    @Test fun restartingClosesOldClientsAndRebindsWithoutUnlockingSettings() {
        val port = ServerSocket(0).use { it.localPort }
        command(ProxyService.ACTION_START, port)
        await { ProxyService.connectionState.value in setOf(ConnectionState.READY, ConnectionState.UNVERIFIED) }
        repeat(3) {
            Socket("127.0.0.1", port).use { client ->
                client.soTimeout = 8_000
                command(ProxyService.ACTION_RESTART)
                assertTrue(ProxyService.isRunning.value)
                assertEquals(-1, client.getInputStream().read())
                await { ProxyService.connectionState.value in setOf(ConnectionState.READY, ConnectionState.UNVERIFIED) }
            }
        }
    }

    @Test fun defaultRouteRecoveryIgnoresDuplicateAndValidationOnlyEvents() {
        val wifi = NetworkSnapshot("wifi", true, true)
        val cell = NetworkSnapshot("cell", true, true)
        val offline = NetworkSnapshot(null, false, false)
        assertFalse(wifi.needsRecoveryAfter(wifi))
        assertFalse(wifi.copy(validated = false).needsRecoveryAfter(wifi))
        assertTrue(cell.needsRecoveryAfter(wifi))
        assertTrue(wifi.needsRecoveryAfter(offline))
        assertFalse(offline.needsRecoveryAfter(wifi))
    }

    @Test fun idleServiceDoesNotKeepCpuAwake() {
        val port = ServerSocket(0).use { it.localPort }
        command(ProxyService.ACTION_START, port)
        await { ProxyService.connectionState.value in setOf(ConnectionState.READY, ConnectionState.UNVERIFIED) }
        val descriptor = instrumentation.uiAutomation.executeShellCommand("dumpsys power")
        val power = ParcelFileDescriptor.AutoCloseInputStream(descriptor).bufferedReader().use { it.readText() }
        assertFalse("Idle proxy is holding a partial wake lock", power.lineSequence().any {
            it.contains("PARTIAL_WAKE_LOCK") && it.contains("TgWsProxy::ServiceWakeLock")
        })
    }

    @Test fun idleOpenClientLosesWakeLeaseAndTrafficRenewsIt() {
        val lease = TrafficWakeLease()
        assertTrue(lease.update(100, true, 1, 0, 0))
        assertTrue(lease.update(29_000, true, 1, 0, 0))
        assertFalse(lease.update(30_100, true, 1, 0, 0))
        assertTrue(lease.update(40_000, true, 1, 1, 0))
        assertFalse(lease.update(40_100, false, 1, 1, 0))
        assertTrue(lease.update(41_000, true, 1, 1, 0))
        assertFalse(lease.update(41_100, true, 0, 1, 0))
    }

    @Test fun airplaneModeRecoversAndAnExplicitStopStaysStopped() {
        assumeTrue("Network toggling is allowed only on the emulator", Build.HARDWARE in setOf("ranchu", "goldfish"))
        val airplane = shell("settings get global airplane_mode_on") == "1"
        val wifi = shell("settings get global wifi_on") != "0"
        val data = shell("settings get global mobile_data") != "0"
        val port = ServerSocket(0).use { it.localPort }
        command(ProxyService.ACTION_START, port)
        await { ProxyService.isVerifiedRunning.value }
        try {
            shell("cmd connectivity airplane-mode enable")
            shell("svc wifi disable")
            shell("svc data disable")
            await { ProxyService.connectionState.value == ConnectionState.NO_NETWORK }
            assertFalse(ProxyService.isVerifiedRunning.value)
            assertTrue(ProxyService.isRunning.value)
            shell("cmd connectivity airplane-mode disable")
            shell("svc wifi enable")
            shell("svc data enable")
            await { ProxyService.isVerifiedRunning.value }
            Socket("127.0.0.1", port).close()
            shell("svc wifi disable")
            shell("svc data disable")
            await { ProxyService.connectionState.value == ConnectionState.NO_NETWORK }
            command(ProxyService.ACTION_STOP)
            await { !ProxyService.isRunning.value }
        } finally {
            shell("cmd connectivity airplane-mode " + if (airplane) "enable" else "disable")
            shell("svc wifi " + if (wifi) "enable" else "disable")
            shell("svc data " + if (data) "enable" else "disable")
        }
        SystemClock.sleep(2_000)
        assertFalse("Network return resurrected a stopped proxy", ProxyService.isRunning.value)
        ServerSocket(port).close()
    }

    @Test fun invalidFieldsAreIdentifiedAndDefaultsRecoverFromThem() {
        val invalid = EngineOptions(workers = "https://example.com", fakeTls = "host:443", bufferKb = 0)
        assertTrue(invalid.invalidWorkers())
        assertTrue(invalid.invalidFakeTls())
        assertFalse(invalid.isValid())
        assertTrue(EngineOptions().isValid())
        assertTrue(EngineOptions(workers = "a.example; b.example\nc.example", bufferKb = 4).isValid())
        assertTrue(EngineOptions(bufferKb = 4096).isValid())
        assertFalse(EngineOptions(bufferKb = 4097).isValid())
    }

    @Test fun wifiToCellularRebuildsExistingConnections() {
        assumeTrue(Build.HARDWARE in setOf("ranchu", "goldfish"))
        val wifi = shell("settings get global wifi_on") != "0"
        val data = shell("settings get global mobile_data") != "0"
        val snapshot = java.util.concurrent.atomic.AtomicReference<NetworkSnapshot?>()
        val monitor = NetworkMonitor(context) { snapshot.set(it) }
        instrumentation.runOnMainSync { monitor.start() }
        try {
            shell("svc data enable")
            shell("svc wifi enable")
            await { snapshot.get()?.available == true }
            // Wait for the actual default route, not just the Wi-Fi radio being enabled.
            val connectivity = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            await {
                val default = connectivity.activeNetwork
                connectivity.getNetworkCapabilities(default)?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true &&
                    snapshot.get()?.route == default?.toString()
            }
            val route = snapshot.get()?.route
            val port = ServerSocket(0).use { it.localPort }
            command(ProxyService.ACTION_START, port)
            await { ProxyService.isVerifiedRunning.value }
            Socket("127.0.0.1", port).use { client ->
                client.soTimeout = 15_000
                shell("svc wifi disable")
                await { snapshot.get()?.available == true && snapshot.get()?.route != route }
                assertEquals(-1, client.getInputStream().read())
                await { ProxyService.isVerifiedRunning.value }
                Socket("127.0.0.1", port).close()
            }
        } finally {
            instrumentation.runOnMainSync { monitor.stop() }
            shell("svc wifi " + if (wifi) "enable" else "disable")
            shell("svc data " + if (data) "enable" else "disable")
        }
    }
}
