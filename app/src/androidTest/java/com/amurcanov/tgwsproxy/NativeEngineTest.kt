package com.amurcanov.tgwsproxy

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.net.ServerSocket
import java.net.Socket

@RunWith(AndroidJUnit4::class)
class NativeEngineTest {
    private val secret = "0123456789abcdef0123456789abcdef"

    private fun configure() {
        NativeProxy.setPoolSize(0)
        NativeProxy.setCfProxyConfig(false, false, "")
        NativeProxy.setCfWorkerDomains("")
        NativeProxy.setFakeTlsDomain("")
        NativeProxy.setForceTestDc(false)
        NativeProxy.setProxyProtocol(false)
    }

    @After fun stop() { NativeProxy.stopProxy() }

    @Test fun startsStopsAndRebindsWhileAnIncompleteHandshakeIsConnected() {
        configure()
        val port = ServerSocket(0).use { it.localPort }
        repeat(3) {
            assertEquals(0, NativeProxy.startProxy("127.0.0.1", port, "", secret, 0))
            Socket("127.0.0.1", port).use { client ->
                assertTrue(client.isConnected)
                assertEquals(0, NativeProxy.stopProxy())
            }
            ServerSocket(port).close()
        }
    }

    @Test fun rejectsInvalidPortsAndSecrets() {
        configure()
        assertEquals(-2, NativeProxy.startProxy("127.0.0.1", 65536, "", secret, 0))
        assertEquals(-2, NativeProxy.startProxy("127.0.0.1", 1443, "", "bad", 0))
    }

    @Test fun exposesFakeTlsSecretAndCanReturnToStandardSecret() {
        configure()
        val port = ServerSocket(0).use { it.localPort }
        assertEquals(0, NativeProxy.startProxy("127.0.0.1", port, "", secret, 0))
        NativeProxy.setFakeTlsDomain("example.com")
        assertEquals("ee" + secret + "6578616d706c652e636f6d", NativeProxy.getSecretWithPrefix())
        NativeProxy.setFakeTlsDomain("")
        assertEquals("dd$secret", NativeProxy.getSecretWithPrefix())
    }

    @Test fun engineSettingsRoundTripAndValidation() {
        val value = EngineOptions(h2 = false, noSecure = true, workers = "one.example,two.example", fakeTls = "example.com", bufferKb = 512)
        assertEquals(value, EngineOptions.fromJson(value.toJson()))
        assertTrue(value.isValid())
        assertFalse(value.copy(fakeTls = "https://example.com").isValid())
        assertFalse(value.copy(bufferKb = 0).isValid())
    }

    @Test fun exportsExactTrafficCountersForPowerPolicy() {
        configure()
        val port = ServerSocket(0).use { it.localPort }
        assertEquals(0, NativeProxy.startProxy("127.0.0.1", port, "", secret, 0))
        val stats = NativeProxy.getStats().orEmpty()
        assertTrue(stats.contains("up_bytes=0"))
        assertTrue(stats.contains("down_bytes=0"))
    }
}
