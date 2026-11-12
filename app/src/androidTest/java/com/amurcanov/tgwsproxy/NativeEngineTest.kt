package com.amurcanov.tgwsproxy

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

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

    @After fun stop() { NativeProxy.stopProxy(); configure() }

    @Test fun fakeTlsRejectsAuthenticatedReplayAfterProxyRestart() {
        configure()
        NativeProxy.setFakeTlsDomain("127.0.0.1")
        val key = secret.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val hello = ByteArray(64)
        java.security.SecureRandom().nextBytes(hello)
        byteArrayOf(0x16, 3, 1, 0, 59, 1).copyInto(hello)
        hello.fill(0, 11, 48)
        val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(key, "HmacSHA256")) }
        val random = mac.doFinal(hello)
        val timestamp = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN)
            .putInt((System.currentTimeMillis() / 1000).toInt()).array()
        repeat(4) { random[28 + it] = (random[28 + it].toInt() xor timestamp[it].toInt()).toByte() }
        random.copyInto(hello, 11)
        repeat(2) { attempt ->
            val port = ServerSocket(0).use { it.localPort }
            assertEquals(0, NativeProxy.startProxy("127.0.0.1", port, "", secret, 0))
            Socket("127.0.0.1", port).use { client ->
                client.soTimeout = 5_000
                client.getOutputStream().write(hello)
                assertEquals(if (attempt == 0) 0x16 else -1, client.getInputStream().read())
            }
            assertEquals(0, NativeProxy.stopProxy())
        }
    }

    @Test fun invalidHandshakeClosesAfterTheDrainByteLimit() {
        configure()
        val port = ServerSocket(0).use { it.localPort }
        assertEquals(0, NativeProxy.startProxy("127.0.0.1", port, "", secret, 0))
        Socket("127.0.0.1", port).use { client ->
            client.soTimeout = 5_000
            client.getOutputStream().write(ByteArray(64 + 64 * 1024))
            assertEquals(-1, client.getInputStream().read())
        }
    }

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
