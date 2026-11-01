package com.amurcanov.tgwsproxy

import android.content.Intent
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.json.JSONArray
import java.io.File
import java.net.ServerSocket

@RunWith(AndroidJUnit4::class)
class DiagnosticLogTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test fun directServiceLogsDoNotNeedAnActivityOrLogcat() {
        LogManager.clearLogs()
        AppLog.i("ProxyService", "Proxy ready: listening on port 1443")
        assertTrue(LogManager.logs.value.any { it.message.contains("Proxy ready") && it.isEssential })
    }

    @Test fun nativeStartupLogsReachJournalWithoutSystemLogReader() {
        LogManager.clearLogs()
        val port = ServerSocket(0).use { it.localPort }
        try {
            NativeProxy.setPoolSize(0)
            NativeProxy.setCfProxyConfig(false, false, "")
            assertEquals(0, NativeProxy.startProxy("127.0.0.1", port, "", "0123456789abcdef0123456789abcdef", 1))
            assertTrue("Rust startup events missing", LogManager.logs.value.any { it.message.startsWith("Rust:") })
        } finally { NativeProxy.stopProxy() }
    }

    @Test fun redactsSecretsEndpointsAndSensitiveHeadersBeforePersistence() {
        val sensitive = listOf("0123456789abcdef0123456789abcdef", "192.168.12.34", "2001:db8::1234",
            "private.example.com", "somebody@example.com", "bearerPrivateValue", "cookiePrivateValue")
        val raw = "secret=dd${sensitive[0]} https://t.me/proxy?server=${sensitive[1]}&secret=${sensitive[0]} " +
            "[${sensitive[2]}]:443 ${sensitive[3]} ${sensitive[4]}\nAuthorization: Bearer ${sensitive[5]}\nCookie: session=${sensitive[6]}"
        LogManager.record(Log.ERROR, raw)
        LogManager.persist()
        val memory = LogManager.logs.value.last().message
        val disk = File(context.filesDir, "diagnostics/journal.json").readText()
        for (value in sensitive) {
            assertFalse("Sensitive value present in memory", memory.contains(value))
            assertFalse("Sensitive value present on disk", disk.contains(value))
        }
        assertTrue(memory.contains("[IP]"))
    }

    @Test fun journalIsBoundedAndClearAlsoUpdatesDisk() {
        LogManager.clearLogs()
        repeat(560) { LogManager.record(Log.INFO, "test event $it") }
        assertEquals(500, LogManager.logs.value.size)
        assertEquals("test event 60", LogManager.logs.value.first().message)
        LogManager.persist()
        assertEquals(500, JSONArray(File(context.filesDir, "diagnostics/journal.json").readText()).length())
        LogManager.clearLogs()
        LogManager.persist()
        assertEquals(0, JSONArray(File(context.filesDir, "diagnostics/journal.json").readText()).length())
    }

    @Test fun preparedReportIsIndependentOfDisplayFiltersAndSharedFileIsReadable() = runBlocking {
        val store = SettingsStore(context)
        store.saveLogFilters(false, false, false, true)
        LogManager.record(Log.WARN, "Support test event")
        val report = SupportReport.prepare(context, store, "Cannot connect to https://private.example.com")
        assertTrue(report.contains("Support test event"))
        assertTrue(report.contains("Created UTC:"))
        assertFalse(report.contains("private.example.com"))
        assertFalse(report.contains("Fingerprint:"))
        val intent = SupportReport.shareIntent(context, report)
        assertEquals(Intent.ACTION_SEND, intent.action)
        assertEquals("text/plain", intent.type)
        assertTrue(intent.flags and Intent.FLAG_GRANT_READ_URI_PERMISSION != 0)
        val uri = intent.clipData!!.getItemAt(0).uri
        assertEquals("content", uri.scheme)
        val fileText = context.contentResolver.openInputStream(uri)!!.bufferedReader().use { it.readText() }
        assertEquals(report, fileText)
        store.saveLogFilters(false, true, true, false)
    }

    @Test fun zzPersistsAnEventForProcessRestartVerification() {
        LogManager.record(Log.INFO, "Diagnostic persistence marker")
        LogManager.persist()
        assertTrue(File(context.filesDir, "diagnostics/journal.json").readText().contains("Diagnostic persistence marker"))
    }
}
