package com.amurcanov.tgwsproxy

import android.content.ClipData
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.PowerManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import androidx.core.content.FileProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.UUID

object SupportReport {
    @Suppress("DEPRECATION")
    private fun network(context: Context): String {
        val manager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        if (Build.VERSION.SDK_INT >= 23) {
            val caps = manager.getNetworkCapabilities(manager.activeNetwork) ?: return "none"
            val types = listOf(
                NetworkCapabilities.TRANSPORT_WIFI to "Wi-Fi", NetworkCapabilities.TRANSPORT_CELLULAR to "cellular",
                NetworkCapabilities.TRANSPORT_VPN to "VPN", NetworkCapabilities.TRANSPORT_ETHERNET to "ethernet"
            ).filter { caps.hasTransport(it.first) }.joinToString { it.second }
            return "$types, internet=${caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)}, " +
                "validated=${caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)}"
        }
        return manager.activeNetworkInfo?.let { "${it.typeName}, connected=${it.isConnected}" } ?: "none"
    }
    fun utc(time: Long): String = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US)
        .apply { timeZone = TimeZone.getTimeZone("UTC") }.format(Date(time))

    suspend fun prepare(context: Context, store: SettingsStore, note: String): String = withContext(Dispatchers.IO) {
        if (ProxyService.isRunning.value) LogManager.captureNative()
        val options = store.engineOptions.first()
        val stats = if (ProxyService.isRunning.value) runCatching { NativeProxy.getStats() }.getOrNull() else null
        val settings = "Cloudflare=${store.cfproxyEnabled.first()}, pool=${store.poolSize.first()}, " +
            "port=${store.port.first().toIntOrNull() ?: "invalid"}, " +
            "h2=${options.h2}, noSecure=${options.noSecure}, testDc=${options.testDc}, " +
            "proxyProtocol=${options.proxyProtocol}, bufferKb=${options.bufferKb}, " +
            "workersConfigured=${options.workers.isNotBlank()}, fakeTlsConfigured=${options.fakeTls.isNotBlank()}, " +
            "valid=${options.isValid()}"
        val power = context.getSystemService(Context.POWER_SERVICE) as PowerManager
        render(
            "TG WS Proxy support report v1\nReport ID: ${UUID.randomUUID()}\nCreated UTC: ${utc(System.currentTimeMillis())}\n" +
                "App: ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE}), ${BuildConfig.BUILD_TYPE}\n" +
                "Engine: Rust / Flowseal ${BuildConfig.UPSTREAM_VERSION}\n" +
                "Android: ${Build.VERSION.RELEASE} / API ${Build.VERSION.SDK_INT}\n" +
                "Device: ${Build.MANUFACTURER} ${Build.MODEL}\nABI: ${Build.SUPPORTED_ABIS.joinToString()}\n" +
                "State: ${ProxyService.connectionState.value}\nNetwork: ${network(context)}\n" +
                "Power saver: ${power.isPowerSaveMode}, screenOn=${power.isInteractive}\n" +
                "$settings\nStats: ${stats ?: "unavailable"}",
                // No SSID, network handle, serial, Android ID, fingerprint or custom domain values.
            note.take(2000), LogManager.logs.value
        )
    }

    internal fun render(header: String, note: String, entries: List<LogEntry>): String = LogPrivacy.sanitize(buildString {
        appendLine(header)
        appendLine("\nUser description:\n${note.ifBlank { "not provided" }}")
        appendLine("\nRecent events (oldest first, UTC; maximum 500):")
        if (entries.isEmpty()) appendLine("Journal is empty")
        for (entry in entries.takeLast(500)) {
            val level = when (entry.priority) { 6 -> "ERROR"; 5 -> "WARN"; 3 -> "DEBUG"; else -> "INFO" }
            appendLine("${utc(entry.timestamp)} [$level] ${entry.message}${if (entry.count > 1) " (x${entry.count})" else ""}")
        }
        appendLine("\nPrivacy: common credentials, URLs, addresses and domains are redacted. Review this report before sharing.")
    })

    fun shareIntent(context: Context, report: String): Intent {
        val directory = File(context.cacheDir, "support-reports").apply { mkdirs() }
        directory.listFiles()?.filter { it.name.startsWith("tgws-support-") }?.sortedByDescending { it.lastModified() }
            ?.drop(2)?.forEach { it.delete() }
        val file = File(directory, "tgws-support-${UUID.randomUUID()}.txt")
        file.writeText(LogPrivacy.sanitize(report), Charsets.UTF_8)
        val uri = FileProvider.getUriForFile(context, "${BuildConfig.APPLICATION_ID}.diagnostics", file)
        return Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_STREAM, uri)
            clipData = ClipData.newRawUri("TG WS Proxy support report", uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
    }
}
