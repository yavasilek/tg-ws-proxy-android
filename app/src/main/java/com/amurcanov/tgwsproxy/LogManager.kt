package com.amurcanov.tgwsproxy

import android.app.Application
import android.content.Context
import android.util.AtomicFile
import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.concurrent.atomic.AtomicLong

class ProxyApplication : Application() {
    override fun onCreate() { super.onCreate(); LogManager.initialize(this) }
}

object AppLog {
    private fun emit(priority: Int, tag: String, message: String, error: Throwable?): Int {
        val detail = error?.let { throwable ->
            "\n${throwable.javaClass.simpleName}: ${throwable.message.orEmpty()}\n" +
                throwable.stackTrace.take(8).joinToString("\n") { "${it.className.substringAfterLast('.')}#${it.methodName}:${it.lineNumber}" } +
                throwable.cause?.let { "\nCause: ${it.javaClass.simpleName}: ${it.message.orEmpty()}" }.orEmpty()
        }.orEmpty()
        LogManager.record(priority, "$tag: $message$detail", essential = tag == "ProxyService")
        return Log.println(priority, tag, LogPrivacy.sanitize(message + detail).take(4096))
    }
    fun d(tag: String, message: String, error: Throwable? = null) = emit(Log.DEBUG, tag, message, error)
    fun i(tag: String, message: String, error: Throwable? = null) = emit(Log.INFO, tag, message, error)
    fun w(tag: String, message: String, error: Throwable? = null) = emit(Log.WARN, tag, message, error)
    fun e(tag: String, message: String, error: Throwable? = null) = emit(Log.ERROR, tag, message, error)
}

object LogManager {
    private const val LIMIT = 500
    private val mutableLogs = MutableStateFlow<List<LogEntry>>(emptyList())
    val logs = mutableLogs.asStateFlow()
    private val keys = AtomicLong()
    private var journal: AtomicFile? = null
    private var revision = 0L
    private var persisted = -1L
    private val nativeLock = Any()
    private val diskLock = Any()
    private var nativeErrorReported = false
    private var diskErrorReported = false
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    @Synchronized fun initialize(context: Context) {
        if (journal != null) return
        val file = File(context.filesDir, "diagnostics/journal.json")
        file.parentFile?.mkdirs()
        journal = AtomicFile(file)
        try {
            if (file.exists() && file.length() <= 8_000_000) {
                val saved = JSONArray(journal!!.openRead().bufferedReader().use { it.readText() })
                val restored = (maxOf(0, saved.length() - LIMIT) until saved.length()).map { index ->
                    val item = saved.getJSONObject(index)
                    val priority = item.getInt("priority")
                    LogEntry("log_${keys.incrementAndGet()}", LogPrivacy.sanitize(item.getString("message")).take(2048),
                        item.optInt("count", 1), priority >= Log.ERROR, priority, item.optBoolean("essential"), item.getLong("time"))
                }
                mutableLogs.value = restored
            }
        } catch (_: Exception) {
            record(Log.WARN, "Journal history could not be restored")
        }
        record(Log.INFO, "App process started - v${BuildConfig.VERSION_NAME}", essential = true)
        scope.launch {
            while (isActive) {
                if (ProxyService.isRunning.value) captureNative()
                try { persist(); diskErrorReported = false } catch (_: Exception) {
                    if (!diskErrorReported) {
                        diskErrorReported = true
                        record(Log.WARN, "Journal could not be saved")
                    }
                }
                delay(if (ProxyService.isRunning.value) 2_000L else 5_000L)
            }
        }
    }

    @Synchronized fun record(priority: Int, message: String, time: Long = System.currentTimeMillis(), essential: Boolean = false) {
        val safe = LogPrivacy.sanitize(message).take(2048).trim()
        if (safe.isBlank()) return
        val current = mutableLogs.value
        val last = current.lastOrNull()
        val entry = LogEntry("log_${keys.incrementAndGet()}", safe, 1, priority >= Log.ERROR,
            priority, essential || priority >= Log.WARN, time)
        mutableLogs.value = if (last != null && last.message == safe && last.priority == priority) {
            current.dropLast(1) + last.copy(count = last.count + 1, timestamp = time)
        } else (current + entry).takeLast(LIMIT)
        revision++
    }

    fun captureNative() = synchronized(nativeLock) {
        try {
            val raw = NativeProxy.drainLogs()
            if (raw.isBlank()) return@synchronized
            val lines = JSONArray(raw)
            for (i in 0 until lines.length()) {
                val line = lines.getJSONArray(i)
                val text = line.getString(1)
                val priority = when {
                    text.startsWith("[ERROR]") -> Log.ERROR
                    text.startsWith("[WARN]") -> Log.WARN
                    text.startsWith("[DEBUG]") -> Log.DEBUG
                    else -> Log.INFO
                }
                record(priority, "Rust: $text", line.optLong(0).takeIf { it > 0 } ?: System.currentTimeMillis())
            }
            nativeErrorReported = false
        } catch (e: Exception) { reportNativeFailure(e) }
        catch (e: LinkageError) { reportNativeFailure(e) }
    }

    private fun reportNativeFailure(error: Throwable) {
        if (!nativeErrorReported) {
            nativeErrorReported = true
            record(Log.ERROR, "Native log collector unavailable: ${error.javaClass.simpleName}")
        }
    }

    @Synchronized fun clearLogs() {
        mutableLogs.value = emptyList()
        revision++
        scope.launch {
            try { persist() } catch (_: Exception) { record(Log.WARN, "Journal could not be saved") }
        }
    }

    fun persist() = synchronized(diskLock) disk@{
        val (file, snapshot, entries) = synchronized(this) state@{
            val file = journal ?: return@state null
            if (revision == persisted) null else Triple(file, revision, logs.value)
        } ?: return@disk
        val array = JSONArray()
        for (entry in entries) array.put(JSONObject().apply {
            put("message", entry.message); put("time", entry.timestamp); put("count", entry.count)
            put("priority", entry.priority); put("essential", entry.isEssential)
        })
        val output = file.startWrite()
        try {
            output.write(array.toString().toByteArray(Charsets.UTF_8)); file.finishWrite(output)
            synchronized(this) { persisted = snapshot }
        }
        catch (error: Exception) { file.failWrite(output); throw error }
    }
}
