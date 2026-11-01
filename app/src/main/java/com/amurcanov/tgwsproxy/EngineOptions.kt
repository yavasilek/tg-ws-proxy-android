package com.amurcanov.tgwsproxy

import org.json.JSONObject

data class EngineOptions(
    val h2: Boolean = true,
    val noSecure: Boolean = false,
    val workers: String = "",
    val fakeTls: String = "",
    val testDc: Boolean = false,
    val proxyProtocol: Boolean = false,
    val bufferKb: Int = 256
) {
    fun toJson(): String = JSONObject().apply {
        put("h2", h2); put("noSecure", noSecure); put("workers", workers)
        put("fakeTls", fakeTls); put("testDc", testDc)
        put("proxyProtocol", proxyProtocol); put("bufferKb", bufferKb)
    }.toString()

    fun isValid(): Boolean {
        fun domain(value: String): Boolean = value.length in 4..253 && value.split('.').let { labels ->
            labels.size >= 2 && labels.all { label ->
                label.length in 1..63 && label.first() != '-' && label.last() != '-' &&
                    label.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it == '-' }
            } && labels.last().length >= 2 && labels.last().any { it in 'a'..'z' || it in 'A'..'Z' }
        }
        return bufferKb in 4..4096 && (fakeTls.isBlank() || domain(fakeTls.trim())) &&
            workers.split(Regex("[,;\\s]+")).filter { it.isNotBlank() }.all(::domain)
    }

    companion object {
        fun fromJson(raw: String): EngineOptions = runCatching {
            val json = JSONObject(raw)
            EngineOptions(json.optBoolean("h2", true), json.optBoolean("noSecure", false),
                json.optString("workers"), json.optString("fakeTls"), json.optBoolean("testDc", false),
                json.optBoolean("proxyProtocol", false), json.optInt("bufferKb", 256))
        }.getOrDefault(EngineOptions())
    }
}
