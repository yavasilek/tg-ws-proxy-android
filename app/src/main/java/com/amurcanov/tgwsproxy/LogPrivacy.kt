package com.amurcanov.tgwsproxy

/** Applied before display, persistence and export. Reports still have a human-readable preview. */
object LogPrivacy {
    private val rules = listOf(
        Regex("(?i)\\b(?:https?|tg|socks5?)://[^\\s<>\"']+") to "[URL]",
        Regex("(?im)\\b(?:authorization|cookie|set-cookie)\\s*[:=][^\\r\\n]*") to "[credential]",
        Regex("(?i)\\b(?:secret(?: key)?|token|password|authorization|cookie|api[_-]?key)\\s*[:=]\\s*(?:\"[^\"]*\"|'[^']*'|\\S+)") to "[credential]",
        Regex("(?i)\\b(?:dd|ee)?[0-9a-f]{32,}\\b") to "[key]",
        Regex("\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}(?::[0-9]+)?\\b") to "[IP]",
        Regex("(?i)(?<![\\w:])(?:[0-9a-f]{0,4}:){2,}[0-9a-f:.]+(?:%[\\w.-]+)?") to "[IP]",
        Regex("[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}") to "[email]",
        Regex("(?i)(?<![\\w])(?:[a-z0-9*_-]+\\.)+[a-z*]{2,}(?![\\w])") to "[domain]",
        Regex("(?i)(?:[a-z]:\\\\|/(?:data|storage|sdcard|home|Users)/)[^\\s\"']+") to "[path]",
        Regex("(?<!\\w)@[A-Za-z0-9_]{4,}") to "[username]"
    )

    fun sanitize(value: String): String {
        var safe = value
        for ((pattern, replacement) in rules) safe = pattern.replace(safe, replacement)
        return safe.replace(Regex("[\\p{Cc}&&[^\\n\\t]]"), "")
    }
}
