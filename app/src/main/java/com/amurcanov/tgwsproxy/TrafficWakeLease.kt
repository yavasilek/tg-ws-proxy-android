package com.amurcanov.tgwsproxy

/** Uses elapsed time and exact counters, so an idle open TCP connection cannot hold the CPU forever. */
class TrafficWakeLease {
    private var lastUp = 0L
    private var lastDown = 0L
    private var lastActive = 0
    private var until = 0L

    fun update(now: Long, online: Boolean, active: Int, up: Long, down: Long): Boolean {
        if (!online || active == 0) until = 0L
        else if (active > lastActive || up != lastUp || down != lastDown) until = now + 30_000L
        lastUp = up
        lastDown = down
        lastActive = if (online) active else 0
        return online && active > 0 && now < until
    }
}
