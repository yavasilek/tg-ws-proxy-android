package com.amurcanov.tgwsproxy

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Handler
import android.os.Looper

data class NetworkSnapshot(val route: String?, val available: Boolean, val validated: Boolean) {
    fun needsRecoveryAfter(previous: NetworkSnapshot): Boolean = available &&
        (!previous.available || route != previous.route)
}

/** Observes the app default route, including VPNs; never forces a physical network. */
class NetworkMonitor(context: Context, private val changed: (NetworkSnapshot) -> Unit) {
    private val context = context.applicationContext
    private val manager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    private val handler = Handler(Looper.getMainLooper())
    private var registered = false
    private var current: Network? = null
    private var blocked = false
    private var latest = NetworkSnapshot(null, false, false)
    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            handler.post {
                if (registered && current != network) { current = network; blocked = false }
            }
        }
        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
            val snapshot = NetworkSnapshot(network.toString(),
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET),
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED))
            handler.post {
                if (registered && current == network) {
                    latest = snapshot
                    changed(snapshot.copy(available = snapshot.available && !blocked))
                }
            }
        }
        override fun onBlockedStatusChanged(network: Network, isBlocked: Boolean) {
            handler.post {
                if (registered && current == network) {
                    blocked = isBlocked
                    changed(latest.copy(available = latest.available && !blocked))
                }
            }
        }
        override fun onLost(network: Network) {
            handler.post {
                if (registered && current == network) {
                    current = null
                    changed(NetworkSnapshot(null, false, false))
                }
            }
        }
    }
    private val legacyReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) { if (registered) changed(snapshot()) }
    }

    @Suppress("DEPRECATION")
    private fun snapshot(): NetworkSnapshot {
        if (Build.VERSION.SDK_INT >= 23) {
            val network = manager.activeNetwork
            current = network
            val caps = manager.getNetworkCapabilities(network)
            return NetworkSnapshot(network?.toString(),
                caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true,
                caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true)
        }
        val info = manager.activeNetworkInfo
        val route = manager.allNetworks.firstOrNull {
            val candidate = manager.getNetworkInfo(it)
            candidate?.isConnected == true && candidate.type == info?.type
        }
        return NetworkSnapshot(route?.toString(), info?.isConnected == true, false)
    }

    @Suppress("DEPRECATION")
    fun start() {
        if (registered) return
        registered = true
        if (Build.VERSION.SDK_INT >= 24) manager.registerDefaultNetworkCallback(callback)
        else context.registerReceiver(legacyReceiver, IntentFilter(ConnectivityManager.CONNECTIVITY_ACTION))
        latest = snapshot()
        changed(latest)
    }

    fun stop() {
        if (!registered) return
        registered = false
        if (Build.VERSION.SDK_INT >= 24) manager.unregisterNetworkCallback(callback)
        else context.unregisterReceiver(legacyReceiver)
    }
}
