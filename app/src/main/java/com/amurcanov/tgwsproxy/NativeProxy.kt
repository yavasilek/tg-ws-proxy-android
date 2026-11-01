package com.amurcanov.tgwsproxy

import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Pointer

interface ProxyLibrary : Library {
    companion object {
        val INSTANCE = Native.load("tgwsproxy", ProxyLibrary::class.java) as ProxyLibrary
    }

    fun StartProxy(host: String, port: Int, dcIps: String, secret: String, verbose: Int): Int
    fun StopProxy(): Int
    fun SetPoolSize(size: Int)
    fun SetBufferSizeKb(kb: Int)
    fun SetCfProxyCacheDir(cacheDir: String)
    fun SetCfProxyConfig(enabled: Int, priority: Int, userDomain: String)
    fun SetCfWorkerDomains(domains: String)
    fun SetFakeTlsDomain(domain: String)
    fun SetH2Enabled(v: Int)
    fun SetDisableSecure(v: Int)
    fun SetForceTestDc(v: Int)
    fun SetProxyProtocol(v: Int)
    fun GetSecretWithPrefix(): Pointer?
    fun GetStats(): Pointer?
    fun DrainLogs(): Pointer?
    fun FreeString(p: Pointer)
}

object NativeProxy {
    fun drainLogs(): String {
        val ptr = ProxyLibrary.INSTANCE.DrainLogs() ?: return ""
        return try { ptr.getString(0, "UTF-8") } finally { ProxyLibrary.INSTANCE.FreeString(ptr) }
    }

    fun startProxy(host: String, port: Int, dcIps: String, secret: String, verbose: Int): Int {
        val result = ProxyLibrary.INSTANCE.StartProxy(host, port, dcIps, secret, verbose)
        LogManager.captureNative()
        return result
    }

    fun stopProxy(): Int {
        val result = ProxyLibrary.INSTANCE.StopProxy()
        LogManager.captureNative()
        return result
    }

    fun setPoolSize(size: Int) {
        ProxyLibrary.INSTANCE.SetPoolSize(size)
    }

    fun setBufferSizeKb(kb: Int) {
        ProxyLibrary.INSTANCE.SetBufferSizeKb(kb)
    }

    fun setCfProxyCacheDir(cacheDir: String) {
        ProxyLibrary.INSTANCE.SetCfProxyCacheDir(cacheDir)
    }

    fun setCfProxyConfig(enabled: Boolean, priority: Boolean, userDomain: String) {
        ProxyLibrary.INSTANCE.SetCfProxyConfig(
            if (enabled) 1 else 0,
            if (priority) 1 else 0,
            userDomain
        )
    }

    fun setCfWorkerDomains(domains: String) {
        ProxyLibrary.INSTANCE.SetCfWorkerDomains(domains)
    }

    fun setFakeTlsDomain(domain: String) {
        ProxyLibrary.INSTANCE.SetFakeTlsDomain(domain)
    }

    fun setH2Enabled(v: Boolean) { ProxyLibrary.INSTANCE.SetH2Enabled(if (v) 1 else 0) }

    fun setDisableSecure(v: Boolean) {
        ProxyLibrary.INSTANCE.SetDisableSecure(if (v) 1 else 0)
    }

    fun setForceTestDc(v: Boolean) {
        ProxyLibrary.INSTANCE.SetForceTestDc(if (v) 1 else 0)
    }

    fun setProxyProtocol(v: Boolean) {
        ProxyLibrary.INSTANCE.SetProxyProtocol(if (v) 1 else 0)
    }

    /** Returns the full secret with correct prefix (dd or ee+domain_hex) */
    fun getSecretWithPrefix(): String? {
        val ptr = ProxyLibrary.INSTANCE.GetSecretWithPrefix() ?: return null
        val res = ptr.getString(0)
        ProxyLibrary.INSTANCE.FreeString(ptr)
        return res
    }

    fun getStats(): String? {
        val ptr = ProxyLibrary.INSTANCE.GetStats() ?: return null
        val res = ptr.getString(0)
        ProxyLibrary.INSTANCE.FreeString(ptr)
        return res
    }
}
