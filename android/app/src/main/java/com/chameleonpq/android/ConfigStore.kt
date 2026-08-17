package com.chameleonpq.android

import android.content.Context
import android.net.Uri
import org.json.JSONObject
import java.io.File

/**
 * address/netmask/mtu/dns, as reported by [NativeBridge.nativeTunParams] —
 * exactly what [ChameleonVpnService] needs to build a `VpnService.Builder`.
 */
data class TunParams(
    val address: String,
    val netmask: String,
    val mtu: Int,
    val dns: List<String>,
) {
    companion object {
        fun parse(json: String): TunParams {
            val o = JSONObject(json)
            val dnsArray = o.getJSONArray("dns")
            val dns = (0 until dnsArray.length()).map { dnsArray.getString(it) }
            return TunParams(
                address = o.getString("address"),
                netmask = o.getString("netmask"),
                mtu = o.getInt("mtu"),
                dns = dns,
            )
        }
    }
}

/**
 * Reads an imported `config.toml` from wherever the document picker points
 * (a `content://` URI via Storage Access Framework — no plain filesystem
 * path), validates it via the SAME parser the tunnel itself will use
 * ([NativeBridge.nativeTunParams] — no second TOML implementation here),
 * and — only on success — persists it. This file holds private key
 * material: app-private storage only ([Context.filesDir]), never
 * external/shared storage.
 */
object ConfigStore {
    private const val FILE_NAME = "config.toml"

    fun configFile(context: Context): File = File(context.filesDir, FILE_NAME)

    fun hasConfig(context: Context): Boolean = configFile(context).exists()

    /** Reads the persisted config, or null if none has been imported yet. */
    fun readConfig(context: Context): String? =
        configFile(context).takeIf { it.exists() }?.readText()

    /**
     * Imports [uri] (from `ACTION_OPEN_DOCUMENT`): reads it, validates via
     * `nativeTunParams`, and on success persists it to app-private storage.
     * Returns the parsed [TunParams] on success; throws on failure (with a
     * message fit to show the user directly — the caller decides how).
     */
    fun importFrom(context: Context, uri: Uri): TunParams {
        val text = context.contentResolver.openInputStream(uri)?.use { stream ->
            stream.readBytes().toString(Charsets.UTF_8)
        } ?: throw IllegalArgumentException("could not open the selected file")

        // Validates AND tells us what we'll need later — one call, reusing
        // the core crate's own parser instead of a second one here.
        val params = TunParams.parse(NativeBridge.nativeTunParams(text))

        configFile(context).writeText(text)
        return params
    }
}
