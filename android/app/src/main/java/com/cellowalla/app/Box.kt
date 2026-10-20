package com.cellowalla.app

import android.content.Context
import android.net.http.SslCertificate
import android.os.Build
import android.webkit.CookieManager
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager

/**
 * Which box this phone talks to, and the fingerprint of the certificate it trusted on the first
 * connection (the box makes its own certificate, so no authority can vouch for it: from then on,
 * only that exact certificate is accepted).
 */
class Box(context: Context) {
    private val prefs = context.getSharedPreferences("box", Context.MODE_PRIVATE)

    var url: String
        get() = prefs.getString("url", "") ?: ""
        set(v) = prefs.edit().putString("url", v).apply()

    /** SHA-256 of the trusted certificate, hex; "" before the first connection. */
    var pin: String
        get() = prefs.getString("pin", "") ?: ""
        set(v) = prefs.edit().putString("pin", v).apply()

    var seen: Set<String>
        get() = prefs.getStringSet("seen", emptySet()) ?: emptySet()
        set(v) = prefs.edit().putStringSet("seen", v).apply()

    val host: String? get() = runCatching { URL(url).host }.getOrNull()

    /** A request to the box with the dashboard's sign-in cookie. Throws on errors; 401 → NotSignedIn. */
    fun call(method: String, path: String, body: String? = null): JSONObject {
        val conn = URL(url.trimEnd('/') + path).openConnection() as HttpURLConnection
        if (conn is HttpsURLConnection) {
            val ctx = SSLContext.getInstance("TLS")
            ctx.init(null, arrayOf(PinnedTrust(pin)), null)
            conn.sslSocketFactory = ctx.socketFactory
            conn.hostnameVerifier = javax.net.ssl.HostnameVerifier { _, _ -> pin.isNotEmpty() } // the pin is the check
        }
        conn.requestMethod = method
        conn.connectTimeout = 8000
        conn.readTimeout = 10000
        conn.setRequestProperty("x-cellowalla", "1")
        conn.setRequestProperty("content-type", "application/json")
        CookieManager.getInstance().getCookie(url)?.let { conn.setRequestProperty("cookie", it) }
        if (body != null) { conn.doOutput = true; conn.outputStream.use { it.write(body.toByteArray()) } }
        val code = conn.responseCode
        if (code == 401) throw NotSignedIn()
        val text = (if (code < 400) conn.inputStream else conn.errorStream)?.bufferedReader()?.use { it.readText() } ?: "{}"
        val json = runCatching { JSONObject(text) }.getOrDefault(JSONObject())
        if (code >= 400) throw Exception(json.optString("error", "Error $code"))
        return json
    }

    class NotSignedIn : Exception("Open Cellowalla and sign in")

    private class PinnedTrust(private val pin: String) : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) = throw CertificateException()
        override fun checkServerTrusted(chain: Array<out X509Certificate>, authType: String?) {
            if (pin.isEmpty() || chain.isEmpty() || sha256(chain[0].encoded) != pin) throw CertificateException("Not the trusted box")
        }
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    }

    companion object {
        fun sha256(b: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(b).joinToString("") { "%02x".format(it) }

        /** The fingerprint of a certificate WebView shows us. */
        fun fingerprint(c: SslCertificate): String? {
            val x509 = if (Build.VERSION.SDK_INT >= 29) c.x509Certificate else {
                val bytes = SslCertificate.saveState(c).getByteArray("x509-certificate") ?: return null
                CertificateFactory.getInstance("X.509").generateCertificate(bytes.inputStream()) as X509Certificate
            }
            return x509?.let { sha256(it.encoded) }
        }

        /** "AB:CD:…" groups, for showing people. */
        fun pretty(hex: String) = hex.uppercase().chunked(2).joinToString(":")
    }
}
