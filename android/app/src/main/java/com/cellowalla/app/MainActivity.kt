package com.cellowalla.app

import android.Manifest
import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.net.http.SslError
import android.os.Build
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.view.WindowInsets
import android.view.inputmethod.EditorInfo
import android.webkit.CookieManager
import android.webkit.JavascriptInterface
import android.webkit.SslErrorHandler
import android.webkit.WebResourceError
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Button
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.core.content.FileProvider
import java.io.File

/**
 * Cellowalla for Android: the box's dashboard in a WebView (trusting the box's own certificate
 * once, then only that one), a menu to pause Shield, Pings as notifications, and Tunnel passes
 * handed straight to the WireGuard app.
 */
class MainActivity : Activity() {
    private lateinit var box: Box
    private lateinit var root: FrameLayout
    private var web: WebView? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        box = Box(this)
        root = FrameLayout(this)
        root.setOnApplyWindowInsetsListener { v, insets ->
            val bars = if (Build.VERSION.SDK_INT >= 30) insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.ime()) else null
            if (bars != null) v.setPadding(bars.left, 0, bars.right, bars.bottom)
            else @Suppress("DEPRECATION") v.setPadding(insets.systemWindowInsetLeft, 0, insets.systemWindowInsetRight, insets.systemWindowInsetBottom)
            insets
        }
        setContentView(root)
        if (box.url.isEmpty()) showSetup(null) else showDashboard()
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
        }
        PingsWorker.schedule(this)
    }

    override fun onResume() {
        super.onResume()
        if (box.url.isNotEmpty()) Thread { runCatching { PingsWorker.check(applicationContext, box) } }.start()
    }

    override fun onPause() {
        super.onPause()
        CookieManager.getInstance().flush()
    }

    // ---- choosing the box ------------------------------------------------------------------------

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    private fun showSetup(error: String?) {
        web?.destroy(); web = null
        actionBar?.title = "Cellowalla"
        val col = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(24), dp(32), dp(24), dp(24)) }
        col.addView(TextView(this).apply { text = "Connect to your Cellowalla box"; textSize = 22f; setTextColor(Color.rgb(21, 32, 27)) })
        col.addView(TextView(this).apply {
            text = "Type the address the installer showed, for example 192.168.1.50, or cellowalla.lan if this phone already uses the box. You must be on your home Wi-Fi (or connected through the Tunnel)."
            setPadding(0, dp(8), 0, dp(16)); textSize = 15f
        })
        if (error != null) col.addView(TextView(this).apply { text = error; setTextColor(Color.rgb(179, 38, 30)); setPadding(0, 0, 0, dp(12)) })
        val input = EditText(this).apply {
            hint = "192.168.1.50"; setSingleLine(); inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            imeOptions = EditorInfo.IME_ACTION_GO
            setText(box.url.removePrefix("https://"))
        }
        col.addView(input)
        val connect = { connect(input.text.toString()) }
        input.setOnEditorActionListener { _, _, _ -> connect(); true }
        col.addView(Button(this).apply { text = "Connect"; setOnClickListener { connect() } })
        val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.START }
        for (a in listOf("cellowalla.lan", "192.168.50.1")) row.addView(Button(this, null, android.R.attr.borderlessButtonStyle).apply { text = a; isAllCaps = false; setOnClickListener { input.setText(a) } })
        col.addView(row)
        root.removeAllViews()
        root.addView(ScrollView(this).apply { addView(col) })
    }

    private fun connect(address: String) {
        val a = address.trim()
        if (a.isEmpty()) return
        val url = runCatching { Uri.parse(if (a.startsWith("http://") || a.startsWith("https://")) a else "https://$a") }.getOrNull()
        if (url?.host.isNullOrEmpty()) { toast("That doesn't look like an address."); return }
        val origin = "${url!!.scheme}://${url.host}${if (url.port > 0) ":${url.port}" else ""}"
        if (Uri.parse(box.url).host != url.host) box.pin = ""
        box.url = origin
        showDashboard()
    }

    // ---- the dashboard -----------------------------------------------------------------------------

    @Suppress("SetJavaScriptEnabled")
    private fun showDashboard() {
        actionBar?.title = "Cellowalla"
        val w = WebView(this)
        w.settings.javaScriptEnabled = true
        w.settings.domStorageEnabled = true
        w.settings.allowFileAccess = false
        w.settings.allowContentAccess = false
        CookieManager.getInstance().setAcceptCookie(true)
        w.addJavascriptInterface(Bridge(), "CellowallaApp")
        w.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                val u = request.url
                if (u.host == box.host && u.scheme == Uri.parse(box.url).scheme) return false
                runCatching { startActivity(Intent(Intent.ACTION_VIEW, u)) }
                return true
            }

            override fun onReceivedSslError(view: WebView, handler: SslErrorHandler, error: SslError) {
                val fp = error.certificate?.let { Box.fingerprint(it) }
                if (Uri.parse(error.url).host != box.host || fp == null) { handler.cancel(); return }
                when {
                    box.pin == fp -> handler.proceed()
                    box.pin.isEmpty() -> AlertDialog.Builder(this@MainActivity)
                        .setTitle("First connection to ${box.host}")
                        .setMessage("Your box made its own certificate, so your phone can't vouch for it. If this is your Cellowalla box, trust it once; after that only this exact certificate is accepted.\n\nFingerprint:\n${Box.pretty(fp)}")
                        .setPositiveButton("Trust this box") { _, _ -> box.pin = fp; handler.proceed() }
                        .setNegativeButton("Cancel") { _, _ -> handler.cancel(); showSetup(null) }
                        .setCancelable(false)
                        .show()
                    else -> {
                        handler.cancel()
                        AlertDialog.Builder(this@MainActivity)
                            .setTitle("This box's certificate changed")
                            .setMessage("If you didn't reinstall Cellowalla, something may be pretending to be your box, so the connection was refused.\n\nTo trust the new certificate, use Change box in the menu and connect again.")
                            .setPositiveButton("OK", null)
                            .show()
                    }
                }
            }

            override fun onReceivedError(view: WebView, request: WebResourceRequest, error: WebResourceError) {
                if (request.isForMainFrame && error.errorCode != ERROR_FAILED_SSL_HANDSHAKE) showSetup("Couldn't reach ${box.url} (${error.description}).")
            }
        }
        web = w
        root.removeAllViews()
        root.addView(w, ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT))
        w.loadUrl(box.url)
    }

    /** What the dashboard's JavaScript can ask the app to do. */
    inner class Bridge {
        /** Hands a Tunnel pass to the WireGuard app (or anywhere the person picks). */
        @JavascriptInterface
        fun shareConf(name: String, conf: String) {
            val dir = File(cacheDir, "passes").apply { mkdirs(); listFiles()?.forEach { it.delete() } }
            val safe = name.replace(Regex("[^A-Za-z0-9_-]"), "").take(15).ifEmpty { "cellowalla" }
            val file = File(dir, "$safe.conf").apply { writeText(conf) }
            val uri = FileProvider.getUriForFile(this@MainActivity, "com.cellowalla.app.files", file)
            val send = Intent(Intent.ACTION_SEND).apply {
                type = "application/octet-stream"
                putExtra(Intent.EXTRA_STREAM, uri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            runOnUiThread { startActivity(Intent.createChooser(send, "Add the Tunnel pass to WireGuard")) }
        }
    }

    // ---- menu ----------------------------------------------------------------------------------------

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menu.add(0, 1, 0, "Reload")
        menu.add(0, 2, 0, "Pause Shield 15 min")
        menu.add(0, 3, 0, "Resume Shield")
        menu.add(0, 4, 0, "Change box")
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        when (item.itemId) {
            1 -> if (web != null) web?.reload() else showDashboard()
            2 -> pause(15)
            3 -> pause(0)
            4 -> { box.url = ""; box.pin = ""; showSetup(null) }
        }
        return true
    }

    private fun pause(minutes: Int) {
        CookieManager.getInstance().flush()
        Thread {
            val msg = runCatching { box.call("POST", "/api/shield/pause", "{\"minutes\":$minutes}"); if (minutes > 0) "Shield paused for $minutes minutes" else "Shield is back on" }
                .getOrElse { it.message ?: "Couldn't reach the box" }
            runOnUiThread { toast(msg); web?.reload() }
        }.start()
    }

    private fun toast(s: String) = Toast.makeText(this, s, Toast.LENGTH_LONG).show()

    @Deprecated("Back goes back in the dashboard first")
    override fun onBackPressed() {
        val w = web
        if (w != null && w.canGoBack()) w.goBack() else @Suppress("DEPRECATION") super.onBackPressed()
    }
}
