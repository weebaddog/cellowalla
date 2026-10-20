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
        // Android 15+ draws apps edge to edge: keep clear of the status bar, title bar, keyboard and gesture bar.
        val tv = android.util.TypedValue()
        val barHeight = if (theme.resolveAttribute(android.R.attr.actionBarSize, tv, true)) android.util.TypedValue.complexToDimensionPixelSize(tv.data, resources.displayMetrics) else 0
        root.setOnApplyWindowInsetsListener { v, insets ->
            if (Build.VERSION.SDK_INT >= 35) {
                val bars = insets.getInsets(WindowInsets.Type.systemBars() or WindowInsets.Type.ime())
                v.setPadding(bars.left, bars.top + barHeight, bars.right, bars.bottom)
            }
            insets
        }
        setContentView(root)
        // A saved box is checked from the setup screen first, so an unreachable one shows
        // "Connecting…" and then a clear message instead of a blank screen.
        showSetup(null)
        if (box.url.isNotEmpty()) connect(box.url)
        if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
        }
        PingsWorker.schedule(this)
        SelfUpdate.schedule(this)
    }

    override fun onResume() {
        super.onResume()
        SelfUpdate.inForeground = true
        if (box.url.isNotEmpty()) Thread { runCatching { PingsWorker.check(applicationContext, box) } }.start()
    }

    override fun onPause() {
        super.onPause()
        SelfUpdate.inForeground = false
        CookieManager.getInstance().flush()
    }

    // ---- choosing the box ------------------------------------------------------------------------

    private fun dp(v: Int) = (v * resources.displayMetrics.density).toInt()

    private var errorView: TextView? = null
    private var statusView: TextView? = null
    private var input: EditText? = null
    private var foundRow: LinearLayout? = null
    private val busyButtons = mutableListOf<Button>()
    private var busy = false

    private fun showSetup(error: String?) {
        // Never destroy the WebView from inside one of its own callbacks: do it after.
        web?.let { w -> web = null; root.post { w.destroy() } }
        updateBack()
        busy = false
        actionBar?.title = "Cellowalla"
        val col = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(dp(24), dp(32), dp(24), dp(24)) }
        col.addView(TextView(this).apply { text = "Connect to your Cellowalla box"; textSize = 22f; setTextAppearance(android.R.style.TextAppearance_Material_Headline) })
        col.addView(TextView(this).apply {
            text = "Type the address the installer showed, for example 192.168.1.50, or cellowalla.lan if this phone already uses the box. Not sure? Use Find my box. You must be on your home Wi-Fi (or connected through the Tunnel)."
            setPadding(0, dp(8), 0, dp(16)); textSize = 15f
        })
        errorView = TextView(this).apply { text = error ?: ""; setTextColor(Color.rgb(229, 72, 63)); setPadding(0, 0, 0, dp(12)); visibility = if (error == null) View.GONE else View.VISIBLE }
        col.addView(errorView)
        statusView = TextView(this).apply { setPadding(0, 0, 0, dp(12)); visibility = View.GONE }
        col.addView(statusView)
        val field = EditText(this).apply {
            hint = "192.168.1.50"; setSingleLine(); inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            imeOptions = EditorInfo.IME_ACTION_GO
            setText(box.url.removePrefix("https://"))
        }
        input = field
        col.addView(field)
        // (Enter on a hardware keyboard sends both a key-down and a key-up: act once.)
        field.setOnEditorActionListener { _, action, ev -> if (ev == null || ev.action == android.view.KeyEvent.ACTION_DOWN) connect(field.text.toString()); action == EditorInfo.IME_ACTION_GO || ev != null }
        busyButtons.clear()
        col.addView(Button(this).apply { text = "Connect"; setOnClickListener { connect(field.text.toString()) } }.also { busyButtons += it })
        col.addView(Button(this).apply { text = "Find my box"; setOnClickListener { findBox() } }.also { busyButtons += it })
        foundRow = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        col.addView(foundRow)
        val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; gravity = Gravity.START }
        for ((a, label) in listOf("cellowalla.lan" to "cellowalla.lan", "192.168.50.1" to "192.168.50.1 (Gatekeeper mode)")) {
            row.addView(Button(this, null, android.R.attr.borderlessButtonStyle).apply { text = label; isAllCaps = false; setOnClickListener { field.setText(a) } })
        }
        col.addView(row)
        root.removeAllViews()
        root.addView(ScrollView(this).apply { addView(col) })
    }

    private fun setBusy(text: String?) {
        busy = text != null
        statusView?.apply { this.text = text ?: ""; visibility = if (text == null) View.GONE else View.VISIBLE }
        for (b in busyButtons) b.isEnabled = !busy
    }

    private fun showError(text: String?) {
        errorView?.apply { this.text = text ?: ""; visibility = if (text == null) View.GONE else View.VISIBLE }
    }

    private val gone get() = isFinishing || isDestroyed

    /** This phone's own IPv4 networks ("192.168.1"), for hints and for Find my box. */
    private fun localNets(): List<String> = runCatching {
        val cm = getSystemService(android.net.ConnectivityManager::class.java)
        val home = listOf(android.net.NetworkCapabilities.TRANSPORT_WIFI, android.net.NetworkCapabilities.TRANSPORT_ETHERNET, android.net.NetworkCapabilities.TRANSPORT_VPN)
        @Suppress("DEPRECATION") cm.allNetworks
            .filter { n -> cm.getNetworkCapabilities(n)?.let { c -> home.any { c.hasTransport(it) } } == true } // never mobile data
            .mapNotNull { cm.getLinkProperties(it) }.flatMap { it.linkAddresses }
            .map { it.address }.filterIsInstance<java.net.Inet4Address>()
            .filter { !it.isLoopbackAddress && !it.isLinkLocalAddress }
            .map { it.hostAddress!!.substringBeforeLast('.') }.distinct()
    }.getOrDefault(emptyList())

    private fun whyNot(host: String, error: String): String {
        val nets = localNets()
        val here = if (nets.isNotEmpty()) " This phone is on ${nets.joinToString(" and ") { "$it.x" }}, so your box's address usually starts with ${nets[0]}." else " This phone isn't on Wi-Fi right now."
        return when (error) {
            "name" -> "This phone can't find \"$host\". That name only works once your devices use the box for DNS: type the box's number address instead, or use Find my box."
            "notbox" -> "Something answered at $host, but it isn't a Cellowalla box (it may be your router).$here Try Find my box."
            "refused" -> "$host is there but isn't running Cellowalla's dashboard. Check the box finished installing."
            else -> "Nothing answered at $host. Make sure the box is switched on and this phone is on the same Wi-Fi.$here Try Find my box."
        }
    }

    private fun connect(address: String) {
        if (busy) return
        val a = address.trim()
        if (a.isEmpty()) return
        val url = runCatching { Uri.parse(if (a.startsWith("http://") || a.startsWith("https://")) a.replaceFirst("http://", "https://") else "https://$a") }.getOrNull()
        if (url?.host.isNullOrEmpty()) { showError("That doesn't look like an address."); return }
        val hostPort = "${url!!.host}${if (url.port > 0) ":${url.port}" else ""}"
        val origin = "https://$hostPort"
        showError(null)
        setBusy("Connecting to $hostPort…")
        Thread {
            val r = Box.hello(origin)
            runOnUiThread {
                if (gone) return@runOnUiThread
                setBusy(null)
                if (!r.ok) { showError(whyNot(hostPort, r.error)); return@runOnUiThread }
                val pinned = if (Uri.parse(box.url).host == url.host) box.pin else ""
                when {
                    pinned.isNotEmpty() && pinned != r.fp -> showError("$hostPort's certificate changed. If you didn't reinstall Cellowalla, something may be pretending to be your box, so the connection was refused.\n\nTo trust the new certificate, use Change box in the menu and connect again.")
                    pinned.isNotEmpty() -> { box.url = origin; showDashboard() }
                    else -> AlertDialog.Builder(this)
                        .setTitle("First connection to $hostPort")
                        .setMessage("Your box made its own certificate, so your phone can't vouch for it. If this is your Cellowalla box, trust it once; after that only this exact certificate is accepted.\n\nFingerprint:\n${Box.pretty(r.fp)}")
                        .setPositiveButton("Trust this box") { _, _ -> box.url = origin; box.pin = r.fp; showDashboard() }
                        .setNegativeButton("Cancel") { _, _ -> showError("Not connected: the box's certificate wasn't trusted.") }
                        .setCancelable(false)
                        .show()
                }
            }
        }.start()
    }

    /** Find my box: asks every address on the phone's own networks (and cellowalla.lan) at once. */
    private fun findBox() {
        if (busy) return
        showError(null)
        foundRow?.removeAllViews()
        val nets = localNets().take(2)
        if (nets.isEmpty()) { showError("This phone isn't on Wi-Fi. Join your home Wi-Fi (the one the box is on) and try again."); return }
        setBusy("Looking for your box on this network… (up to 10 seconds)")
        Thread {
            val candidates = listOf("cellowalla.lan") + nets.flatMap { n -> (1..254).map { "$n.$it" } }
            val found = java.util.Collections.synchronizedList(mutableListOf<String>())
            val pool = java.util.concurrent.Executors.newFixedThreadPool(64)
            for (h in candidates) pool.execute { if (Box.hello("https://$h", 1500).ok) found += h }
            pool.shutdown()
            pool.awaitTermination(30, java.util.concurrent.TimeUnit.SECONDS)
            runOnUiThread {
                if (gone) return@runOnUiThread
                setBusy(null)
                if (found.isEmpty()) {
                    showError("No Cellowalla box answered on ${nets.joinToString(" or ") { "$it.x" }}. Check the box is switched on and on the same Wi-Fi as this phone.")
                    return@runOnUiThread
                }
                statusView?.apply { text = if (found.size == 1) "Found your box. Tap it to connect." else "Found these boxes. Tap yours to connect."; visibility = View.VISIBLE }
                for (h in found.sorted()) foundRow?.addView(Button(this).apply { text = "Box at $h"; isAllCaps = false; setOnClickListener { input?.setText(h); connect(h) } })
            }
        }.start()
    }

    // ---- the dashboard -----------------------------------------------------------------------------

    @Suppress("SetJavaScriptEnabled")
    private fun showDashboard() {
        actionBar?.title = "Cellowalla"
        web?.let { old -> root.post { old.destroy() } }
        val w = WebView(this)
        w.settings.javaScriptEnabled = true
        w.settings.domStorageEnabled = true
        w.settings.allowFileAccess = false
        w.settings.allowContentAccess = false
        CookieManager.getInstance().setAcceptCookie(true)
        w.addJavascriptInterface(Bridge(), "CellowallaApp")
        // "Restore from a file…" in Settings: the phone's file picker.
        w.webChromeClient = object : android.webkit.WebChromeClient() {
            override fun onShowFileChooser(view: WebView, callback: android.webkit.ValueCallback<Array<Uri>>, params: FileChooserParams): Boolean {
                pendingPick?.onReceiveValue(null)
                pendingPick = callback
                return try {
                    @Suppress("DEPRECATION") startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*"), REQ_PICK)
                    true
                } catch (e: Exception) { pendingPick = null; false }
            }
        }
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
                // connect() already asked about this certificate; only the trusted one gets through.
                if (box.pin.isNotEmpty() && box.pin == fp) { handler.proceed(); return }
                handler.cancel()
                view.post {
                    if (gone) return@post
                    showSetup(if (box.pin.isEmpty()) null else "This box's certificate changed. If you didn't reinstall Cellowalla, something may be pretending to be your box, so the connection was refused.\n\nTo trust the new certificate, use Change box in the menu and connect again.")
                }
            }

            override fun doUpdateVisitedHistory(view: WebView, url: String, isReload: Boolean) { updateBack() }

            override fun onPageFinished(view: WebView, url: String) {
                view.evaluateJavascript("window.cwSetTheme && window.cwSetTheme('$themeMode', true)", null) // the app's choice wins
            }

            override fun onReceivedError(view: WebView, request: WebResourceRequest, error: WebResourceError) {
                if (request.isForMainFrame && error.errorCode != ERROR_FAILED_SSL_HANDSHAKE) {
                    val msg = "Couldn't reach ${box.url} (${error.description})."
                    view.post { if (!gone && web === view) showSetup(msg) }
                }
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

        @JavascriptInterface fun updates(): String = updatesJson()
        @JavascriptInterface fun setAutoUpdate(on: Boolean): String { SelfUpdate.setOn(this@MainActivity, on); return updatesJson() }
        /** Checks (and installs a newer signed version); the answer goes to window.cwAppUpdates. */
        @JavascriptInterface fun checkUpdates() {
            runOnUiThread { this@MainActivity.checkUpdates { web?.evaluateJavascript("window.cwAppUpdates && window.cwAppUpdates(${org.json.JSONObject.quote(updatesJson())})", null) } }
        }

        /** Saves a file the dashboard made (the box's backup) wherever the person picks. */
        @JavascriptInterface
        fun saveFile(name: String, text: String) {
            runOnUiThread {
                pendingSave = text
                @Suppress("DEPRECATION")
                startActivityForResult(Intent(Intent.ACTION_CREATE_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE)
                    .setType("application/json").putExtra(Intent.EXTRA_TITLE, name), REQ_SAVE)
            }
        }

        /** The dashboard's own theme switch was used: the app's screens follow. */
        @JavascriptInterface
        fun themeChanged(mode: String) { runOnUiThread { applyTheme(mode, fromPage = true) } }
    }

    // ---- Light / Dark / Auto ----------------------------------------------------------------------
    // One setting for the whole app: the title bar, the setup screen and the dashboard follow it.

    private val themes = listOf("auto" to "Auto (follow the phone)", "light" to "Light", "dark" to "Dark")
    private val themeMode: String get() = getSharedPreferences("ui", MODE_PRIVATE).getString("theme", "auto") ?: "auto"

    private fun applyTheme(mode: String, fromPage: Boolean = false) {
        val m = if (mode == "light" || mode == "dark") mode else "auto"
        getSharedPreferences("ui", MODE_PRIVATE).edit().putString("theme", m).apply()
        val native = {
            if (Build.VERSION.SDK_INT >= 31) {
                getSystemService(android.app.UiModeManager::class.java).setApplicationNightMode(when (m) {
                    "light" -> android.app.UiModeManager.MODE_NIGHT_NO
                    "dark" -> android.app.UiModeManager.MODE_NIGHT_YES
                    else -> android.app.UiModeManager.MODE_NIGHT_AUTO
                })
            }
        }
        val w = web
        // Tell the dashboard first (it saves the choice), then switch the app (which redraws the screen).
        if (!fromPage && w != null) w.evaluateJavascript("window.cwSetTheme && window.cwSetTheme('$m', true)") { native() } else native()
    }

    private fun chooseTheme() {
        val current = themes.indexOfFirst { it.first == themeMode }.coerceAtLeast(0)
        AlertDialog.Builder(this)
            .setTitle("Appearance")
            .setSingleChoiceItems(themes.map { it.second }.toTypedArray(), current) { d, which -> d.dismiss(); applyTheme(themes[which].first) }
            .setNegativeButton("Cancel", null)
            .show()
    }

    // ---- menu ----------------------------------------------------------------------------------------

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menu.add(0, 1, 0, "Reload")
        menu.add(0, 2, 0, "Pause Shield 15 min")
        menu.add(0, 3, 0, "Resume Shield")
        menu.add(0, 5, 0, "Appearance (light / dark)")
        menu.add(0, 6, 0, "Update automatically").isCheckable = true
        menu.add(0, 7, 0, "Check for updates")
        menu.add(0, 4, 0, "Change box")
        return true
    }

    override fun onPrepareOptionsMenu(menu: Menu): Boolean {
        menu.findItem(6)?.isChecked = SelfUpdate.isOn(this)
        return true
    }

    private fun checkUpdates(then: (String) -> Unit) {
        Thread { val msg = SelfUpdate.run(applicationContext); runOnUiThread { if (!gone) then(msg) } }.start()
    }

    /** This app's updates, for the dashboard's Settings → Updates card. */
    private fun updatesJson(): String = org.json.JSONObject()
        .put("auto", SelfUpdate.isOn(this)).put("current", SelfUpdate.versionName(this)).put("last", SelfUpdate.lastResult).toString()

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        when (item.itemId) {
            1 -> if (web != null) web?.reload() else if (box.url.isNotEmpty()) connect(box.url)
            2 -> pause(15)
            3 -> pause(0)
            4 -> { box.url = ""; box.pin = ""; showSetup(null) }
            5 -> chooseTheme()
            6 -> { SelfUpdate.setOn(this, !item.isChecked); item.isChecked = !item.isChecked; toast(if (item.isChecked) "Automatic updates on" else "Automatic updates off") }
            7 -> { toast("Checking for updates…"); checkUpdates { toast(it) } }
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

    // ---- files for Settings → Backup ------------------------------------------------------------------

    private var pendingSave: String? = null
    private var pendingPick: android.webkit.ValueCallback<Array<Uri>>? = null

    @Deprecated("Plain Activity: no Activity Result API without AndroidX")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        @Suppress("DEPRECATION") super.onActivityResult(requestCode, resultCode, data)
        val uri = if (resultCode == RESULT_OK) data?.data else null
        when (requestCode) {
            REQ_SAVE -> {
                val text = pendingSave; pendingSave = null
                if (uri != null && text != null) {
                    val ok = runCatching { contentResolver.openOutputStream(uri, "wt")!!.use { it.write(text.toByteArray()) } }.isSuccess
                    toast(if (ok) "Backup saved" else "Couldn't save the backup")
                }
            }
            REQ_PICK -> { pendingPick?.onReceiveValue(uri?.let { arrayOf(it) }); pendingPick = null }
        }
    }

    private companion object { const val REQ_SAVE = 41; const val REQ_PICK = 42 }

    // Back goes back in the dashboard first. Android 13+ (and every back gesture on Android 16) uses
    // the back dispatcher: the callback is only registered while the dashboard has somewhere to go back to.
    private var backCallback: Any? = null

    private fun updateBack() {
        if (Build.VERSION.SDK_INT < 33) return
        val want = web?.canGoBack() == true
        val have = backCallback != null
        if (want && !have) {
            val cb = android.window.OnBackInvokedCallback { web?.let { if (it.canGoBack()) it.goBack() }; updateBack() }
            onBackInvokedDispatcher.registerOnBackInvokedCallback(android.window.OnBackInvokedDispatcher.PRIORITY_DEFAULT, cb)
            backCallback = cb
        } else if (!want && have) {
            onBackInvokedDispatcher.unregisterOnBackInvokedCallback(backCallback as android.window.OnBackInvokedCallback)
            backCallback = null
        }
    }

    @Deprecated("Android 12 and older; newer versions use updateBack()")
    @Suppress("GestureBackNavigation")
    override fun onBackPressed() {
        val w = web
        if (w != null && w.canGoBack()) w.goBack() else @Suppress("DEPRECATION") super.onBackPressed()
    }
}
