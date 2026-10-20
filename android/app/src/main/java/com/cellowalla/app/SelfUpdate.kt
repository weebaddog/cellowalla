package com.cellowalla.app

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.os.Build
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.Worker
import androidx.work.WorkerParameters
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.math.BigInteger
import java.net.HttpURLConnection
import java.net.URL
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.util.concurrent.TimeUnit

/**
 * Automatic updates. cellosig.com's signed release list (release.json, signed on the owner's PC with the
 * release key) says which Cellowalla version is current and the APK's fingerprint; an update is put in
 * only if that signature checks out with the key built in here AND the download matches (and Android
 * only accepts an APK signed with Cellowalla's own key). Updates come only from the owner: nothing
 * outside this file can change the key. The first update asks you to tap Update; after that, Android
 * lets the app update itself.
 */
object SelfUpdate {
    // The same public key as cellosig.com's service worker (cellocloud/web/sw.js RELEASE_KEY).
    private const val RELEASE_KEY = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEP9FLBRIG9RyIl+JFTBhVlyFz3QPoIvpVhU1iDmnfudQa+FhQ/9xj5F3741yOZUbZggvrxO7hrBkE+UPJUhrhAQ=="
    private const val SITE = "https://cellosig.com"

    class Release(val versionCode: Int, val versionName: String, val size: Long, val sha256: String, val path: String)

    @Volatile var inForeground = false
    @Volatile var lastResult = ""

    private fun prefs(ctx: Context) = ctx.getSharedPreferences("updates", Context.MODE_PRIVATE)
    fun isOn(ctx: Context) = prefs(ctx).getBoolean("auto", true)
    fun setOn(ctx: Context, on: Boolean) = prefs(ctx).edit().putBoolean("auto", on).apply()

    fun versionCode(ctx: Context): Long = ctx.packageManager.getPackageInfo(ctx.packageName, 0).let { if (Build.VERSION.SDK_INT >= 28) it.longVersionCode else @Suppress("DEPRECATION") it.versionCode.toLong() }
    fun versionName(ctx: Context): String = ctx.packageManager.getPackageInfo(ctx.packageName, 0).versionName ?: ""

    /** The Cellowalla entry of a signed release list, or null if none; throws if the signature is wrong. */
    fun release(text: String): Release? {
        val outer = JSONObject(text)
        val payload = outer.optString("payload").ifEmpty { throw SecurityException("no release list") }
        val sig = Base64.getDecoder().decode(outer.optString("sig").ifEmpty { throw SecurityException("not signed") })
        val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(RELEASE_KEY)))
        val ok = sig.size == 64 && Signature.getInstance("SHA256withECDSA").run { initVerify(key); update(payload.toByteArray(Charsets.UTF_8)); verify(derOf(sig)) }
        if (!ok) throw SecurityException("the release list isn't signed with the release key")
        val a = JSONObject(payload).optJSONObject("apps")?.optJSONObject("cellowallaAndroid") ?: return null
        val r = Release(a.optInt("versionCode"), a.optString("versionName"), a.optLong("size"), a.optString("sha256"), a.optString("path"))
        if (r.versionCode <= 0 || r.size <= 0 || !Regex("^[0-9a-f]{64}$").matches(r.sha256) || !Regex("^/download/[\\w.-]+\\.apk$").matches(r.path)) return null
        return r
    }

    /** The signature as it's made (raw r‖s, 64 bytes) in the form Java checks (DER). */
    private fun derOf(raw: ByteArray): ByteArray {
        fun int(b: ByteArray): ByteArray { val v = BigInteger(1, b).toByteArray(); return byteArrayOf(0x02, v.size.toByte()) + v }
        val body = int(raw.copyOfRange(0, 32)) + int(raw.copyOfRange(32, 64))
        return byteArrayOf(0x30, body.size.toByte()) + body
    }

    private fun open(url: String): HttpURLConnection = (URL(url).openConnection() as HttpURLConnection).apply {
        connectTimeout = 20_000; readTimeout = 120_000; setRequestProperty("Cache-Control", "no-cache")
    }

    /** Check now; install if there's a newer signed version. Returns what happened (for the screen). Network: not on the main thread. */
    fun run(ctx: Context): String {
        val r = try {
            val c = open("$SITE/release.json")
            val text = c.inputStream.bufferedReader().use { if (c.responseCode != 200) throw IOException("release list: HTTP ${c.responseCode}"); it.readText() }
            release(text)
        } catch (e: Exception) { return "Couldn't check for updates: ${e.message}".also { lastResult = it } }
        if (r == null || r.versionCode <= versionCode(ctx)) return "Cellowalla ${versionName(ctx)} is the newest version.".also { lastResult = it }
        return try {
            install(ctx, download(ctx, r))
            "Updating to Cellowalla ${r.versionName}…"
        } catch (e: Exception) { "Couldn't update: ${e.message}" }.also { lastResult = it }
    }

    private fun download(ctx: Context, r: Release): File {
        val dir = File(ctx.cacheDir, "updates").apply { mkdirs(); listFiles()?.forEach { it.delete() } }
        val file = File(dir, "cellowalla-${r.versionCode}.apk")
        try {
            // (The fingerprint in the address: Cloudflare's cached copy of an older version is never handed out.)
            val c = open("$SITE${r.path}?v=${r.sha256.take(16)}")
            if (c.responseCode != 200) throw IOException("download: HTTP ${c.responseCode}")
            val md = MessageDigest.getInstance("SHA-256")
            var got = 0L
            c.inputStream.use { input ->
                file.outputStream().use { out ->
                    val buf = ByteArray(64 * 1024)
                    while (true) {
                        val n = input.read(buf)
                        if (n < 0) break
                        got += n
                        if (got > r.size) throw SecurityException("the download is bigger than the signed version")
                        md.update(buf, 0, n)
                        out.write(buf, 0, n)
                    }
                }
            }
            if (got != r.size || md.digest().joinToString("") { "%02x".format(it) } != r.sha256) throw SecurityException("the download doesn't match the signed version")
            return file
        } catch (e: Exception) { file.delete(); throw e }
    }

    private fun install(ctx: Context, apk: File) {
        val installer = ctx.packageManager.packageInstaller
        val params = PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL).apply {
            setAppPackageName(ctx.packageName)
            setSize(apk.length())
            if (Build.VERSION.SDK_INT >= 31) setRequireUserAction(PackageInstaller.SessionParams.USER_ACTION_NOT_REQUIRED)
        }
        val id = installer.createSession(params)
        installer.openSession(id).use { s ->
            s.openWrite("cellowalla.apk", 0, apk.length()).use { out -> apk.inputStream().use { it.copyTo(out) }; s.fsync(out) }
            val done = PendingIntent.getBroadcast(ctx, id, Intent(ctx, UpdateResultReceiver::class.java).setPackage(ctx.packageName),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE) // (mutable: Android adds the result)
            s.commit(done.intentSender)
        }
    }

    /** Twice a day in the background, while the switch is on. */
    fun schedule(ctx: Context) {
        val req = PeriodicWorkRequestBuilder<Work>(12, TimeUnit.HOURS).build()
        WorkManager.getInstance(ctx).enqueueUniquePeriodicWork("updates", ExistingPeriodicWorkPolicy.KEEP, req)
    }

    class Work(context: Context, params: WorkerParameters) : Worker(context, params) {
        override fun doWork(): Result {
            if (isOn(applicationContext)) runCatching { run(applicationContext) }
            return Result.success()
        }
    }

    internal fun notify(ctx: Context, title: String, text: String, open: PendingIntent?) {
        if (Build.VERSION.SDK_INT >= 33 && ctx.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) return
        val nm = ctx.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel("app-updates", "App updates", NotificationManager.IMPORTANCE_DEFAULT))
        val n = android.app.Notification.Builder(ctx, "app-updates").setSmallIcon(R.drawable.ic_notify).setColor(0xFF0F7A5A.toInt())
            .setContentTitle(title).setContentText(text).setStyle(android.app.Notification.BigTextStyle().bigText(text))
            .setContentIntent(open).setAutoCancel(true).build()
        nm.notify(7_200_201, n)
    }
}

/** Android's answer about an update: done, or it needs you to tap Update (the first time). */
class UpdateResultReceiver : BroadcastReceiver() {
    override fun onReceive(ctx: Context, intent: Intent) {
        if (intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE) != PackageInstaller.STATUS_PENDING_USER_ACTION) return
        val confirm = (if (Build.VERSION.SDK_INT >= 33) intent.getParcelableExtra(Intent.EXTRA_INTENT, Intent::class.java)
            else @Suppress("DEPRECATION") intent.getParcelableExtra(Intent.EXTRA_INTENT)) ?: return
        confirm.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        if (SelfUpdate.inForeground) ctx.startActivity(confirm)
        else SelfUpdate.notify(ctx, "Cellowalla update ready", "Tap to install the new version of Cellowalla.",
            PendingIntent.getActivity(ctx, 1, confirm, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT))
    }
}
